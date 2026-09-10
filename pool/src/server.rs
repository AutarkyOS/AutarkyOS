//! The listener, and nothing else.
//!
//! Every decision lives in `pool.rs`; this file moves bytes. The split is the
//! one `update::decide` and `code::locate` already have here, and it is what
//! lets `Pool::submit` be tested without a socket.
//!
//! ### The framing is the kernel's own
//!
//! `stratum::take_line` splits the stream, which means the pool and the miner
//! agree about what a frame is because they are running the same function --
//! including `MAX_LINE`, and including the refusal of a line longer than it.
//! A pool that framed differently from its miners would produce a connection
//! that works until somebody sends a large job and then desynchronises, which
//! is the failure mode hardest to attribute.
//!
//! ### A thread per connection, and why that is enough
//!
//! A mining connection is idle almost all of the time: a job every thirty
//! seconds and a share every few. The interesting concurrency is in the
//! miners, not here. An async runtime would be a dependency, and this
//! repository's rule about those is stated in the kernel's own manifest --
//! so a thread that sleeps in `read` is both simpler and the right shape until
//! there are enough connections for the stacks to matter.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::json::Json;
use crate::mine::proto;
use crate::mine::stratum::take_line;
use crate::budget::Budget;
use crate::pool::{Pool, Verdict};
use crate::vardiff::VarDiff;

/// How often a connection is given fresh work.
///
/// A job carries a timestamp, so re-issuing is also what stops a miner
/// searching one header forever. Short enough that a stale job never
/// accumulates much wasted work; long enough that it is not the reason a
/// yespower slice never finishes a batch.
const JOB_PERIOD: Duration = Duration::from_secs(30);

/// ### Why an unauthenticated pool needs these three numbers
///
/// Validating a share means computing it, and a yespower validation is 7.5 ms.
/// `submit` does that *before* anything has established the sender is a real
/// miner -- it cannot do otherwise, since computing the hash is how you find
/// out. So a stranger who connects, takes the job pushed at them, and submits
/// garbage nonces buys 7.5 ms of this machine's CPU per message, and one such
/// connection saturates a core at about 133 a second.
///
/// That is not a subtle hole and it is not solved by being a small target. It
/// is bounded here instead, at the connection, before the mutex is taken.
///
/// **None of this stops a distributed attack**, and on a home connection that
/// is the case that matters most: the upstream link saturates long before this
/// daemon does, and nothing running on the server can prevent that. What these
/// limits buy is that a *single* stranger cannot take the machine down by
/// accident or on a whim.
///
/// A correct miner produces zero bad shares, so thirty-two is not a tolerance
/// -- it is room for one genuine bug or one bad build before the connection is
/// dropped.
const MAX_BAD: u32 = 32;
/// A miner submitting to four coins at one share every ten seconds sends 0.4 a
/// second. Twenty is fifty times that, so it never touches a real miner, and it
/// caps one connection at 150 ms of validation per second -- fifteen percent of
/// a core even if every message is garbage.
const MAX_SUBMITS_PER_SEC: u32 = 20;
/// A `glados.work` costs one job build rather than a validation, so the bound
/// is about the job ring rather than about the CPU: `KEEP_JOBS` is 64, and a
/// connection allowed to ask freely would evict every job every other miner is
/// working. Four a second is well above what any real device needs -- an RTX
/// 3050 on sha256d spends a nonce space every eight and a half seconds, so a
/// card sixty times faster than that one is still inside this.
const MAX_WORK_PER_SEC: u32 = 4;
/// A ceiling on threads as much as on miners, and deliberately below the
/// `TasksMax=512` in the systemd unit so the daemon refuses before the service
/// manager kills it. A refusal is a log line; being killed is an outage.
const MAX_CONNECTIONS: usize = 256;

static LIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Decrements the connection count however the thread leaves -- returned,
/// errored, or panicked. A count that only decremented on the happy path would
/// drift upward until the pool refused everybody, which reads exactly like
/// being under attack.
struct ConnectionSlot;

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The pool-wide validation budget, shared by every connection.
///
/// **A `Mutex` and not an atomic**, because admitting costs a refill against
/// the clock, a lookup and a subtraction, and doing that as three atomics
/// makes an interleaving where two connections both see enough budget and both
/// spend it -- which is the bound failing exactly when it is under pressure.
/// It is held for a few hundred nanoseconds and never across a validation.
static BUDGET: Mutex<Option<Budget>> = Mutex::new(None);

/// Set the share of one core the pool may spend validating. Zero is no limit.
pub fn set_cpu_percent(percent: f64) {
    *BUDGET.lock().unwrap() = Some(Budget::new(percent));
}

/// What the budget has measured, for the operator's report.
pub fn budget_report() -> Vec<(String, f64, f64)> {
    BUDGET.lock().unwrap().as_ref().map(|b| b.report()).unwrap_or_default()
}

pub fn budget_denied() -> u64 {
    BUDGET.lock().unwrap().as_ref().map(|b| b.denied()).unwrap_or(0)
}

pub fn serve(addr: &str, pool: Arc<Mutex<Pool>>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    // Printed rather than assumed: binding is the step that fails when another
    // copy is already running, and `stratumstub.py` records what it cost to
    // have that be silent.
    println!("[pool] listening on {}", listener.local_addr()?);
    {
        let p = pool.lock().unwrap();
        for (i, c) in p.coins.iter().enumerate() {
            println!(
                "[pool] slot {i}  {}  {}  ({})",
                c.label,
                c.algo.detail(),
                c.source.name()
            );
        }
    }
    for stream in listener.incoming() {
        let stream = stream?;
        // Counted before the thread exists. Spawning first and checking inside
        // would make the ceiling a suggestion: what is being bounded is the
        // thread and its stack, and by then it is already allocated.
        if LIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
            LIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            println!("[pool] refused a connection: {MAX_CONNECTIONS} already open");
            continue;
        }
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            let _slot = ConnectionSlot;
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| String::from("?"));
            if let Err(e) = handle(stream, pool, &peer) {
                println!("[pool] {peer} closed: {e}");
            }
        });
    }
    Ok(())
}

fn handle(mut stream: TcpStream, pool: Arc<Mutex<Pool>>, peer: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(JOB_PERIOD))?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut worker = String::from("(unauthenticated)");
    let mut greeted = false;
    let mut bad: u32 = 0;
    let mut submits_this_second: u32 = 0;
    let mut works_this_second: u32 = 0;
    let mut window = Instant::now();
    // One retargeter per coin, not one per connection. A single machine works
    // several coins on different algorithms and its rate on them differs by
    // three orders of magnitude -- 248,884 H/s of sha256d beside 342 H/s of
    // yespower, measured on the kernel in one run -- so a shared difficulty
    // would be wrong for at least one of them by a factor of a thousand.
    let mut vd: Vec<VarDiff> = Vec::new();

    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            // **The timeout is the only thing that re-issues work**, and this
            // was wrong the other way first. The comment here used to argue
            // that re-issuing on every wake was needed or "a miner that talks
            // constantly works one header for as long as it keeps talking",
            // which is not a real problem -- the timeout sets the cadence and a
            // talkative miner is still on the clock.
            //
            // What it *was* is a bug the abuse check found. Every message
            // re-issued every slot, so a miner sending shares generated two
            // jobs per share; thirty-two shares against two coins pushed
            // sixty-four jobs through a sixty-four entry ring and evicted the
            // job being worked on. The miner's own submissions were then
            // answered `stale`. **A busy miner starved itself**, and the
            // busier it was the worse it got.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if greeted {
                    // The idle path is what finds a miner set *too hard*. It
                    // will never reach a share window, so without a clock the
                    // pool would wait forever to discover it asked too much.
                    for (slot, v) in vd.iter_mut().enumerate() {
                        if let Some(b) = v.on_idle() {
                            println!("[pool] {worker} slot {slot} eased to {b} bits");
                        }
                    }
                    issue_all(&mut stream, &pool, &vd)?;
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        buf.extend_from_slice(&chunk[..n]);

        loop {
            let line = match take_line(&mut buf) {
                Ok(Some(l)) => l,
                Ok(None) => break,
                // A frame longer than `MAX_LINE` is not recoverable: the stream
                // is desynchronised and everything after it is a guess.
                Err(_) => return Ok(()),
            };
            let Some(v) = Json::parse(line.trim()) else {
                continue;
            };
            let Some(method) = v.get("method").and_then(|m| m.as_str()) else {
                continue;
            };
            let id = v.get("id").and_then(|i| i.as_i64()).unwrap_or(0) as u64;
            let params = v.get("params");

            match method {
                "glados.hello" => {
                    let Some(h) = params.and_then(proto::parse_hello) else {
                        continue;
                    };
                    // Refused rather than negotiated. Two ends that disagree
                    // about the wire have nothing to talk about, and a
                    // negotiation is a code path that only runs against
                    // versions nobody has.
                    if h.v != proto::VERSION {
                        let msg = format!(
                            "{{\"id\":{id},\"result\":null,\"error\":\"protocol v{} wanted, v{} offered\"}}\n",
                            proto::VERSION,
                            h.v
                        );
                        stream.write_all(msg.as_bytes())?;
                        return Ok(());
                    }
                    worker = h.worker.clone();
                    println!("[pool] {peer} hello  worker={} agent={}", h.worker, h.agent);
                    let slots = pool.lock().unwrap().slots();
                    vd = {
                        let p = pool.lock().unwrap();
                        (0..slots as usize).map(|i| VarDiff::new(p.start_bits(i))).collect()
                    };
                    let w = proto::Welcome {
                        v: proto::VERSION,
                        slots,
                        session: format!("{peer}"),
                    };
                    stream.write_all(proto::encode_welcome(id, &w).as_bytes())?;
                    greeted = true;
                    issue_all(&mut stream, &pool, &vd)?;
                }
                "glados.submit" => {
                    // Before the greeting there is no worker to attribute a
                    // share to, so this is only ever an attempt to skip the
                    // handshake and spend CPU.
                    if !greeted {
                        return Ok(());
                    }
                    let Some(sh) = params.and_then(proto::parse_share) else {
                        continue;
                    };

                    // The rate check comes before the validation and before the
                    // mutex, which is the whole point: past this line the cost
                    // is 7.5 ms of somebody else's machine.
                    if window.elapsed() >= Duration::from_secs(1) {
                        window = Instant::now();
                        submits_this_second = 0;
                        works_this_second = 0;
                    }
                    submits_this_second += 1;
                    if submits_this_second > MAX_SUBMITS_PER_SEC {
                        // Dropped rather than answered. A reply is a second
                        // thing to send to somebody already sending too much,
                        // and a miner at this rate has a bug an error message
                        // will not fix.
                        continue;
                    }

                    // **The total bound, which the per-connection one is not.**
                    // `MAX_SUBMITS_PER_SEC` caps this connection; nothing
                    // capped two hundred and fifty-six of them, and the
                    // arithmetic that made the per-connection figure look safe
                    // was never multiplied by `MAX_CONNECTIONS`.
                    //
                    // The algorithm is looked up before validating because
                    // that is what the cost depends on -- a sha256d share is
                    // 2.4 us on the machine this was deployed to and a
                    // yespower one is 19,000.
                    let algo_name = {
                        let p = pool.lock().unwrap();
                        p.algo_of_job(&sh.job)
                    };
                    let name = algo_name.unwrap_or_else(|| String::from("?"));
                    let admitted = {
                        let mut g = BUDGET.lock().unwrap();
                        match g.as_mut() {
                            None => true,
                            Some(b) => b.admit(&name),
                        }
                    };
                    if !admitted {
                        // Dropped rather than answered, like the rate limit
                        // above and for the same reason: a reply is a second
                        // thing to send to somebody the pool is already
                        // struggling to serve. The miner treats an unanswered
                        // submit as its own category, which is what it is.
                        if bad < 4 {
                            println!("[pool] {worker} share deferred: validation budget spent");
                        }
                        continue;
                    }

                    let began = Instant::now();
                    let verdict = pool.lock().unwrap().submit(&worker, &sh);
                    // Timed here rather than estimated anywhere, because
                    // assuming this number is precisely what went wrong: the
                    // 7.5 ms in the comment above was measured on a different
                    // machine and the real one is 19 ms.
                    {
                        let took = began.elapsed().as_secs_f64() * 1e6;
                        let mut g = BUDGET.lock().unwrap();
                        if let Some(b) = g.as_mut() {
                            b.record(&name, took);
                        }
                    }
                    // Accepted shares are the record and are always logged. A
                    // refusal is logged for the first few and then counted,
                    // because at twenty a second one line each fills a journal
                    // -- and on a borrowed machine, filling somebody's disk is
                    // a worse way to fail than dropping a connection.
                    if verdict == Verdict::Accepted || bad < 4 {
                        println!(
                            "[pool] {worker} share job={} nonce={:08x} -> {}",
                            sh.job,
                            sh.nonce,
                            verdict.name()
                        );
                    }
                    let ok = verdict == Verdict::Accepted;
                    let msg = format!(
                        "{{\"id\":{id},\"result\":{{\"ok\":{ok},\"verdict\":\"{}\"}},\"error\":null}}\n",
                        verdict.name()
                    );
                    stream.write_all(msg.as_bytes())?;

                    // Retarget on accepted shares only. A stale share is work
                    // against a job that aged out and says nothing about the
                    // rate now, and counting rejected ones would let a miner
                    // talk its own difficulty upward by sending noise.
                    if verdict == Verdict::Accepted {
                        let slot = {
                            let p = pool.lock().unwrap();
                            p.slot_of_job(&sh.job)
                        };
                        if let Some(slot) = slot {
                            if let Some(v) = vd.get_mut(slot) {
                                if let Some(b) = v.on_share() {
                                    println!("[pool] {worker} slot {slot} retargeted to {b} bits");
                                    // Sent straight away rather than at the next
                                    // job period: a miner that just proved it is
                                    // fast should not spend another thirty
                                    // seconds flooding at the old difficulty.
                                    issue_all(&mut stream, &pool, &vd)?;
                                }
                            }
                        }
                    }

                    // Only `Bad` counts. `Stale` is a job that aged out and is
                    // nobody's fault, and `Duplicate` is a retry -- treating
                    // either as abuse would disconnect honest miners on a slow
                    // link, which is the failure this limit must not have.
                    if verdict == Verdict::Bad {
                        bad += 1;
                        if bad == 4 {
                            println!("[pool] {worker} is sending bad shares; quietening the log");
                        }
                        if bad > MAX_BAD {
                            println!("[pool] {worker} dropped after {bad} bad shares");
                            return Ok(());
                        }
                    }
                }
                "glados.work" => {
                    // **A job is a finite search and a fast device finishes
                    // it.** The nonce is four bytes at a fixed offset, so a job
                    // carries 2^32 hashes and nothing more; at half a gigahash
                    // a second that is eight and a half seconds against a
                    // thirty-second re-issue. Before this existed the miner
                    // wrapped and rescanned the same space, and the pool saw 35
                    // duplicates against 23 accepted shares, every repeated
                    // nonce arriving exactly six times. The duplicate counter
                    // was reporting a real defect and nobody had read it as
                    // one.
                    //
                    // One slot, not all of them. `make_job` advances the
                    // extranonce2 for an upstream coin and the job counter for
                    // a local one, so the answer is a genuinely different
                    // search either way -- and re-issuing every slot on every
                    // request is the exact shape of the churn bug the abuse
                    // test found.
                    if !greeted {
                        return Ok(());
                    }
                    if window.elapsed() >= Duration::from_secs(1) {
                        window = Instant::now();
                        submits_this_second = 0;
                        works_this_second = 0;
                    }
                    works_this_second += 1;
                    if works_this_second > MAX_WORK_PER_SEC {
                        continue;
                    }
                    let Some(slot) = params.and_then(proto::parse_work) else {
                        continue;
                    };
                    let job = {
                        let mut p = pool.lock().unwrap();
                        if slot as usize >= p.slots() as usize {
                            None
                        } else {
                            let bits = vd
                                .get(slot as usize)
                                .map(|v| v.bits())
                                .unwrap_or_else(|| p.start_bits(slot as usize));
                            p.make_job(slot, bits)
                        }
                    };
                    // Silence when there is nothing to give. An upstream coin
                    // with no template yet yields no job, and inventing one
                    // would put a miner on a search that can never pay.
                    if let Some(j) = job {
                        stream.write_all(proto::encode_job(&j).as_bytes())?;
                    }
                }
                // Unknown methods are ignored rather than refused. A miner
                // newer than this pool may greet with something extra, and
                // closing on it would make every forward-compatible addition a
                // breaking change.
                _ => {}
            }
        }
    }
}

fn issue_all(
    stream: &mut TcpStream,
    pool: &Arc<Mutex<Pool>>,
    vd: &[VarDiff],
) -> std::io::Result<()> {
    let jobs: Vec<proto::Job> = {
        let mut p = pool.lock().unwrap();
        (0..p.slots())
            .filter_map(|s| {
                // A connection that has not greeted yet has no retargeters, so
                // fall back to the coin's configured start rather than
                // refusing: the alternative is a miner that greets and is told
                // nothing until the first timeout.
                let bits = vd
                    .get(s as usize)
                    .map(|v| v.bits())
                    .unwrap_or_else(|| p.start_bits(s as usize));
                p.make_job(s, bits)
            })
            .collect()
    };
    for j in jobs {
        stream.write_all(proto::encode_job(&j).as_bytes())?;
    }
    Ok(())
}
