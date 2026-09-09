//! The task that owns the pool connection.
//!
//! One task, one socket, and nothing else in the kernel ever touches that
//! handle. `mine off` sets an atomic and the task closes on its next wake;
//! closing it from the shell would put two tasks in the TCP state machine,
//! which is the thing `net`'s `StackGuard` and `tcp::at`'s masking exist to
//! prevent.
//!
//! ### Why the loop blocks rather than polls
//!
//! `tcp::service()` has one call site, the shell's idle loop, so the stack does
//! not advance while a command runs. But `tcp::wait_until` polls the NIC
//! sixteen times and runs `pump()` on every iteration, and `pump` services all
//! sixteen connection slots. **So a task blocked inside `recv_at` is driving
//! the whole stack**, and a task that polled `pending()` and yielded would
//! drive nothing and watch its own connection die.
//!
//! That is also why there is no `yield_now` here. `task::yield_now`'s own doc
//! records the hang that a hundred-times-a-second yield loop in `net::tcp`
//! caused, and `initiative` states the house rule. The waiting happens inside
//! `wait_until`'s `hlt`; the parked case is a plain spin that preemption shares
//! out.
//!
//! ### Waiting for a job and sending a share are the same wait
//!
//! There is one thread of control on the socket, so there is no conflict to
//! resolve, only a latency to bound. `RECV_MS` is that bound: a share found
//! while the task is blocked waits at most that long before the queue is
//! drained. Two hundred milliseconds against a share found once an hour is not
//! a trade worth widening `recv_at`'s signature for, and if it ever is, the
//! wake-predicate form is written up in the plan.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::net::tcp;
use crate::sync::{Racy, Spin};

use super::stratum::{self, Message};

/// How long a blocked read waits before the submit queue is drained.
const RECV_MS: u64 = 200;
/// How long to wait for the TCP handshake.
const CONNECT_MS: u64 = 8_000;
/// Reconnect backoff, doubling, in milliseconds.
const BACKOFF_MIN: u64 = 1_000;
const BACKOFF_MAX: u64 = 60_000;
/// Journal depth for `mine log`.
const JOURNAL: usize = 32;

/// Set by `mine on`, cleared by `mine off`. The task never exits.
pub static ENABLED: AtomicBool = AtomicBool::new(false);
/// Serial of the current template. Bumped on every job and on every
/// disconnection, so a hash loop can tell that its work is now worthless.
pub static JOB_SERIAL: AtomicU64 = AtomicU64::new(0);
/// Whether the handshake got all the way through.
pub static LIVE: AtomicBool = AtomicBool::new(false);
static SPAWNED: AtomicBool = AtomicBool::new(false);
static NEXT_ID: AtomicU64 = AtomicU64::new(3);
/// Share difficulty as the pool last set it, mantissa and scale.
static DIFF_M: AtomicU64 = AtomicU64::new(1);
static DIFF_S: AtomicU32 = AtomicU32::new(0);

/// Where to connect and as whom. Not the connection itself.
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

pub static CONFIG: Spin<Option<Config>> = Spin::new(None);

/// The job in force, already reduced to what a hash loop needs.
///
/// Carries the midstate rather than only the header, so the hash loop clones a
/// forty-byte state per batch instead of re-absorbing sixty-four bytes. And it
/// carries `extranonce2` and `ntime_be` because the submit has to send the
/// *same* bytes that were hashed: formatting them a second time at submit is
/// how a client ends up submitting a share for a header it never built.
pub struct Template {
    pub serial: u64,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime_be: Vec<u8>,
    /// The assembled header with a zero nonce. The miner substitutes into it.
    ///
    /// Not a midstate any more: that is a SHA-256d-only optimisation, since it
    /// rests on the first 64 bytes being absorbable once, and yespower puts all
    /// eighty through every nonce. The midstate is rebuilt on the miner's side
    /// for the algorithms that can use one.
    pub header: [u8; 80],
    pub target: super::u256::U256,
    /// The network's own target, for the expected-value block. On the wire,
    /// so it moves with the job and is never a constant.
    pub nbits: u32,
    /// What the pool is paying itself for this block, summed from the coinbase
    /// outputs. `None` when the transaction did not parse exactly, in which
    /// case the report omits every line that depends on it.
    pub coin_value: Option<u64>,
    /// How long the assembled coinbase was, and its first bytes. Printed when
    /// the parse fails, because "could not read it" without saying what was
    /// read is a diagnostic that sends you to the wrong file -- it cost a run
    /// working out whether the stub or the assembly was wrong.
    pub coinbase_len: usize,
    pub coinbase_head: [u8; 8],
}

pub static TEMPLATE: Spin<Option<Template>> = Spin::new(None);

/// Which proof-of-work to compute.
///
/// A setting rather than something the pool says, because Stratum V1 has no
/// field for it -- the pool and the miner are simply assumed to agree, which is
/// true when a pool serves one coin and is the whole reason our own pool wants
/// a protocol that says so out loud. See `design/mining.md`.
pub static ALGO: Spin<Option<super::algo::Algo>> = Spin::new(None);

pub fn algo_in_force() -> super::algo::Algo {
    ALGO.lock_irq().clone().unwrap_or(super::algo::Algo::Sha256d)
}

/// A share, waiting for the socket task to send it.
pub struct Share {
    pub serial: u64,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime_be: Vec<u8>,
    pub nonce_be: Vec<u8>,
}

pub static SHARES: Spin<Vec<Share>> = Spin::new(Vec::new());

/// Set by `mine hash on|off`, separately from the connection.
pub static MINING: AtomicBool = AtomicBool::new(true);
pub static HASHES: AtomicU64 = AtomicU64::new(0);
pub static FOUND: AtomicU64 = AtomicU64::new(0);
pub static ACCEPTED: AtomicU64 = AtomicU64::new(0);
pub static REJECTED: AtomicU64 = AtomicU64::new(0);
/// Best leading-zero count this run. A display figure, never a decision.
pub static BEST: AtomicU32 = AtomicU32::new(0);
/// When hashing started, for the rate. TSC milliseconds, never `lapic::ticks`.
static HASH_SINCE: AtomicU64 = AtomicU64::new(0);

/// Nonces per batch. About 1.5 ms of work, so the template check between
/// batches costs nothing and `mine off` is felt within one.
const BATCH: u32 = 4096;

pub fn hash_ms() -> u64 {
    let t0 = HASH_SINCE.load(Ordering::Relaxed);
    if t0 == 0 {
        return 0;
    }
    now_ms().saturating_sub(t0)
}

/// Connection and share history, newest last.
static LOG: Racy<Vec<String>> = Racy::new(Vec::new());

pub fn note(s: &str) {
    let v = unsafe { &mut *LOG.get() };
    if v.len() == JOURNAL {
        v.remove(0);
    }
    v.push(String::from(s));
}

pub fn journal() -> Vec<String> {
    unsafe { &*LOG.get() }.clone()
}

pub fn difficulty() -> (u64, u32) {
    (DIFF_M.load(Ordering::Relaxed), DIFF_S.load(Ordering::Relaxed))
}

/// Where the session is. One enum so the report cannot invent a state.
#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    Off,
    Resolving,
    Connecting,
    Subscribed,
    Authorized,
    Live,
}

static PHASE: Racy<Phase> = Racy::new(Phase::Off);

pub fn phase() -> Phase {
    unsafe { *PHASE.get() }
}

fn set_phase(p: Phase) {
    unsafe { *PHASE.get() = p };
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Off => "off",
            Phase::Resolving => "resolving",
            Phase::Connecting => "connecting",
            Phase::Subscribed => "subscribed",
            Phase::Authorized => "authorized",
            Phase::Live => "live",
        }
    }
}

/// Start the connection task, once. A second `mine on` re-arms the atomic
/// rather than spawning again: `MAX_TASKS` is 24, slots are never reclaimed,
/// and on the GF63 most of them are already spoken for by idle tasks.
pub fn start() -> Result<(), &'static str> {
    if CONFIG.lock_irq().is_none() {
        return Err("no pool set -- try `mine pool <host:port>` first");
    }
    ENABLED.store(true, Ordering::Release);
    if SPAWNED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    match crate::task::spawn("stratum", stratum_task) {
        Some(_) => {}
        None => {
            SPAWNED.store(false, Ordering::Release);
            ENABLED.store(false, Ordering::Release);
            return Err("no task slot free");
        }
    }
    // The hash loop is a second task and not a branch of the first. The socket
    // task spends its life blocked in `recv_at`, which is what keeps the TCP
    // stack alive; hashing inside that loop would stop it doing so for the
    // length of every batch.
    if crate::task::spawn("miner", mine_task).is_none() {
        note("no task slot for the hash loop -- connected, but not mining");
    }
    Ok(())
}

pub fn stop() {
    ENABLED.store(false, Ordering::Release);
}

/// A short spin, for the parked case. Not `yield_now`: see the module header.
fn idle() {
    for _ in 0..2000 {
        core::hint::spin_loop();
    }
}

/// Milliseconds since boot, off the TSC.
///
/// **Never `lapic::ticks()`.** That counter is the timer-interrupt count and
/// only the bootstrap processor advances it now, but the whole class of bug is
/// worth staying away from in code whose entire output is a rate.
fn now_ms() -> u64 {
    let mhz = crate::time::tsc_mhz();
    if mhz == 0 {
        return 0;
    }
    crate::time::rdtsc() / (mhz * 1000)
}

fn sleep_ms(ms: u64) {
    let deadline = now_ms() + ms;
    while now_ms() < deadline && ENABLED.load(Ordering::Acquire) {
        idle();
    }
}

struct Session {
    h: tcp::Handle,
    buf: Vec<u8>,
    e1: Vec<u8>,
    e2_size: usize,
    /// The job as the pool last described it, before a template is built.
    job: Option<stratum::Job>,
    /// Counter feeding extranonce2.
    e2: u64,
    /// Submit ids we are still waiting on.
    pending: Vec<u64>,
}

fn stratum_task() {
    let mut backoff = BACKOFF_MIN;
    loop {
        if !ENABLED.load(Ordering::Acquire) {
            if phase() != Phase::Off {
                set_phase(Phase::Off);
                LIVE.store(false, Ordering::Release);
                JOB_SERIAL.fetch_add(1, Ordering::AcqRel);
                *TEMPLATE.lock_irq() = None;
                note("disconnected on request");
            }
            idle();
            continue;
        }
        match connect() {
            Some(mut s) => {
                backoff = BACKOFF_MIN;
                run(&mut s);
                tcp::abort_at(s.h);
            }
            None => {
                sleep_ms(backoff);
                backoff = core::cmp::min(backoff * 2, BACKOFF_MAX);
            }
        }
        LIVE.store(false, Ordering::Release);
        // A share found against the old connection cannot be submitted on the
        // next one: `extranonce1` is per-connection, so the work is not merely
        // stale, it is unsubmittable.
        JOB_SERIAL.fetch_add(1, Ordering::AcqRel);
        *TEMPLATE.lock_irq() = None;
        if ENABLED.load(Ordering::Acquire) {
            set_phase(Phase::Connecting);
        }
    }
}

/// Resolve, connect, subscribe, authorize. `None` on any refusal.
fn connect() -> Option<Session> {
    let (host, port, user, pass) = {
        let g = CONFIG.lock_irq();
        let c = g.as_ref()?;
        (c.host.clone(), c.port, c.user.clone(), c.pass.clone())
    };

    set_phase(Phase::Resolving);
    let ip = match crate::net::dns::lookup(&host) {
        Ok(ip) => ip,
        Err(_) => {
            note("could not resolve the pool host");
            return None;
        }
    };

    set_phase(Phase::Connecting);
    let h = match tcp::open(ip, port, CONNECT_MS) {
        Ok(h) => h,
        Err(_) => {
            note("connection refused or timed out");
            return None;
        }
    };
    let mut s = Session {
        h,
        buf: Vec::new(),
        e1: Vec::new(),
        e2_size: 4,
        job: None,
        e2: 0,
        pending: Vec::new(),
    };

    if tcp::send_at(s.h, stratum::subscribe(1).as_bytes(), 5_000).is_err() {
        tcp::abort_at(s.h);
        return None;
    }
    if !await_id(&mut s, 1, |s, body| match stratum::subscribe_result(body) {
        Some((e1, size)) => {
            s.e1 = e1;
            s.e2_size = size;
            true
        }
        None => false,
    }) {
        note("the pool's subscribe reply could not be read");
        tcp::abort_at(s.h);
        return None;
    }
    set_phase(Phase::Subscribed);

    if tcp::send_at(s.h, stratum::authorize(2, &user, &pass).as_bytes(), 5_000).is_err() {
        tcp::abort_at(s.h);
        return None;
    }
    if !await_id(&mut s, 2, |_, _| true) {
        note("the pool refused this worker");
        tcp::abort_at(s.h);
        return None;
    }
    set_phase(Phase::Authorized);
    note("subscribed and authorized");
    Some(s)
}

/// Read until the response with `id` arrives, handling notifications on the way.
///
/// The notifications are not a distraction to be skipped: a pool sends
/// `set_difficulty` and the first `notify` *before* it answers the authorize on
/// several implementations, so a reader that discarded anything that was not
/// the awaited id would throw away the first job of every session.
fn await_id(
    s: &mut Session,
    id: u64,
    mut on_ok: impl FnMut(&mut Session, &crate::json::Json) -> bool,
) -> bool {
    let deadline = now_ms() + 15_000;
    while now_ms() < deadline {
        if !ENABLED.load(Ordering::Acquire) {
            return false;
        }
        if !fill(s) {
            return false;
        }
        loop {
            match stratum::take_line(&mut s.buf) {
                Ok(Some(line)) => match stratum::classify(&line) {
                    Ok(Message::Response { id: got, ok, body }) if got == id => {
                        return ok && on_ok(s, &body);
                    }
                    Ok(Message::Notify { method, params }) => handle_notify(s, &method, &params),
                    // Somebody else's id, or a line we cannot read. Neither is
                    // fatal: pools send things this client does not implement.
                    Ok(_) => {}
                    Err(_) => {}
                },
                Ok(None) => break,
                Err(_) => return false,
            }
        }
    }
    false
}

/// One blocking read. `false` when the peer has gone.
///
/// `recv_at` answers an empty vector for both a timeout and end of file, and
/// its own doc says so -- a handle has no `LAST_DATA` cushion to tell them
/// apart. So `alive` is asked every time round, or a dead pool reads as a quiet
/// one forever and the miner keeps hashing a job it can never submit.
fn fill(s: &mut Session) -> bool {
    let data = tcp::recv_at(s.h, RECV_MS);
    if data.is_empty() && !tcp::alive(s.h) {
        note("the pool closed the connection");
        return false;
    }
    s.buf.extend_from_slice(&data);
    true
}

fn run(s: &mut Session) {
    set_phase(Phase::Live);
    LIVE.store(true, Ordering::Release);
    while ENABLED.load(Ordering::Acquire) {
        if !drain_shares(s) {
            return;
        }
        if !fill(s) {
            return;
        }
        loop {
            match stratum::take_line(&mut s.buf) {
                Ok(Some(line)) => match stratum::classify(&line) {
                    Ok(Message::Notify { method, params }) => handle_notify(s, &method, &params),
                    Ok(Message::Response { id, ok, body }) => on_submit_reply(s, id, ok, &body),
                    Err(_) => {}
                },
                Ok(None) => break,
                Err(_) => {
                    note("the pool sent a line too long to be a message");
                    return;
                }
            }
        }
    }
}

/// Send whatever the hash loop found. `false` if the socket has gone.
fn drain_shares(s: &mut Session) -> bool {
    loop {
        let Some(sh) = SHARES.lock_irq().pop() else {
            return true;
        };
        let user = {
            let g = CONFIG.lock_irq();
            match g.as_ref() {
                Some(c) => c.user.clone(),
                None => return true,
            }
        };
        let id = next_id();
        let msg = stratum::submit(
            id,
            &user,
            &sh.job_id,
            &sh.extranonce2,
            &sh.ntime_be,
            &sh.nonce_be,
        );
        if tcp::send_at(s.h, msg.as_bytes(), 5_000).is_err() {
            note("could not send a share; the connection is going");
            return false;
        }
        // Bounded. A pool that never answers must not grow this forever, and
        // what an unanswered submit means is a half-dead connection rather
        // than a rejection -- which is why it is not counted as one.
        if s.pending.len() >= 32 {
            s.pending.remove(0);
        }
        s.pending.push(id);
    }
}

/// A reply to one of our submits.
///
/// The reason string is printed verbatim and that is the instrument, not
/// decoration. A pool saying "job not found" is telling you about staleness;
/// "low difficulty share" is telling you the target arithmetic is wrong; and
/// "invalid nonce" is telling you the byte order is. Folding those into a
/// counter throws away the only feedback loop that can tell them apart, and
/// nothing in this tree has yet seen one from a real server.
fn on_submit_reply(s: &mut Session, id: u64, ok: bool, body: &crate::json::Json) {
    let Some(pos) = s.pending.iter().position(|&p| p == id) else {
        return;
    };
    s.pending.remove(pos);
    if ok {
        ACCEPTED.fetch_add(1, Ordering::Relaxed);
        note("share accepted");
        return;
    }
    REJECTED.fetch_add(1, Ordering::Relaxed);
    let why = body
        .get("error")
        .and_then(|e| e.idx(1))
        .and_then(|m| m.as_str())
        .unwrap_or("no reason given");
    let mut line = String::from("share rejected: ");
    line.push_str(why);
    note(&line);
}

fn handle_notify(s: &mut Session, method: &str, params: &crate::json::Json) {
    match method {
        "mining.set_difficulty" => {
            let Some(first) = params.idx(0) else { return };
            // The raw token, not `as_i64`. See `stratum::decimal`.
            let text = match first {
                crate::json::Json::Num(t) => t.as_str(),
                _ => return,
            };
            match stratum::decimal(text) {
                Some((m, sc)) => {
                    DIFF_M.store(m, Ordering::Relaxed);
                    DIFF_S.store(sc, Ordering::Relaxed);
                    rebuild(s);
                }
                // Never silently. Keeping the previous difficulty leaves the
                // miner hashing against a target the pool did not set and
                // submitting nothing, which looks exactly like a miner that is
                // broken. Found by a stub whose difficulty Python serialised
                // as `1e-05`.
                None => note("could not read the difficulty the pool sent"),
            }
        }
        "mining.notify" => {
            if let Some(job) = stratum::parse_job(params) {
                s.job = Some(job);
                s.e2 = s.e2.wrapping_add(1);
                rebuild(s);
            }
        }
        "mining.set_extranonce" => {
            // Some altcoin pools rotate this. A client that ignored it would
            // submit into a stale extranonce space and have every share
            // rejected with nothing in the message saying why.
            let Some(e1) = params.idx(0).and_then(|j| j.as_str()) else { return };
            let Some(bytes) = stratum::unhex(e1) else { return };
            s.e1 = bytes;
            if let Some(size) = params.idx(1).and_then(|j| j.as_i64()) {
                if (0..=64).contains(&size) {
                    s.e2_size = size as usize;
                }
            }
            rebuild(s);
        }
        "client.reconnect" => {
            // Refused rather than followed. Redirecting to an address no human
            // typed is not something this kernel should do quietly.
            note("the pool asked us to reconnect elsewhere; refused");
        }
        _ => {}
    }
}

/// Turn the current job, extranonce and difficulty into something hashable.
fn rebuild(s: &mut Session) {
    let Some(job) = s.job.as_ref() else { return };
    let (m, sc) = difficulty();
    let Some(target) = super::u256::target_for(m, sc) else { return };

    let mut e2 = Vec::with_capacity(s.e2_size);
    // Big-endian, so a hex dump reads in order. Which encoding does not matter
    // for validity; what matters is that the same bytes reach the coinbase and
    // the submit, which is why they are stored rather than formatted twice.
    for i in (0..s.e2_size).rev() {
        e2.push((s.e2 >> (8 * (i % 8))) as u8);
    }
    let coinbase = super::header::coinbase(&job.coinb1, &s.e1, &e2, &job.coinb2);
    let root = super::header::merkle_root(&coinbase, &job.branch);
    let header = super::header::assemble(
        job.version,
        &job.prev_wire,
        &root,
        job.ntime,
        job.nbits,
        0,
    );
    let (ntime_be, _) = super::header::submit_hex(&header);
    let serial = JOB_SERIAL.fetch_add(1, Ordering::AcqRel) + 1;
    *TEMPLATE.lock_irq() = Some(Template {
        serial,
        job_id: job.id.clone(),
        extranonce2: e2,
        ntime_be,
        header,
        target,
        nbits: job.nbits,
        coin_value: super::ev::coinbase_value(&coinbase),
        coinbase_len: coinbase.len(),
        coinbase_head: {
            let mut h = [0u8; 8];
            for (i, b) in coinbase.iter().take(8).enumerate() {
                h[i] = *b;
            }
            h
        },
    });
    // Shares for a template nobody holds any more cannot be submitted: the job
    // id is gone and the extranonce2 has moved. Dropping them here is cheaper
    // than filtering at submit and cannot leave one behind.
    SHARES.lock_irq().retain(|sh| sh.serial == serial);
}

/// The hash loop. One task, pinned to core 0 like everything else.
///
/// Deliberately the slow version. `smp::parallel_split` is the obvious reach
/// and it is the wrong instrument: it allows one job system-wide and its only
/// other callers are the model's forward and backward passes, so a mining batch
/// in flight makes every projection go serial and vice versa. Worse, it *spins*
/// on the bootstrap processor, and its `count * width >= 2^19` floor forces
/// batches large enough that the spin freezes the shell, the clock and this
/// connection for the whole of one. There is no batch size that is both
/// accepted and short.
///
/// So: one task, taking its round-robin share, which on a machine with seven
/// runnable tasks is about a seventh of one core. `mine` prints the measured
/// rate and the task count beside it rather than a flat-out figure, because the
/// flat-out figure is not one this machine ever delivers.
fn mine_task() {
    // The hasher lives here rather than in the template, because it owns a
    // working set that must not be shared with the socket task. Rebuilt only
    // when the algorithm changes; a new job only retargets it.
    let mut held: Option<(super::algo::Algo, super::algo::Hasher)> = None;
    let mut held_serial = 0u64;

    loop {
        if !ENABLED.load(Ordering::Acquire) || !MINING.load(Ordering::Acquire) {
            idle();
            continue;
        }
        // Snapshot under the lock and hash outside it. Holding it across a
        // batch would block `rebuild` for the length of one every time.
        let snap = {
            let g = TEMPLATE.lock_irq();
            g.as_ref().map(|t| {
                (
                    t.serial,
                    t.header,
                    t.target,
                    t.job_id.clone(),
                    t.extranonce2.clone(),
                    t.ntime_be.clone(),
                )
            })
        };
        let Some((serial, header, target, job_id, e2, ntime_be)) = snap else {
            idle();
            continue;
        };
        let algo = algo_in_force();

        if held.as_ref().map(|(a, _)| a != &algo).unwrap_or(true) {
            match super::algo::Hasher::new(&algo, &header) {
                Some(h) => {
                    note("hasher built");
                    held = Some((algo.clone(), h));
                    held_serial = serial;
                }
                None => {
                    // Parameters the algorithm refuses, or a working set that
                    // will not fit. Said once rather than spun on.
                    note("the algorithm refused its parameters; not mining");
                    MINING.store(false, Ordering::Release);
                    continue;
                }
            }
        } else if serial != held_serial {
            if let Some((_, h)) = held.as_mut() {
                h.retarget(&header);
            }
            held_serial = serial;
        }
        let Some((_, hasher)) = held.as_mut() else {
            idle();
            continue;
        };

        if HASH_SINCE.load(Ordering::Relaxed) == 0 {
            HASH_SINCE.store(now_ms(), Ordering::Relaxed);
        }

        // The nonce is derived from the count rather than kept, so a template
        // change restarts the sweep and two templates never share a nonce
        // space by accident.
        let batch = algo.batch();
        let base = (HASHES.load(Ordering::Relaxed) & 0xffff_ffff) as u32;
        for i in 0..batch {
            let nonce = base.wrapping_add(i);
            let d = hasher.hash(&header, nonce);
            let z = super::hash::leading_zero_bits(&d);
            if z > BEST.load(Ordering::Relaxed) {
                BEST.store(z, Ordering::Relaxed);
            }
            if super::hash::below_target(&d, &target) {
                FOUND.fetch_add(1, Ordering::Relaxed);
                let mut q = SHARES.lock_irq();
                // Bounded: a misconfigured difficulty of nearly zero would
                // otherwise queue faster than the socket can drain, and the
                // heap is the thing that runs out.
                if q.len() < 64 {
                    q.push(Share {
                        serial,
                        job_id: job_id.clone(),
                        extranonce2: e2.clone(),
                        ntime_be: ntime_be.clone(),
                        nonce_be: nonce.to_be_bytes().to_vec(),
                    });
                }
            }
        }
        HASHES.fetch_add(batch as u64, Ordering::Relaxed);
    }
}

/// Hash as fast as this machine can for `ms`, with no pool and no network.
///
/// Bounded, and that is not a nicety: `drive.py` sends the next command when it
/// sees a prompt, so an unbounded measurement leaves the harness with commands
/// unsent -- the lesson `port bars <ms>` records. Runs on the caller's task.
///
/// The header is a fixture rather than a real job, because the rate does not
/// depend on which bytes go in and requiring a pool to measure a hash rate
/// would make the number impossible to take before the pool exists.
pub fn bench(algo: &super::algo::Algo, ms: u64) -> Option<(u64, u64, usize)> {
    let header: [u8; 80] = core::array::from_fn(|i| (i as u32 * 3) as u8);
    let mut h = super::algo::Hasher::new(algo, &header)?;
    let foot = h.footprint();
    let t0 = now_ms();
    let deadline = t0 + ms;
    let mut n = 0u64;
    let mut nonce = 0u32;
    // In chunks, so the clock is read once per chunk rather than once per hash
    // -- at sha256d speed the read would otherwise be a measurable part of what
    // is being measured.
    let chunk = algo.batch();
    while now_ms() < deadline {
        for _ in 0..chunk {
            core::hint::black_box(h.hash(&header, nonce));
            nonce = nonce.wrapping_add(1);
        }
        n += chunk as u64;
    }
    Some((n, now_ms().saturating_sub(t0), foot))
}

pub fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Connect, subscribe, listen for a few seconds, print what a real server said,
/// and disconnect. No hashing, no worker address, no background task.
///
/// This exists because the stub cannot produce the two things that matter most:
/// a **non-empty merkle branch** and a real coinbase. `merkle_root`'s fold has
/// never run against real data -- the fixture's branch is empty, so the loop
/// body has literally never executed outside a one-element synthetic case --
/// and `from_nbits` has never met a live network target. Both are decoded and
/// printed here so a person can check them against a block explorer.
///
/// Runs on the caller's task and blocks, the way `https` does. Bounded, because
/// `drive.py` sends the next command when it sees a prompt and an unbounded
/// full-screen command deadlocks it -- the lesson `port bars <ms>` records.
pub fn probe(host: &str, port: u16, worker: &str, seconds: u64) {
    use crate::kprintln;

    kprintln!("  resolving {}", host);
    let ip = match crate::net::dns::lookup(host) {
        Ok(ip) => ip,
        Err(e) => {
            kprintln!("  could not resolve: {:?}", e);
            return;
        }
    };
    kprintln!("  {}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port);

    let h = match tcp::open(ip, port, CONNECT_MS) {
        Ok(h) => h,
        Err(e) => {
            kprintln!("  could not connect: {:?}", e);
            return;
        }
    };
    let mut s = Session {
        h,
        buf: Vec::new(),
        e1: Vec::new(),
        e2_size: 4,
        job: None,
        e2: 0,
        pending: Vec::new(),
    };

    if tcp::send_at(s.h, stratum::subscribe(1).as_bytes(), 5_000).is_err() {
        kprintln!("  could not send subscribe");
        tcp::abort_at(s.h);
        return;
    }
    // Authorize as well, because many pools send no work until a worker is
    // named. A refusal is printed and the probe carries on: the subscribe
    // result is worth having either way, and what the pool says when it says no
    // is itself one of the things nothing here has ever seen.
    if !worker.is_empty() {
        let _ = tcp::send_at(s.h, stratum::authorize(2, worker, "x").as_bytes(), 5_000);
    }

    let deadline = now_ms() + seconds * 1000;
    let mut jobs = 0usize;
    while now_ms() < deadline {
        let data = tcp::recv_at(s.h, 500);
        if data.is_empty() && !tcp::alive(s.h) {
            kprintln!("  the pool closed the connection");
            break;
        }
        s.buf.extend_from_slice(&data);
        loop {
            match stratum::take_line(&mut s.buf) {
                Ok(Some(line)) => {
                    match stratum::classify(&line) {
                        Ok(Message::Response { id, ok, body }) => {
                            kprintln!("  <- response id {} {}", id, if ok { "ok" } else { "error" });
                            if id == 1 {
                                match stratum::subscribe_result(&body) {
                                    Some((e1, size)) => {
                                        kprintln!(
                                            "     extranonce1 {} ({} byte(s)), extranonce2 size {}",
                                            stratum::hex(&e1),
                                            e1.len(),
                                            size
                                        );
                                        s.e1 = e1;
                                        s.e2_size = size;
                                    }
                                    None => kprintln!("     could not read the subscribe result"),
                                }
                            }
                            if !ok {
                                let why = body
                                    .get("error")
                                    .and_then(|e| e.idx(1))
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("no reason given");
                                kprintln!("     reason: {}", why);
                            }
                        }
                        Ok(Message::Notify { method, params }) => {
                            kprintln!("  <- {}", method);
                            if method == "mining.set_difficulty" {
                                if let Some(crate::json::Json::Num(t)) = params.idx(0) {
                                    match stratum::decimal(t) {
                                        Some((m, sc)) => {
                                            kprintln!("     difficulty {} / 10^{}", m, sc)
                                        }
                                        None => kprintln!("     unreadable difficulty '{}'", t),
                                    }
                                }
                            } else if method == "mining.notify" {
                                match stratum::parse_job(&params) {
                                    Some(j) => {
                                        jobs += 1;
                                        dump_job(&s, &j);
                                    }
                                    None => kprintln!("     could not parse the job"),
                                }
                            }
                        }
                        Err(_) => kprintln!("  <- unreadable line"),
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    kprintln!("  the pool sent a line too long to be a message");
                    break;
                }
            }
        }
    }
    tcp::close_at(s.h, 2_000);
    kprintln!("  done -- {} job(s) seen", jobs);
}

/// Print a real job in enough detail to check it against a block explorer.
fn dump_job(s: &Session, j: &stratum::Job) {
    use crate::kprintln;
    kprintln!("     job      {}", j.id);
    kprintln!("     prevhash {}", stratum::hex(&j.prev_wire));
    kprintln!(
        "     coinbase {} + {} byte(s) around a {}-byte extranonce",
        j.coinb1.len(),
        j.coinb2.len(),
        s.e1.len() + s.e2_size
    );
    kprintln!(
        "     version {:08x}  nbits {:08x}  ntime {:08x}  clean {}",
        j.version,
        j.nbits,
        j.ntime,
        j.clean
    );
    match super::u256::U256::from_nbits(j.nbits) {
        Some(t) => {
            let b = t.to_be_bytes();
            kprintln!(
                "     network target {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}..",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
            );
        }
        None => kprintln!("     nbits {:08x} is not a target this can express", j.nbits),
    }
    // The part the stub could not reach. A real branch is several levels deep,
    // and until now the fold has only ever run over an empty one.
    kprintln!("     merkle branch {} level(s)", j.branch.len());
    let mut e2 = alloc::vec![0u8; s.e2_size];
    if let Some(last) = e2.last_mut() {
        *last = 1;
    }
    let cb = super::header::coinbase(&j.coinb1, &s.e1, &e2, &j.coinb2);
    let root = super::header::merkle_root(&cb, &j.branch);
    kprintln!("     coinbase {} byte(s), merkle root {}", cb.len(), stratum::hex(&root));
    let header = super::header::assemble(j.version, &j.prev_wire, &root, j.ntime, j.nbits, 0);
    kprintln!("     header   {}", stratum::hex(&header[..16]));
}
