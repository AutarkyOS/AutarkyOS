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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::json::Json;
use crate::mine::proto;
use crate::mine::stratum::take_line;
use crate::pool::{Pool, Verdict};

/// How often a connection is given fresh work.
///
/// A job carries a timestamp, so re-issuing is also what stops a miner
/// searching one header forever. Short enough that a stale job never
/// accumulates much wasted work; long enough that it is not the reason a
/// yespower slice never finishes a batch.
const JOB_PERIOD: Duration = Duration::from_secs(30);

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
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
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

    loop {
        // Re-issue on every wake, whether that was a timeout or a message. A
        // job whose only trigger is a timeout leaves a miner that talks
        // constantly working one header for as long as it keeps talking.
        if greeted {
            issue_all(&mut stream, &pool)?;
        }

        let n = match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
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
                    let w = proto::Welcome {
                        v: proto::VERSION,
                        slots,
                        session: format!("{peer}"),
                    };
                    stream.write_all(proto::encode_welcome(id, &w).as_bytes())?;
                    greeted = true;
                    issue_all(&mut stream, &pool)?;
                }
                "glados.submit" => {
                    let Some(sh) = params.and_then(proto::parse_share) else {
                        continue;
                    };
                    let verdict = pool.lock().unwrap().submit(&worker, &sh);
                    println!(
                        "[pool] {worker} share job={} nonce={:08x} -> {}",
                        sh.job,
                        sh.nonce,
                        verdict.name()
                    );
                    let ok = verdict == Verdict::Accepted;
                    let msg = format!(
                        "{{\"id\":{id},\"result\":{{\"ok\":{ok},\"verdict\":\"{}\"}},\"error\":null}}\n",
                        verdict.name()
                    );
                    stream.write_all(msg.as_bytes())?;
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

fn issue_all(stream: &mut TcpStream, pool: &Arc<Mutex<Pool>>) -> std::io::Result<()> {
    let jobs: Vec<proto::Job> = {
        let mut p = pool.lock().unwrap();
        (0..p.slots()).filter_map(|s| p.make_job(s)).collect()
    };
    for j in jobs {
        stream.write_all(proto::encode_job(&j).as_bytes())?;
    }
    Ok(())
}
