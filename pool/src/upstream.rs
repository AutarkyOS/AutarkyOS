//! The Stratum V1 client, host-side.
//!
//! `design/mining.md` predicted this file before it existed: "the Stratum V1
//! client already in `src/mine/` is not wasted -- it moves to the pool as its
//! *upstream* client, host-side, where it is ordinary code." That turned out to
//! be true in the strongest sense available, because it is not a move at all.
//! `mine::stratum` is the kernel's own file, included by `#[path]`, and this
//! module is the socket around it.
//!
//! So the messages the kernel sends to somebody else's pool and the messages
//! this sends are built by one function each. There is no second implementation
//! to drift.
//!
//! ### One thread per coin, and no shared connection
//!
//! Each upstream is a different pool with its own extranonce, its own
//! difficulty and its own idea of what a job is. Multiplexing them would mean
//! inventing a routing layer to undo something nobody asked for; a thread that
//! blocks in `read` costs a stack and nothing else.
//!
//! ### What this is not
//!
//! It is a **proxy** and not a full pool: there is no node, no block template,
//! no coinbase of ours. Upstream decides what is mined and pays its own
//! address, and every share good enough goes straight back to it. That is the
//! B1 sequencing in `design/mining.md`'s plan -- share accounting and the entry
//! gate get to work against an upstream that already produces correct work,
//! and running nodes is a decision deferred until volume justifies it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::json::Json;
use crate::mine::stratum::{self, Message};
use crate::mine::u256::{target_for, U256};
use crate::pool::{Pool, Source, Work};

/// How long to wait for the subscribe and authorize replies.
const HANDSHAKE_MS: u64 = 15_000;
/// Reconnect backoff, doubling.
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long a connection may go silent before it is assumed dead.
///
/// A pool sends a job every so often even when nothing changes, so silence for
/// this long is a connection that is open at the socket layer and finished in
/// every way that matters -- the half-dead case, which is invisible to `read`
/// because `read` is simply blocked.
const SILENCE_LIMIT: Duration = Duration::from_secs(300);

/// Start a client thread for every coin that has an upstream.
pub fn start_all(pool: Arc<Mutex<Pool>>) {
    let coins: Vec<(usize, String, Source)> = {
        let p = pool.lock().unwrap();
        p.coins
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.label.clone(), c.source.clone()))
            .collect()
    };
    for (slot, label, source) in coins {
        let Source::Upstream {
            host,
            port,
            user,
            pass,
        } = source
        else {
            continue;
        };
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            let mut backoff = BACKOFF_MIN;
            loop {
                match session(&pool, slot, &label, &host, port, &user, &pass) {
                    Ok(()) => {
                        println!("[up {label}] upstream closed the connection");
                        backoff = BACKOFF_MIN;
                    }
                    Err(e) => println!("[up {label}] {e}"),
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        });
    }
}

fn session(
    pool: &Arc<Mutex<Pool>>,
    slot: usize,
    label: &str,
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> Result<(), String> {
    println!("[up {label}] connecting to {host}:{port}");
    let mut sock = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    // Short, so the loop below gets a turn to check for shares to forward and
    // to notice silence. The read timing out is the ordinary case here rather
    // than an error.
    sock.set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| format!("{e}"))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];

    // The handshake. `stratum::subscribe` and `authorize` are the kernel's own,
    // so what goes on this wire is byte for byte what the kernel would send.
    sock.write_all(stratum::subscribe(1).as_bytes())
        .map_err(|e| format!("subscribe: {e}"))?;

    let mut e1: Vec<u8> = Vec::new();
    let mut e2_size = 4usize;
    let mut got_sub = false;
    let mut authorized = false;
    // `set_difficulty` and the first `notify` routinely arrive *before* the
    // reply to a call, so notifications are handled throughout rather than
    // skipped while an id is awaited. `stratum.rs` records the same thing about
    // the kernel's own `await_id`.
    let mut up_target = target_for(1, 0).unwrap_or(U256::ZERO);
    let mut pending_notify: Option<stratum::Job> = None;

    let deadline = Instant::now() + Duration::from_millis(HANDSHAKE_MS);
    while Instant::now() < deadline && !(got_sub && authorized) {
        if !pump(&mut sock, &mut buf, &mut chunk)? {
            return Err(String::from("upstream hung up during the handshake"));
        }
        while let Ok(Some(line)) = stratum::take_line(&mut buf) {
            match stratum::classify(&line) {
                Ok(Message::Response { id, ok, body }) => {
                    if id == 1 {
                        let Some((got_e1, got_size)) = stratum::subscribe_result(&body) else {
                            return Err(String::from("the subscribe reply could not be read"));
                        };
                        e1 = got_e1;
                        e2_size = got_size;
                        got_sub = true;
                        sock.write_all(stratum::authorize(2, user, pass).as_bytes())
                            .map_err(|e| format!("authorize: {e}"))?;
                    } else if id == 2 {
                        if !ok {
                            // Named rather than retried. A refused worker is a
                            // wrong address or a wrong password, and a backoff
                            // loop against that is a machine reconnecting
                            // forever for a reason nobody is being told.
                            return Err(String::from(
                                "upstream refused this worker -- check the address and password",
                            ));
                        }
                        authorized = true;
                    }
                }
                Ok(Message::Notify { method, params }) => {
                    take_notification(&method, &params, &mut up_target, &mut pending_notify);
                }
                Err(_) => {}
            }
        }
    }
    if !(got_sub && authorized) {
        return Err(String::from("upstream did not finish the handshake in time"));
    }
    println!(
        "[up {label}] subscribed and authorized, extranonce1 {} bytes, extranonce2 {}",
        e1.len(),
        e2_size
    );

    if let Some(job) = pending_notify.take() {
        install(pool, slot, label, job, &e1, e2_size, up_target);
    }

    let mut last_heard = Instant::now();
    loop {
        if !pump(&mut sock, &mut buf, &mut chunk)? {
            return Ok(());
        }
        let mut heard = false;
        while let Ok(Some(line)) = stratum::take_line(&mut buf) {
            heard = true;
            match stratum::classify(&line) {
                Ok(Message::Notify { method, params }) => {
                    let mut job = None;
                    take_notification(&method, &params, &mut up_target, &mut job);
                    if let Some(j) = job {
                        install(pool, slot, label, j, &e1, e2_size, up_target);
                    }
                }
                Ok(Message::Response { id, ok, .. }) => {
                    // A submit's answer. Logged either way: a pool that
                    // rejects everything and a pool that is not there look
                    // identical from a share counter alone.
                    println!(
                        "[up {label}] submit {id} {}",
                        if ok { "accepted" } else { "REJECTED" }
                    );
                }
                Err(_) => {}
            }
        }
        if heard {
            last_heard = Instant::now();
        } else if last_heard.elapsed() > SILENCE_LIMIT {
            return Err(String::from("upstream went silent; reconnecting"));
        }

        // Anything the miners found that is good enough for upstream.
        let forwards = {
            let mut p = pool.lock().unwrap();
            p.take_forwards()
        };
        for f in forwards {
            if f.slot as usize != slot {
                continue;
            }
            let id = 1000 + (Instant::now().elapsed().as_nanos() as u64 & 0xffff);
            let msg = stratum::submit(
                id,
                user,
                &f.job_id,
                &f.extranonce2,
                &f.ntime_be,
                &f.nonce_be,
            );
            println!("[up {label}] forwarding a share for job {}", f.job_id);
            sock.write_all(msg.as_bytes())
                .map_err(|e| format!("submit: {e}"))?;
        }
    }
}

/// Read whatever is there. `false` means upstream closed.
fn pump(sock: &mut TcpStream, buf: &mut Vec<u8>, chunk: &mut [u8]) -> Result<bool, String> {
    match sock.read(chunk) {
        Ok(0) => Ok(false),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(true)
        }
        Err(e) => Err(format!("read: {e}")),
    }
}

fn take_notification(
    method: &str,
    params: &Json,
    up_target: &mut U256,
    job: &mut Option<stratum::Job>,
) {
    match method {
        "mining.set_difficulty" => {
            // Through `stratum::decimal` and never `as_i64`, which is the trap
            // that module exists to document: altcoin pools routinely send a
            // fractional difficulty, `as_i64` reads `0.001` as `0`, and a
            // target built from zero accepts everything.
            let Some(text) = params.idx(0).and_then(raw_number) else {
                return;
            };
            let Some((m, scale)) = stratum::decimal(&text) else {
                return;
            };
            if let Some(t) = target_for(m, scale) {
                *up_target = t;
            }
        }
        "mining.notify" => {
            *job = stratum::parse_job(params);
        }
        // `client.reconnect` is refused here exactly as the kernel refuses it:
        // following a redirect to an address no human typed is not a thing to
        // do quietly, and the reconnect loop will return to the configured host.
        _ => {}
    }
}

/// The literal token of a JSON number, which is what `decimal` wants.
///
/// `Json::Num` keeps the source text precisely so a fractional difficulty
/// survives being read, and a pool that sends its difficulty as a *string* is
/// common enough to accept as well.
fn raw_number(j: &Json) -> Option<String> {
    match j {
        Json::Num(t) => Some(t.clone()),
        Json::Str(t) => Some(t.clone()),
        _ => None,
    }
}

fn install(
    pool: &Arc<Mutex<Pool>>,
    slot: usize,
    label: &str,
    job: stratum::Job,
    e1: &[u8],
    e2_size: usize,
    up_target: U256,
) {
    let t = up_target.to_be_bytes();
    println!(
        "[up {label}] job {}, {} merkle level(s), target {:02x}{:02x}{:02x}{:02x}..",
        job.id,
        job.branch.len(),
        t[0],
        t[1],
        t[2],
        t[3]
    );
    let w = Work {
        job_id: job.id,
        prev_wire: job.prev_wire,
        coinb1: job.coinb1,
        coinb2: job.coinb2,
        branch: job.branch,
        version: job.version,
        ntime: job.ntime,
        nbits: job.nbits,
        extranonce1: e1.to_vec(),
        extranonce2_size: e2_size,
        up_target,
    };
    pool.lock().unwrap().set_work(slot, w);
}
