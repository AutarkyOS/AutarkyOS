//! `glados-pool`, the thing GLaDOS mines against.
//!
//! ```text
//! glados-pool [--listen ADDR] [--ledger PATH] [COIN ...]
//! glados-pool --selftest
//! ```
//!
//! A coin is one token, `label:algo:bits`, because an algorithm is parameters
//! and not a name -- BitZeny, Yenten and Koto all run yespower and all run it
//! differently, so a preset table would be this program asserting numbers about
//! somebody else's chain. `bits` is how many leading zero bits a share must
//! have, which is a difficulty said in a way that has no float in it.
//!
//! ```text
//! bitzeny:yespower-10-2048-8:16
//! yenten:yespower-10-2048-32-59656e74656e:16
//! testnet:sha256d:20
//! ```

use std::sync::{Arc, Mutex};

use glados_pool::mine::algo::Algo;
use glados_pool::mine::stratum::unhex;
use glados_pool::pool::{target_with_leading_zeros, Coin, Pool, Source};
use glados_pool::server;

fn parse_coin(spec: &str) -> Result<Coin, String> {
    let mut it = spec.split(':');
    let label = it.next().unwrap_or("").trim();
    let algo_s = it.next().unwrap_or("");
    let bits_s = it.next().unwrap_or("");
    if label.is_empty() || algo_s.is_empty() || bits_s.is_empty() {
        return Err(format!("'{spec}' is not label:algo:bits"));
    }
    let bits: u32 = bits_s
        .parse()
        .map_err(|_| format!("'{bits_s}' is not a number of bits"))?;
    // 256 leading zero bits is a target of zero, which nothing ever meets. A
    // pool configured that way accepts no share ever and looks exactly like a
    // pool with a broken hash, so it is refused at the argument instead.
    if bits >= 256 {
        return Err(format!("{bits} leading bits is a target nothing can meet"));
    }

    let mut parts = algo_s.split('-');
    let algo = match parts.next().unwrap_or("") {
        "sha256d" => Algo::Sha256d,
        "blake2s" => Algo::Blake2s,
        "yespower" => {
            let v = parts.next().unwrap_or("");
            let n: u32 = parts
                .next()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| String::from("yespower needs N"))?;
            let r: u32 = parts
                .next()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| String::from("yespower needs r"))?;
            let pers = match parts.next() {
                Some(h) => Some(unhex(h).ok_or_else(|| String::from("pers is not hex"))?),
                None => None,
            };
            let v10 = match v {
                "10" => true,
                "05" => false,
                _ => return Err(String::from("yespower version is 10 or 05")),
            };
            Algo::Yespower { v10, n, r, pers }
        }
        other => return Err(format!("no such algorithm '{other}'")),
    };

    Ok(Coin {
        label: String::from(label),
        algo,
        share_target: target_with_leading_zeros(bits),
        // No chain behind it, so no network target, and it is `None` rather
        // than a plausible constant: an expected value derived from an invented
        // difficulty is worse than one that refuses to print.
        network_target: None,
        source: Source::Local,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        std::process::exit(if selftest() { 0 } else { 1 });
    }

    let mut listen = String::from("0.0.0.0:3334");
    let mut ledger: Option<String> = None;
    let mut coins: Vec<Coin> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => match it.next() {
                Some(v) => listen = v.clone(),
                None => {
                    eprintln!("--listen wants an address");
                    std::process::exit(2);
                }
            },
            "--ledger" => match it.next() {
                Some(v) => ledger = Some(v.clone()),
                None => {
                    eprintln!("--ledger wants a path");
                    std::process::exit(2);
                }
            },
            "-h" | "--help" => {
                println!("glados-pool [--listen ADDR] [--ledger PATH] [label:algo:bits ...]");
                println!("            --selftest");
                println!();
                println!("--ledger writes the share log as canonical JSON, for publishing.");
                return;
            }
            other => match parse_coin(other) {
                Ok(c) => coins.push(c),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            },
        }
    }
    if coins.is_empty() {
        // A default so the thing runs, and a loud one so nobody mistakes it for
        // a configured pool.
        eprintln!("[pool] no coins given, serving one sha256d coin at 20 bits");
        coins.push(parse_coin("local:sha256d:20").unwrap());
    }

    let pool = Arc::new(Mutex::new(Pool::new(coins)));
    let reporter = Arc::clone(&pool);
    // The share log is the whole product of a non-custodial pool: Layer 1
    // never holds a miner's coins, so there is no wallet to audit and this
    // record plus whatever checks against it is all a miner has. It goes to
    // stdout always, and to a file when asked.
    //
    // **A file rather than an endpoint, deliberately.** The intended home is a
    // static site whose history is a commit chain, and a commit chain cannot
    // be quietly rewritten where a live endpoint can. For a pool whose only
    // asset is being checkable, tamper-evidence beats freshness.
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        let p = reporter.lock().unwrap();
        for (w, c, t) in p.ledger() {
            println!(
                "[ledger] {w}  {c}  {} accepted, {} stale, {} bad, {} dup",
                t.accepted, t.stale, t.bad, t.duplicate
            );
        }
        if let Some(path) = &ledger {
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let doc = p.ledger_json(1, at);
            // Written through a temporary and renamed, because a publisher may
            // be reading this file at any moment and half a document is worse
            // than a stale one -- it parses as far as the truncation and then
            // does not.
            let tmp = format!("{path}.new");
            let wrote = std::fs::write(&tmp, doc.as_bytes())
                .and_then(|_| std::fs::rename(&tmp, path));
            if let Err(e) = wrote {
                eprintln!("[pool] could not write {path}: {e}");
            }
        }
    });

    if let Err(e) = server::serve(&listen, pool) {
        eprintln!("[pool] {listen}: {e}");
        std::process::exit(1);
    }
}

/// The whole path, in one process, with no kernel and no network beyond
/// loopback: listen, greet, take a job, mine it, submit, be believed.
///
/// It exists because every other check here is of a piece in isolation. The
/// interesting failures in a pool are between the pieces -- a job encoded one
/// way and decoded another, a nonce byte order that differs across the wire, a
/// share validated against the wrong header -- and none of those shows up in a
/// codec round-trip, because a round-trip uses one encoder against its own
/// decoder rather than against a socket and a second process's view of a job.
fn selftest() -> bool {
    use glados_pool::json::Json;
    use glados_pool::mine::algo::Hasher;
    use glados_pool::mine::hash::below_target;
    use glados_pool::mine::proto;
    use glados_pool::mine::stratum::take_line;
    use std::io::{Read, Write};

    // Port 0, so the operating system picks one. A fixed port is how two runs
    // of a test collide, which `stratumstub.py` records at length.
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            println!("FAIL  could not bind loopback: {e}");
            return false;
        }
    };
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Two coins on two different algorithms, because one coin proves the
    // plumbing and this protocol exists for the other thing. A pool that
    // served both from one connection but validated both under one algorithm
    // would pass a single-coin test perfectly.
    let coins = vec![
        parse_coin("selftest-a:sha256d:12").unwrap(),
        parse_coin("selftest-b:blake2s:12").unwrap(),
    ];
    let pool = Arc::new(Mutex::new(Pool::new(coins)));
    let served = Arc::clone(&pool);
    let bind = addr.to_string();
    std::thread::spawn(move || {
        let _ = server::serve(&bind, served);
    });

    let mut sock = None;
    for _ in 0..50 {
        if let Ok(s) = std::net::TcpStream::connect(addr) {
            sock = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    let Some(mut sock) = sock else {
        println!("FAIL  the listener never came up");
        return false;
    };
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();

    if sock
        .write_all(proto::encode_hello(1, "selftest.rig", "glados-pool/selftest").as_bytes())
        .is_err()
    {
        println!("FAIL  could not greet");
        return false;
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut welcomed = false;
    let mut pending: Vec<proto::Job> = Vec::new();
    let mut sent: Vec<String> = Vec::new();
    let mut accepted = 0usize;
    let mut algos: Vec<String> = Vec::new();
    let want = 2usize;

    for _ in 0..200 {
        let n = match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                println!("FAIL  read: {e}");
                return false;
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Ok(Some(line)) = take_line(&mut buf) {
            let Some(v) = Json::parse(line.trim()) else {
                continue;
            };
            if let Some(r) = v.get("result") {
                if let Some(w) = proto::parse_welcome(r) {
                    if w.v != proto::VERSION {
                        println!("FAIL  welcomed at v{} against v{}", w.v, proto::VERSION);
                        return false;
                    }
                    welcomed = true;
                    continue;
                }
                // The submit's answer. This is the claim: the pool
                // independently recomputed the hash and agreed.
                if !sent.is_empty() {
                    let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    let verdict = r.get("verdict").and_then(|x| x.as_str()).unwrap_or("?");
                    if !ok {
                        println!("FAIL  the pool refused a share it could reproduce: {verdict}");
                        return false;
                    }
                    accepted += 1;
                    if accepted == want {
                        println!(
                            "ok    greeted, mined {want} coins ({}), and every share was accepted",
                            algos.join(" + ")
                        );
                        return true;
                    }
                }
            }
            if v.get("method").and_then(|m| m.as_str()) == Some("glados.job") {
                if let Some(j) = v.get("params").and_then(proto::parse_job) {
                    // One share per slot. The server re-issues on every wake,
                    // so without this the first coin would be mined forever
                    // and the second never reached.
                    if !sent.iter().any(|s| s == &j.job)
                        && !pending.iter().any(|p| p.slot == j.slot)
                        && !algos.iter().any(|a| a == j.algo.name())
                    {
                        pending.push(j);
                    }
                }
            }
        }

        if !welcomed {
            continue;
        }
        while let Some(j) = pending.pop() {
            let Some(mut h) = Hasher::new(&j.algo, &j.header) else {
                println!("FAIL  the pool issued parameters its own algorithm refuses");
                return false;
            };
            let mut found = None;
            for nonce in 0..5_000_000u32 {
                if below_target(&h.hash(&j.header, nonce), &j.target) {
                    found = Some(nonce);
                    break;
                }
            }
            let Some(nonce) = found else {
                println!("FAIL  no {} share inside five million nonces", j.algo.name());
                return false;
            };
            let sh = proto::Share {
                job: j.job.clone(),
                nonce,
                echo: j.echo.clone(),
            };
            if sock
                .write_all(proto::encode_submit(2, &sh).as_bytes())
                .is_err()
            {
                println!("FAIL  could not submit");
                return false;
            }
            sent.push(j.job.clone());
            algos.push(String::from(j.algo.name()));
        }
    }

    println!(
        "FAIL  the exchange never completed (welcomed={welcomed} sent={} accepted={accepted})",
        sent.len()
    );
    false
}
