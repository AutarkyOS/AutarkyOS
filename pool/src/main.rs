//! `glados-pool`, the thing GLaDOS mines against.
//!
//! ```text
//! glados-pool [--listen ADDR] [--ledger PATH] [COIN ...]
//! glados-pool --selftest
//! glados-pool --bench
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
    if args.iter().any(|a| a == "--bench") {
        bench();
        return;
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

/// What one share costs to check, which is what sizing a host comes down to.
///
/// **The pool's work is per share and the miner's is per hash**, and the two
/// differ by the difficulty: a miner grinds several million nonces to find one
/// share and the pool hashes exactly once to agree. So the load here does not
/// scale with anybody's hashrate, only with how often shares arrive -- which is
/// a number the operator sets, by choosing the share target.
///
/// Best of nine, like `video bench` and `core bench`, and for the reason those
/// record: a single sample on a shared machine measures the host's scheduler.
fn bench() {
    use glados_pool::mine::algo::{Algo, Hasher};
    use std::time::Instant;

    let algos = [
        ("sha256d", Algo::Sha256d),
        ("blake2s", Algo::Blake2s),
        (
            "yespower 2 MiB",
            Algo::Yespower { v10: true, n: 2048, r: 8, pers: None },
        ),
        (
            "yespower 8 MiB",
            Algo::Yespower { v10: true, n: 2048, r: 32, pers: None },
        ),
    ];
    let header: [u8; 80] = core::array::from_fn(|i| (i as u32 * 3) as u8);

    println!("what one share costs to validate, best of nine");
    println!();
    println!("  algorithm        per share   working set   shares/s on one core");
    for (name, algo) in algos.iter() {
        let Some(h) = Hasher::new(algo, &header) else {
            continue;
        };
        let foot = h.footprint();
        drop(h);

        let mut best = u128::MAX;
        for _ in 0..9 {
            // A fresh `Hasher` every time, because that is what validating a
            // share actually does: the pool holds no per-miner scratch, so the
            // allocation is part of the cost rather than something amortised
            // away by a benchmark that reuses one.
            let t = Instant::now();
            let reps = if foot > 0 { 20 } else { 2000 };
            for n in 0..reps {
                let mut hh = Hasher::new(algo, &header).unwrap();
                core::hint::black_box(hh.hash(&header, n));
            }
            let per = t.elapsed().as_nanos() / reps as u128;
            best = best.min(per);
        }
        let per_s = if best > 0 { 1_000_000_000 / best } else { 0 };
        println!(
            "  {name:<15}  {:>7} us   {:>7} KiB   {:>10}",
            best as f64 / 1000.0,
            foot / 1024,
            per_s
        );
    }
    println!();
    println!("A miner grinds millions of nonces per share; the pool hashes once.");
    println!("So this scales with the share *rate*, which the operator sets by");
    println!("choosing the target -- not with anybody's hashrate.");
}

/// A stranger cannot spend this machine's CPU without limit.
///
/// Checked rather than asserted, because a limit nobody has watched fire is a
/// limit written in a comment -- the objection `diag paging` makes about page
/// rights, which faults on purpose for exactly this reason.
///
/// The garbage is a *valid* submit for a *real* job with a nonce that does not
/// meet the target, which is the expensive case: the pool has to compute the
/// hash to find out, so every one of these costs it a full validation. A
/// malformed message would be rejected by the parser for free and would prove
/// nothing.
fn abuse_check(addr: std::net::SocketAddr) -> bool {
    use glados_pool::json::Json;
    use glados_pool::mine::proto;
    use glados_pool::mine::stratum::take_line;
    use std::io::{Read, Write};

    let Ok(mut sock) = std::net::TcpStream::connect(addr) else {
        println!("FAIL  could not open a second connection");
        return false;
    };
    sock.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .unwrap();
    if sock
        .write_all(proto::encode_hello(1, "abuse.rig", "abuse-check").as_bytes())
        .is_err()
    {
        println!("FAIL  could not greet on the second connection");
        return false;
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut job: Option<proto::Job> = None;
    for _ in 0..40 {
        let Ok(n) = sock.read(&mut chunk) else { break };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Ok(Some(line)) = take_line(&mut buf) {
            let Some(v) = Json::parse(line.trim()) else { continue };
            if v.get("method").and_then(|m| m.as_str()) == Some("glados.job") {
                if let Some(j) = v.get("params").and_then(proto::parse_job) {
                    job = Some(j);
                }
            }
        }
        if job.is_some() {
            break;
        }
    }
    let Some(j) = job else {
        println!("FAIL  the second connection was never given a job");
        return false;
    };

    // Nonce zero against a twelve-bit target is a solution about one time in
    // four thousand, so a few dozen of these are bad shares with near
    // certainty -- and the one-in-4096 case is an *accepted* share, which
    // simply does not count toward the limit and costs an extra round.
    for i in 0..200u32 {
        let sh = proto::Share { job: j.job.clone(), nonce: i, echo: vec![] };
        if sock
            .write_all(proto::encode_submit(2, &sh).as_bytes())
            .is_err()
        {
            println!("ok    a stranger sending garbage was cut off after {i} shares");
            return true;
        }
        // Under the per-second cap, so the drop that ends this is the bad-share
        // limit rather than the rate limit. Testing both at once would leave it
        // unclear which one fired.
        std::thread::sleep(std::time::Duration::from_millis(80));

        // A closed connection shows as a read of zero as readily as a failed
        // write, and which one appears depends on timing rather than on
        // behaviour.
        let mut probe = [0u8; 1024];
        match sock.read(&mut probe) {
            Ok(0) => {
                println!("ok    a stranger sending garbage was cut off after {i} shares");
                return true;
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {
                println!("ok    a stranger sending garbage was cut off after {i} shares");
                return true;
            }
        }
    }
    println!("FAIL  200 bad shares and the connection is still open");
    false
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
                        // The second half. A pool that accepts good shares and
                        // never refuses a stranger is half checked, and on a
                        // machine somebody lent us it is the wrong half.
                        return abuse_check(addr);
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
