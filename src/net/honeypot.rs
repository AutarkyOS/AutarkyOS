//! A service that exists only to be attacked.
//!
//! Phase 3 of the Mirror. Phase 1 made banners a scanner cannot tell from real
//! services; this makes one *answer*. The operator points it at a port and a
//! protocol, and from then on a connection to that port completes a handshake,
//! receives a convincing decoy banner, has whatever it sends captured, and is
//! logged -- peer, protocol, bytes -- to an append-only record it cannot erase.
//!
//! ### Why one victim at a time is a feature
//!
//! The kernel's TCP holds a single control block; the honeypot serves one
//! connection, then the next. That is not a limitation worth apologising for
//! here. A honeypot carries no legitimate load, so there is nothing to starve,
//! and a second stack to handle concurrency would be a second stack to audit
//! for exactly the memory-safety faults an attacker is hunting for. A second
//! attacker meets silence, which is cheaper to serve than a race.
//!
//! ### Why it says its line and hangs up
//!
//! On the handshake completing, `tcp` queues the banner and a FIN together: the
//! trap greets, captures what rode in on the handshake or arrives before the
//! peer's own FIN, and closes through the same tested path a client uses. A
//! slow, interactive tarpit that holds the line open to burn an attacker's time
//! is phase 4; this is the capture, not the cruelty.
//!
//! ### Attribution is the product
//!
//! The point is not to deny the attacker -- they were always going to find a
//! service somewhere. The point is that engaging *this* one costs them their
//! source address, their tooling's banner-grab behaviour, and the first bytes
//! they send, written to `/ai/mirror/sessions`, which is a `guard` record: an
//! intruder can be captured but cannot un-capture themselves. Operator-only, so
//! the model can neither arm a trap nor read who fell into one.

use super::Ipv4;
use crate::sync::Racy;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The append-only record of captured sessions. A `guard` record, so a
/// session an attacker had cannot be rewritten out of the log by a later one.
pub const SESSIONS: &str = "/ai/mirror/sessions";

/// What the honeypot is impersonating, and where.
struct Listener {
    proto: String,
    port: u16,
}

static LISTEN: Racy<Option<Listener>> = Racy::new(None);

/// True while a listener is armed, so the TCP hot path's check is one relaxed
/// load rather than a lock on a mostly-`None` option.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Rotates the decoy identity per connection, so a scanner that hits the trap
/// twice does not see byte-identical banners -- the fleet-diversity argument
/// from phase 1, applied across time on one port.
static SEED: AtomicU32 = AtomicU32::new(0);

/// Sessions captured since boot. The log is the durable record; this is the
/// cheap number a status line reads.
static SEEN: AtomicU32 = AtomicU32::new(0);

/// Arm the trap: impersonate `proto` on `port`. Refuses a protocol the decoy
/// layer cannot dress as, because a banner the recon engine would see through
/// is worse than no trap. Operator-only.
pub fn listen(proto: &str, port: u16) -> bool {
    if super::decoy::banner(proto, 0).is_none() || port == 0 {
        return false;
    }
    let l = Listener { proto: proto.to_string(), port };
    unsafe { *LISTEN.get() = Some(l) };
    ARMED.store(true, Ordering::Relaxed);
    true
}

/// Disarm. In-flight connections finish on their own; no new ones are accepted.
pub fn stop() {
    ARMED.store(false, Ordering::Relaxed);
    unsafe { *LISTEN.get() = None };
}

/// The port a SYN must target to be accepted, or `None` when disarmed. The one
/// question `tcp::passive_open` asks on the receive path.
pub fn port() -> Option<u16> {
    if !ARMED.load(Ordering::Relaxed) {
        return None;
    }
    unsafe { (*LISTEN.get()).as_ref().map(|l| l.port) }
}

/// The banner to serve a freshly-established victim, rotating the decoy
/// identity so repeat probes see a plausibly different host.
pub fn banner() -> Vec<u8> {
    let seed = SEED.fetch_add(1, Ordering::Relaxed);
    let proto = unsafe {
        (*LISTEN.get()).as_ref().map(|l| l.proto.clone())
    };
    match proto {
        Some(p) => super::decoy::banner(&p, seed).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// What is armed, for the operator's status line.
pub fn status() -> Option<(String, u16)> {
    unsafe { (*LISTEN.get()).as_ref().map(|l| (l.proto.clone(), l.port)) }
}

/// Sessions captured since boot.
pub fn seen() -> u32 {
    SEEN.load(Ordering::Relaxed)
}

/// Record a finished session: append one line to the log and count it. Called
/// from `tcp::pump` when a honeypot connection reaches Closed, outside the TCB
/// borrow because it writes the namespace.
pub fn log_session(peer: Ipv4, captured: &[u8]) {
    SEEN.fetch_add(1, Ordering::Relaxed);
    let when = crate::dev::rtc::now()
        .map(|d| crate::dev::rtc::unix_seconds(&d) as u64)
        .unwrap_or(0);
    let proto = status().map(|(p, _)| p).unwrap_or_else(|| "?".to_string());

    let mut line = String::new();
    push_u64(&mut line, when);
    line.push(' ');
    line.push_str(&super::recon::ip_dotted(peer));
    line.push(' ');
    line.push_str(&proto);
    line.push_str(" bytes=");
    push_u64(&mut line, captured.len() as u64);
    // The first line of what they sent, printable only and clipped -- the
    // banner-grab request or the first command, which is the identifying part.
    // The full capture is not stored: a log an attacker could stuff to
    // exhaustion is a denial of the record, and the shape of the probe is what
    // attribution needs.
    if !captured.is_empty() {
        line.push_str(" first=");
        for &c in captured.iter().take(80) {
            if c == b'\r' || c == b'\n' {
                break;
            }
            line.push(if (0x20..0x7f).contains(&c) { c as char } else { '.' });
        }
    }
    line.push('\n');

    let mut next = crate::sysbox::read_blob_raw(SESSIONS).unwrap_or_default();
    next.extend_from_slice(line.as_bytes());
    crate::sysbox::write_text(SESSIONS, core::str::from_utf8(&next).unwrap_or(""));

    crate::kprintln!(
        "  [honeypot] session: {} spoke to the {} decoy, {} byte(s) captured",
        super::recon::ip_dotted(peer),
        proto,
        captured.len()
    );
}

/// The durable session log, newest last.
pub fn sessions() -> Vec<String> {
    match crate::sysbox::read_blob_raw(SESSIONS) {
        Some(b) => core::str::from_utf8(&b)
            .unwrap_or("")
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect(),
        None => Vec::new(),
    }
}

fn push_u64(s: &mut String, mut v: u64) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        s.push(digits[n] as char);
    }
}

/// What can be checked without a peer to connect: that arming validates the
/// protocol, that a served banner round-trips through the recon engine (the
/// same contract phase 1 holds), and that the seed actually rotates. The
/// handshake itself needs a second host and is exercised under QEMU with
/// hostfwd, not here.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   honeypot  {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // Arming refuses a protocol the decoy layer cannot dress as, and port 0.
    check(!listen("gopher", 22), "an undisguisable protocol is refused");
    check(!listen("ssh", 0), "port 0 is refused");
    check(port().is_none(), "a refused listen arms nothing");

    // A real arming takes, and the served banner is one the recon engine reads
    // back as the impersonated service -- the phase-1 contract, on this path.
    check(listen("ssh", 2222), "ssh on 2222 arms");
    check(port() == Some(2222), "the armed port is reported");
    let b = banner();
    let fp = super::fingerprint::identify(22, &b);
    check(fp.proto == "ssh", "the served banner reads back as ssh");

    // The seed rotates: two consecutive banners are drawn independently. (They
    // may coincide when the pool is small, so this only checks the seed moved.)
    let s0 = SEED.load(Ordering::Relaxed);
    let _ = banner();
    check(SEED.load(Ordering::Relaxed) != s0, "the decoy seed rotates per session");

    stop();
    check(port().is_none(), "stop disarms");

    ok
}
