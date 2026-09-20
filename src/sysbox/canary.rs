//! Honeytokens: secrets whose only reader is an intruder.
//!
//! The decoy banners in `net/decoy.rs` are the network face of the Mirror; this
//! is the data face. A canary is a file the operator plants and then never
//! touches, at a path a legitimate process has no reason to read -- fake
//! credentials, a fake key, a fake config with a password in it. Because
//! nothing that belongs here reads it, *any* read is an intrusion, and that is
//! the whole trick: the defender does not have to distinguish an attacker from
//! a user, because a user never goes near the bait.
//!
//! ### Why the alarm is trustworthy, and why that is the invariant's doing
//!
//! A tripwire is only worth having if an attacker who trips it cannot then
//! erase the fact. So the alarm log is one of the append-only records
//! `sysbox::guard` protects, exactly like `godel`'s ledger: it can be added to
//! and never rewritten, truncated or unnamed. The one invariant -- the machine
//! may change anything except the record of what it changed -- was written for
//! the self-modification history, and it turns out to be the same property a
//! canary needs. An intruder can read the bait (that is the point, let them
//! take it), but the record that they did is beyond their reach.
//!
//! ### What trips and what does not
//!
//! A read of a planted path trips. Reading the registry or the alarm log does
//! not, because those are not planted paths -- a subtlety that matters because
//! tripping *writes* the alarm log, and if the alarm log were itself a canary
//! the first trip would recurse. The armed flag makes the common case -- no
//! canaries planted -- a single relaxed atomic load on the read path, so an
//! unarmed machine pays essentially nothing.
//!
//! ### Who may know the bait
//!
//! Planting and listing are operator-only, never an Aiksi builtin and never an
//! applet, for the reason `skill trust` is shell-only: a model that could
//! enumerate the canaries would route around them, and a model that could plant
//! one could bait the operator. The model can *read* -- and if it reads a
//! canary it trips one, which is exactly the rogue-skill case worth catching.

use crate::sync::Racy;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The append-only record of every trip. Protected by `guard` so an intruder
/// who springs it cannot erase having done so.
pub const ALARMS: &str = "/ai/mirror/alarms";

/// The planted paths, one per line. Mutable by the operator (a canary can be
/// retired), unlike the alarm log -- the evidence is permanent, the traps are
/// not.
pub const REGISTRY: &str = "/ai/mirror/canaries";

/// The planted paths, in memory for a fast read-path check. Seeded from
/// `REGISTRY` at init and kept in step by `plant`/`retire`.
static CANARIES: Racy<BTreeSet<String>> = Racy::new(BTreeSet::new());

/// False until at least one canary is planted, so the read path costs one
/// relaxed load rather than a lock and a set lookup on an unarmed machine.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Trips since boot. The alarm log is the durable record; this is the cheap
/// "has anything happened" a status line reads.
static TRIPS: AtomicU32 = AtomicU32::new(0);

/// Load the planted set from the namespace. Called once `sysbox` exists.
pub fn arm_from_namespace() {
    if let Some(bytes) = super::read_blob_raw(REGISTRY) {
        if let Ok(text) = core::str::from_utf8(&bytes) {
            let set = unsafe { &mut *CANARIES.get() };
            for line in text.lines() {
                let p = line.trim();
                if !p.is_empty() {
                    set.insert(p.to_string());
                }
            }
            if !set.is_empty() {
                ARMED.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Is this absolute path a planted canary? Pure over the set and the flag.
pub fn is_canary(abs: &str) -> bool {
    if !ARMED.load(Ordering::Relaxed) {
        return false;
    }
    let set = unsafe { &*CANARIES.get() };
    set.contains(abs)
}

/// Whether a path may be a canary at all -- the two Mirror records never are,
/// so tripping (which writes the alarm log) cannot recurse and reading the
/// registry cannot spring every trap it lists. Pure, and asserted, because it
/// is the one rule whose failure is a loop rather than a wrong answer.
pub fn eligible(abs: &str) -> bool {
    abs != ALARMS && abs != REGISTRY
}

/// Called from `read_blob` with the resolved absolute path, after the borrow
/// that read the blob has been released. Trips if the path is a live canary.
pub fn on_read(abs: &str) {
    if eligible(abs) && is_canary(abs) {
        trip(abs);
    }
}

/// Record a trip: append to the alarm log and count it. The append is a
/// read-modify-write that begins with the old content, so `guard` admits it as
/// an extension and refuses anything that is not -- the same shape
/// `godel::ledger_append` relies on.
fn trip(abs: &str) {
    TRIPS.fetch_add(1, Ordering::Relaxed);
    let when = crate::dev::rtc::now()
        .map(|d| crate::dev::rtc::unix_seconds(&d))
        .unwrap_or(0);
    let mut line = String::new();
    push_u64(&mut line, when as u64);
    line.push(' ');
    line.push_str(abs);
    line.push('\n');

    let mut next = super::read_blob_raw(ALARMS).unwrap_or_default();
    next.extend_from_slice(line.as_bytes());
    super::write_text(ALARMS, core::str::from_utf8(&next).unwrap_or(""));

    // Loud, because a canary trip is not routine. On the GF63 the framebuffer
    // is the only channel, so this goes through the console like a fault notice.
    crate::kprintln!("  [canary] tripped: {} read", abs);
}

/// Plant a canary: write the decoy content at `abs`, remember the path, and
/// persist the registry. Operator-only. Returns false if the write is refused.
pub fn plant(abs: &str, content: &[u8]) -> bool {
    if !eligible(abs) {
        return false;
    }
    if !super::write_blob(abs, content.to_vec()) {
        return false;
    }
    {
        let set = unsafe { &mut *CANARIES.get() };
        set.insert(abs.to_string());
    }
    ARMED.store(true, Ordering::Relaxed);
    persist();
    true
}

/// Retire a canary: forget the path so future reads no longer trip. The decoy
/// blob and any alarms it already raised stay -- retiring a trap does not
/// unsay that it was sprung.
pub fn retire(abs: &str) -> bool {
    let removed = {
        let set = unsafe { &mut *CANARIES.get() };
        set.remove(abs)
    };
    if removed {
        let empty = unsafe { (*CANARIES.get()).is_empty() };
        if empty {
            ARMED.store(false, Ordering::Relaxed);
        }
        persist();
    }
    removed
}

fn persist() {
    let set = unsafe { &*CANARIES.get() };
    let mut text = String::new();
    for p in set.iter() {
        text.push_str(p);
        text.push('\n');
    }
    super::write_text(REGISTRY, &text);
}

/// The planted paths, for the operator. Never reachable by the model.
pub fn list() -> Vec<String> {
    let set = unsafe { &*CANARIES.get() };
    set.iter().cloned().collect()
}

/// Trips since boot.
pub fn trips() -> u32 {
    TRIPS.load(Ordering::Relaxed)
}

/// The durable alarm log, newest last.
pub fn alarms() -> Vec<String> {
    match super::read_blob_raw(ALARMS) {
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

/// The rules that make a canary a canary, asserted without planting one on the
/// live namespace. The eligibility rule is the load-bearing one: it is what
/// keeps a trip from recursing through its own alarm log.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   canary    {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // The two Mirror records are never canaries, or a trip writes the alarm log
    // which springs the trap which writes the alarm log.
    check(!eligible(ALARMS), "the alarm log is not itself a canary");
    check(!eligible(REGISTRY), "the registry is not itself a canary");
    check(eligible("/ai/secrets/aws"), "an ordinary bait path is eligible");

    // is_canary is false when nothing is armed, whatever the path -- the
    // unarmed machine trips nothing.
    let was = ARMED.swap(false, Ordering::Relaxed);
    check(!is_canary("/anything"), "an unarmed machine trips nothing");
    ARMED.store(was, Ordering::Relaxed);

    // push_u64 renders a timestamp the alarm log's reader can parse back.
    let mut s = String::new();
    push_u64(&mut s, 1_725_000_000);
    check(s == "1725000000", "timestamp renders as decimal");
    let mut z = String::new();
    push_u64(&mut z, 0);
    check(z == "0", "zero renders");

    ok
}
