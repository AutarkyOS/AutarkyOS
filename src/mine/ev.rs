//! What this machine can expect to earn, said plainly enough to be discouraging.
//!
//! `out/release/ROADMAP.md` promised the miner would print "its own terrible
//! expected value on every run", and this is that. It exists because the
//! arithmetic is the single most important fact about CPU mining and the one
//! every miner-shaped product declines to state.
//!
//! ### The rules, each of which this tree has already paid to learn
//!
//! **Every figure names its source on its own line** -- measured this run, on
//! the wire, or as configured. A reader cannot otherwise tell a reading from an
//! assumption, and here they sit in the same column.
//!
//! **A missing input omits its line. Nothing defaults.** A guessed block
//! subsidy or an assumed network difficulty produces a number that is
//! confidently wrong, which is worse than a gap. Same rule `linux::proc` states
//! for `/proc`: a field this machine does not know means the answer does not
//! exist.
//!
//! **No price, ever.** Nothing here can reach one, so every figure is in coins.
//! A currency number would be the one claim on this page that nobody could
//! check, and `docs/token/index.html` already says this project does not make
//! predictions about price.
//!
//! **The sample size sits beside the rate**, and a run under five seconds is
//! tagged unquotable. `design/xpu.md` records three answers spanning 50% from
//! one binary because nobody said how long the runs were.

use super::u256::U256;

/// 2^256, as the closest `f64`. Written out rather than computed because
/// `powi` needs libm and this is a constant.
const TWO_256: f64 = 1.157_920_892_373_162e77;
/// 2^32, the hashes a difficulty-1 share is expected to cost.
const TWO_32: f64 = 4_294_967_296.0;

impl U256 {
    /// The value as an `f64`, losing the low bits.
    ///
    /// Exact enough by a wide margin: an `f64` carries 53 bits of mantissa and
    /// everything below is an order-of-magnitude figure. Doing this in 256-bit
    /// integers would need a full division and would not change a printed
    /// digit.
    pub fn to_f64(self) -> f64 {
        let mut v = 0.0f64;
        for w in self.w {
            v = v * TWO_32 + w as f64;
        }
        v
    }
}

/// Expected hashes to find one at or below `target`.
///
/// `2^256 / target`. The `+1` of the exact form is lost in the `f64` and is
/// irrelevant at this scale.
pub fn expected_hashes(target: &U256) -> Option<f64> {
    let t = target.to_f64();
    if t <= 0.0 {
        return None;
    }
    Some(TWO_256 / t)
}

/// Expected hashes for a share at difficulty `m / 10^scale`.
pub fn share_hashes(m: u64, scale: u32) -> f64 {
    let mut d = m as f64;
    for _ in 0..scale {
        d /= 10.0;
    }
    d * TWO_32
}

/// Read a varint. Answers the value and how many bytes it took.
fn varint(b: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *b.get(at)?;
    match first {
        0..=0xfc => Some((first as u64, 1)),
        0xfd => {
            let s = b.get(at + 1..at + 3)?;
            Some((u16::from_le_bytes([s[0], s[1]]) as u64, 3))
        }
        0xfe => {
            let s = b.get(at + 1..at + 5)?;
            Some((u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64, 5))
        }
        _ => {
            let s = b.get(at + 1..at + 9)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            Some((u64::from_le_bytes(a), 9))
        }
    }
}

/// Sum the output values of a coinbase transaction, in satoshi.
///
/// **The subsidy is not a Stratum field**, and a hardcoded per-coin constant is
/// a number that goes stale silently across a halving. But the assembled
/// coinbase *is* a complete transaction, so its outputs are the pool's actual
/// take plus fees, read from the thing itself.
///
/// **Walks and never seeks, and must land exactly on the last byte.** That is
/// the bargain `v4.py` makes about the model file and it matters for the same
/// reason: a parser that seeks lands on plausible garbage, and every number
/// after it is wrong in a way nothing reports. Anything that does not consume
/// the transaction exactly answers `None`, and the caller omits the line.
///
/// A segwit marker is refused rather than skipped. Stratum's coinbase is the
/// non-witness serialisation by construction, because it is what the merkle
/// root is computed over -- so a marker here means this is not the transaction
/// this code thinks it is.
pub fn coinbase_value(tx: &[u8]) -> Option<u64> {
    let mut at = 4usize; // version
    if tx.get(4) == Some(&0x00) {
        return None; // segwit marker where there cannot be one
    }
    let (n_in, k) = varint(tx, at)?;
    at += k;
    for _ in 0..n_in {
        at = at.checked_add(36)?; // prevout hash and index
        let (slen, k) = varint(tx, at)?;
        at = at.checked_add(k)?.checked_add(slen as usize)?;
        at = at.checked_add(4)?; // sequence
    }
    let (n_out, k) = varint(tx, at)?;
    at = at.checked_add(k)?;
    let mut total: u64 = 0;
    for _ in 0..n_out {
        let v = tx.get(at..at + 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(v);
        total = total.checked_add(u64::from_le_bytes(a))?;
        at += 8;
        let (slen, k) = varint(tx, at)?;
        at = at.checked_add(k)?.checked_add(slen as usize)?;
    }
    at = at.checked_add(4)?; // locktime
    // The whole point. A transaction that does not end here is one this parser
    // has misread, and its output total is a number rather than an answer.
    if at == tx.len() {
        Some(total)
    } else {
        None
    }
}

/// Render a duration in the largest unit that leaves a number under a thousand,
/// which for this machine is usually the one that embarrasses.
pub fn render_seconds(s: f64) -> (f64, &'static str) {
    const STEPS: [(f64, &str); 6] = [
        (1.0, "seconds"),
        (60.0, "minutes"),
        (3600.0, "hours"),
        (86_400.0, "days"),
        (31_557_600.0, "years"),
        (31_557_600_000.0, "millennia"),
    ];
    let mut best = (s, "seconds");
    for (div, name) in STEPS {
        if s / div >= 1.0 {
            best = (s / div, name);
        }
    }
    best
}
