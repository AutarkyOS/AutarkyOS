//! Stratum V1: line framing, the messages, and the job they describe.
//!
//! No socket here. The framing and the parsing are free functions over bytes
//! and `Json`, so a selftest can drive the whole protocol from recorded
//! transcripts on a machine with no network at all. That is the same split
//! `ws::take_frame` makes and its comment gives the reason.
//!
//! ### The two things that are silently wrong rather than loudly
//!
//! **Messages are dispatched on shape, not on order.** Stratum is asynchronous:
//! a `mining.notify` routinely lands between a submit and its answer, so a
//! client that reads "the next line after a submit" as that submit's response
//! attributes shares to the wrong jobs and jobs to the wrong shares. An object
//! carrying `id` with `result` or `error` is a response; an object carrying
//! `method` is a notification, and its `id` is null and must be ignored.
//!
//! **Share difficulty is fractional and this kernel's JSON reader truncates.**
//! `Json::as_i64` splits at `.` and returns the integer part, so
//! `set_difficulty [0.001]` reads as **0** and a target computed from zero
//! either faults or accepts everything until the pool bans the worker. Nothing
//! prints. Altcoin pools send fractional difficulties as a matter of course, so
//! `decimal` reads the raw `Json::Num` token instead -- which the parser keeps
//! verbatim, and says so, precisely so this is possible.

use alloc::string::String;
use alloc::vec::Vec;

use crate::json::Json;

/// Largest line accepted before the connection is treated as hostile.
///
/// 128 KiB, not 16. A `mining.notify` carries `coinb1`, `coinb2` and a merkle
/// branch of a dozen 64-character hex strings, and on some coins the coinbase
/// script is long. A bound that is too small does not fail loudly; it presents
/// as a pool that stops sending after a few minutes.
pub const MAX_LINE: usize = 128 * 1024;

/// Digits of fraction kept from a difficulty. See `decimal`.
pub const MAX_SCALE: u32 = 8;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// A line ran past `MAX_LINE` without a terminator.
    Oversize,
    /// The line was not a JSON object.
    Malformed,
}

/// Pull one whole line out of a buffer, if there is one.
///
/// A free function so the splitter is reachable from a selftest without a
/// socket, the same reason `ws::take_frame` is one. TCP segments and JSON-RPC
/// lines have no relationship whatever: one read can return half a line or
/// three of them, and treating one read as one message is the mistake this
/// exists to prevent.
pub fn take_line(buf: &mut Vec<u8>) -> Result<Option<String>, Error> {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        // Only oversize once there is no terminator in sight. A buffer that is
        // large *and* contains a newline is several messages, not one long one.
        if buf.len() > MAX_LINE {
            return Err(Error::Oversize);
        }
        return Ok(None);
    };
    if nl > MAX_LINE {
        return Err(Error::Oversize);
    }
    let mut line: Vec<u8> = buf.drain(..=nl).collect();
    line.pop(); // the newline
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    // Lossy rather than refusing: a pool that sends one stray byte should cost
    // a malformed message, not the connection. `sys_write` records what
    // swallowing the error arm instead costs.
    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
}

/// A difficulty, as mantissa and decimal scale: the value is `m / 10^scale`.
///
/// Reads the raw token because `as_i64` cannot. `scale` is capped at
/// `MAX_SCALE`, and digits past it are truncated toward zero, which yields a
/// *smaller* difficulty and therefore a *larger* target. That direction is
/// deliberate: erring large means submitting shares the pool rejects, which is
/// visible in the reject reason, where erring small means finding nothing at
/// all and looking exactly like a miner that is not working.
///
/// The cap is also what makes `target_for`'s multiplication provably safe:
/// `diff1` has 32 leading zero bits, so multiplying it by `10^8` cannot
/// overflow 256 bits.
pub fn decimal(text: &str) -> Option<(u64, u32)> {
    let t = text.trim();
    if t.is_empty() || t.starts_with('-') {
        return None;
    }
    let (int_part, frac_part) = match t.split_once('.') {
        Some((a, b)) => (a, b),
        None => (t, ""),
    };
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let scale = core::cmp::min(frac_part.len(), MAX_SCALE as usize);
    let mut m: u64 = 0;
    for b in int_part.bytes().chain(frac_part.bytes().take(scale)) {
        m = m.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    // A difficulty small enough to truncate to nothing is still not zero, and a
    // zero mantissa is a division this cannot do. The smallest representable
    // one errs toward a larger target, which is the safe direction above.
    if m == 0 && t.bytes().any(|b| b.is_ascii_digit() && b != b'0') {
        m = 1;
    }
    Some((m, scale as u32))
}

/// Decode hex. Refuses odd length and any non-hex byte.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in b.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

/// What one line from the pool turned out to be.
pub enum Message {
    /// A reply to something we sent. `ok` is false when the pool sent `error`.
    Response { id: u64, ok: bool, body: Json },
    /// The pool telling us something. `id` is null on these and is ignored.
    Notify { method: String, params: Json },
}

/// Classify a line by shape.
///
/// The order of these two tests matters and the reason is not obvious: some
/// pools send a `method` alongside a non-null `id` for calls they expect a
/// reply to. Checking `result`/`error` first means anything that answers one of
/// our ids is treated as an answer, which is what the pending table needs, and
/// only a message that answers nothing is dispatched as a notification.
pub fn classify(line: &str) -> Result<Message, Error> {
    let j = Json::parse(line).ok_or(Error::Malformed)?;
    let has_result = j.get("result").is_some();
    let has_error = matches!(j.get("error"), Some(e) if !e.is_null());
    if has_result || has_error {
        let id = j.get("id").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
        // A null result with a null error is still a success on some pools,
        // notably for `mining.authorize` on older servers. Only an explicit
        // error is a failure.
        let ok = !has_error && !matches!(j.get("result"), Some(r) if matches!(r.as_bool(), Some(false)));
        return Ok(Message::Response { id, ok, body: j });
    }
    if let Some(m) = j.get("method").and_then(|v| v.as_str()) {
        let method = String::from(m);
        let params = j.get("params").cloned().unwrap_or(Json::Null);
        return Ok(Message::Notify { method, params });
    }
    Err(Error::Malformed)
}

/// `extranonce1` and the size of the `extranonce2` we must supply.
///
/// **`result[0]` is never read.** Pools disagree wildly about its shape --
/// nested arrays, flat arrays, sometimes absent entirely -- and none of that
/// disagreement matters, because the only two fields a miner needs are at
/// indices 1 and 2. A parser that walked index 0 would break on a pool whose
/// subscription list happens to be shaped differently, for no benefit.
pub fn subscribe_result(body: &Json) -> Option<(Vec<u8>, usize)> {
    let r = body.get("result")?;
    let e1 = unhex(r.idx(1)?.as_str()?)?;
    let size = r.idx(2)?.as_i64()?;
    if !(0..=64).contains(&size) {
        return None;
    }
    Some((e1, size as usize))
}

/// One unit of work, as `mining.notify` describes it.
pub struct Job {
    pub id: String,
    pub prev_wire: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub branch: Vec<[u8; 32]>,
    pub version: u32,
    pub nbits: u32,
    pub ntime: u32,
    /// The pool saying work in flight is now worthless.
    pub clean: bool,
}

/// Parse `mining.notify`'s parameter list.
///
/// Nine positional parameters, and every one of them is required. A pool that
/// sends eight is a pool this cannot mine for, and answering `None` says so
/// where filling in a default would produce a header that is quietly wrong.
pub fn parse_job(params: &Json) -> Option<Job> {
    let p = params.items();
    if p.len() < 9 {
        return None;
    }
    let word = |j: &Json| -> Option<u32> {
        let b = unhex(j.as_str()?)?;
        if b.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let mut prev_wire = [0u8; 32];
    let pw = unhex(p[1].as_str()?)?;
    if pw.len() != 32 {
        return None;
    }
    prev_wire.copy_from_slice(&pw);

    let mut branch = Vec::new();
    for item in p[4].items() {
        let b = unhex(item.as_str()?)?;
        if b.len() != 32 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        branch.push(a);
    }

    Some(Job {
        id: String::from(p[0].as_str()?),
        prev_wire,
        coinb1: unhex(p[2].as_str()?)?,
        coinb2: unhex(p[3].as_str()?)?,
        branch,
        version: word(&p[5])?,
        nbits: word(&p[6])?,
        ntime: word(&p[7])?,
        // Absent reads as true. A pool that omits it is telling us nothing, and
        // discarding work we could have kept costs a few shares where keeping
        // work the pool has moved on from costs every one of them.
        clean: p[8].as_bool().unwrap_or(true),
    })
}

// --- what we send -----------------------------------------------------------
//
// Built as strings rather than through a JSON writer. The three messages are
// fixed shapes with no user-supplied structure, only user-supplied *scalars*,
// and `json::write_str` escapes those. A writer would be more code for a
// grammar that never varies.

pub fn subscribe(id: u64) -> String {
    let mut s = String::new();
    s.push_str("{\"id\":");
    push_u64(&mut s, id);
    s.push_str(",\"method\":\"mining.subscribe\",\"params\":[");
    crate::json::write_str(&mut s, concat!("glados/", env!("CARGO_PKG_VERSION")));
    s.push_str("]}\n");
    s
}

pub fn authorize(id: u64, user: &str, pass: &str) -> String {
    let mut s = String::new();
    s.push_str("{\"id\":");
    push_u64(&mut s, id);
    s.push_str(",\"method\":\"mining.authorize\",\"params\":[");
    crate::json::write_str(&mut s, user);
    s.push(',');
    crate::json::write_str(&mut s, pass);
    s.push_str("]}\n");
    s
}

/// A found share. `ntime` and `nonce` are big-endian hex, which `submit_hex`
/// produces from the header's own bytes so it cannot drift from what was hashed.
pub fn submit(
    id: u64,
    user: &str,
    job_id: &str,
    extranonce2: &[u8],
    ntime_be: &[u8],
    nonce_be: &[u8],
) -> String {
    let mut s = String::new();
    s.push_str("{\"id\":");
    push_u64(&mut s, id);
    s.push_str(",\"method\":\"mining.submit\",\"params\":[");
    crate::json::write_str(&mut s, user);
    s.push(',');
    crate::json::write_str(&mut s, job_id);
    s.push(',');
    crate::json::write_str(&mut s, &hex(extranonce2));
    s.push(',');
    crate::json::write_str(&mut s, &hex(ntime_be));
    s.push(',');
    crate::json::write_str(&mut s, &hex(nonce_be));
    s.push_str("]}\n");
    s
}

fn push_u64(s: &mut String, mut v: u64) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &buf[i..] {
        s.push(b as char);
    }
}
