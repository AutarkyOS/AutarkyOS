//! Mining: block headers, targets, and the hash loop.
//!
//! Stage one is arithmetic and nothing else. No network, no task, no shell
//! verb -- the pure half first, because every mistake available here is silent.
//! A header with two bytes swapped hashes at full speed and is rejected by the
//! pool forever; a target compared by counting zeros accepts and rejects the
//! wrong shares; a midstate taken at the wrong offset produces digests for a
//! header that never existed. None of that faults.
//!
//! So the fixture is a real block, decomposed into the fields a pool actually
//! sends, and the claim is that reassembling them reproduces the header byte
//! for byte and hashes to the published id. That single claim pins the version
//! reversal, the prevhash word swap, the ntime and nbits reversals, the merkle
//! root's *non*-reversal, every field offset, and the double hash.
//!
//! `tools/algocheck.py` holds the same header and computes the same digest with
//! `hashlib`, which is the bargain `tokenizer.py --verify` makes: the reader is
//! deliberately not the writer.

pub mod client;
pub mod hash;
pub mod header;
pub mod stratum;
pub mod u256;

use alloc::vec::Vec;

use u256::U256;

/// Block 125552's header, as bytes. The same array `tools/algocheck.py` holds.
///
/// Its hash is public and checkable against any explorer, which is what makes
/// it worth more than a synthetic fixture: nothing here chose the answer.
const BTC_HEADER: [u8; 80] = [
    0x01, 0x00, 0x00, 0x00, 0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b, 0xcd, 0x93, 0x17, 0xe2,
    0xfe, 0x99, 0xf2, 0xde, 0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4, 0xa3, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75, 0x04, 0x23, 0xdb, 0x8b,
    0x1e, 0xb9, 0x42, 0xae, 0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf, 0xfc, 0x88, 0x92, 0xb0,
    0xf1, 0xfc, 0x12, 0x2b, 0xc7, 0xf5, 0xd7, 0x4d, 0xf2, 0xb9, 0x44, 0x1a, 0x42, 0xa1, 0x46, 0x95,
];

/// The same block's prevhash **as a pool sends it**: each 4-byte word of the
/// header's own bytes, reversed. Words in the same order.
const BTC_PREV_WIRE: [u8; 32] = [
    0xab, 0x02, 0xcd, 0x81, 0x8b, 0x9e, 0x56, 0x7e, 0xe2, 0x17, 0x93, 0xcd, 0xde, 0xf2, 0x99, 0xfe,
    0xb2, 0x9a, 0xd4, 0x44, 0xa4, 0x1b, 0x85, 0xb8, 0x00, 0x00, 0x08, 0xa3, 0x00, 0x00, 0x00, 0x00,
];

/// And its merkle root, which needs no transform at all.
const BTC_MERKLE: [u8; 32] = [
    0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75, 0x04, 0x23, 0xdb, 0x8b, 0x1e, 0xb9, 0x42, 0xae,
    0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf, 0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b,
];

const BTC_VERSION: u32 = 1;
const BTC_NTIME: u32 = 0x4dd7_f5c7;
const BTC_NBITS: u32 = 0x1a44_b9f2;
const BTC_NONCE: u32 = 0x9546_a142;

/// The raw digest, least-significant byte first. Bitcoin *displays* the reverse
/// of this, which is the trap the constant is written out to pin down.
const BTC_DIGEST: [u8; 32] = [
    0x1d, 0xbd, 0x98, 0x1f, 0xe6, 0x98, 0x57, 0x76, 0xb6, 0x44, 0xb1, 0x73, 0xa4, 0xd0, 0x38, 0x5d,
    0xdc, 0x1a, 0xa2, 0xa8, 0x29, 0x68, 0x8d, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Build a little-endian digest from a big-endian 256-bit value, for the
/// comparison claims. A digest is stored the opposite way round from a target,
/// which is the whole reason `below_target` reverses before comparing.
fn le_digest(be: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = be[31 - i];
    }
    d
}

pub fn checks() -> Vec<(&'static str, bool)> {
    let mut out = Vec::new();

    // --- the fixture, which pins six things at once ---
    let h = header::assemble(
        BTC_VERSION,
        &BTC_PREV_WIRE,
        &BTC_MERKLE,
        BTC_NTIME,
        BTC_NBITS,
        BTC_NONCE,
    );
    out.push((
        "block 125552 reassembles from pool fields, byte for byte",
        h == BTC_HEADER,
    ));
    out.push((
        "and hashes to its published digest",
        hash::sha256d(&h) == BTC_DIGEST,
    ));

    // The prevhash swap is not a whole-string reversal, and it is not a no-op.
    // Both of those are what somebody writes when the table is skimmed, and
    // both would pass a claim that only checked the length.
    let mut whole_rev = [0u8; 32];
    for i in 0..32 {
        whole_rev[i] = BTC_PREV_WIRE[31 - i];
    }
    out.push((
        "the prevhash swap is neither a whole reversal nor a no-op",
        h[4..36] != whole_rev[..] && h[4..36] != BTC_PREV_WIRE[..],
    ));

    // --- the midstate, which is the only optimisation in the tree ---
    let mid = hash::Midstate::new(&h);
    out.push((
        "a midstate reproduces the whole-header hash",
        mid.hash_with(BTC_NONCE) == BTC_DIGEST,
    ));
    out.push((
        "and a different nonce gives a different digest",
        mid.hash_with(BTC_NONCE.wrapping_add(1)) != BTC_DIGEST,
    ));

    // --- targets, produced two ways that must agree ---
    let d1 = u256::diff1();
    let mut want = [0u8; 32];
    want[4] = 0xff;
    want[5] = 0xff;
    out.push((
        "nbits 0x1d00ffff is the difficulty-1 target",
        d1.to_be_bytes() == want,
    ));
    out.push((
        "difficulty 1 gives the same target by the other route",
        u256::target_for(1, 0) == Some(d1),
    ));
    out.push((
        "an exponent off either end is refused, not clamped",
        U256::from_nbits(0x0200_ffff).is_none() && U256::from_nbits(0x2100_ffff).is_none(),
    ));

    // Fractional difficulty. `Json::as_i64` truncates at the decimal point, so
    // 0.001 would arrive as 0 and a target from zero either faults or accepts
    // everything until the worker is banned. This is the arithmetic that makes
    // the split worth carrying.
    let easy = u256::target_for(1, 3); // difficulty 0.001
    out.push((
        "difficulty 0.001 is a larger target than difficulty 1",
        matches!(easy, Some(t) if t > d1),
    ));
    let hard = u256::target_for(8192, 0);
    out.push((
        "and a large difficulty is a smaller one",
        matches!(hard, Some(t) if t < d1),
    ));
    out.push((
        "a zero difficulty is refused rather than divided by",
        u256::target_for(0, 0).is_none(),
    ));
    out.push((
        "overflow refuses instead of wrapping to a smaller target",
        U256::from_be_bytes(&[0xff; 32]).mul_u32(2).is_none(),
    ));

    // --- the comparison, and the case a zero count cannot express ---
    //
    // Both digests below have exactly 32 leading zero bits, so a leading-zero
    // implementation calls them equal. One is under the difficulty-1 target and
    // one is over it. This is the claim `cuda/algo.cuh`'s comment is about.
    let mut lo = [0u8; 32];
    lo[4] = 0xff;
    lo[5] = 0xfe;
    let mut hi = [0u8; 32];
    hi[4] = 0xff;
    hi[5] = 0xff;
    hi[31] = 0x01;
    out.push((
        "a digest under the target passes",
        hash::below_target(&le_digest(&lo), &d1),
    ));
    out.push((
        "one over it does not, though both have 32 leading zeros",
        !hash::below_target(&le_digest(&hi), &d1)
            && hash::leading_zero_bits(&le_digest(&lo)) == 32
            && hash::leading_zero_bits(&le_digest(&hi)) == 32,
    ));
    out.push((
        "a digest exactly on the target counts as below it",
        hash::below_target(&le_digest(&d1.to_be_bytes()), &d1),
    ));

    // --- the pieces the stratum client will lean on ---
    let cb = header::coinbase(b"\x01\x02", b"\xaa\xbb", b"\xcc\xdd", b"\x03\x04");
    out.push((
        "a coinbase is its four parts in order",
        cb == [0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x03, 0x04],
    ));
    out.push((
        "an empty merkle branch leaves the coinbase hash alone",
        header::merkle_root(&cb, &[]) == hash::sha256d(&cb),
    ));
    let sib = [0x11u8; 32];
    out.push((
        "and one step folds the sibling in on the right",
        header::merkle_root(&cb, &[sib]) != hash::sha256d(&cb),
    ));

    let (ntime_hex, nonce_hex) = header::submit_hex(&h);
    out.push((
        "submit sends ntime and nonce big-endian, the header's bytes reversed",
        ntime_hex == [0x4d, 0xd7, 0xf5, 0xc7] && nonce_hex == [0x95, 0x46, 0xa1, 0x42],
    ));

    out.extend(stratum_checks());
    out
}

/// The protocol half: framing, classification, and the difficulty trap.
fn stratum_checks() -> Vec<(&'static str, bool)> {
    use crate::json::Json;
    use alloc::vec;
    use stratum::{classify, decimal, parse_job, subscribe_result, take_line, unhex, Error, Message};

    let mut out = Vec::new();

    // --- framing ---
    let mut buf: Vec<u8> = b"{\"id\":1}".to_vec();
    out.push((
        "a partial line is withheld rather than guessed at",
        matches!(take_line(&mut buf), Ok(None)),
    ));
    buf.extend_from_slice(b"\n{\"id\":2}\n");
    let first = take_line(&mut buf);
    out.push((
        "and completes when the rest of it arrives",
        matches!(&first, Ok(Some(s)) if s == "{\"id\":1}"),
    ));
    out.push((
        "a second line survives the first being taken",
        matches!(take_line(&mut buf), Ok(Some(s)) if s == "{\"id\":2}"),
    ));
    out.push((
        "and the buffer is empty afterwards",
        matches!(take_line(&mut buf), Ok(None)) && buf.is_empty(),
    ));
    let mut crlf: Vec<u8> = b"{\"a\":1}\r\n".to_vec();
    out.push((
        "a CRLF terminator leaves no carriage return behind",
        matches!(take_line(&mut crlf), Ok(Some(s)) if s == "{\"a\":1}"),
    ));
    let mut huge: Vec<u8> = vec![b'x'; stratum::MAX_LINE + 2];
    out.push((
        "a line with no terminator in sight is refused, not buffered forever",
        take_line(&mut huge) == Err(Error::Oversize),
    ));

    // --- the difficulty trap, and the contrast that explains it ---
    //
    // The first of these two is the bug. `as_i64` splits at the decimal point,
    // so a pool sending 0.001 hands the kernel a zero, and a target computed
    // from zero either faults or accepts everything until the worker is banned.
    // Asserting the wrong answer beside the right one is what stops somebody
    // "simplifying" `decimal` back into `as_i64`.
    out.push((
        "as_i64 really does read 0.001 as zero, which is why decimal exists",
        matches!(Json::parse("0.001"), Some(j) if j.as_i64() == Some(0)),
    ));
    out.push(("difficulty 0.001 reads as 1/10^3", decimal("0.001") == Some((1, 3))));
    out.push(("difficulty 8192.5 keeps its half", decimal("8192.5") == Some((81925, 1))));
    out.push(("a whole difficulty has no scale", decimal("8192") == Some((8192, 0))));
    out.push((
        "a difficulty too small to represent errs large, never to zero",
        matches!(decimal("0.0000000001"), Some((m, _)) if m > 0),
    ));
    out.push((
        "and a genuine zero is still zero, for target_for to refuse",
        decimal("0") == Some((0, 0)),
    ));
    out.push((
        "garbage and negatives are refused",
        decimal("-1").is_none() && decimal("abc").is_none() && decimal("").is_none(),
    ));

    // --- hex ---
    out.push((
        "hex refuses an odd length and a non-hex byte",
        unhex("abc").is_none() && unhex("zz").is_none(),
    ));
    out.push((
        "and round-trips what it accepts",
        unhex("00ff10").as_deref() == Some(&[0x00, 0xff, 0x10][..]),
    ));

    // --- classification by shape ---
    let resp = classify("{\"id\":7,\"result\":true,\"error\":null}");
    out.push((
        "a message carrying result is a response, with its id",
        matches!(&resp, Ok(Message::Response { id: 7, ok: true, .. })),
    ));
    out.push((
        "an explicit error is a failed response, not a lost one",
        matches!(
            classify("{\"id\":8,\"result\":null,\"error\":[21,\"Job not found\",null]}"),
            Ok(Message::Response { id: 8, ok: false, .. })
        ),
    ));
    out.push((
        "a result of false is a rejection even with no error object",
        matches!(
            classify("{\"id\":9,\"result\":false,\"error\":null}"),
            Ok(Message::Response { ok: false, .. })
        ),
    ));
    out.push((
        "a method with a null id is a notification",
        matches!(
            classify("{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[0.5]}"),
            Ok(Message::Notify { .. })
        ),
    ));

    // --- subscribe, whose result[0] differs between pools and is never read ---
    let a = Json::parse(
        "{\"id\":1,\"result\":[[[\"mining.set_difficulty\",\"b4b6\"],\
         [\"mining.notify\",\"ae6812\"]],\"08000002\",4],\"error\":null}",
    );
    let b = Json::parse("{\"id\":1,\"result\":[\"deadbeef\",\"1a2b3c4d\",8],\"error\":null}");
    out.push((
        "a nested subscribe result gives up extranonce1 and its size",
        matches!(a.as_ref().and_then(subscribe_result), Some((ref e, 4)) if e == &[0x08, 0x00, 0x00, 0x02]),
    ));
    out.push((
        "and so does a flat one, because result[0] is never read",
        matches!(b.as_ref().and_then(subscribe_result), Some((ref e, 8)) if e == &[0x1a, 0x2b, 0x3c, 0x4d]),
    ));

    // --- a job, with the real block's own fields ---
    let notify = alloc::format!(
        "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job1\",\"{}\",\
         \"01000000\",\"ffffffff\",[],\"00000001\",\"1a44b9f2\",\"4dd7f5c7\",true]}}",
        stratum::hex(&BTC_PREV_WIRE)
    );
    let job = match classify(&notify) {
        Ok(Message::Notify { params, .. }) => parse_job(&params),
        _ => None,
    };
    out.push((
        "a notify parses into a job with the fields in the right order",
        matches!(&job, Some(j)
            if j.id == "job1"
            && j.prev_wire == BTC_PREV_WIRE
            && j.version == BTC_VERSION
            && j.nbits == BTC_NBITS
            && j.ntime == BTC_NTIME
            && j.clean),
    ));
    out.push((
        "a notify one parameter short is refused rather than defaulted",
        matches!(
            classify("{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"j\",\"00\"]}"),
            Ok(Message::Notify { ref params, .. }) if parse_job(params).is_none()
        ),
    ));

    // --- what we send ---
    let s = stratum::submit(3, "wk", "job1", &[0xaa, 0xbb], &[0x4d, 0xd7, 0xf5, 0xc7], &[0x95, 0x46, 0xa1, 0x42]);
    out.push((
        "a submit carries the job, the extranonce and both words as hex",
        s.contains("\"mining.submit\"")
            && s.contains("\"job1\"")
            && s.contains("\"aabb\"")
            && s.contains("\"4dd7f5c7\"")
            && s.contains("\"9546a142\"")
            && s.ends_with('\n'),
    ));
    out.push((
        "and every message we send is one line",
        stratum::subscribe(1).matches('\n').count() == 1
            && stratum::authorize(2, "u", "p").matches('\n').count() == 1,
    ));

    out
}
