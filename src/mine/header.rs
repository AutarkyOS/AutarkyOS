//! An 80-byte block header, built from the fields a pool sends.
//!
//! **Byte order is the whole of this file.** Every field in `mining.notify`
//! arrives as hex, four of them need transforming before they are a header, and
//! getting one wrong produces a header of exactly the right length that hashes
//! at exactly the right speed and is wrong. There is no error to catch. The
//! pool rejects every share and the reason string is the only clue.
//!
//! | header bytes | source | transform |
//! |---|---|---|
//! | `[0..4]` version | `version` hex | parse big-endian, write little |
//! | `[4..36]` prevhash | `prevhash` hex | **reverse each 4-byte word in place**, words stay in order |
//! | `[36..68]` merkle root | computed | as `sha256d` produced it, no reversal |
//! | `[68..72]` ntime | `ntime` hex | parse big-endian, write little |
//! | `[72..76]` nbits | `nbits` hex | parse big-endian, write little |
//! | `[76..80]` nonce | ours | little-endian |
//!
//! The prevhash word swap is the one nobody gets right first time. It is not a
//! whole-string reversal and it is not a no-op: the eight words keep their
//! order and each one's four bytes flip. It is pinned by the block-125552
//! vector, which is why that fixture is the most valuable check in this tree.
//!
//! On the way back out, `mining.submit` sends `ntime` and `nonce` as
//! **big-endian** hex. `submit_hex` writes them as the header's own bytes
//! reversed rather than as `to_be_bytes` of the value, deliberately: that is
//! one rule instead of two, and it cannot drift out of step with what was
//! actually hashed.

use alloc::vec::Vec;

use super::hash;

/// Assemble a header. Every argument is already parsed; nothing here sees hex.
pub fn assemble(
    version: u32,
    prev_wire: &[u8; 32],
    merkle: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    // Words in order, bytes within each word reversed.
    for w in 0..8 {
        for b in 0..4 {
            h[4 + w * 4 + b] = prev_wire[w * 4 + 3 - b];
        }
    }
    h[36..68].copy_from_slice(merkle);
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&nbits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// The coinbase transaction, assembled from the pool's two halves.
///
/// `coinb1 || extranonce1 || extranonce2 || coinb2`. The extranonce bytes are
/// handed in rather than formatted here, because the *same* bytes have to reach
/// the submit, and a counter formatted twice is a counter that can be formatted
/// two ways.
pub fn coinbase(c1: &[u8], e1: &[u8], e2: &[u8], c2: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(c1.len() + e1.len() + e2.len() + c2.len());
    v.extend_from_slice(c1);
    v.extend_from_slice(e1);
    v.extend_from_slice(e2);
    v.extend_from_slice(c2);
    v
}

/// Fold the coinbase through the merkle branch.
///
/// The branch is always the right-hand sibling at each level, because the
/// coinbase is always the leftmost leaf. That is why a pool can send a branch
/// at all rather than the whole tree, and why there is no ordering decision to
/// get wrong here: it is concatenate-and-hash, in the order given, every time.
pub fn merkle_root(coinbase: &[u8], branch: &[[u8; 32]]) -> [u8; 32] {
    let mut root = hash::sha256d(coinbase);
    let mut buf = [0u8; 64];
    for sib in branch {
        buf[..32].copy_from_slice(&root);
        buf[32..].copy_from_slice(sib);
        root = hash::sha256d(&buf);
    }
    root
}

/// `ntime` and `nonce` as `mining.submit` wants them: the header's own bytes,
/// reversed.
pub fn submit_hex(header: &[u8; 80]) -> (Vec<u8>, Vec<u8>) {
    let be = |s: &[u8]| -> Vec<u8> {
        let mut v = Vec::with_capacity(4);
        for i in (0..4).rev() {
            v.push(s[i]);
        }
        v
    };
    (be(&header[68..72]), be(&header[76..80]))
}
