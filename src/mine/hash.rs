//! Double SHA-256 over a block header, with the midstate cached.
//!
//! **No SHA-256 is implemented here.** `store::sha256` already has one, checked
//! against the FIPS vectors at every boot, and it was already `Clone` with
//! `snapshot`/`from_snapshot` for exactly this: its own doc comment says
//! midstate snapshots are "the whole trick of header mining". This module is
//! the trick, not the hash.
//!
//! The trick is that a header is 80 bytes and only the last four of them move.
//! SHA-256 absorbs in 64-byte blocks, so the first 64 bytes of a header are one
//! whole block that is constant for a given job, extranonce and timestamp.
//! Absorb them once, keep the state, and every nonce after that costs one
//! compression of the remaining 16 bytes plus padding, instead of two.
//!
//! Roughly a factor of two, and it is the only optimisation in this file.

use crate::store::sha256::Sha256;

use super::u256::U256;

/// SHA-256 applied twice, which is what Bitcoin's header hash is.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = crate::store::sha256::hash(data);
    crate::store::sha256::hash(&first)
}

/// The absorbed first 64 bytes of a header, ready to be cloned per nonce.
///
/// Carries the tail with it so a caller cannot pair a midstate with the wrong
/// 16 bytes, which would hash a header that never existed and produce shares
/// the pool rejects for a reason it cannot explain.
#[derive(Clone)]
pub struct Midstate {
    h: [u32; 8],
    bits: u64,
    tail: [u8; 16],
}

impl Midstate {
    /// Absorb the constant half of a header.
    ///
    /// Exactly 64 bytes and no fewer: `snapshot` is only meaningful with an
    /// empty buffer, because a partial block lives in the buffer rather than in
    /// the state. Feeding 63 or 65 here silently snapshots something that
    /// cannot be resumed correctly.
    pub fn new(header: &[u8; 80]) -> Midstate {
        let mut s = Sha256::new();
        s.update(&header[..64]);
        let (h, bits) = s.snapshot();
        let mut tail = [0u8; 16];
        tail.copy_from_slice(&header[64..80]);
        Midstate { h, bits, tail }
    }

    /// Hash the header this midstate came from, with `nonce` substituted.
    ///
    /// The nonce is the last four bytes of the header, so it lives at offset 12
    /// of the tail. Little-endian, because every multi-byte field in a Bitcoin
    /// header is.
    pub fn hash_with(&self, nonce: u32) -> [u8; 32] {
        let mut tail = self.tail;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());
        let mut s = Sha256::from_snapshot(self.h, self.bits);
        s.update(&tail);
        let first = s.finish();
        crate::store::sha256::hash(&first)
    }
}

/// Whether a header digest is at or below a target.
///
/// Transcribed from `cuda/algo.cuh`, and its comment is the reason this is a
/// real comparison: the digest is a little-endian 256-bit integer, so byte 31
/// is the most significant, and **a leading-zero count answers a different
/// question and cannot express a target that is not a power of two**. Every
/// real target is not a power of two.
///
/// At or below, not below. Bitcoin's rule is `hash <= target`, and a share
/// landing exactly on it is valid; refusing it would throw away a share once in
/// a very long while and be undebuggable when it happened.
pub fn below_target(digest: &[u8; 32], target: &U256) -> bool {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = digest[31 - i];
    }
    U256::from_be_bytes(&be) <= *target
}

/// How many leading zero bits a digest has, for the "best this run" line.
///
/// A display figure and never a decision. It is here because it reads well in a
/// status report and because a run that has never lowered its best is a run
/// that is not hashing, which is worth being able to see.
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut n = 0;
    for i in (0..32).rev() {
        let b = digest[i];
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}
