//! BLAKE2s-256, from RFC 7693.
//!
//! Written from the specification rather than ported, which is available here
//! and was not for yespower: BLAKE2s *has* a specification, published as an
//! RFC with its own test vectors, so a from-scratch implementation can be
//! settled against something that is not somebody's source file. The licence
//! gate in `design/mining.md` therefore never comes up.
//!
//! Third algorithm, and the reason to add it is not the coins. It is that
//! `algo.rs`'s whole claim -- one `Algo`, one `Hasher`, and the header
//! assembly, merkle fold, target comparison and Stratum client shared unchanged
//! -- cannot be established by two algorithms, because with two there is no
//! telling a seam from a coincidence. Nothing above `Hasher` moved for this one.
//!
//! ### It has a midstate, and `algo.rs` said it did not
//!
//! That module's comment read "the only one with a usable midstate, because it
//! is the only one whose first 64 header bytes can be absorbed once". The
//! reasoning was right and the conclusion was about SHA-256 rather than about
//! midstates: BLAKE2s is also a 64-byte block function over an 80-byte header
//! with the nonce at offset 76, so block 0 is constant across every nonce and
//! is compressed once. What made yespower different is not its block size, it
//! is that yespower puts all eighty bytes through PBKDF2 before any of the
//! expensive part begins.
//!
//! The saving is exactly half the compression work per nonce, and the claim
//! that it is *correct* is the same one SHA-256d carries: hashing through the
//! midstate must equal hashing the whole eighty bytes, checked against a digest
//! this kernel did not compute.

/// RFC 7693 section 2.6. The SHA-256 initialisation vector, unchanged.
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// RFC 7693 section 2.7. Ten rounds, so ten permutations -- BLAKE2**s** stops
/// at ten where BLAKE2b takes twelve and wraps back to rows 0 and 1.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// RFC 7693 section 3.2. `t` is the count of bytes fed *including* this block,
/// and `last` marks the final one.
///
/// `t` is what the padding of a short final block rests on: the block is zero
/// filled to 64 bytes and the counter still says 80, so two messages differing
/// only in length cannot compress to the same thing. A `t` taken as the block
/// index instead -- the obvious misreading, and the one a 64-byte-aligned test
/// message never catches -- makes `"a"` and `"a\0"` collide.
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }

    for s in SIGMA.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// The unkeyed 32-byte-digest parameter block, folded into `h[0]`.
///
/// `0x0101_0020` is depth 1, fanout 1, key length 0, digest length 32. It is
/// not decoration: a wrong digest length here produces a perfectly well-formed
/// 32-byte hash that no other BLAKE2s implementation agrees with, which is the
/// failure mode this whole file is checked against a published vector to catch.
fn init() -> [u32; 8] {
    let mut h = IV;
    h[0] ^= 0x0101_0020;
    h
}

/// BLAKE2s-256 of an arbitrary message, unkeyed.
pub fn hash(msg: &[u8]) -> [u8; 32] {
    let mut h = init();
    let mut t = 0u64;
    let mut i = 0;

    // Every block but the last goes through as a full one. The loop condition
    // is `+ 64 < len` rather than `<=`, because a message that is an exact
    // multiple of 64 must keep its final block for the `last` flag -- a
    // strictly-less test would compress it as an interior block and then
    // compress an all-zero block as the final one, which is a different hash.
    while i + 64 < msg.len() {
        let mut b = [0u8; 64];
        b.copy_from_slice(&msg[i..i + 64]);
        t += 64;
        compress(&mut h, &b, t, false);
        i += 64;
    }

    let mut b = [0u8; 64];
    b[..msg.len() - i].copy_from_slice(&msg[i..]);
    t += (msg.len() - i) as u64;
    compress(&mut h, &b, t, true);

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

/// The first block of an 80-byte header, absorbed once.
///
/// The same trade `hash::Midstate` makes, and worth the same caution: a
/// midstate built from a *different* header hashes a block that never existed
/// while looking perfectly healthy, so `Hasher::retarget` has to rebuild this
/// on every job and the header argument to `hash_with` is not consulted below
/// offset 64.
#[derive(Clone)]
pub struct Midstate {
    h: [u32; 8],
    tail: [u8; 16],
}

impl Midstate {
    pub fn new(header: &[u8; 80]) -> Midstate {
        let mut h = init();
        let mut b = [0u8; 64];
        b.copy_from_slice(&header[..64]);
        compress(&mut h, &b, 64, false);
        let mut tail = [0u8; 16];
        tail.copy_from_slice(&header[64..]);
        Midstate { h, tail }
    }

    /// The digest for this header with `nonce` substituted at offset 76.
    pub fn hash_with(&self, nonce: u32) -> [u8; 32] {
        let mut h = self.h;
        let mut b = [0u8; 64];
        b[..16].copy_from_slice(&self.tail);
        b[12..16].copy_from_slice(&nonce.to_le_bytes());
        // 80 and never 16: the counter is the whole message length, and the
        // final block is zero filled from 16 to 64.
        compress(&mut h, &b, 80, true);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
        }
        out
    }
}
