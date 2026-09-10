//! NeoScrypt, the proof-of-work Feathercoin, Phoenixcoin and Orbitcoin use.
//!
//! Transliterated from `neoscrypt.c` (ghostlander), which is 2-clause BSD:
//!
//! > Copyright (c) 2009 Colin Percival, 2011 ArtForz
//! > Copyright (c) 2012-2013 John Doering <ghostlander@phoenixcoin.org>
//! > All rights reserved.
//! >
//! > Redistribution and use in source and binary forms, with or without
//! > modification, are permitted provided that the following conditions are
//! > met: 1. Redistributions of source code must retain the above copyright
//! > notice, this list of conditions and the following disclaimer. [...]
//!
//! Same arrangement `src/mine/yespower.rs` has with openwall and `src/doom/`
//! has with room4doom: one file, marked at the top, saying where it came from.
//! `design/mining.md`'s rule holds -- the algorithm's own upstream, never
//! cpuminer-opt, which is GPL-2 and would put an obligation on the whole
//! kernel.
//!
//! ### The reference path, and upstream ships two
//!
//! `neoscrypt.c` carries a readable `blkmix` "for any reasonable r" and an
//! optimised branch that unrolls r = 1 and r = 2. This follows the readable
//! one, for the reason yespower follows `yespower-ref.c`: a hash that is fast
//! and wrong runs at full speed and has every share rejected with nothing
//! reporting why, and there is no way to tell fast-and-wrong from
//! fast-and-right except by comparing against something.
//!
//! ### What it is compared against
//!
//! `tools/neoscrypt.py`, which is the same transliteration in Python with the
//! PRF taken from `hashlib` rather than written -- the bargain
//! `tokenizer.py --verify` makes, where the reader is deliberately not the
//! writer. And underneath that, the thing that actually settles it: **two real
//! Feathercoin blocks the network accepted.** Upstream ships no test vectors at
//! all, so there is no published constant to check against; a block is
//! stronger anyway, because it was only ever on the chain if its NeoScrypt
//! digest landed under the target its own `nbits` declares. Reproducing that by
//! accident is 1 in 7e7 for block 432,001 and 1 in 4.1e9 for block 6,346,000.
//!
//! **And the vector has already earned its place twice.** In Python, a `blkmix`
//! that swapped the wrong pair of chunks produced a 32-byte digest,
//! deterministically, with 133 of 256 bits changing on a one-bit input change,
//! which is textbook avalanche. Every structural claim passed. Only a real
//! block said no. That is why `checks()` below spends most of its lines on two
//! headers and treats determinism and avalanche as hygiene.

use alloc::vec;
use alloc::vec::Vec;

use super::blake2s;

/// The default profile, which is what every coin using this actually runs:
/// N = 128, r = 2, ChaCha20/20 and Salsa20/20 both, FastKDF-BLAKE2s either
/// side. Written as constants rather than as parameters because a NeoScrypt
/// with different ones is a different network's proof-of-work, and the two
/// alternative profiles upstream admits (Scrypt(1024,1,1), PBKDF2 KDFs) have no
/// coin behind them here.
const N: usize = 128;
const R: usize = 2;
const ROUNDS: u32 = 20;
/// Words in one working block: `32 * r`, so 64 words and 256 bytes.
const WORDS: usize = 32 * R;
/// Blocks in one working block, `2 * r`. The mixer chains over these.
const CHUNKS: usize = 2 * R;

const KDF_BUF: usize = 256;
/// Upstream's `N` argument to FastKDF, which is 32 at both call sites. A
/// summary of `neoscrypt.c` put this at one, which would have produced a hash
/// that computes something, quickly.
const KDF_ROUNDS: usize = 32;
const PRF_INPUT: usize = 64;
const PRF_KEY: usize = 32;
const PRF_OUTPUT: usize = 32;

/// The Salsa20 core over 16 words, in upstream's index order.
///
/// **Not scrypt's word order.** scrypt shuffles the block through `i * 5 % 16`
/// on the way in and out, as `yespower.rs` does and says so; NeoScrypt does
/// not, and mixes the natural layout. Borrowing the shuffled version from the
/// file next door gives a permutation that is stable, fast and not NeoScrypt.
fn salsa(x: &mut [u32; 16], rounds: u32) {
    #[inline(always)]
    fn q(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        v[b] ^= v[a].wrapping_add(v[d]).rotate_left(7);
        v[c] ^= v[b].wrapping_add(v[a]).rotate_left(9);
        v[d] ^= v[c].wrapping_add(v[b]).rotate_left(13);
        v[a] ^= v[d].wrapping_add(v[c]).rotate_left(18);
    }

    let o = *x;
    let mut v = *x;
    // Two rounds per iteration, because a round here is a half of a double
    // round. A count silently halved or doubled produces a perfectly plausible
    // digest, which is why `checks()` asserts that 2 and 4 differ.
    for _ in 0..rounds / 2 {
        q(&mut v, 0, 4, 8, 12);
        q(&mut v, 5, 9, 13, 1);
        q(&mut v, 10, 14, 2, 6);
        q(&mut v, 15, 3, 7, 11);
        q(&mut v, 0, 1, 2, 3);
        q(&mut v, 5, 6, 7, 4);
        q(&mut v, 10, 11, 8, 9);
        q(&mut v, 15, 12, 13, 14);
    }
    for i in 0..16 {
        x[i] = o[i].wrapping_add(v[i]);
    }
}

/// The ChaCha20 core over 16 words. Same feed-forward, different quarter round.
fn chacha(x: &mut [u32; 16], rounds: u32) {
    #[inline(always)]
    fn q(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        v[a] = v[a].wrapping_add(v[b]);
        v[d] = (v[d] ^ v[a]).rotate_left(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_left(12);
        v[a] = v[a].wrapping_add(v[b]);
        v[d] = (v[d] ^ v[a]).rotate_left(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_left(7);
    }

    let o = *x;
    let mut v = *x;
    for _ in 0..rounds / 2 {
        q(&mut v, 0, 4, 8, 12);
        q(&mut v, 1, 5, 9, 13);
        q(&mut v, 2, 6, 10, 14);
        q(&mut v, 3, 7, 11, 15);
        q(&mut v, 0, 5, 10, 15);
        q(&mut v, 1, 6, 11, 12);
        q(&mut v, 2, 7, 8, 13);
        q(&mut v, 3, 4, 9, 14);
    }
    for i in 0..16 {
        x[i] = o[i].wrapping_add(v[i]);
    }
}

/// Upstream's mixer: chain all `2r` chunks through the core, then permute.
///
/// **The permutation is the whole difference from scrypt** and is the one place
/// in this file where a wrong answer looks entirely healthy. scrypt writes its
/// mixed chunks back in order; NeoScrypt writes evens first and then odds, so
/// `X[i] = Y[2i]` and `X[i + r] = Y[2i + 1]`.
///
/// At r = 2 that reduces to exchanging the **middle two** chunks, 1 and 2 --
/// which is exactly what upstream's optimised branch spells as a single
/// `blkswp(&X[16], &X[32])`. Its comment beside that reads `Xa" = Ya; Xb" = Yc;
/// Xc" = Yb; Xd" = Yd`, and the Python reference read that comment and swapped
/// 1 with **3**. The result hashed, deterministically, with textbook
/// avalanche, and was not NeoScrypt. The general form is written out here
/// rather than the r = 2 swap for that reason: it says what the rule is instead
/// of what it happens to equal.
///
/// The write-back order inside the chain is load-bearing too. Chunk 0 XORs the
/// **last** chunk as this call found it, and every later chunk XORs the chunk
/// mixed immediately before it, so `y` cannot be filled first and permuted
/// afterwards from a copy taken at entry.
fn blkmix(x: &mut [u32; WORDS], y: &mut [u32; WORDS], chacha_mode: bool, rounds: u32) {
    for i in 0..CHUNKS {
        let prev = if i > 0 { i - 1 } else { CHUNKS - 1 };
        for k in 0..16 {
            let t = x[16 * prev + k];
            x[16 * i + k] ^= t;
        }
        let mut blk = [0u32; 16];
        blk.copy_from_slice(&x[16 * i..16 * i + 16]);
        if chacha_mode {
            chacha(&mut blk, rounds);
        } else {
            salsa(&mut blk, rounds);
        }
        x[16 * i..16 * i + 16].copy_from_slice(&blk);
        y[16 * i..16 * i + 16].copy_from_slice(&blk);
    }
    for i in 0..R {
        let src = 16 * (2 * i);
        let (a, b) = (16 * i, 16 * i + 16);
        x[a..b].copy_from_slice(&y[src..src + 16]);
    }
    for i in 0..R {
        let src = 16 * (2 * i + 1);
        let (a, b) = (16 * (i + R), 16 * (i + R) + 16);
        x[a..b].copy_from_slice(&y[src..src + 16]);
    }
}

/// `integerify` mod N, which upstream takes from the **last** chunk's first
/// word rather than the first chunk's. Reading word 0 gives a walk over the
/// scratchpad that is uniform, deterministic and wrong.
#[inline]
fn integerify(x: &[u32; WORDS]) -> usize {
    (x[16 * (CHUNKS - 1)] as usize) & (N - 1)
}

/// One SMix pass: fill `v` with N snapshots, then read N of them back at
/// data-dependent offsets. Both halves mix in place.
fn smix(x: &mut [u32; WORDS], y: &mut [u32; WORDS], v: &mut [u32], chacha_mode: bool) {
    for i in 0..N {
        v[i * WORDS..(i + 1) * WORDS].copy_from_slice(&x[..]);
        blkmix(x, y, chacha_mode, ROUNDS);
    }
    for _ in 0..N {
        let j = integerify(x) * WORDS;
        for k in 0..WORDS {
            x[k] ^= v[j + k];
        }
        blkmix(x, y, chacha_mode, ROUNDS);
    }
}

/// One instance, holding its whole working set and reused across nonces.
///
/// **The allocation is the point of the type**, the same argument
/// `yespower.rs` makes: `v` alone is `N * 2r * 64` = 32 KiB, a miner hashes
/// millions of nonces against one header, and this kernel's heap takes a lock
/// on every allocation. Allocating per hash would spend more time in the
/// allocator than in the algorithm.
///
/// Only `v` is heap: it is the one buffer large enough to matter, and putting
/// the other 1,376 bytes inline keeps `new()` from touching the heap four
/// times. That matters here rather than in yespower because there is no
/// parameter to size them from -- N, r and the round count are the profile, so
/// the shapes are known at compile time.
pub struct Neoscrypt {
    /// The Salsa half, and the block the final KDF is salted with.
    x: [u32; WORDS],
    /// The ChaCha half. Upstream's `Z`.
    z: [u32; WORDS],
    /// `blkmix`'s output space. Upstream's `Y`, and it must not be shared with
    /// either half: the permutation reads it after the chain has overwritten
    /// the chunks it came from.
    y: [u32; WORDS],
    /// The scratchpad, `N` snapshots of a working block.
    v: Vec<u32>,
    /// FastKDF's password buffer: 256 bytes plus a 64-byte wrapped copy of the
    /// head. The tail is not padding -- the round loop genuinely reads a whole
    /// 64-byte input starting at any offset up to 255.
    a: [u8; KDF_BUF + PRF_INPUT],
    /// FastKDF's salt buffer, with a 32-byte tail for the same reason, and it
    /// is written as well as read.
    b: [u8; KDF_BUF + PRF_KEY],
}

impl Default for Neoscrypt {
    fn default() -> Neoscrypt {
        Neoscrypt::new()
    }
}

impl Neoscrypt {
    pub fn new() -> Neoscrypt {
        Neoscrypt {
            x: [0u32; WORDS],
            z: [0u32; WORDS],
            y: [0u32; WORDS],
            v: vec![0u32; N * WORDS],
            a: [0u8; KDF_BUF + PRF_INPUT],
            b: [0u8; KDF_BUF + PRF_KEY],
        }
    }

    /// Bytes of working memory this instance holds, for the resource budget.
    ///
    /// Upstream sizes one stack allocation as `(N + 3) * r * 2 * BLOCK_SIZE`,
    /// which is 33,536 bytes and covers X, Z, Y and V. A summary of that file
    /// put it at about a megabyte, which is the sort of error a budget built on
    /// it would carry into every decision about how many of these can run at
    /// once. The KDF buffers are upstream's separate 608 bytes.
    pub fn footprint(&self) -> usize {
        (self.x.len() + self.z.len() + self.y.len() + self.v.len()) * 4
            + self.a.len()
            + self.b.len()
    }

    /// Upstream's FastKDF. `rounds` is its `N`, which is 32 at both call sites.
    ///
    /// It is a keyed BLAKE2s walked over a pair of 256-byte ring buffers, where
    /// the digest of each round both modifies the salt buffer and chooses where
    /// the next round reads from. The offset is the **sum of all 32 output
    /// bytes**, not a slice of them: a sum uses every byte, which is what stops
    /// the walk correlating with any particular part of the output. Upstream's
    /// optimised path sums the four bytes of each of the eight words rather
    /// than the words themselves, and confirms the reading.
    fn fastkdf(&mut self, password: &[u8], salt: &[u8], rounds: usize, out: &mut [u8]) {
        fill(&mut self.a, password, PRF_INPUT);
        fill(&mut self.b, salt, PRF_KEY);

        let mut bufptr = 0usize;
        for _ in 0..rounds {
            let mut input = [0u8; PRF_INPUT];
            input.copy_from_slice(&self.a[bufptr..bufptr + PRF_INPUT]);
            let mut key = [0u8; PRF_KEY];
            key.copy_from_slice(&self.b[bufptr..bufptr + PRF_KEY]);
            let prf = blake2s::keyed_64(&key, &input);

            let mut sum = 0usize;
            for &byte in prf.iter() {
                sum += byte as usize;
            }
            bufptr = sum & (KDF_BUF - 1);

            for j in 0..PRF_OUTPUT {
                self.b[bufptr + j] ^= prf[j];
            }

            // Keep the wrapped tail and the head in step, in whichever
            // direction the write landed. Skipping this reads stale bytes on
            // any later round that happens to start near a boundary, which is
            // a wrong answer on some inputs and not on others -- the shape of
            // bug that passes every avalanche test and fails against a chain.
            if bufptr < PRF_KEY {
                let n = core::cmp::min(PRF_OUTPUT, PRF_KEY - bufptr);
                self.b.copy_within(bufptr..bufptr + n, KDF_BUF + bufptr);
            } else if KDF_BUF - bufptr < PRF_OUTPUT {
                let n = PRF_OUTPUT - (KDF_BUF - bufptr);
                self.b.copy_within(KDF_BUF..KDF_BUF + n, 0);
            }
        }

        // The output is the salt buffer from wherever the walk stopped, XORed
        // with the head of the password buffer and wrapping if it runs off the
        // end. The wrap cannot overlap what it is about to copy out, because
        // `output_len - avail` is at most `bufptr`.
        let len = core::cmp::min(out.len(), KDF_BUF);
        let avail = KDF_BUF - bufptr;
        if avail >= len {
            for j in 0..len {
                self.b[bufptr + j] ^= self.a[j];
            }
            out[..len].copy_from_slice(&self.b[bufptr..bufptr + len]);
        } else {
            for j in 0..avail {
                self.b[bufptr + j] ^= self.a[j];
            }
            for j in 0..len - avail {
                self.b[j] ^= self.a[avail + j];
            }
            out[..avail].copy_from_slice(&self.b[bufptr..bufptr + avail]);
            out[avail..len].copy_from_slice(&self.b[..len - avail]);
        }
    }

    /// Hash an 80-byte block header.
    ///
    /// **No midstate, and there cannot be one.** `blake2s::Midstate` works
    /// because the first 64 header bytes are constant across nonces and go
    /// through one compression; here all eighty bytes are tiled across a
    /// 256-byte buffer before the first PRF call, so a nonce change at offset
    /// 76 moves bytes at four places in `A` and four in `B`, and every round
    /// after the first reads from a data-dependent offset anyway. The same
    /// objection `algo.rs` records about yespower, arriving by a different
    /// route.
    pub fn hash(&mut self, header: &[u8; 80]) -> [u8; 32] {
        // The password *is* the salt for the first KDF, which is upstream's
        // `p = 1, salt = password`.
        let mut seed = [0u8; WORDS * 4];
        self.fastkdf(header, header, KDF_ROUNDS, &mut seed);
        for i in 0..WORDS {
            self.x[i] = u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ]);
        }
        self.z = self.x;

        // ChaCha first into Z, Salsa second into X, then XOR. Both passes read
        // and write the same scratchpad, one after the other -- they are not
        // concurrent and V carries nothing between them.
        smix(&mut self.z, &mut self.y, &mut self.v, true);
        smix(&mut self.x, &mut self.y, &mut self.v, false);
        for k in 0..WORDS {
            self.x[k] ^= self.z[k];
        }

        let mut packed = [0u8; WORDS * 4];
        for i in 0..WORDS {
            packed[i * 4..i * 4 + 4].copy_from_slice(&self.x[i].to_le_bytes());
        }
        // The password is the header again and the salt is the mixed block, not
        // the other way round. Swapping them is a perfectly good FastKDF of the
        // wrong thing.
        let mut out = [0u8; 32];
        self.fastkdf(header, &packed, KDF_ROUNDS, &mut out);
        out
    }
}

/// Tile `src` across the 256-byte body of `buf`, then append `tail` bytes of
/// its head past the end.
///
/// The tile is by repetition and not by zero padding: an 80-byte header goes in
/// three times and then the first 16 bytes again. Padding instead would leave
/// most of the buffer constant across every nonce, which is a KDF that still
/// produces 32 bytes.
///
/// The tail is copied from `src` rather than from the buffer, which is the same
/// bytes only because the tile starts at offset 0 -- upstream reads it from the
/// source and so does this, so the two cannot come apart if the fill ever
/// changes.
fn fill(buf: &mut [u8], src: &[u8], tail: usize) {
    let n = core::cmp::min(src.len(), KDF_BUF);
    let mut at = 0;
    while at < KDF_BUF {
        let take = core::cmp::min(n, KDF_BUF - at);
        buf[at..at + take].copy_from_slice(&src[..take]);
        at += take;
    }
    buf[KDF_BUF..KDF_BUF + tail].copy_from_slice(&src[..tail]);
}

/// Feathercoin block 432,001 -- the first block after the fork to NeoScrypt --
/// and 6,346,000, so the two span the whole NeoScrypt era. Assembled from the
/// explorer's fields and pinned separately: Feathercoin is a Litecoin fork, so
/// its *block* hash is SHA-256d while its *proof of work* is NeoScrypt, which
/// means the published block id already checks these eighty bytes before
/// NeoScrypt is asked anything. `tools/neoscrypt.py --check` re-derives them
/// from the live chain.
const BLOCK_432001: [u8; 80] = [
    0x02, 0x00, 0x00, 0x00, 0x54, 0xaa, 0x94, 0xa4, 0x6a, 0x70, 0x93, 0x1d, 0x29, 0xf2, 0xa2, 0xed,
    0x3e, 0xe4, 0xab, 0x58, 0x32, 0xcd, 0x64, 0x46, 0xa0, 0x90, 0xf6, 0xf6, 0x32, 0x92, 0xd0, 0x04,
    0xdd, 0x30, 0x6e, 0x96, 0xbc, 0xa6, 0xf3, 0xf2, 0x29, 0x28, 0xee, 0x4a, 0xa4, 0x68, 0xed, 0x5d,
    0x5f, 0xf0, 0xf0, 0xa3, 0x11, 0x37, 0xc2, 0xf9, 0xe7, 0x80, 0xe0, 0xa7, 0x04, 0x11, 0xa4, 0xa3,
    0x9b, 0x98, 0xd9, 0x1c, 0x1b, 0x36, 0x4d, 0x54, 0xdc, 0xdd, 0x3d, 0x1d, 0x52, 0x66, 0x04, 0x00,
];

/// Its digest, least-significant byte first. A chain displays the reverse,
/// which is the trap `mod.rs` writes out for SHA-256d and it is the same trap
/// here.
const DIGEST_432001: [u8; 32] = [
    0xaa, 0xc8, 0xea, 0xae, 0xa3, 0xc7, 0x56, 0xf5, 0x84, 0xd8, 0x84, 0xf2, 0xde, 0x9e, 0x0e, 0x8c,
    0x40, 0x1f, 0x3b, 0xa0, 0xa6, 0x40, 0xa1, 0x42, 0x21, 0x55, 0x0d, 0x2d, 0x06, 0x00, 0x00, 0x00,
];

const NBITS_432001: u32 = 0x1d3d_dddc;

const BLOCK_6346000: [u8; 80] = [
    0x04, 0x00, 0x00, 0x20, 0x0a, 0x92, 0x45, 0xb1, 0x19, 0x88, 0x25, 0xab, 0x30, 0xd6, 0xdb, 0xae,
    0x2b, 0x18, 0x5e, 0x31, 0xf3, 0x42, 0xd1, 0x05, 0x8c, 0xc3, 0x68, 0x51, 0x62, 0x9b, 0xf4, 0x35,
    0xfc, 0x68, 0x2b, 0x55, 0x4d, 0x10, 0x07, 0x71, 0xe4, 0xa2, 0x3d, 0x21, 0x0c, 0xd3, 0xa1, 0x50,
    0x3e, 0x3b, 0x1c, 0xa5, 0x24, 0xe8, 0x48, 0x29, 0x13, 0xee, 0x5b, 0x40, 0x36, 0xed, 0xf4, 0xbd,
    0x20, 0xdb, 0x6a, 0x29, 0x93, 0xc0, 0xa1, 0x6a, 0xdc, 0x09, 0x01, 0x1d, 0x00, 0x2c, 0x5f, 0x48,
];

const DIGEST_6346000: [u8; 32] = [
    0xff, 0x87, 0x01, 0x0b, 0x15, 0xaf, 0xee, 0x12, 0x37, 0x59, 0xc6, 0xcb, 0x14, 0xfe, 0x33, 0x07,
    0x8d, 0x17, 0x95, 0xca, 0x6f, 0x39, 0x28, 0x6c, 0x35, 0x66, 0xd5, 0x25, 0x00, 0x00, 0x00, 0x00,
];

const NBITS_6346000: u32 = 0x1d01_09dc;

/// Published keyed BLAKE2s vectors, from the reference `blake2s-kat.txt` that
/// ships with the BLAKE2 sources: key `00 01 .. 1f`, and messages of 0 and 64
/// bytes counting up the same way. The 64-byte one is the shape FastKDF uses,
/// so it checks the specialised path against something nobody here computed.
const KAT_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const KAT_EMPTY: [u8; 32] = [
    0x48, 0xa8, 0x99, 0x7d, 0xa4, 0x07, 0x87, 0x6b, 0x3d, 0x79, 0xc0, 0xd9, 0x23, 0x25, 0xad, 0x3b,
    0x89, 0xcb, 0xb7, 0x54, 0xd8, 0x6a, 0xb7, 0x1a, 0xee, 0x04, 0x7a, 0xd3, 0x45, 0xfd, 0x2c, 0x49,
];

const KAT_64: [u8; 32] = [
    0x89, 0x75, 0xb0, 0x57, 0x7f, 0xd3, 0x55, 0x66, 0xd7, 0x50, 0xb3, 0x62, 0xb0, 0x89, 0x7a, 0x26,
    0xc3, 0x99, 0x13, 0x6d, 0xf0, 0x7b, 0xab, 0xab, 0xbd, 0xe6, 0x20, 0x3f, 0xf2, 0x95, 0x4e, 0xd4,
];

/// Claims. Pure arithmetic, so none of this needs a pool, a task or a device.
///
/// The two blocks are the check. Everything above them is hygiene, and the
/// reason to say so plainly is that **every one of those hygiene claims passed
/// on the version with the wrong swap in `blkmix`** -- it was deterministic, it
/// produced 32 bytes, and one bit in changed half of them.
pub fn checks() -> Vec<(&'static str, bool)> {
    let mut out: Vec<(&'static str, bool)> = Vec::new();

    // The parameter block, against the constant upstream's optimised path
    // hard-codes. This is what says the keying here is the keying there.
    out.push((
        "the keyed BLAKE2s parameter block matches upstream's IV constant",
        0x6a09_e667u32 ^ 0x0101_2020 == 0x6b08_c647,
    ));
    out.push((
        "keyed BLAKE2s agrees with the published empty-message vector",
        blake2s::keyed(&KAT_KEY, &[]) == KAT_EMPTY,
    ));
    let mut kat_msg = [0u8; 64];
    for (i, b) in kat_msg.iter_mut().enumerate() {
        *b = i as u8;
    }
    out.push((
        "and with the 64-byte one, which is the shape FastKDF asks for",
        blake2s::keyed(&KAT_KEY, &kat_msg) == KAT_64,
    ));
    // The specialised path is a copy of the general one, and a copy drifts.
    out.push((
        "the specialised two-block path equals the general keyed hash",
        blake2s::keyed_64(&KAT_KEY, &kat_msg) == KAT_64,
    ));

    // The cores move, are different functions, and count their rounds. A round
    // count silently halved still produces a plausible digest.
    let seed: [u32; 16] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let mut sa = seed;
    salsa(&mut sa, 20);
    let mut ch = seed;
    chacha(&mut ch, 20);
    out.push(("salsa moves its input", sa != seed));
    out.push(("chacha moves its input", ch != seed));
    out.push(("and they are different functions", sa != ch));
    let mut two = seed;
    salsa(&mut two, 2);
    let mut four = seed;
    salsa(&mut four, 4);
    out.push(("the round count changes the answer", two != four));

    // The permutation, stated as the thing it is rather than as the swap it
    // reduces to. A `blkmix` that exchanged chunks 1 and 3 would leave chunk 1
    // holding Y3 here, and that is the exact bug the Python reference shipped.
    let mut px = [0u32; WORDS];
    for (i, w) in px.iter_mut().enumerate() {
        *w = i as u32;
    }
    let mut py = [0u32; WORDS];
    // `y` holds each chunk as the chain mixed it, in chain order, so this
    // compares the permutation against its own input and says nothing about
    // the mixer. It therefore holds at the real round count rather than
    // needing a degenerate one.
    blkmix(&mut px, &mut py, false, ROUNDS);
    out.push((
        "blkmix writes evens then odds, so chunk 1 takes what chunk 2 mixed",
        px[16..32] == py[32..48] && px[32..48] == py[16..32],
    ));
    out.push((
        "and leaves the outer two chunks where they were",
        px[..16] == py[..16] && px[48..] == py[48..],
    ));

    // The scratchpad arithmetic a summary of upstream got wrong by two orders
    // of magnitude.
    let ns = Neoscrypt::new();
    out.push((
        "the working set is upstream's 33,536 bytes plus its KDF buffers",
        (N + 3) * R * 2 * 64 == 33_536 && ns.footprint() == 33_536 + 608,
    ));

    let mut h = Neoscrypt::new();

    // --- the vectors that actually settle it ---
    let got = h.hash(&BLOCK_432001);
    out.push((
        "Feathercoin block 432,001 hashes to what the chain accepted",
        got == DIGEST_432001,
    ));
    // What makes it a proof rather than a stored answer: the network only ever
    // accepted this block because the digest beat the target its own header
    // declares, which is 1 in 6.9e7 by chance.
    out.push((
        "and lands under block 432,001's own target",
        super::u256::U256::from_nbits(NBITS_432001)
            .map(|t| super::hash::below_target(&got, &t))
            .unwrap_or(false),
    ));

    let got = h.hash(&BLOCK_6346000);
    out.push((
        "block 6,346,000 does too, on the same instance",
        got == DIGEST_6346000,
    ));
    out.push((
        "and lands under its target, 1 in 4.1e9 by chance",
        super::u256::U256::from_nbits(NBITS_6346000)
            .map(|t| super::hash::below_target(&got, &t))
            .unwrap_or(false),
    ));

    // Hygiene, and stated as such. The second call above already proves the
    // buffers are reset between hashes -- an instance that carried state would
    // have got the first block right and the second wrong.
    out.push((
        "hashing the first block again gives the same digest",
        h.hash(&BLOCK_432001) == DIGEST_432001,
    ));

    out
}
