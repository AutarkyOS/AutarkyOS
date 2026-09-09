//! Which proof-of-work a job wants, and the thing that computes it.
//!
//! Every algorithm here answers one question -- given an 80-byte header and a
//! nonce, what is the digest -- and the header assembly, the merkle fold, the
//! target comparison and the whole Stratum client above are shared unchanged.
//! That is the payoff of picking Bitcoin-family coins: yespower chains inherit
//! Bitcoin's header, so only the hash differs.
//!
//! ### Why the hasher lives on the task and not in the template
//!
//! `Yespower` holds its working set -- up to 8 MiB at N=2048, r=32 -- and
//! reuses it across nonces, because allocating per hash would spend more time
//! in this kernel's locking allocator than in the algorithm. That makes it a
//! large, mutable, single-owner object, which is exactly what a `Spin<Template>`
//! shared with the socket task must not contain. So the template carries the
//! *parameters* and the miner task builds the hasher from them, rebuilding only
//! when they change.
//!
//! ### The batch size is a property of the algorithm
//!
//! SHA-256d runs about 4,000 nonces in a millisecond and yespower runs single
//! digits, so one constant cannot serve both: 4,096 yespower hashes is seconds
//! of a task holding its quantum, which starves the pool connection and makes
//! `mine off` take that long to be felt. `Algo::batch` is the per-algorithm
//! answer and it is sized to roughly a millisecond and a half of work.

use alloc::string::String;
use alloc::vec::Vec;

use super::hash;
use super::yespower::{Version, Yespower};

#[derive(Clone, PartialEq)]
pub enum Algo {
    /// Bitcoin's own. The only one with a usable midstate, because it is the
    /// only one whose first 64 header bytes can be absorbed once.
    Sha256d,
    /// The scheme BitZeny, Yenten, Koto, WAVI, Veco and PRiVCY use.
    ///
    /// Parameters are explicit rather than named per coin. A preset table would
    /// be a set of numbers this tree asserts about somebody else's network
    /// without having read their source, and a wrong one hashes a different
    /// function perfectly correctly -- which is the failure `Yespower::new`
    /// refuses to clamp its way into.
    Yespower {
        v10: bool,
        n: u32,
        r: u32,
        pers: Option<Vec<u8>>,
    },
}

impl Algo {
    pub fn name(&self) -> &'static str {
        match self {
            Algo::Sha256d => "sha256d",
            Algo::Yespower { v10: true, .. } => "yespower-1.0",
            Algo::Yespower { v10: false, .. } => "yespower-0.5",
        }
    }

    /// Nonces per batch, sized to about a millisecond and a half.
    ///
    /// The batch is what bounds how long the miner holds its quantum, so it is
    /// also what bounds how promptly a new job or a `mine off` is felt.
    pub fn batch(&self) -> u32 {
        match self {
            Algo::Sha256d => 4096,
            // Measured rather than guessed: see `mine bench`. Small because one
            // yespower hash is three orders of magnitude more work than one
            // sha256d, by design.
            Algo::Yespower { .. } => 8,
        }
    }

    /// A human-readable parameter line for the report.
    pub fn detail(&self) -> String {
        match self {
            Algo::Sha256d => String::from("sha256d"),
            Algo::Yespower { v10, n, r, pers } => {
                let mut s = String::from(if *v10 { "yespower 1.0 N=" } else { "yespower 0.5 N=" });
                push_u32(&mut s, *n);
                s.push_str(" r=");
                push_u32(&mut s, *r);
                if let Some(p) = pers {
                    s.push_str(" pers=");
                    for b in p.iter().take(16) {
                        s.push(*b as char);
                    }
                }
                s
            }
        }
    }
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 10];
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

/// A prepared hasher, holding whatever working set its algorithm needs.
pub enum Hasher {
    Sha256d(hash::Midstate),
    Yespower(Yespower, Option<Vec<u8>>),
}

impl Hasher {
    /// `None` when the parameters are ones the algorithm refuses, or when the
    /// working set will not fit.
    pub fn new(algo: &Algo, header: &[u8; 80]) -> Option<Hasher> {
        match algo {
            Algo::Sha256d => Some(Hasher::Sha256d(hash::Midstate::new(header))),
            Algo::Yespower { v10, n, r, pers } => {
                let v = if *v10 { Version::V1_0 } else { Version::V0_5 };
                Some(Hasher::Yespower(Yespower::new(v, *n, *r)?, pers.clone()))
            }
        }
    }

    /// Bytes of working memory. What the slice budget in `design/mining.md` is
    /// actually spending, and the reason the supervisor will need to ask.
    pub fn footprint(&self) -> usize {
        match self {
            Hasher::Sha256d(_) => 0,
            Hasher::Yespower(y, _) => y.footprint(),
        }
    }

    /// Point an existing hasher at a new job's header.
    ///
    /// Separate from `new` because the two algorithms differ in what a new
    /// header costs. SHA-256d must re-absorb its constant 64 bytes, which is
    /// one compression; yespower does not depend on the header at all until
    /// `hash` is called, so rebuilding it per job would throw away and
    /// reallocate up to 8 MiB every time the pool sends work.
    pub fn retarget(&mut self, header: &[u8; 80]) {
        match self {
            Hasher::Sha256d(mid) => *mid = hash::Midstate::new(header),
            Hasher::Yespower(..) => {}
        }
    }

    /// The digest for this header with `nonce` substituted.
    ///
    /// Little-endian at offset 76, because every multi-byte field in a Bitcoin
    /// header is and yespower chains inherited the header unchanged.
    pub fn hash(&mut self, header: &[u8; 80], nonce: u32) -> [u8; 32] {
        match self {
            // The midstate already holds the constant 64 bytes, so the header
            // argument is unused here -- and it must stay that way, because a
            // midstate built from a *different* header would hash a block that
            // never existed while looking perfectly healthy.
            Hasher::Sha256d(mid) => mid.hash_with(nonce),
            Hasher::Yespower(y, pers) => {
                let mut h = *header;
                h[76..80].copy_from_slice(&nonce.to_le_bytes());
                y.hash(&h, pers.as_deref())
            }
        }
    }
}
