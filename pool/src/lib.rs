//! The pool that GLaDOS mines against.
//!
//! ### The kernel's source is included rather than ported
//!
//! A pool that accounts shares has to validate them, and validating a share
//! means computing the same hash the miner computed. A second implementation
//! of yespower, in another language, is two things that are supposed to agree
//! and will not stay agreeing -- the objection `model.rs` makes twice,
//! `tokenizer.py --verify` exists to answer, and `differ.rs` was written
//! before there was anything to differ.
//!
//! So the modules below are the kernel's own files, reached by `#[path]`. Not
//! copies: the same bytes the ring-0 miner compiles. A change to yespower that
//! breaks agreement is a build failure or a failing vector here, in the same
//! commit, rather than a share the pool rejects a week later for a reason
//! nobody can find.
//!
//! What that cost was, precisely, because it is the reason it is affordable at
//! all: `sha256`, `blake2s`, `u256`, `header` and `ev` name nothing outside
//! themselves. `hash` and `yespower` need `store::sha256` and `crypto::hkdf`.
//! `stratum` needs `json`. `json` needs one macro. That is the whole of it, and
//! the mirrored module tree below exists so those `crate::` paths mean here
//! what they mean there.
//!
//! Deliberately **not** included: `mine::client` and `mine::work`, which reach
//! for `net::tcp`, `task` and `sync`. Those are the kernel's answers to
//! problems the host solves with `std::net` and threads, and porting them
//! would be inventing a disagreement rather than avoiding one.
//!
//! ### This is the project's first `cargo test`
//!
//! CLAUDE.md's testing section opens "There is no `cargo test`", which is true
//! of a `no_std` UEFI binary and was true of everything inside it. The hash
//! core is not kernel code in any useful sense -- it touches no hardware and
//! allocates from a heap -- so on the host it is ordinary Rust, and the
//! vectors that cost a boot to check cost about a second.
//!
//! The boot claims stay exactly where they are. They check the same arithmetic
//! on the machine that will actually run it, which is the distinction
//! `diag paging` draws about permissions: reading a table back is not watching
//! the processor refuse.

extern crate alloc;

/// The kernel's console macro, reduced to what the included files use.
///
/// `json::selftest` is the only thing that reaches for it, and only to report
/// a failing claim. Routing it to stderr rather than to nothing keeps a failure
/// visible; routing it to stdout would put it in a pool's log output as though
/// the pool had said it.
#[macro_export]
macro_rules! kprintln {
    () => { eprintln!() };
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[path = "../../src/json.rs"]
pub mod json;

pub mod store {
    #[path = "../../../src/store/sha256.rs"]
    pub mod sha256;
}

pub mod crypto {
    #[path = "../../../src/crypto/hkdf.rs"]
    pub mod hkdf;
}

/// The kernel's mining core, minus the two modules that are about the kernel.
///
/// Declared inline rather than by including `src/mine/mod.rs`, because that
/// file also declares `client` and `work` and carries a `checks()` that reaches
/// into `sync`. Naming the eight that travel is a list somebody has to keep
/// current, and that is the right cost: a new module here is a deliberate act,
/// where inheriting one would be silent.
pub mod mine {
    #[path = "../../../src/mine/u256.rs"]
    pub mod u256;
    #[path = "../../../src/mine/hash.rs"]
    pub mod hash;
    #[path = "../../../src/mine/header.rs"]
    pub mod header;
    #[path = "../../../src/mine/blake2s.rs"]
    pub mod blake2s;
    #[path = "../../../src/mine/yespower.rs"]
    pub mod yespower;
    #[path = "../../../src/mine/algo.rs"]
    pub mod algo;
    #[path = "../../../src/mine/stratum.rs"]
    pub mod stratum;
    #[path = "../../../src/mine/proto.rs"]
    pub mod proto;
    #[path = "../../../src/mine/ev.rs"]
    pub mod ev;
}

pub mod pool;
pub mod server;
pub mod upstream;
