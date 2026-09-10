//! Which worker names have a payout address, checked when a miner greets.
//!
//! **The failure this exists to remove is unrecoverable and silent.** A rig
//! configured with a name nobody registered mines perfectly for thirty-six
//! hours, and the first anybody hears of it is `distribute.py` printing "these
//! workers have no payout address" after the event is over. The work is real,
//! the shares are in the ledger, and there is no address to pay them to. The
//! miner cannot fix it retroactively and neither can the operator.
//!
//! Answering at `glados.hello` costs one lookup and turns that into a
//! connection error the miner reads while they still have a keyboard in front
//! of them.
//!
//! ### It reads a file, and does not fetch
//!
//! The mapping is served by `supabase/functions/worker` over HTTPS. This
//! process has no dependencies and no TLS, and the two ways to get one are to
//! take a dependency or to shell out -- a hidden `curl` in the middle of a
//! pool being the worse of the two, since it fails differently on every host
//! and nothing in the process would say why.
//!
//! So an operator refreshes a file and this re-reads it. The runbook carries
//! the one-line cron. That is a real operational cost and it buys a pool whose
//! dependency list is still empty and whose behaviour when the mapping service
//! is unreachable is decided here rather than by somebody else's timeout.
//!
//! ### It fails open, and that is the whole policy
//!
//! A roster that has never loaded answers `Unknown`, and `Unknown` admits the
//! miner. Refusing everybody because a file is missing turns an operator
//! mistake into an outage, and the thing being protected against is a miner
//! losing their own work -- which is theirs to risk, and which they can only
//! risk if they are allowed to connect at all.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What the pool knows about one name.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Payability {
    /// The name is an address, or is registered to one.
    Yes,
    /// The roster loaded and does not carry this name.
    No,
    /// No roster has ever loaded, so nothing is known and nothing is refused.
    Unknown,
}

pub struct Roster {
    names: HashSet<String>,
    /// `None` until a file has been read successfully. Distinct from an empty
    /// set, which is a roster that loaded and holds nobody -- those two must
    /// never answer the same, since one admits everyone and the other admits
    /// only address-shaped names.
    loaded: Option<Instant>,
    path: Option<String>,
    every: Duration,
}

/// The same rule `tools/distribute.py` applies, and it has to stay the same
/// rule.
///
/// A name that is an address is its own payout address, so it needs no
/// registration and the mapping is never consulted for it. If these two
/// implementations drift, the pool admits names the distributor cannot pay or
/// refuses names it could -- and the first of those is exactly the silent loss
/// this module exists to prevent, arriving by a different route.
pub fn is_address(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 42
        && (b[0] == b'0')
        && (b[1] == b'x' || b[1] == b'X')
        && b[2..].iter().all(|c| c.is_ascii_hexdigit())
}

/// `name.rig1` is the usual spelling for one person's several machines, and
/// the distributor folds on the first dot. Folding here too means a miner who
/// registered `alice` may run `alice.rig1` without registering each rig.
pub fn base_of(name: &str) -> &str {
    match name.find('.') {
        Some(i) => &name[..i],
        None => name,
    }
}

impl Roster {
    pub fn new(path: Option<String>, every: Duration) -> Self {
        Roster { names: HashSet::new(), loaded: None, path, every }
    }

    pub fn ready(&self) -> bool {
        self.loaded.is_some()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Parse the document `/worker/map` serves, or a flat `{name: address}`.
    ///
    /// Only the keys are kept. The pool never needs the address -- it is the
    /// distributor that pays -- and holding one here would be a second copy of
    /// a fact with one source, which is how a pool ends up crediting an address
    /// the epoch does not.
    pub fn parse(text: &str) -> Result<HashSet<String>, String> {
        let doc = crate::json::Json::parse(text).ok_or("the roster is not JSON")?;
        let obj = match doc.get("workers") {
            Some(w) => w,
            None => &doc,
        };
        let crate::json::Json::Obj(pairs) = obj else {
            return Err(String::from("the roster must be a JSON object"));
        };
        let mut out = HashSet::new();
        for (k, _) in pairs {
            // Folded, because a rig sending `Alice` where `alice` was
            // registered is the case a case-sensitive check would refuse while
            // the distributor -- which looks up the exact string -- would also
            // refuse it. Matching loosely here and exactly there would admit a
            // miner who cannot be paid, so this deliberately errs the other
            // way and lets the greeting through only to warn.
            out.insert(k.to_lowercase());
        }
        Ok(out)
    }

    /// Re-read if the interval has passed. Answers whether anything changed.
    ///
    /// A read that fails leaves the previous roster in place rather than
    /// emptying it: a file being rewritten by `curl` is briefly absent or
    /// truncated, and treating that as "nobody is registered" would refuse
    /// every miner for as long as the write took.
    pub fn refresh(&mut self) -> Option<String> {
        let path = self.path.clone()?;
        if let Some(at) = self.loaded {
            if at.elapsed() < self.every {
                return None;
            }
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => match Self::parse(&text) {
                Ok(set) => {
                    let before = self.names.len();
                    let first = self.loaded.is_none();
                    self.names = set;
                    self.loaded = Some(Instant::now());
                    if first || self.names.len() != before {
                        Some(format!("[pool] roster {} name(s) from {path}", self.names.len()))
                    } else {
                        None
                    }
                }
                Err(why) => Some(format!("[pool] roster at {path} will not parse: {why}")),
            },
            Err(e) => Some(format!("[pool] roster at {path} could not be read: {e}")),
        }
    }

    pub fn payable(&self, name: &str) -> Payability {
        let base = base_of(name);
        if is_address(base) {
            return Payability::Yes;
        }
        if self.loaded.is_none() {
            return Payability::Unknown;
        }
        if self.names.contains(&base.to_lowercase()) {
            Payability::Yes
        } else {
            Payability::No
        }
    }
}

/// One roster for the process, because every connection asks the same question
/// of the same file and a copy per thread would be a copy per thread to keep
/// fresh.
pub static ROSTER: Mutex<Option<Roster>> = Mutex::new(None);

/// Whether an unregistered name is refused or merely warned about.
///
/// Off by default and it has to be: an event run with no mapping service at
/// all is a supported configuration, and the address-as-name convention makes
/// it a good one. Turning this on is a statement that a roster exists.
pub static REQUIRE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn require() -> bool {
    REQUIRE.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn check(name: &str) -> Payability {
    match ROSTER.lock().unwrap().as_ref() {
        Some(r) => r.payable(name),
        None => Payability::Unknown,
    }
}

/// Where a refused miner is told to go. Set alongside the roster path so the
/// message names the operator's own site rather than a URL compiled in here.
pub static WHERE: Mutex<String> = Mutex::new(String::new());

pub fn where_to_register() -> String {
    let w = WHERE.lock().unwrap();
    if w.is_empty() {
        String::from("ask the pool operator how to register a worker name")
    } else {
        w.clone()
    }
}

// ------------------------------------------------------------------ checks

pub fn checks() -> (usize, usize) {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut claim = |c: bool, what: &str| {
        println!("{}  {what}", if c { "ok   " } else { "FAIL " });
        if c { pass += 1 } else { fail += 1 }
    };

    claim(is_address("0x00000000000000000000000000000000000000aa"), "an address is an address");
    claim(is_address("0X00000000000000000000000000000000000000AA"), "and so is one in capitals");
    claim(!is_address("0x00000000000000000000000000000000000000a"), "41 characters is not");
    claim(!is_address("0xzz000000000000000000000000000000000000aa"), "nor is one with non-hex in it");
    claim(!is_address("alice"), "nor is a nickname");

    claim(base_of("alice.rig1") == "alice", "a rig suffix folds to its base");
    claim(base_of("alice") == "alice", "and a bare name is its own base");

    let set = Roster::parse("{\"workers\":{\"Alice\":\"0xaa\"},\"updated_at\":{}}").unwrap();
    claim(set.contains("alice"), "the served document parses, folded");
    let flat = Roster::parse("{\"bob\":\"0xbb\"}").unwrap();
    claim(flat.contains("bob"), "and so does a flat file");
    claim(Roster::parse("not json").is_err(), "a roster that is not JSON is refused");

    // The distinction the whole module turns on: never loaded admits
    // everybody, loaded-and-empty admits only addresses.
    let never = Roster::new(None, Duration::from_secs(60));
    claim(never.payable("alice") == Payability::Unknown, "an unloaded roster knows nothing");
    claim(never.payable("0x00000000000000000000000000000000000000aa") == Payability::Yes,
          "but an address needs no roster");

    let mut empty = Roster::new(None, Duration::from_secs(60));
    empty.loaded = Some(Instant::now());
    claim(empty.payable("alice") == Payability::No, "a loaded empty roster refuses a nickname");
    claim(empty.payable("0x00000000000000000000000000000000000000aa") == Payability::Yes,
          "and still admits an address");

    let mut one = Roster::new(None, Duration::from_secs(60));
    one.names.insert(String::from("alice"));
    one.loaded = Some(Instant::now());
    claim(one.payable("alice") == Payability::Yes, "a registered name is payable");
    claim(one.payable("ALICE") == Payability::Yes, "case does not matter to the pool");
    claim(one.payable("alice.rig7") == Payability::Yes, "and neither does a rig suffix");
    claim(one.payable("mallory") == Payability::No, "an unregistered name is not payable");

    (pass, fail)
}
