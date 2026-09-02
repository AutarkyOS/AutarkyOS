//! What may not be rewritten.
//!
//! AUTARK's one invariant: **the machine may change anything except the record
//! of what it changed.**
//!
//! Everything else in `godel` can come off and still leave an experiment. The
//! declared grid, the frozen base, the fixed rotation of proposal kinds -- each
//! is a bound whose removal produces a result worth writing down. This one is
//! different in kind rather than in degree, because it is not a bound on what
//! the machine may do. It is the condition under which any of the others yield
//! evidence at all. A loop that can edit its own history makes "improved every
//! night for a month" and "learned to edit the ledger" produce byte-identical
//! files, and no amount of care spent on the judges recovers the difference.
//!
//! So this is not a safety hedge bolted onto a research system. It is the
//! difference between an experiment and an anecdote.
//!
//! ### Why append-only rather than read-only
//!
//! The obvious enforcement -- the loop may not write these paths -- does not
//! work, because the loop is exactly what writes them. `godel::ledger_append`
//! reads the whole ledger, adds a line and writes it back; `spend_test_read`
//! rewrites a count. A rule that refused those would refuse the record being
//! kept at all.
//!
//! The rule that admits the legitimate write and nothing else is a rule about
//! *shape*: text that may only grow at its end, and a counter that may only
//! rise. `ledger_append`'s read-modify-write passes because the new content
//! literally begins with the old. A truncation, a reordering, a doctored line
//! and a deletion all fail the same test, and none of them needed to be
//! enumerated.
//!
//! ### Why it is here and not in `godel`
//!
//! Because `godel` is not the only thing that can write. A judged skill, an
//! authored application, an Aiksi program with `Touch::Write`, the agent under
//! `Trust::Full` and the operator's own `rm` all reach the namespace through
//! `sysbox`, and a guard living in the module it is meant to constrain protects
//! against that module's own good behaviour. Every real caller of `tree::put`
//! and `tree::remove` in this kernel is in `sysbox/mod.rs`, which makes that
//! one file a genuine chokepoint -- the only one this design needs.
//!
//! ### Why it is a pure function
//!
//! `update::decide` is the model: a pure function whose every state is asserted
//! at boot without staging an update, because the states that matter are the
//! ones a live test is least likely to reach. The same applies here and more
//! so. The interesting verdicts are refusals, a refusal that fires is a bug
//! somewhere else, and a guard exercised only by its own good citizens is
//! indistinguishable from one that returns `Open` unconditionally.

use alloc::vec::Vec;

/// The paths whose shape is enforced, and how.
///
/// Deliberately two exact paths and not the `/ai/godel` subtree. Nodes, the
/// head pointer and the `tried` markers under there are ordinary state that a
/// trial legitimately rewrites; protecting the directory wholesale would make
/// the loop unable to run while claiming to protect its history.
const RECORDS: [(&str, Kind); 2] = [
    ("/ai/godel/ledger.txt", Kind::AppendOnly),
    ("/ai/godel/test-budget", Kind::Monotone),
];

/// How a record is allowed to change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// No rule. Everything that is not a record.
    Open,
    /// Text that may only grow, and only at its end.
    AppendOnly,
    /// A decimal count that may only rise.
    Monotone,
}

/// What is being done to a path.
#[derive(Clone, Copy)]
pub enum Change<'a> {
    /// A blob with these bytes is being put here.
    Write(&'a [u8]),
    /// A directory is being created here, on a path where nothing exists.
    MakeDir,
    /// An arbitrary node is being placed here, replacing whatever is there.
    ///
    /// Separate from `Write` because `mv` and `cp` move whole subtrees. Putting
    /// a *different directory* over `/ai/godel` would take the ledger's name
    /// away without the ledger's path ever appearing in the operation, which is
    /// the second way round a rule that only looked at exact paths.
    Graft(&'a [u8]),
    /// The name here is being taken away.
    Remove,
}

/// What the guard says, in enough detail to print.
///
/// Seven states rather than a bool, because a refusal has to be able to say
/// which rule it broke: "the ledger may not be rewritten" and "the budget may
/// not be lowered" are different bugs in different modules, and a caller that
/// could only report *refused* would send whoever hit it to read this file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not a record, and not above one.
    Open,
    /// A record, and this write only adds to its end.
    Extends,
    /// A counter, and this write does not lower it.
    Rises,
    /// A record, and the new content is not the old content plus more.
    Rewrite,
    /// A counter, and the new value is below the stored one.
    Regress,
    /// A counter, and the new value is not a count at all.
    Unreadable,
    /// A record, or something a record lives under, losing its name.
    Unname,
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        matches!(self, Verdict::Open | Verdict::Extends | Verdict::Rises)
    }

    /// Why, phrased for an operator who did not expect to see it.
    pub fn why(&self) -> &'static str {
        match self {
            Verdict::Open => "not a record",
            Verdict::Extends => "appended",
            Verdict::Rises => "raised",
            Verdict::Rewrite => "the record may only be added to, never rewritten",
            Verdict::Regress => "the budget may only rise",
            Verdict::Unreadable => "the budget must stay a count",
            Verdict::Unname => "the record may not lose its name",
        }
    }
}

/// The rule for a path, if it has one.
pub fn kind_of(path: &str) -> Kind {
    for (p, k) in RECORDS.iter() {
        if *p == path {
            return *k;
        }
    }
    Kind::Open
}

/// Is this path a strict ancestor of a record?
///
/// `/ai/godel` is, `/ai/godel/ledger.txt` is not (it *is* the record), and
/// `/ai/godelx` is not -- the boundary has to be a separator, or a sibling
/// whose name merely starts the same way would be protected by accident.
fn above_record(path: &str) -> bool {
    // The root is above everything and is spelled without a trailing separator,
    // so the general test below reads its first byte as `a` and says no. Caught
    // by the claim that `rm /` is refused, which is the one path an operator
    // most obviously expects to be.
    if path == "/" {
        return true;
    }
    for (p, _) in RECORDS.iter() {
        if p.len() > path.len() && p.as_bytes()[path.len()] == b'/' && p.starts_with(path) {
            return true;
        }
    }
    false
}

/// Read a decimal count, ignoring surrounding whitespace.
///
/// Returns `None` for anything that is not one. That distinction carries
/// weight: an unreadable *new* value is refused, because turning a counter into
/// prose is how you would erase it without ever writing a smaller number, while
/// an unreadable *old* value is treated as zero so a record already broken can
/// be repaired upward instead of being frozen for good.
fn count(b: &[u8]) -> Option<u32> {
    let s = core::str::from_utf8(b).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<u32>().ok()
}

/// The whole decision, over (path, what is stored, what is being done).
///
/// `old` is the blob currently at `path`, or `None` if there is nothing there
/// or what is there is a directory.
pub fn judge(path: &str, old: Option<&[u8]>, change: Change) -> Verdict {
    match kind_of(path) {
        Kind::AppendOnly => match change {
            // Creating it is fine; extending it is the point. Anything else is
            // a rewrite, including turning it into a directory.
            Change::Write(new) => match old {
                None => Verdict::Extends,
                Some(o) if new.starts_with(o) => Verdict::Extends,
                Some(_) => Verdict::Rewrite,
            },
            Change::MakeDir => Verdict::Rewrite,
            Change::Graft(_) => Verdict::Rewrite,
            Change::Remove => Verdict::Unname,
        },
        Kind::Monotone => match change {
            Change::Write(new) => match count(new) {
                None => Verdict::Unreadable,
                // An absent or corrupt stored value reads as zero, so the first
                // write lands and a broken one can be mended.
                Some(n) if n >= old.and_then(count).unwrap_or(0) => Verdict::Rises,
                Some(_) => Verdict::Regress,
            },
            Change::MakeDir => Verdict::Unreadable,
            Change::Graft(_) => Verdict::Unreadable,
            Change::Remove => Verdict::Unname,
        },
        Kind::Open => {
            if above_record(path) {
                // A record is only as durable as the names above it. Removing
                // `/ai/godel`, or writing a blob over it, unnames the ledger
                // without the ledger's own path ever being mentioned -- which
                // is the obvious way round a rule that only looked at exact
                // paths. Making or keeping a directory there is ordinary.
                return match change {
                    // `mkdir` fails on a path that already exists, and every
                    // ancestor of a live record does, so this arm can only be
                    // reached where there is nothing to lose.
                    Change::MakeDir => Verdict::Open,
                    _ => Verdict::Unname,
                };
            }
            Verdict::Open
        }
    }
}

/// Every state of `judge`, plus the two claims that make the rule mean
/// anything: that the protected paths are the ones `godel` actually writes,
/// and that `ledger_append`'s own read-modify-write survives the rule.
pub fn selftest() -> bool {
    let led = "/ai/godel/ledger.txt";
    let bud = "/ai/godel/test-budget";

    // The paths here and the paths godel writes are the same paths. Two
    // spellings of one fact is how a guard comes to protect a file nobody
    // writes while the real one stays open.
    let mut ok = kind_of(crate::ai::godel::LEDGER) == Kind::AppendOnly
        && kind_of(crate::ai::godel::BUDGET) == Kind::Monotone;

    // --- append-only -----------------------------------------------------
    ok &= judge(led, None, Change::Write(b"a\n")) == Verdict::Extends;
    ok &= judge(led, Some(b"a\n"), Change::Write(b"a\nb\n")) == Verdict::Extends;
    // Writing back exactly what is there is an append of nothing.
    ok &= judge(led, Some(b"a\n"), Change::Write(b"a\n")) == Verdict::Extends;
    // The four ways history gets lost, none of which had to be enumerated in
    // the rule: truncation, reordering, a doctored line, and emptying.
    ok &= judge(led, Some(b"a\nb\n"), Change::Write(b"a\n")) == Verdict::Rewrite;
    ok &= judge(led, Some(b"a\nb\n"), Change::Write(b"b\na\n")) == Verdict::Rewrite;
    ok &= judge(led, Some(b"a\nb\n"), Change::Write(b"a\nX\n")) == Verdict::Rewrite;
    ok &= judge(led, Some(b"a\n"), Change::Write(b"")) == Verdict::Rewrite;
    ok &= judge(led, Some(b"a\n"), Change::Remove) == Verdict::Unname;
    ok &= judge(led, Some(b"a\n"), Change::MakeDir) == Verdict::Rewrite;
    ok &= judge(led, Some(b"a\n"), Change::Graft(b"")) == Verdict::Rewrite;

    // --- monotone --------------------------------------------------------
    ok &= judge(bud, None, Change::Write(b"0")) == Verdict::Rises;
    ok &= judge(bud, Some(b"1"), Change::Write(b"2")) == Verdict::Rises;
    ok &= judge(bud, Some(b"2"), Change::Write(b"2")) == Verdict::Rises;
    ok &= judge(bud, Some(b"3"), Change::Write(b"1")) == Verdict::Regress;
    // Erasing a count by making it stop being one.
    ok &= judge(bud, Some(b"3"), Change::Write(b"none")) == Verdict::Unreadable;
    ok &= judge(bud, Some(b"3"), Change::Write(b"")) == Verdict::Unreadable;
    ok &= judge(bud, Some(b"3"), Change::Remove) == Verdict::Unname;
    // A corrupt stored value reads as zero rather than freezing the file.
    ok &= judge(bud, Some(b"???"), Change::Write(b"5")) == Verdict::Rises;
    // Whitespace is not corruption: write_text may end a line.
    ok &= judge(bud, Some(b"2\n"), Change::Write(b"3\n")) == Verdict::Rises;

    // --- the way round an exact-path rule --------------------------------
    ok &= judge("/ai/godel", None, Change::Remove) == Verdict::Unname;
    ok &= judge("/ai/godel", None, Change::Write(b"x")) == Verdict::Unname;
    ok &= judge("/ai", None, Change::Remove) == Verdict::Unname;
    ok &= judge("/", None, Change::Remove) == Verdict::Unname;
    // ...and making the directory the record lives in is not that.
    ok &= judge("/ai/godel", None, Change::MakeDir) == Verdict::Open;
    // ...but grafting a different subtree over it is.
    ok &= judge("/ai/godel", None, Change::Graft(b"")) == Verdict::Unname;
    // A sibling whose name merely starts the same way is not above anything.
    ok &= judge("/ai/godelx", None, Change::Remove) == Verdict::Open;
    ok &= judge("/ai/godel/nodes", None, Change::Remove) == Verdict::Open;
    ok &= judge("/tmp/x", Some(b"a"), Change::Write(b"")) == Verdict::Open;

    // --- and the legitimate writer still gets through --------------------
    // godel::ledger_append reads the whole file, pushes a line, writes it back.
    // If that shape ever failed here the loop would keep no record at all,
    // which is the failure this module would be causing rather than catching.
    let mut text = alloc::vec![];
    for line in ["1 adopted", "2 rejected, and reverted"] {
        let mut next: Vec<u8> = text.clone();
        next.extend_from_slice(line.as_bytes());
        next.push(b'\n');
        let old: Option<&[u8]> = if text.is_empty() { None } else { Some(&text) };
        ok &= judge(crate::ai::godel::LEDGER, old, Change::Write(&next)) == Verdict::Extends;
        text = next;
    }

    ok
}
