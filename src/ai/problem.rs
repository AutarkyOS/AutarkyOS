//! A problem the machine can be set, and the means to tell whether it solved it.
//!
//! Named `problem` rather than `task` because `crate::task` is the scheduler
//! and in a kernel "task" means a thing with a stack.
//!
//! **Why this exists.** Everything the model is trained on today is one
//! question -- which applet a phrasing means -- over 717 compiled-in examples
//! split 357/180/180. The two held-out slices are 360 items and no mechanism
//! in this kernel produces a 361st: `teach` appends past the corpus length and
//! `harness::split_of` maps anything there to *train*, deliberately, so that
//! an appended example can never enter the one number that is read once. That
//! is the right safety property and it means a loop improving against those
//! 360 has a finish line. `godel` reaches it and reports "search space
//! exhausted".
//!
//! A problem is the other kind of question: one whose answer can be *checked
//! by running something*, so the supply is bounded by what can be generated
//! rather than by what somebody typed. That is the only label source in this
//! tree that is not either compiled in, typed by the operator, or -- as
//! `work.rs` records about harvested role examples -- the base model's own
//! argmax fed back to it, where "the adapter's target is the thing that
//! produced it, and the best it can do is agree".
//!
//! **What a problem is.** A statement, the name of the function a solution
//! must define, a list of (arguments, expected answer) cases, a step ceiling,
//! and a *reference*: a program already known to solve it. The reference is
//! not a hint for the solver and is never shown to it. It is what makes the
//! problem checkable as an object -- a problem nothing is known to solve
//! cannot be told apart from one nothing *can* solve, and a generator that
//! emitted those would fill the archive with noise that reads as difficulty.
//!
//! Generating the answer first and deriving the question from it is how
//! procedural problem generation normally works, and it is why `reference`
//! costs the generator nothing: it already had one.
//!
//! **Admission, and the attractor it guards.** A self-generating,
//! self-verifying loop degenerates in a specific way: it learns to emit
//! problems that look hard and are trivially checkable, then improves against
//! them forever while every certificate stays true. Five conditions, four of
//! which mirror discipline already in this tree:
//!
//! 1. **Shaped.** Two cases at least, and every field non-empty.
//! 2. **Solved.** The reference answers every case correctly. Without this a
//!    problem is a guess.
//! 3. **Discriminating.** A *constant* function returning the first expected
//!    answer must fail at least one case. This is `differ`'s canary rule --
//!    "a suite that has never reported a difference is indistinguishable from
//!    one that compares nothing" -- applied to problems, and the foil is
//!    synthesised rather than declared so a generator cannot forget to supply
//!    a convincing one.
//! 4. **Deterministic.** The reference agrees with itself across two routes on
//!    value, cost, error text *and* console output. `differ` does this; the
//!    console half only became comparable when `Outcome` grew the field.
//! 5. **Bounded.** The reference stays under the ceiling, so a solver has a
//!    number to be measured against rather than a wall clock.
//!
//! None of the five needs a model, a corpus or a network, which is why they
//! are asserted at boot.
//!
//! **What is deliberately not here.** Whether a problem is *at the frontier*
//! -- that the current solver cannot already solve it -- is the condition that
//! makes the arms race an arms race, and it is a question about the solver
//! rather than about the problem. It belongs where the two populations meet,
//! not in the definition of the object.
//!
//! **Cases hold integers and strings and nothing else.** `Value::render` is
//! lossy in exactly the way that matters here: `Str("5")` and `Int(5)` render
//! to the same three characters, so a stored case cannot be read back from a
//! rendering alone. The encoding therefore carries a type tag, and the two
//! types tagged are the two every family below needs. Lists and records can
//! join when something asks; guessing at their spelling now would be a format
//! nobody has parsed.

use crate::store::sha256;
use crate::aiksi::differ::{self, Entry, Route};
use crate::aiksi::eval::Value;
use crate::sysbox;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

/// Where problems live, content-addressed like cores and skills.
pub const ROOT: &str = "/ai/problems";

/// What a problem is about.
///
/// The four are not a taxonomy for its own sake; each has a different source
/// of ground truth, which is the only thing that distinguishes a problem worth
/// storing from a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    /// Write a function satisfying input/output pairs. Truth is arithmetic.
    Program,
    /// Operate this machine -- the namespace, the applets. Truth is the state
    /// afterwards, which `sysbox::shadow` can observe and undo.
    Machine,
    /// Answer something about the kernel's own source. Truth is the tree.
    Source,
    /// Something fetched. Truth still has to be established locally: an
    /// imported problem is a *candidate*, never a verdict, because a verifier
    /// that trusts the network has outsourced what it believes.
    Imported,
}

/// Where a problem came from, which decides how far it may be trusted and
/// which archive cells it competes in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// Compiled in, or written by the operator.
    Seeded,
    /// The machine invented it.
    SelfMade,
    /// Fetched, with the digest of what was fetched.
    Fetched([u8; 32]),
}

/// One (arguments, expected answer) pair.
#[derive(Clone, PartialEq)]
pub struct Case {
    pub args: Vec<Value>,
    pub want: Value,
}

/// A problem, as stored.
#[derive(Clone)]
pub struct Problem {
    pub family: Family,
    pub origin: Origin,
    /// One line, for a prompt and for a person reading the archive.
    pub statement: String,
    /// The function a solution must define.
    pub entry: String,
    /// The most steps a solution may take on any single case.
    pub ceiling: u64,
    pub cases: Vec<Case>,
    /// A program known to solve it. Never shown to a solver.
    pub reference: String,
}

/// Why a problem was refused. Named rather than a bool, because "it was not
/// admitted" is not a report and the generator has to know which condition to
/// stop violating.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// Fewer than two cases, or an empty field.
    Shape,
    /// The reference does not answer every case.
    Unsolved,
    /// A constant answer passes, so the cases decide nothing.
    Trivial,
    /// The reference does not agree with itself across routes.
    Unstable,
    /// The reference exceeds the ceiling.
    Costly,
}

impl Refused {
    pub fn why(&self) -> &'static str {
        match self {
            Refused::Shape => "fewer than two cases, or a field left empty",
            Refused::Unsolved => "the reference does not answer every case",
            Refused::Trivial => "a constant answer passes, so the cases decide nothing",
            Refused::Unstable => "the reference does not agree with itself",
            Refused::Costly => "the reference costs more than the ceiling allows",
        }
    }
}

/// Two cases at least, and every field filled.
///
/// Two rather than one because a single case is satisfied by returning its
/// answer, which condition three would catch anyway -- but catching it here is
/// cheaper and says something more useful about what went wrong.
const MIN_CASES: usize = 2;

fn tag_family(f: Family) -> &'static str {
    match f {
        Family::Program => "program",
        Family::Machine => "machine",
        Family::Source => "source",
        Family::Imported => "imported",
    }
}

fn read_family(s: &str) -> Option<Family> {
    Some(match s {
        "program" => Family::Program,
        "machine" => Family::Machine,
        "source" => Family::Source,
        "imported" => Family::Imported,
        _ => return None,
    })
}

/// One value, with its type. See the module header on why a tag is required.
fn enc(v: &Value) -> Option<String> {
    Some(match v {
        Value::Int(i) => format!("i {}", i),
        // Newlines would end the record, so a string carrying one cannot be
        // stored in this format. Refused rather than escaped: an escape is a
        // second thing to get right in both directions, and nothing needs one.
        Value::Str(s) if !s.contains('\n') => format!("s {}", s),
        _ => return None,
    })
}

fn dec(line: &str) -> Option<Value> {
    let (tag, rest) = line.split_once(' ')?;
    Some(match tag {
        "i" => Value::Int(rest.parse().ok()?),
        "s" => Value::Str(rest.to_string()),
        _ => return None,
    })
}

impl Problem {
    /// The text that *is* this problem, and therefore its address.
    ///
    /// Rendered rather than packed, for the reason `Variant::render` gives: a
    /// hash over a struct layout changes when the struct does, and an archive
    /// full of addresses nobody can reproduce is an archive of nothing. The
    /// reference goes last and unquoted, so a multi-line program needs no
    /// escaping and the parser can take the remainder verbatim.
    pub fn render(&self) -> Option<String> {
        let mut s = String::from("problem 1\n");
        s.push_str("family ");
        s.push_str(tag_family(self.family));
        s.push_str("\norigin ");
        match self.origin {
            Origin::Seeded => s.push_str("seeded"),
            Origin::SelfMade => s.push_str("selfmade"),
            Origin::Fetched(h) => {
                s.push_str("fetched ");
                s.push_str(&super::voter::hex(&h));
            }
        }
        s.push_str("\nceiling ");
        s.push_str(&format!("{}", self.ceiling));
        s.push_str("\nentry ");
        s.push_str(&self.entry);
        s.push_str("\nstatement ");
        s.push_str(&self.statement);
        s.push('\n');
        for c in &self.cases {
            s.push_str(&format!("case {}\n", c.args.len()));
            for a in &c.args {
                s.push_str(&enc(a)?);
                s.push('\n');
            }
            s.push_str(&enc(&c.want)?);
            s.push('\n');
        }
        s.push_str("reference\n");
        s.push_str(&self.reference);
        Some(s)
    }

    /// Read one back. `None` on anything that is not exactly this format --
    /// there is no partial parse, because a problem read wrong is a wrong
    /// answer that looks like a right one.
    pub fn parse(text: &str) -> Option<Problem> {
        let mut lines = text.lines();
        if lines.next()? != "problem 1" {
            return None;
        }
        let family = read_family(lines.next()?.strip_prefix("family ")?)?;
        let o = lines.next()?.strip_prefix("origin ")?;
        let origin = match o {
            "seeded" => Origin::Seeded,
            "selfmade" => Origin::SelfMade,
            _ => {
                let hx = o.strip_prefix("fetched ")?;
                let mut h = [0u8; 32];
                if hx.len() != 64 {
                    return None;
                }
                for (i, b) in h.iter_mut().enumerate() {
                    *b = u8::from_str_radix(hx.get(i * 2..i * 2 + 2)?, 16).ok()?;
                }
                Origin::Fetched(h)
            }
        };
        let ceiling: u64 = lines.next()?.strip_prefix("ceiling ")?.parse().ok()?;
        let entry = lines.next()?.strip_prefix("entry ")?.to_string();
        let statement = lines.next()?.strip_prefix("statement ")?.to_string();

        let mut cases = Vec::new();
        let mut consumed = 0usize;
        loop {
            let line = lines.next()?;
            consumed += 1;
            if line == "reference" {
                break;
            }
            let n: usize = line.strip_prefix("case ")?.parse().ok()?;
            let mut args = Vec::with_capacity(n);
            for _ in 0..n {
                args.push(dec(lines.next()?)?);
                consumed += 1;
            }
            let want = dec(lines.next()?)?;
            consumed += 1;
            cases.push(Case { args, want });
        }
        // Everything after the marker, verbatim. Counted rather than
        // re-joined, so a reference containing a line that looks like a header
        // survives intact.
        let head = 6 + consumed;
        let reference = text
            .lines()
            .skip(head)
            .collect::<Vec<_>>()
            .join("\n");
        Some(Problem { family, origin, statement, entry, ceiling, cases, reference })
    }

    /// The address, which is the hash of the rendering.
    pub fn hash(&self) -> Option<[u8; 32]> {
        Some(sha256::hash(self.render()?.as_bytes()))
    }

    /// Store it, and answer where. Idempotent: an identical problem is one
    /// object however many times it is offered.
    pub fn store(&self) -> Option<[u8; 32]> {
        let text = self.render()?;
        let h = sha256::hash(text.as_bytes());
        let mut path = String::from(ROOT);
        path.push('/');
        path.push_str(&super::voter::hex(&h));
        if sysbox::read_blob(&path).is_none() {
            sysbox::write_text(&path, &text);
        }
        Some(h)
    }

    /// Read one back from its address.
    pub fn load(h: &[u8; 32]) -> Option<Problem> {
        let mut path = String::from(ROOT);
        path.push('/');
        path.push_str(&super::voter::hex(h));
        let raw = sysbox::read_blob(&path)?;
        Problem::parse(core::str::from_utf8(&raw).ok()?)
    }

    /// Run one program against every case. `Ok(steps)` with the worst case's
    /// cost when all of them answered correctly.
    ///
    /// The comparison is on the *rendering*, which is what `differ` compares
    /// and is therefore the same notion of "the same answer" the rest of the
    /// verification stack uses. It is also why a case may not hold a value
    /// whose rendering is ambiguous -- see the module header.
    pub fn run(&self, src: &str) -> Result<u64, usize> {
        let mut worst = 0u64;
        for (i, c) in self.cases.iter().enumerate() {
            let Some(out) = differ::observe(src, Entry::Call(&self.entry, &c.args), Route::Armed)
            else {
                return Err(i);
            };
            if out.errored() || out.value() != c.want.render() {
                return Err(i);
            }
            worst = worst.max(out.steps());
        }
        Ok(worst)
    }

    /// A program that ignores its arguments and answers the first case.
    ///
    /// Synthesised rather than declared, so a generator cannot supply a foil
    /// convincing enough to pass. If this passes, the cases decide nothing:
    /// whatever the statement claims, the problem is "return this constant".
    fn foil(&self) -> Option<String> {
        let c = self.cases.first()?;
        let params: Vec<String> =
            (0..c.args.len()).map(|i| format!("a{}: any", i)).collect();
        let body = match &c.want {
            Value::Int(v) => format!("return {}", v),
            Value::Str(s) if !s.contains('"') && !s.contains('\n') => {
                format!("return \"{}\"", s)
            }
            _ => return None,
        };
        Some(format!("fn {}({}) {{ {} }}", self.entry, params.join(", "), body))
    }

    /// Whether this problem is fit to keep. See the module header for the five
    /// conditions and what each one guards.
    pub fn admit(&self) -> Result<(), Refused> {
        if self.cases.len() < MIN_CASES
            || self.entry.is_empty()
            || self.statement.is_empty()
            || self.reference.trim().is_empty()
        {
            return Err(Refused::Shape);
        }

        let worst = self.run(&self.reference).map_err(|_| Refused::Unsolved)?;
        if worst > self.ceiling {
            return Err(Refused::Costly);
        }

        // The foil must fail. A foil this shape cannot be built for every
        // value -- a want holding a quote has no literal here -- and when it
        // cannot, the problem is refused rather than admitted unchecked: an
        // unrun canary is the thing this condition exists to prevent.
        let foil = self.foil().ok_or(Refused::Trivial)?;
        if self.run(&foil).is_ok() {
            return Err(Refused::Trivial);
        }

        // Agreement with itself, across two routes, on every field `differ`
        // compares -- which now includes what the program printed. A route
        // declining is not a disagreement: `Prepared` refuses any top level
        // that computes, by design, and that is coverage rather than a fault.
        for c in &self.cases {
            let entry = Entry::Call(&self.entry, &c.args);
            let a = differ::observe(&self.reference, entry, Route::Armed);
            let b = differ::observe(&self.reference, entry, Route::Prepared);
            if let (Some(a), Some(b)) = (a, b) {
                if differ::disagree(&a, &b).is_some() {
                    return Err(Refused::Unstable);
                }
            }
        }
        Ok(())
    }
}

/// How many problems are stored.
pub fn count() -> usize {
    sysbox::children(ROOT).len()
}

/// Every stored problem, newest last. Addresses, not bodies: a caller that
/// wants one loads it, and a caller that wants a count does not pay for any.
pub fn stored() -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for name in sysbox::children(ROOT) {
        if name.len() != 64 {
            continue;
        }
        let mut h = [0u8; 32];
        let mut good = true;
        for (i, b) in h.iter_mut().enumerate() {
            match name.get(i * 2..i * 2 + 2).and_then(|p| u8::from_str_radix(p, 16).ok()) {
                Some(v) => *b = v,
                None => {
                    good = false;
                    break;
                }
            }
        }
        if good {
            out.push(h);
        }
    }
    out
}

/// A small seeded set, so the machinery has something to be exercised on
/// before anything can generate one.
///
/// Deliberately easy. These exist to prove the substrate round-trips and
/// admits, not to be a benchmark -- a seeded problem the machine can already
/// solve teaches it nothing, which is exactly the frontier condition that
/// lives with the solver rather than here.
pub fn seeds() -> Vec<Problem> {
    vec![
        Problem {
            family: Family::Program,
            origin: Origin::Seeded,
            statement: String::from("double a number"),
            entry: String::from("twice"),
            ceiling: 10_000,
            cases: vec![
                Case { args: vec![Value::Int(3)], want: Value::Int(6) },
                Case { args: vec![Value::Int(-4)], want: Value::Int(-8) },
                Case { args: vec![Value::Int(0)], want: Value::Int(0) },
            ],
            reference: String::from("fn twice(n: int): int { return n * 2 }"),
        },
        Problem {
            family: Family::Program,
            origin: Origin::Seeded,
            statement: String::from("answer 1 when the text holds the letter, else 0"),
            entry: String::from("holds"),
            ceiling: 10_000,
            cases: vec![
                Case {
                    args: vec![Value::Str(String::from("axb")), Value::Str(String::from("x"))],
                    want: Value::Int(1),
                },
                Case {
                    args: vec![Value::Str(String::from("abc")), Value::Str(String::from("x"))],
                    want: Value::Int(0),
                },
            ],
            reference: String::from(
                "fn holds(t: str, c: str): int { if (contains(t, c)) { return 1 } return 0 }",
            ),
        },
    ]
}

/// Put the seeded problems in the namespace, if nothing is there.
///
/// The same arrangement the corpus has: problems live in the namespace, so
/// they are restored with everything else and a snapshot carries them. Only
/// seeded when the directory is empty, so a machine that has generated its own
/// is not handed these back on top of them.
///
/// Admission runs here rather than being assumed. A seed that stopped being
/// admissible -- because a condition tightened, or a builtin its reference
/// uses changed -- would otherwise be stored anyway and then refused by
/// everything downstream, which reads as the substrate being broken rather
/// than as a seed being wrong.
pub fn seed() -> (usize, usize) {
    if !sysbox::children(ROOT).is_empty() {
        return (0, count());
    }
    let mut kept = 0usize;
    for p in seeds() {
        if p.admit().is_ok() && p.store().is_some() {
            kept += 1;
        }
    }
    (kept, count())
}

/// Boot self-test. Every claim is arithmetic or parsing; none needs a model,
/// a corpus, a network or a store.
pub fn selftest() -> bool {
    use crate::kprintln;
    let mut ok = true;
    let mut claim = |what: &str, pass: bool| {
        if !pass {
            ok = false;
        }
        kprintln!("  {}   {}", if pass { "ok " } else { "FAIL" }, what);
    };

    let seeds = seeds();
    let good = seeds[0].clone();

    // Round-trip. The address is the rendering, so a parse that lost anything
    // would give a different one, and an archive keyed on it would hold two
    // entries for one problem.
    let text = good.render().expect("renderable");
    match Problem::parse(&text) {
        Some(back) => {
            claim("a problem read back renders to the bytes it was stored as", back.render().as_deref() == Some(text.as_str()));
            claim("and to the same address", back.hash() == good.hash());
            claim("with its cases intact", back.cases.len() == good.cases.len());
            claim("and its reference intact", back.reference == good.reference);
        }
        None => {
            claim("a problem read back renders to the bytes it was stored as", false);
        }
    }

    claim(
        "a rendering that is not one is refused rather than half read",
        Problem::parse("problem 2\nfamily program\n").is_none(),
    );

    // The five conditions, one claim each, each on a problem that violates
    // exactly one of them.
    claim("a well-formed problem is admitted", good.admit().is_ok());
    claim("and so is one taking two arguments", seeds[1].admit().is_ok());

    let mut one = good.clone();
    one.cases.truncate(1);
    claim("one case is not a problem", one.admit() == Err(Refused::Shape));

    let mut wrong = good.clone();
    wrong.reference = String::from("fn twice(n: int): int { return n * 3 }");
    claim(
        "a reference that does not solve it is refused",
        wrong.admit() == Err(Refused::Unsolved),
    );

    // The canary condition, and the one this whole object exists to enforce:
    // every case wanting the same answer means the cases decide nothing, and
    // a constant passes.
    let flat = Problem {
        family: Family::Program,
        origin: Origin::SelfMade,
        statement: String::from("always seven"),
        entry: String::from("seven"),
        ceiling: 10_000,
        cases: vec![
            Case { args: vec![Value::Int(1)], want: Value::Int(7) },
            Case { args: vec![Value::Int(2)], want: Value::Int(7) },
        ],
        reference: String::from("fn seven(n: int): int { return 7 }"),
    };
    claim(
        "a problem a constant answers is refused however hard it looks",
        flat.admit() == Err(Refused::Trivial),
    );

    let mut dear = good.clone();
    dear.ceiling = 1;
    claim(
        "a reference over the ceiling is refused",
        dear.admit() == Err(Refused::Costly),
    );

    // Running a candidate: the operation the whole arms race is scored on.
    claim(
        "a correct candidate answers every case",
        good.run("fn twice(n: int): int { return n + n }").is_ok(),
    );
    match good.run("fn twice(n: int): int { if (n > 0) { return n * 2 } return 1 }") {
        Err(i) => claim("and a wrong one is caught, on the case it failed", i == 1),
        Ok(_) => claim("and a wrong one is caught, on the case it failed", false),
    }
    claim(
        "a candidate that does not parse fails rather than throwing",
        good.run("fn twice(").is_err(),
    );
    claim(
        "and one defining the wrong function fails too",
        good.run("fn other(n: int): int { return n * 2 }").is_err(),
    );

    // A refusal names its condition. A generator told only "no" cannot learn
    // which rule to stop breaking, which is the whole reason `Refused` is an
    // enum and not a bool.
    claim(
        "a refusal says which condition it failed",
        !Refused::Trivial.why().is_empty() && Refused::Trivial.why() != Refused::Shape.why(),
    );

    // The store, round-tripped through the namespace rather than only through
    // `render`. Content addressing means storing the same problem twice is one
    // object, which is what lets an archive point at problems by address.
    match good.store() {
        Some(h) => {
            let before = count();
            let again = good.store();
            claim("storing a problem twice stores one object", again == Some(h) && count() == before);
            match Problem::load(&h) {
                Some(back) => {
                    claim("a stored problem loads back", back.hash() == Some(h));
                    claim("and is still admissible", back.admit().is_ok());
                }
                None => claim("a stored problem loads back", false),
            }
            claim("and is listed among the stored", stored().contains(&h));
        }
        None => claim("a problem can be stored", false),
    }

    ok
}
