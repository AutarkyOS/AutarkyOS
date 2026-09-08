//! Two populations that make each other harder.
//!
//! A proposer invents problems, a solver tries to answer them, and each is
//! rewarded for beating the other. The name is the Red Queen hypothesis: an
//! organism runs to stay in the same place because everything around it is
//! running too.
//!
//! **Why this rather than more of what `godel` already does.** `godel` is a
//! good loop -- paired statistics, four adversarial judges, a re-derivable
//! ledger -- pointed at a fixed target. There are 360 held-out corpus items
//! and no in-kernel mechanism produces a 361st, so the loop converges and
//! reports "search space exhausted", which it does. Nothing about the loop is
//! wrong; it has finished. What is missing is a supply of questions.
//!
//! `problem.rs` made a question into a storable object. This makes more of
//! them, and makes them *harder*, which is the part that cannot be done by
//! generating at random: a random problem is usually either trivial or
//! impossible, and both are worthless. A problem is worth keeping only if it
//! sits just past what the solver can currently do.
//!
//! ## Difficulty is measured, not declared
//!
//! The one thing this design needed and did not have was a definition of hard
//! that is not somebody's opinion. It comes out of the solver.
//!
//! The solver enumerates candidate programs in increasing size and tries each
//! against the problem's cases, stopping at the first that answers all of
//! them. **The difficulty of a problem is the number of candidates that had to
//! be tried.** That is a property of the problem and the solver together,
//! which is exactly right for a coevolutionary loop: it moves when either side
//! moves, and it is measured by running rather than estimated by looking.
//!
//! It also makes "the solver improved" a checkable claim rather than a
//! feeling. A better *ordering* of the same grammar, or a wider grammar,
//! solves the same problem after fewer candidates. That is a number, it is
//! paired across problems, and it is the shape `godel`'s J1 already judges.
//!
//! ## The frontier condition
//!
//! `problem::admit` answers whether a problem is well formed, solvable and
//! non-trivial. It deliberately does not ask whether it is *interesting*,
//! because that is a question about the solver. Here it is: a proposed problem
//! is kept only when the current solver **fails** it within budget. A problem
//! the solver already answers teaches nothing and inflates the archive with
//! things that look like progress.
//!
//! This is the guard against the degenerate attractor, working with the
//! synthesised foil in `problem::admit`. The foil stops problems that are
//! trivially checkable; the frontier stops problems that are merely already
//! solved. A generator that games either one has to game both at once, and the
//! two are checked by different machinery.
//!
//! ## No model, on purpose, for now
//!
//! Neither half calls the engine. A decode is about 2.8 s under emulation, so
//! a model-driven loop yields a few dozen generations a night; this one runs
//! thousands and can therefore be plotted, which is what a frontier has to be
//! to be worth anything. It also means both halves are asserted at boot with
//! no checkpoint loaded, and that the loop runs on a machine with no model at
//! all.
//!
//! The model is the obvious next proposer and the obvious next solver, and
//! everything here is shaped so it plugs in as one more source of candidates
//! rather than as a rewrite. That is deferred, not forgotten.
//!
//! ## What the enumerator cannot do, said plainly
//!
//! The grammar is integer arithmetic over the arguments and a handful of small
//! constants. It has no control flow, no strings, no calls. So every `Program`
//! problem over strings is unsolvable by it, and reads as maximally difficult,
//! which is honest but uninformative -- a problem nothing can solve and a
//! problem nothing has yet solved are the same reading here. `unsolved` is
//! reported separately from `difficulty` for that reason, and a proposer that
//! only produced unsolvable problems would be visible as a run where every
//! candidate was unsolved and none was ever answered.

use super::problem::{Case, Family, Origin, Problem};
use crate::aiksi::eval::Value;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

/// How many candidate programs a solver may try before giving up.
///
/// Small enough that a boot self-test finishes, large enough that the seeded
/// problems are inside it and a mutation of one is not. The number is the
/// solver's whole strength, so it is the thing that moves when the solver
/// improves.
pub const BUDGET: usize = 600;

/// The largest expression the enumerator will build, in operator count.
///
/// A bound on shape as well as on count: without it the enumerator spends its
/// whole budget deepening one branch, and the budget stops measuring breadth.
const MAX_OPS: usize = 3;

/// How much stronger the reachability probe is than the solver.
///
/// **The frontier has two edges and the first version only had one.** Keeping
/// a problem because the solver failed it keeps everything the solver cannot
/// do, which includes everything *nothing* of this kind can do. Measured: three
/// rounds took the store from 2 problems to 58, because five mutations of every
/// problem were nearly all unsolvable and therefore nearly all "at the
/// frontier". That is not an arms race, it is a proposer running away from a
/// solver that is standing still.
///
/// So a kept problem must also be solvable by a *stronger* solver -- one given
/// this multiple of the budget. That is the difference between unsolved and
/// unsolvable, which the module header draws and this now enforces: the
/// problem is in reach of this grammar, just not yet in reach of this budget.
/// Growth becomes directed instead of explosive, and every kept problem has a
/// known answer at a known cost, which is what makes it a target rather than
/// noise.
const REACH: usize = 16;

/// The constants the enumerator may use besides the arguments.
///
/// Deliberately few. Every constant multiplies the terminal set, and a solver
/// that can reach any integer solves "return 7" by looking it up rather than
/// by computing anything -- which `problem::admit`'s foil already refuses, but
/// which would also drown every real answer in constants.
const CONSTS: &[i64] = &[0, 1, 2, -1];

/// What a solver knows how to do. The searchable object.
///
/// One field today. It is a struct rather than a bare `usize` because the
/// second field is the point of the exercise -- a wider grammar, a different
/// enumeration order -- and a signature that has to change for it is a
/// signature every caller has to be revisited for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Solver {
    /// Candidates it may try before giving up.
    pub budget: usize,
}

impl Solver {
    pub fn new(budget: usize) -> Solver {
        Solver { budget }
    }
}

impl Default for Solver {
    fn default() -> Solver {
        Solver { budget: BUDGET }
    }
}

/// A problem answered, and what it cost to answer it.
#[derive(Clone)]
pub struct Solved {
    /// The program that answered every case.
    pub src: String,
    /// How many candidates were tried before this one worked. The difficulty.
    pub tried: usize,
    /// The worst case's step count, which is what the ceiling bounds.
    pub steps: u64,
}

/// The type name a value takes in a signature.
fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "int",
        Value::Str(_) => "str",
        _ => "any",
    }
}

/// Wrap an expression in the function the problem asked for.
///
/// The signature is read off the first case rather than declared, because the
/// cases are what a solution is checked against and a signature disagreeing
/// with them would fail every case for a reason that is not about the answer.
fn wrap(p: &Problem, expr: &str) -> Option<String> {
    let c = p.cases.first()?;
    let mut params = String::new();
    for (i, a) in c.args.iter().enumerate() {
        if i > 0 {
            params.push_str(", ");
        }
        params.push_str(&format!("a{}: {}", i, type_of(a)));
    }
    Some(format!(
        "fn {}({}): {} {{ return {} }}",
        p.entry,
        params,
        type_of(&c.want),
        expr
    ))
}

/// Every expression of exactly `ops` operators, given the ones below it.
///
/// Bottom-up rather than top-down: an expression of n operators is two smaller
/// ones joined, so each size is built once from sizes already in hand instead
/// of being re-derived down every branch.
fn grow(by_size: &[Vec<String>], ops: usize) -> Vec<String> {
    let mut out = Vec::new();
    for left in 0..ops {
        let right = ops - 1 - left;
        for a in &by_size[left] {
            for b in &by_size[right] {
                for op in ["+", "-", "*"] {
                    out.push(format!("({} {} {})", a, op, b));
                }
            }
        }
    }
    out
}

/// Try to answer a problem, cheapest candidate first.
///
/// `None` means the budget ran out, which is the frontier condition's whole
/// content: not "impossible", but "not by this solver, this many tries in".
pub fn solve(p: &Problem, s: Solver) -> Option<Solved> {
    let first = p.cases.first()?;
    // Terminals: the arguments, then the constants. Arguments first so a
    // problem answered by one of its inputs costs almost nothing, which keeps
    // the difficulty of an identity honest.
    let mut terms: Vec<String> = (0..first.args.len()).map(|i| format!("a{}", i)).collect();
    for c in CONSTS {
        terms.push(format!("{}", c));
    }

    let mut by_size: Vec<Vec<String>> = vec![terms];
    let mut tried = 0usize;

    for size in 0..=MAX_OPS {
        if size > 0 {
            let next = grow(&by_size, size);
            by_size.push(next);
        }
        for expr in &by_size[size] {
            if tried >= s.budget {
                return None;
            }
            tried += 1;
            let Some(src) = wrap(p, expr) else { return None };
            if let Ok(steps) = p.run(&src) {
                return Some(Solved { src, tried, steps });
            }
        }
    }
    None
}

/// One mutation of a problem into a harder one.
///
/// The mutations are syntactic on the *reference*, and the expected answers
/// are recomputed by running it. That is the whole trick and it is why a
/// generated problem is never a guess: the reference is the ground truth, so
/// deriving the question from the answer cannot produce an unsolvable
/// question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mutation {
    /// `E` becomes `E + k`.
    Offset(i64),
    /// `E` becomes `E * k`.
    Scale(i64),
    /// `E` becomes `(E * k) - a0`, which needs two operators where one did.
    Twist(i64),
}

impl Mutation {
    /// `arg` is the reference's *own* first parameter name.
    ///
    /// Not `a0`. The first version of this built the mutated reference with
    /// `wrap`, which names parameters `a0..`, while the reference it was
    /// mutating named its own `n` -- so the new body referred to a variable
    /// that did not exist, failed to run, and `mutate` answered `None` for
    /// every problem in the store. The loop reported "0 proposed" and looked
    /// like it had nothing to do rather than like it was broken.
    fn apply(&self, expr: &str, arg: &str) -> String {
        match self {
            Mutation::Offset(k) => format!("(({}) + {})", expr, k),
            Mutation::Scale(k) => format!("(({}) * {})", expr, k),
            Mutation::Twist(k) => format!("((({}) * {}) - {})", expr, k, arg),
        }
    }
}

/// The mutations a proposer may reach for, in a fixed order.
///
/// Declared rather than random, so a run is re-derivable: the nth mutation of
/// the nth problem is a function of the archive rather than of a coin. The
/// same argument `godel::frontier` makes about walking its grid.
pub const MUTATIONS: &[Mutation] = &[
    Mutation::Offset(1),
    Mutation::Scale(2),
    Mutation::Twist(2),
    Mutation::Offset(-3),
    Mutation::Scale(3),
];

/// The body of a reference of the shape this module generates.
///
/// Only mutates a reference it can read, which is one `return` of a single
/// expression. A reference with control flow is left alone rather than
/// mangled -- a mutation that produced a program which no longer parses would
/// be refused by `admit` anyway, and reporting "could not mutate" is a more
/// useful answer than a refusal three conditions later.
/// The reference's own signature, with a new body.
///
/// Preserving the signature rather than regenerating it is the whole fix for
/// the bug recorded on `Mutation::apply`: a mutation is a change of body, and
/// anything that also rewrites the parameter list has to rewrite every
/// mention of a parameter inside the expression it is keeping.
fn rebody(reference: &str, expr: &str) -> Option<String> {
    let open = reference.find('{')?;
    Some(format!("{}{{ return {} }}", reference.get(..open)?, expr))
}

/// The name of the reference's first parameter, so a mutation can mention it.
fn first_param(reference: &str) -> Option<&str> {
    let open = reference.find('(')?;
    let close = reference.find(')')?;
    let first = reference.get(open + 1..close)?.split(',').next()?.trim();
    let name = first.split(':').next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

fn body_of(reference: &str) -> Option<&str> {
    let open = reference.find('{')?;
    let close = reference.rfind('}')?;
    let inner = reference.get(open + 1..close)?.trim();
    inner.strip_prefix("return ").map(|e| e.trim())
}

/// Make a harder problem from one that already holds.
///
/// The cases keep their inputs and get new answers, computed by running the
/// mutated reference. So the new problem is about the same inputs and a
/// different function of them, which is what makes the difficulty comparable:
/// two problems over one set of inputs differ in the program needed and in
/// nothing else.
pub fn mutate(p: &Problem, m: Mutation) -> Option<Problem> {
    if p.family != Family::Program {
        return None;
    }
    let expr = body_of(&p.reference)?;
    let arg = first_param(&p.reference)?;
    let mutated = m.apply(expr, arg);
    let reference = rebody(&p.reference, &mutated)?;

    // The reference decides every answer. Run it once per case rather than
    // computing the shift in Rust: a second implementation of the mutation,
    // in another language, is exactly the drift `model.rs` warns about.
    let mut cases = Vec::with_capacity(p.cases.len());
    for c in &p.cases {
        let probe = Problem {
            family: p.family,
            origin: p.origin,
            statement: p.statement.clone(),
            entry: p.entry.clone(),
            ceiling: p.ceiling,
            cases: vec![Case { args: c.args.clone(), want: Value::Int(0) }],
            reference: reference.clone(),
        };
        let want = answer_of(&probe, &c.args)?;
        cases.push(Case { args: c.args.clone(), want });
    }

    Some(Problem {
        family: p.family,
        origin: Origin::SelfMade,
        statement: format!("{}, {}", p.statement, describe(m)),
        entry: p.entry.clone(),
        ceiling: p.ceiling,
        cases,
        reference,
    })
}

fn describe(m: Mutation) -> String {
    match m {
        Mutation::Offset(k) => format!("then add {}", k),
        Mutation::Scale(k) => format!("then multiply by {}", k),
        Mutation::Twist(k) => format!("scaled by {} less the first argument", k),
    }
}

/// What a reference answers for one set of arguments.
///
/// Goes through the same `differ::observe` every other check here uses, so an
/// answer computed while generating and an answer checked while judging come
/// from one implementation.
fn answer_of(p: &Problem, args: &[Value]) -> Option<Value> {
    use crate::aiksi::differ::{observe, Entry, Route};
    let out = observe(&p.reference, Entry::Call(&p.entry, args), Route::Armed)?;
    if out.errored() {
        return None;
    }
    out.value().parse::<i64>().ok().map(Value::Int)
}

/// What one round of the arms race did.
pub struct Round {
    /// Problems proposed.
    pub proposed: usize,
    /// Refused by `problem::admit` -- malformed, unsolved, trivial, unstable.
    pub inadmissible: usize,
    /// Admissible and already solved, so not at the frontier.
    pub already: usize,
    /// Admissible, unsolved, and still unsolved by a solver `REACH` times
    /// stronger -- so out of reach of this grammar rather than merely of this
    /// budget. Dropped, and counted, because a proposer producing only these
    /// is a proposer generating noise and the count is what says so.
    pub beyond: usize,
    /// Kept: admissible, past the solver, inside the stronger one, and *new*.
    ///
    /// New matters. Storing is idempotent, so re-proposing a child already in
    /// the store answers the same address and writes nothing -- and counting
    /// that as kept reported "3 kept" on four consecutive rounds while the
    /// store stayed at five problems. The number now means what it says, which
    /// is also what makes a round that keeps nothing a reliable signal that
    /// the loop has converged for this solver and this mutation set.
    pub kept: usize,
    /// Proposed, admissible, at the frontier, and already stored.
    pub known: usize,
    /// The hardest difficulty the solver reached this round, in candidates.
    pub hardest: usize,
    /// The hardest a *kept* problem cost the stronger solver. This is the
    /// frontier: what the solver would have to become to answer them.
    pub reach: usize,
    /// Addresses of what was kept, so the caller can store or report them.
    pub frontier: Vec<[u8; 32]>,
}

/// Run one round against every stored problem the solver can currently answer.
///
/// The order is the point. A problem is mutated, admitted, and only then asked
/// whether the solver already answers it -- admission first because it is
/// cheap and refuses most bad candidates, the frontier check second because it
/// costs a whole search.
pub fn round(s: Solver) -> Round {
    let mut r = Round {
        proposed: 0,
        inadmissible: 0,
        already: 0,
        beyond: 0,
        kept: 0,
        known: 0,
        hardest: 0,
        reach: 0,
        frontier: Vec::new(),
    };
    let strong = Solver::new(s.budget.saturating_mul(REACH));

    for h in super::problem::stored() {
        let Some(p) = Problem::load(&h) else { continue };
        if p.family != Family::Program {
            continue;
        }
        // How hard the parent is, which is what makes the child's difficulty
        // a comparison rather than a reading.
        if let Some(sol) = solve(&p, s) {
            r.hardest = r.hardest.max(sol.tried);
        }
        for m in MUTATIONS {
            let Some(child) = mutate(&p, *m) else { continue };
            r.proposed += 1;
            if child.admit().is_err() {
                r.inadmissible += 1;
                continue;
            }
            if solve(&child, s).is_some() {
                r.already += 1;
                continue;
            }
            // Past this solver. Is it past every solver of this shape? The
            // stronger probe is what separates a target from noise, and it is
            // asked last because it is the most expensive question here.
            let Some(hard) = solve(&child, strong) else {
                r.beyond += 1;
                continue;
            };
            let Some(ch) = child.hash() else { continue };
            let fresh = Problem::load(&ch).is_none();
            if child.store().is_some() {
                if fresh {
                    r.kept += 1;
                    r.frontier.push(ch);
                } else {
                    r.known += 1;
                }
                r.reach = r.reach.max(hard.tried);
            }
        }
    }
    r
}

/// Report a round to the console.
pub fn report(rounds: usize, s: Solver) {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, YELLOW};
    use crate::kprintln;

    console::set_color(YELLOW);
    kprintln!("[redqueen] {} round(s), solver budget {}", rounds, s.budget);
    console::set_color(LTGRAY);

    let mut total = 0usize;
    for i in 0..rounds.max(1) {
        let r = round(s);
        kprintln!(
            "  round {}: {} proposed, {} inadmissible, {} solved, {} beyond reach, {} known, {} kept",
            i + 1,
            r.proposed,
            r.inadmissible,
            r.already,
            r.beyond,
            r.known,
            r.kept
        );
        if r.reach > 0 {
            kprintln!(
                "    the frontier stands at {} candidate(s) against a budget of {}",
                r.reach,
                s.budget
            );
        }
        if r.hardest > 0 {
            kprintln!("    hardest solved this round: {} candidate(s)", r.hardest);
        }
        if let Some(h) = r.frontier.first().and_then(Problem::load) {
            // What the newest frontier problem costs to *run*, which is the
            // number its ceiling bounds -- a different question from how many
            // candidates it took to find, and the one a solver is billed for.
            if let Ok(steps) = h.run(&h.reference) {
                kprintln!("    newest costs {} step(s) to check", steps);
            }
        }
        total += r.kept;
        // A round that kept nothing will keep nothing next time either: the
        // stored set did not move, the mutations are a fixed list, and the
        // solver did not change. Stopping says so rather than repeating it.
        if r.kept == 0 {
            kprintln!("    the frontier did not move -- every child is known, solved or out of reach");
            break;
        }
    }
    console::set_color(LTGREEN);
    kprintln!("  {} problem(s) now at {}", super::problem::count(), super::problem::ROOT);
    console::set_color(LTGRAY);
    let _ = total;
}

/// Boot self-test. No model, no corpus, no network, no store beyond the
/// namespace every other suite already uses.
pub fn selftest() -> bool {
    use crate::kprintln;
    let mut ok = true;
    let mut claim = |what: &str, pass: bool| {
        if !pass {
            ok = false;
        }
        kprintln!("  {}   {}", if pass { "ok " } else { "FAIL" }, what);
    };

    let seeds = super::problem::seeds();
    let twice = seeds[0].clone();
    let s = Solver::default();

    // The solver, on something it can do. `twice` is `n * 2`, which the
    // enumerator reaches as one operator over an argument and a constant.
    match solve(&twice, s) {
        Some(sol) => {
            claim("the solver answers a problem inside its grammar", sol.tried > 0);
            claim("and the program it found really does answer it", twice.run(&sol.src).is_ok());
            claim("with a difficulty it measured rather than guessed", sol.tried <= s.budget);
            // Two different costs, and conflating them is the easy mistake:
            // `tried` is how long the search took, `steps` is what the answer
            // costs to run. The ceiling bounds the second.
            claim("and an answer that respects the problem's ceiling", sol.steps <= twice.ceiling);
        }
        None => claim("the solver answers a problem inside its grammar", false),
    }

    // And on something it cannot. The string problem is outside the grammar
    // entirely, which is the honest reading of "unsolved" rather than "hard".
    claim(
        "a problem outside the grammar is unsolved rather than wrongly answered",
        solve(&seeds[1], s).is_none(),
    );

    // A solver with no budget answers nothing. The frontier condition rests on
    // failure meaning "not within budget", so a budget of zero has to fail.
    claim(
        "a solver given no budget solves nothing",
        solve(&twice, Solver::new(0)).is_none(),
    );

    // Mutation. The child must be a real problem in its own right -- the
    // reference decides the answers, so if this holds, generation cannot
    // produce an unsolvable question.
    match mutate(&twice, Mutation::Offset(1)) {
        Some(child) => {
            claim("a mutated problem is admissible", child.admit().is_ok());
            claim("and its reference answers its own cases", child.run(&child.reference).is_ok());
            claim("and it is not the problem it came from", child.hash() != twice.hash());
            claim("and it is marked as the machine's own", child.origin == Origin::SelfMade);
            // The point of mutating at all.
            let a = solve(&twice, s).map(|x| x.tried).unwrap_or(usize::MAX);
            let b = solve(&child, s).map(|x| x.tried).unwrap_or(usize::MAX);
            claim("and it is harder than its parent", b > a);
        }
        None => claim("a mutated problem is admissible", false),
    }

    // A mutation of a reference this module cannot read is declined rather
    // than mangled into something that will fail admission for the wrong
    // reason.
    let mut odd = twice.clone();
    odd.reference = String::from("fn twice(n: int): int { if (n > 0) { return n * 2 } return 0 }");
    claim(
        "a reference with control flow is left alone rather than mangled",
        mutate(&odd, Mutation::Offset(1)).is_none(),
    );

    // The frontier condition, which is what makes this an arms race: a strong
    // solver finds the child easy, a weak one does not, and the same child is
    // kept or dropped accordingly.
    if let Some(child) = mutate(&twice, Mutation::Twist(2)) {
        let weak = Solver::new(4);
        claim(
            "a weak solver leaves a mutated problem at the frontier",
            solve(&child, weak).is_none(),
        );
        claim(
            "and a strong one takes it off the frontier",
            solve(&child, Solver::new(BUDGET * 4)).is_some() || solve(&child, s).is_some(),
        );
    }

    // The other edge, and the reason a round is directed rather than
    // explosive: unsolved is not unsolvable. The string problem is outside
    // this grammar entirely, so no budget reaches it, and a round must drop it
    // rather than file it as the hardest thing it has ever seen.
    claim(
        "a problem outside the grammar stays unsolved however strong the solver",
        solve(&seeds[1], Solver::new(BUDGET * REACH)).is_none(),
    );
    claim(
        "while one inside it is reached when the budget is raised",
        solve(&twice, Solver::new(BUDGET * REACH)).is_some(),
    );

    ok
}
