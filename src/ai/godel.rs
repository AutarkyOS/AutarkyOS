//! A Godel machine for this machine.
//!
//! Schmidhuber's construction rewrites any part of itself the moment it can
//! *prove* the rewrite raises expected future utility, and it carries a
//! theorem prover to do it. Nothing here can carry one. There is no formal
//! axiomatisation of "this kernel routes better", no proof calculus over a
//! quantised transformer, and no honest way to fake either. Implementing the
//! literal construction would mean implementing a proof searcher that could
//! never discharge a single goal, which is decoration with extra steps.
//!
//! So the load-bearing property is taken and the mechanism is replaced.
//! Schmidhuber wants proof rather than evidence because evidence can be
//! cherry-picked, overfitted, or unreproducible. There is a second kind of
//! object with that property and this system happens to be built out of it:
//!
//!   **a certificate that is cheaper to refute than it was to produce, over
//!   content-addressed inputs, such that any later run re-derives the same
//!   verdict bit for bit.**
//!
//! That is not a proof of future utility. It is a proof of an empirical
//! claim, permanently falsifiable by re-execution, and it is the strongest
//! thing available to a machine that cannot see its own future.
//!
//! # Why it is affordable here and nowhere else
//!
//! Because the base model is frozen and `train::Trial` caches one hidden
//! state per decision, producing a variant costs a forward pass per example
//! -- 214 s each under TCG -- while *checking* one costs a dot product per
//! cached decision and no forward passes at all. Four orders of magnitude
//! between making a claim and testing it is exactly the asymmetry a proof
//! system provides, arrived at from the other direction. A later boot, a
//! sceptical operator, or the machine itself can re-run any verdict in the
//! ledger for almost nothing.
//!
//! # The five departures from the literature, and why each one is here
//!
//! **Paired judging.** Two adapters answer the *same* cached decisions, so
//! the comparison is paired rather than between two samples. Fifty
//! validation items at 62% against 58% is two items and indistinguishable
//! from noise; the same fifty showing nine repaired and two broken is a
//! different claim, and only the paired form separates them. This is only
//! available because the features are frozen -- it is a property of the
//! machine, not a statistical preference.
//!
//! **The test slice has a budget, and the budget lives in the ledger.** A
//! loop that improves itself forever reads the held-out set forever, and
//! every read makes the number it reports more optimistic. The discipline
//! this tree already works under -- three splits, test read once -- does not
//! survive being put in a loop unless somebody counts. So the ledger counts,
//! the count is part of every certificate, and a test figure is reported as
//! "read N" or not reported at all. This is the machine confronting its own
//! multiple-comparisons problem, which is the specific way a self-improving
//! measurement loop lies to itself.
//!
//! **Predict, then measure.** Before the judges run, the trial records
//! whether the training-set gain predicted a win. Nothing acts on it. What
//! accumulates is a calibration record for a question this project actually
//! wants answered -- does overfitting predict generalisation *on this
//! corpus, at this scale* -- and at the current n it means nothing at all,
//! which the ledger says out loud.
//!
//! **Quiet hours are two independent facts.** An RTC window says the operator
//! has gone to bed; the entropy ring in `godbits` says no key or pointer
//! interrupt has fired. Either alone is wrong: a clock does not know somebody
//! is working late, and silence at noon is a coffee break. Both are required.
//!
//! **Lineage is a Merkle DAG, so history cannot be quietly rewritten.** A
//! variant is named by the hash of its own description, which names its
//! parent by hash. Adoption is a pointer swap and the parent stays addressed,
//! so rollback is O(1) and the whole self-modification history is one object
//! the system can be asked to show.
//!
//! # What it does not do
//!
//! It does not rewrite its own code. It varies an adapter, a policy text, a
//! skill set and the deliberation parameters -- the parts of this system that
//! are data. Rewriting the kernel would need the proof the opening paragraph
//! says is unavailable, and a self-modifying ring-0 image with no isolation
//! and one address space is a machine that gets exactly one mistake.

use super::train::{Budget, Fit, Slice, Trial};
use crate::store::sha256;
use crate::sysbox;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub const ROOT: &str = "/ai/godel";
pub const HEAD: &str = "/ai/godel/head";
pub const LEDGER: &str = "/ai/godel/ledger.txt";
pub const BUDGET: &str = "/ai/godel/test-budget";
/// What the machine says it did, in the voice it says it in.
pub const DISPATCH: &str = "/ai/godel/dispatch.txt";
/// How many sittings the operator has been shown.
pub const REPORTED: &str = "/ai/godel/reported";

// A window and an idleness test answer different questions, so both are
// required. Idleness says nobody is typing at this instant, which is also
// true of a coffee break and of the seconds somebody spends reading output.
// The clock says the operator has gone to bed. Silence at noon is not
// permission, and 03:00 with a hand on the keyboard is somebody working late.
// They are checked independently, below.

/// Where a runtime window override lives, as text: `from until`.
pub const WINDOW: &str = "/ai/godel/window";

/// The in-force J1 significance threshold, as text.
///
/// This is the one piece of state U3 adds and the whole reason it is dangerous:
/// it is the *criterion*, not a variant. Every other axis proposes a change to
/// what the machine is; this one proposes a change to what "better" means. It
/// lives here, loop-writable and rollback-able like `/ai/config`'s rule, so a
/// judged change to the bar is undoable for the cost of a pointer -- and it is
/// deliberately NOT one of the append-only records the invariant protects,
/// because the bar is a decision the loop is allowed to revise. What the
/// invariant protects is the *ledger* of those revisions, so that a machine
/// that loosened its own criterion cannot also erase having done so.
pub const JUDGE: &str = "/ai/godel/judge";

/// The in-force J1 effect-size floor, as text.
///
/// The criterion is two numbers and it was unbound at one of them. J1 admits a
/// candidate only if `fixed - broke >= floor` **and** `chi >= tau`, and until
/// this file existed only the second clause took the bar the loop was running;
/// the first read the constant. That is not a smaller version of the same
/// freedom, it is a different constraint, and a measurement made it concrete:
/// a candidate repairing 2 of 24 validation decisions with none broken, whose
/// held-out anchor rose 52.2% to 60.9%, was refused by *every* bar in
/// `[JUDGE_MIN, JUDGE_MAX]` because the floor is evaluated before chi. The
/// axis could not reach the constraint that was binding.
///
/// It lives beside `JUDGE` and is revisable on the same terms: loop-writable,
/// rollback-able, and outside the append-only records, because what the
/// invariant protects is the ledger of revisions rather than the criterion
/// itself.
pub const FLOOR: &str = "/ai/godel/floor";

/// Proposals already attempted, one empty marker per hash.
///
/// Keyed on the *proposal* and not on the variant, because a variant's hash
/// covers the adapter it produced and that is not known until the trial has
/// already run. Asking "have I tried this?" has to be answerable before paying
/// for the answer.
pub const TRIED: &str = "/ai/godel/tried";

/// What to try, as opposed to what came out.
///
/// The loop had no such thing. `trial` took a `Budget` and both callers passed
/// `Budget::default()`, so every knob was a constant: `lr` 0.02, `rank` 8,
/// `alpha` 16.0, `epochs` 20. Training starts from `Dora::new`, which is all
/// zeros, there is no RNG anywhere in the path, and `scatter` builds a
/// classifier-only adapter so the cached features do not move either. Same
/// inputs, no randomness: **the same adapter came out every night**, with the
/// same content hash, and after the first adoption every later trial compared
/// it against itself -- nothing repaired, nothing broken, J1 answering "no net
/// repair", rejected, forever. The lineage could never hold more than two
/// nodes.
///
/// The fix is emphatically *not* to randomise training. Determinism is what
/// lets any later run re-derive a verdict bit for bit, which is the claim this
/// whole module rests on; randomness would buy variety and sell that. So a
/// trial stays a function of its inputs and gains an input.
/// What kind of change is being proposed.
///
/// The loop began as an adapter search: every proposal was a set of training
/// knobs, and the one other thing the machine could change -- a council core --
/// reached adoption down a separate path with its own entry point. Two ways in
/// meant two places for the bookkeeping to drift, and the second one had to
/// grow its own copy of the lineage discipline before it was safe to use.
///
/// So the kind is in the proposal, and one dispatcher routes it. What that
/// buys is not tidiness: it means the *scheduler* no longer has to know what
/// kind of thing it is running. The night loop asks for the next proposal and
/// runs it, and whether that turns out to be a learning rate or a program the
/// machine wrote an hour ago is a fact about the proposal, not about the loop.
///
/// **A kind here must have a judge.** The obvious extensions -- deep training
/// (J1-J4 exist, the routing does not), skills (no judge at all), the routing
/// rule (needs a calibration judge before `rule` is searchable) -- are absent
/// on purpose. A variant in this enum that `run` cannot judge would be a
/// promise the type makes and the machine cannot keep, and an unjudged change
/// adopted at three in the morning is exactly what this module exists to
/// prevent.
#[derive(Clone, Copy, PartialEq)]
pub enum ProposalKind {
    /// Train a classifier adapter with these knobs. Judged J1-J4.
    Adapter,
    /// Judge a council core already stored under its content address.
    /// Judged J1/J5/J6 by `harness::core_bench_in`.
    Core([u8; 32]),
    /// Adapt the attention path as well as the classifier, and judge what
    /// that bought against what it costs. J1-J4, paired on routing.
    Deep,
    /// Admit a skill the machine compiled from an episode. Judged by
    /// `skill::bench`: it is a program, it runs under the powers it will
    /// really have, it repeats, and it is cheap.
    Skill([u8; 32]),
    /// Change how the council combines its cores. Judged on calibration by
    /// `harness::rule_bench`, because accuracy is not what this axis moves.
    Config(u8),
    /// Change the J1 significance bar itself -- the *criterion*, not a variant.
    /// This is the axis the fork is named for: every other kind proposes a
    /// change to what the machine is, and this one proposes a change to what
    /// "better" means. It cannot be judged by J1-J4, because it *is* J1; it is
    /// judged by the cross-evaluation matrix against a held-out anchor no bar
    /// can see (`trial_judge`), which is the only thing that tells a bar that
    /// found a real gain from one tuned to accept noise.
    Judge(f32, usize),
}

#[derive(Clone, Copy, PartialEq)]
pub struct Proposal {
    pub lr: f32,
    pub rank: usize,
    pub alpha: f32,
    pub epochs: usize,
    /// How the council combines its cores. Carried here so the search space
    /// has somewhere to put it; `trial` records it in the variant, and nothing
    /// varies it yet -- see `GRID`.
    pub rule: u8,
    pub kind: ProposalKind,
}

/// Why a proposal could not be run to a verdict.
///
/// Two error types met here: the trainer refuses for reasons about the machine
/// and the corpus, the core judge for reasons about the program. Flattening
/// them to a bool would lose the difference between "there was nothing to
/// train on" and "the core will not load", which are the two facts a journal
/// line at 3am has to carry.
pub enum Refused {
    Train(super::train::RunError),
    Judge(&'static str),
}

impl Refused {
    pub fn why(&self) -> &'static str {
        match self {
            Refused::Train(super::train::RunError::Hardware) => "the hardware check said no",
            Refused::Train(super::train::RunError::NoCorpus) => "there is no corpus",
            Refused::Train(super::train::RunError::Hybrid) => "the model is a hybrid the trainer will not touch",
            Refused::Train(super::train::RunError::Quantised) => "the base is int4, which serves but is not trained against",
            Refused::Train(super::train::RunError::NoDecisions) => "the corpus produced no decisions",
            Refused::Judge(w) => w,
        }
    }
}

impl Proposal {
    /// A proposal to judge a stored council core.
    ///
    /// The training knobs are zero because a core is not trained -- it is a
    /// program, already written, and the only question is whether it earns a
    /// place in the decision path. They are still rendered, and still in the
    /// hash, because a proposal is identified by its whole text: leaving them
    /// out would make this a different kind of document and the marker
    /// directory holds one kind.
    pub fn core(h: [u8; 32]) -> Proposal {
        Proposal {
            lr: 0.0,
            rank: 0,
            alpha: 0.0,
            epochs: 0,
            rule: super::harness::Rule::WithCore as u8,
            kind: ProposalKind::Core(h),
        }
    }

    /// A proposal to adapt the attention path, with the knobs it trains under.
    ///
    /// Unlike a core, this one is trained here and now, so it carries a real
    /// learning rate, rank and epoch count -- and they are in the rendering,
    /// which means two deep runs at different settings are different points
    /// and the marker directory can tell them apart.
    pub fn deep(lr: f32, rank: usize, alpha: f32, epochs: usize) -> Proposal {
        Proposal { lr, rank, alpha, epochs, rule: 0, kind: ProposalKind::Deep }
    }

    /// A proposal to admit a stored skill.
    ///
    /// No training knobs at all: a skill is a program that already exists and
    /// the question is whether it is fit to keep, not how to make one. They
    /// are still rendered, for the reason `core` renders them -- the marker
    /// directory holds one kind of document.
    pub fn skill(h: [u8; 32]) -> Proposal {
        Proposal { lr: 0.0, rank: 0, alpha: 0.0, epochs: 0, rule: 0, kind: ProposalKind::Skill(h) }
    }

    /// A proposal to change how the council combines its cores.
    pub fn config(rule: u8) -> Proposal {
        Proposal { lr: 0.0, rank: 0, alpha: 0.0, epochs: 0, rule, kind: ProposalKind::Config(rule) }
    }

    /// A proposal to move the J1 significance bar to `tau`.
    ///
    /// No training knobs: it is not an adapter and trains nothing. `tau` rides
    /// in the kind and is rendered at six places like a learning rate, so two
    /// proposed bars a hundredth apart are different points the frontier can
    /// tell apart and the marker directory does not collapse.
    pub fn judge(tau: f32, floor: usize) -> Proposal {
        Proposal {
            lr: 0.0,
            rank: 0,
            alpha: 0.0,
            epochs: 0,
            rule: 0,
            kind: ProposalKind::Judge(tau, floor),
        }
    }

    pub fn budget(&self, examples: usize, millis: u64) -> Budget {
        Budget {
            epochs: self.epochs,
            millis,
            examples,
            lr: self.lr,
            rank: self.rank,
            alpha: self.alpha,
        }
    }

    /// The text that names this point in the space.
    ///
    /// Rendered rather than packed, for the reason `Variant::render` is: a
    /// hash over a struct layout changes when the struct does, and a ledger
    /// full of hashes nobody can reproduce is a ledger of nothing.
    pub fn render(&self) -> String {
        let mut s = String::from("proposal 1\n");
        s.push_str("lambda ");
        push_f6(&mut s, self.lr);
        s.push_str("\nrank ");
        push_u32(&mut s, self.rank as u32);
        s.push_str("\nalpha ");
        push_f6(&mut s, self.alpha);
        s.push_str("\nepochs ");
        push_u32(&mut s, self.epochs as u32);
        s.push_str("\nrule ");
        push_u32(&mut s, self.rule as u32);
        s.push('\n');
        // Emitted only when the kind is not the one every existing marker
        // was written under.
        //
        // The same compatibility rule `Variant::render` follows, and here it
        // guards something with teeth: `tried()` looks a proposal up by the
        // hash of this text, so an unconditional `kind` line would re-address
        // every marker in `/ai/godel/tried` at once and the grid would be
        // walked from the beginning as though nothing had ever been measured.
        match self.kind {
            ProposalKind::Adapter => {}
            ProposalKind::Core(h) => {
                s.push_str("core ");
                s.push_str(&hex32(&h));
                s.push('\n');
            }
            ProposalKind::Deep => s.push_str("deep 1\n"),
            ProposalKind::Skill(h) => {
                s.push_str("skill ");
                s.push_str(&hex32(&h));
                s.push('\n');
            }
            // The rule is already a field of the rendering above, so a config
            // point is distinguished by carrying nothing else: zero knobs and a
            // `rule` line that differs. Emitting a second copy of the rule would
            // make the identity depend on the same fact twice.
            ProposalKind::Config(_) => s.push_str("config 1
"),
            // The bar rides in its own line at six places, the same precision a
            // learning rate needs so two nearby proposals do not collide to one
            // marker. The training knobs above are all zero for a judge
            // proposal, so this line is the whole of what distinguishes two of
            // them.
            ProposalKind::Judge(tau, floor) => {
                s.push_str("judge ");
                push_f6(&mut s, tau);
                s.push('\n');
                // Conditional for the reason `Variant`'s own fields are: a
                // point at the default floor must render to exactly the bytes
                // it rendered before the floor was movable, or every marker
                // already in `/ai/godel/tried` names a proposal that no longer
                // exists and the loop re-walks a grid it has already spent.
                if floor != MIN_FIXED {
                    s.push_str("floor ");
                    push_u32(&mut s, floor as u32);
                    s.push('\n');
                }
            }
        }
        s
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256::hash(self.render().as_bytes())
    }

    fn tried(&self) -> bool {
        let mut path = String::from(TRIED);
        path.push('/');
        path.push_str(&hex32(&self.hash()));
        sysbox::read_blob(&path).is_some()
    }

    /// Record that this point has been visited, whatever the verdict was.
    ///
    /// Written before the trial rather than after. A trial that faults or is
    /// interrupted has still spent the night on this point, and a marker
    /// written only on success would send the loop back to the same failing
    /// place every time.
    pub fn mark(&self) {
        let mut path = String::from(TRIED);
        path.push('/');
        path.push_str(&hex32(&self.hash()));
        sysbox::write_text(&path, &self.render());
    }
}

/// The declared search space, in the order it is walked.
///
/// A fixed table and not a random draw, so the whole search is re-derivable
/// from the ledger: given the markers, the next point is a function and not a
/// coin. First row is today's configuration, so the first trial after this
/// lands reproduces the behaviour that came before it and the comparison is
/// against a known quantity.
///
/// Only the training knobs vary here. `rule` is in `Proposal` and stays 0
/// throughout, because the judges cannot yet see it: J1 is a paired test over
/// routing decisions and the rule changes `Verdict::confident`, which is about
/// how much the council is willing to claim rather than about what it answers.
/// Varying it without a judge that measures it would be search without
/// selection, which is drift.
const GRID: &[Proposal] = &[
    Proposal { lr: 0.02, rank: 8, alpha: 16.0, epochs: 20, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.05, rank: 8, alpha: 16.0, epochs: 20, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.01, rank: 8, alpha: 16.0, epochs: 40, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.02, rank: 16, alpha: 32.0, epochs: 20, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.05, rank: 16, alpha: 32.0, epochs: 20, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.01, rank: 4, alpha: 8.0, epochs: 40, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.08, rank: 8, alpha: 16.0, epochs: 12, rule: 0, kind: ProposalKind::Adapter },
    Proposal { lr: 0.02, rank: 32, alpha: 64.0, epochs: 20, rule: 0, kind: ProposalKind::Adapter },
];

/// The search space itself, checked without running anything.
///
/// This is the test that would have caught the bug it was written for. The
/// loop trained one adapter and re-derived it nightly forever, and nothing
/// failed -- every trial "worked", the ledger filled with rejections, and the
/// rejections were correct: an adapter compared against itself repairs
/// nothing. What was missing was any claim that two successive trials *differ*.
///
/// It runs before `sysbox::init`, so no marker can be read and the frontier
/// always answers the first row. What is checkable here is the space, which is
/// where the failure actually lives.
pub fn space_selftest() -> bool {
    if GRID.is_empty() {
        return false;
    }

    // Every point is distinct. Two identical rows are two nights spent
    // deriving the same weights, which is the whole defect in miniature.
    for (i, a) in GRID.iter().enumerate() {
        for b in GRID.iter().skip(i + 1) {
            if a.hash() == b.hash() {
                return false;
            }
        }
    }

    // Every field the trainer reads reaches the hash. A knob that changes the
    // weights and not the identity means two different variants collapse to
    // one node, which is the same failure from the other side.
    let base = GRID[0];
    let vary = [
        Proposal { lr: base.lr + 0.01, ..base },
        Proposal { rank: base.rank + 1, ..base },
        Proposal { alpha: base.alpha + 1.0, ..base },
        Proposal { epochs: base.epochs + 1, ..base },
        Proposal { rule: base.rule + 1, ..base },
    ];
    for v in vary {
        if v.hash() == base.hash() {
            return false;
        }
    }

    // Rendering is stable: the same point twice is the same hash, which is
    // what makes "have I tried this?" answerable at all.
    if base.hash() != GRID[0].hash() {
        return false;
    }

    // The kind reaches the hash, and only when it is not the default.
    //
    // Both halves are load-bearing and they pull against each other. If an
    // adapter point rendered a `kind` line, every marker already in
    // `/ai/godel/tried` would re-address at once and the grid would be walked
    // again from the top as though nothing had ever been measured -- weeks of
    // nights, silently repeated. If a core point did *not* render one, two
    // different programs would share a marker and the second would never be
    // judged.
    if base.render().contains("core ") {
        return false;
    }
    let c1 = Proposal::core(sha256::hash(b"one core"));
    let c2 = Proposal::core(sha256::hash(b"another core"));
    if !c1.render().contains("core ") || c1.hash() == c2.hash() {
        return false;
    }
    if GRID.iter().any(|p| p.hash() == c1.hash()) {
        return false;
    }
    // A deep point is its own kind, and its knobs are in its identity: two
    // deep runs at different ranks are different experiments, and a marker
    // that could not tell them apart would let the loop believe it had already
    // tried something it had not.
    let d1 = Proposal::deep(0.02, 4, 8.0, 4);
    let d2 = Proposal::deep(0.02, 8, 8.0, 4);
    if !d1.render().contains("deep 1") || d1.hash() == d2.hash() || d1.hash() == c1.hash() {
        return false;
    }
    if GRID.iter().any(|p| p.hash() == d1.hash()) {
        return false;
    }

    // A judge proposal (U3) is its own kind, its bar is its identity, and it
    // collides with nothing else in the space. Two bars a hundredth apart are
    // different points -- which is why the bar is rendered at six places like a
    // learning rate and not at two -- and neither is any adapter, core or deep
    // point. Without this, `next_judge`'s two candidates could share a marker
    // and the second would never be tried.
    let jgrid: alloc::vec::Vec<Proposal> =
        JUDGE_GRID.iter().map(|(t, f)| Proposal::judge(*t, *f)).collect();
    if !jgrid[0].render().contains("judge ") {
        return false;
    }
    // Every grid point distinct from every other. The pairs make this a real
    // claim rather than a formality: two points sharing a bar and differing
    // only in floor would collide to one marker if the floor did not render,
    // and the second would never be tried.
    for (i, a) in jgrid.iter().enumerate() {
        for b in jgrid.iter().skip(i + 1) {
            if a.hash() == b.hash() {
                return false;
            }
        }
    }
    let j_near = Proposal::judge(2.00, MIN_FIXED);
    let j_off = Proposal::judge(2.01, MIN_FIXED);
    if j_near.hash() == j_off.hash() {
        return false;
    }
    // A point at the default floor renders exactly as it did before the floor
    // was movable, so markers already written keep naming it. This is the
    // silent half and the one that would cost a re-walked grid.
    if Proposal::judge(2.00, MIN_FIXED).render().contains("floor") {
        return false;
    }
    if Proposal::judge(2.00, 2).hash() == j_near.hash() {
        return false;
    }
    for p in jgrid.iter() {
        if GRID.iter().chain([&c1, &d1]).any(|q| q.hash() == p.hash()) {
            return false;
        }
    }

    // --- the drawn space -------------------------------------------------
    //
    // The claims that matter here are the two the grid could not make,
    // because a list is trivially re-derivable and trivially finite. A draw
    // is neither by construction, so both have to be asserted.

    let s1 = sha256::hash(b"seed one");
    let s2 = sha256::hash(b"seed two");

    // Re-derivable. The same record draws the same proposal, which is what
    // lets a later run check a verdict instead of taking it on trust.
    if draw(&s1, 7).hash() != draw(&s1, 7).hash() {
        return false;
    }

    // A function *of the record*, not of nothing. If the seed did not reach
    // the draw, every machine would search the same eight points in the same
    // order after the grid ran out, which is the exhaustion this replaced
    // wearing a longer table.
    if draw(&s1, 0).hash() == draw(&s2, 0).hash() {
        return false;
    }

    // Successive draws differ. This is `space_selftest`'s original claim --
    // that two nights are not the same weights twice -- carried into the part
    // of the space nobody wrote down, where it stops being obvious.
    for i in 0..32u32 {
        let a = draw(&s1, i);
        for j in (i + 1)..32u32 {
            if a.hash() == draw(&s1, j).hash() {
                return false;
            }
        }
    }

    // Every draw is a point the trainer and J4 can actually take. A drawn
    // rank of 200 would be caught by J4 the honest way -- after a night spent
    // training it -- so it is caught here instead, and the rate is checked
    // finite because it is built by repeated multiplication and a NaN would
    // propagate all the way into the weights without anything faulting.
    for i in 0..256u32 {
        let d = draw(&s1, i);
        if d.rank < 4 || d.rank > DRAW_MAX_RANK || d.epochs < 8 {
            return false;
        }
        if !(d.lr > 0.0) || !(d.lr < 1.0) || d.lr != d.lr {
            return false;
        }
        if !(d.alpha > 0.0) || d.alpha != d.alpha {
            return false;
        }
        // A draw addresses its marker the way an adapter point does. Rendering
        // a `kind` line here would re-address the whole tried directory, which
        // is the trap the core arm above is written around.
        if d.render().contains("core ") || d.render().contains("deep 1") {
            return false;
        }
    }

    // A config point is its own kind, and its rule is its identity.
    //
    // The rule is already a rendered field, so what the kind line has to do is
    // stop a config point colliding with an adapter point that happens to run
    // under the same rule -- they are different experiments and a shared
    // marker would let the loop believe it had judged one when it judged the
    // other.
    let g1 = Proposal::config(1);
    let g3 = Proposal::config(3);
    if g1.hash() == g3.hash() || !g1.render().contains("config 1") {
        return false;
    }
    if GRID.iter().any(|p| p.hash() == g1.hash() || p.hash() == g3.hash()) {
        return false;
    }
    // The byte in a node is `Rule as u8`, so the mapping back has to be the
    // declaration order and nothing else. A node from a future kernel naming a
    // fifth rule is refused rather than silently routed as `ProbeOnly`.
    use super::harness::Rule;
    if Rule::from_u8(Rule::Majority as u8) != Some(Rule::Majority)
        || Rule::from_u8(Rule::WithCore as u8) != Some(Rule::WithCore)
        || Rule::from_u8(200).is_some()
    {
        return false;
    }

    // The rotation covers every axis and repeats nothing within a lap.
    //
    // What this guards is a rotation that looks like it walks five kinds and
    // walks one: an offset computed the wrong way round, or a `KINDS` that
    // stopped matching the arms, would leave the loop doing exactly what it
    // did before -- adapter points until they run out and then nothing -- and
    // the only symptom would be a ledger that never mentions the other four.
    let mut seen_kinds = [false; KINDS];
    for len in 0..KINDS {
        seen_kinds[len % KINDS] = true;
    }
    if !seen_kinds.iter().all(|s| *s) {
        return false;
    }
    // Deep points are a declared grid like the adapter one, so two of them
    // must be different experiments.
    if DEEP_GRID.len() < 2 {
        return false;
    }
    let d0 = Proposal::deep(DEEP_GRID[0].0, DEEP_GRID[0].1, DEEP_GRID[0].2, DEEP_GRID[0].3);
    let d1 = Proposal::deep(DEEP_GRID[1].0, DEEP_GRID[1].1, DEEP_GRID[1].2, DEEP_GRID[1].3);
    if d0.hash() == d1.hash() {
        return false;
    }

    // Learning rates an order of magnitude apart at the small end stay apart.
    // `push_f2` renders both 3e-4 and 2e-4 as "0.00"; a proposal is identified
    // by its rendering alone, so that would silently merge two points.
    let a = Proposal { lr: 0.0003, ..base };
    let b = Proposal { lr: 0.0002, ..base };
    if a.hash() == b.hash() {
        return false;
    }

    // The budget carries the point through unchanged. `trial` reads the
    // budget, not the proposal, so a field that fails to cross here is a knob
    // that silently keeps its default -- which is exactly what every trial was
    // doing before.
    let bud = base.budget(24, 20_000);
    bud.lr == base.lr
        && bud.rank == base.rank
        && bud.alpha == base.alpha
        && bud.epochs == base.epochs
        && bud.examples == 24
        && bud.millis == 20_000
}

/// The next point nobody has tried, or `None` when the space is exhausted.
///
/// Exhaustion is a real answer and is reported rather than papered over by
/// wrapping. A loop that silently restarts its grid spends every night
/// re-deriving adapters it already has, which is the failure this replaces.
/// How many draws past the declared prefix `frontier` will look at before
/// answering `None`.
///
/// Not a bound on the space, a bound on one night's patience. Every draw is
/// cheap -- one SHA-256 and a namespace read -- but a loop with no ceiling is
/// a loop that hangs when something upstream is wrong, and this one runs at
/// 3am with nobody to stop it.
const DRAW_TRIES: u32 = 64;

/// How many draws one night will look at, for anything that reports it.
pub fn draw_tries() -> u32 {
    DRAW_TRIES
}

/// The largest rank a drawn proposal may carry.
///
/// J4 refuses on resident bytes and would catch a rank of 200 the honest way:
/// by rejecting the trial that produced it, after a night had been spent
/// training it. Bounding the draw costs nothing and leaves J4 judging variants
/// rather than typos.
const DRAW_MAX_RANK: usize = 32;

/// The next proposal, drawn from a space that was never written down.
///
/// **This is the fork's first departure, and the reason for its name.**
///
/// The parent walks `GRID`: eight declared points, in order, skipping what has
/// been tried. That is deliberate and its stated reason is good -- the next
/// point is a function of the markers rather than of a coin, so any verdict can
/// be re-derived later for almost nothing. The cost is equally plain and is
/// recorded in the parent's own notes: the eighth night exhausts the space, and
/// "search space exhausted" is the end of self-improvement, every night
/// forever.
///
/// The obvious repair is a random draw, and it is the wrong one. Randomness
/// buys an inexhaustible space by giving up the property the whole certificate
/// argument rests on: a verdict nobody can re-derive is a verdict nobody can
/// check, and this module replaced proof with re-derivation on purpose.
///
/// So the draw is a *pure function of the record*. Seed it with the hash of the
/// ledger and the space stops being enumerated while staying re-derivable: to
/// re-derive night twelve's proposal, hash the ledger as it stood after night
/// eleven. **That is only possible because the ledger is append-only**, which
/// is the invariant `sysbox::guard` enforces -- so the two halves of this fork
/// hold each other up rather than merely coexisting. A machine that could
/// rewrite its history could not re-derive its own search either.
///
/// The space is large rather than infinite, and saying which is the honest
/// form: 64 rates by 8 ranks by 7 alphas by 56 epoch counts is about 200,000
/// points, which at one a night is longer than the hardware will last. What
/// matters is not that it cannot be exhausted in principle but that it is not
/// *listed*, so nothing has to be added to a table for the loop to keep going.
///
/// Pure, and taking its seed rather than reading it, so `space_selftest` can
/// make every claim here before `sysbox::init` has run.
pub fn draw(seed: &[u8; 32], n: u32) -> Proposal {
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&n.to_le_bytes());
    let h = sha256::hash(&buf);

    // Geometric in the rate, because a learning rate is a scale and a uniform
    // draw over [0.004, 0.085] would spend nine tenths of its nights above
    // 0.01 -- where the parent's own grid put only two of eight points.
    let mut lr = 0.004f32;
    for _ in 0..(h[0] % 64) {
        lr *= 1.05;
    }

    let rank = 4 + (h[1] as usize % 8) * 4;
    // Alpha is drawn as a multiple of rank rather than independently. The two
    // are not free of each other -- alpha/rank is the scaling the adapter
    // actually applies -- so an independent draw would spend most of the space
    // on combinations that differ in nothing that reaches the weights.
    let alpha = rank as f32 * (1.0 + (h[2] as f32 % 7.0) * 0.5);
    let epochs = 8 + (h[3] as usize % 56);

    Proposal { lr, rank, alpha, epochs, rule: 0, kind: ProposalKind::Adapter }
}

/// The seed: what the machine has already written down.
///
/// The ledger and not the clock, not a counter, and not the entropy ring. All
/// three would give an inexhaustible search and none is re-derivable, which is
/// the trade this module exists to refuse.
fn record_seed() -> [u8; 32] {
    match sysbox::read_blob(LEDGER) {
        Some(b) => sha256::hash(&b),
        // Nothing recorded yet. A fixed seed rather than an arbitrary one, so
        // a fresh machine's first draw is the same on every fresh machine.
        None => sha256::hash(b"autark/draw/genesis"),
    }
}

/// The declared prefix first, then draws, and the loop no longer ends.
///
/// `GRID` is kept as a *prefix* rather than deleted, which is worth a sentence
/// because deleting it was the first instinct. Its first row is the parent's
/// configuration, so the first eight nights of an AUTARK machine reproduce the
/// parent's search exactly and are comparable against it point for point. Only
/// after that does the fork's own behaviour begin. A fork that threw the grid
/// away would have no night on which the two systems can be compared at all.
pub fn frontier() -> Option<Proposal> {
    if let Some(p) = GRID.iter().copied().find(|p| !p.tried()) {
        return Some(p);
    }
    // The comparable prefix is spent; now the archive steers. `next_map` aims at
    // the sparsest capacity column -- the MAP-Elites bias toward empty cells --
    // so the search illuminates the behaviour grid rather than walking a list or
    // drawing at random. It is still a function of the record (the archive is a
    // function of the ledger), so re-derivability holds; the random draw stays
    // as the final fallback for when the map is already spread evenly.
    if let Some(p) = next_map() {
        return Some(p);
    }
    let seed = record_seed();
    (0..DRAW_TRIES).map(|n| draw(&seed, n)).find(|p| !p.tried())
}

/// Have the machine write a council core, and store it by content address.
///
/// **Claims the engine only briefly, and never while composing.** The class
/// list is read under one short claim and released; every decode inside
/// `voter::author` then takes its own. That is not an optimisation -- calling
/// this from inside `with_engine` would hand the same task a second `&mut
/// Engine`, which is undefined behaviour in this kernel and was a live defect
/// in `trial_core` until recently.
pub fn write_core() -> Option<[u8; 32]> {
    // One claim, and everything the decodes will need comes out of it.
    //
    // Mining needs the tokenizer, so it needs the engine -- but the decodes
    // that follow each claim it themselves, so the mining has to finish and
    // let go first. Owned data comes back; nothing borrowed escapes.
    let (names, table) = super::with_engine(|e| {
        let names: Vec<String> =
            (0..e.head.len()).map(|i| String::from(e.head.name(i))).collect();
        let table = super::harness::contested_cues(e, &names);
        (names, table)
    })?;
    let src = super::voter::author(&names, &table)?;
    Some(super::voter::store(&src))
}

/// A proposal for a core the machine has just written, if it is new.
///
/// `None` when nothing could be composed, or when this exact program has
/// already been judged. The second case is the marker doing its job: the
/// composition is a function of the corpus and the model's choices, so a
/// machine that keeps making the same choices keeps writing the same program,
/// and judging it nightly would fill the ledger with one result reported
/// forever.
pub fn author_core() -> Option<Proposal> {
    // Do not spend a night writing something that cannot win.
    //
    // The census says how many validation items a core could repair even if it
    // got every one of them right; J1 says how many it must. When the first is
    // below the second, no program of any construction clears the judge on
    // this slice, and composing one is a night spent producing a rejection
    // that was arithmetic before it was a measurement. The number is whatever
    // the last bench measured, so the first night still tries.
    if let Some((prize, need)) = core_room() {
        if prize < need {
            return None;
        }
    }
    let p = Proposal::core(write_core()?);
    if p.tried() {
        return None;
    }
    Some(p)
}

/// Throw away every marker, so the grid is walked from the start again.
///
/// Not an undo: the nodes and the ledger stay, so a re-walk rediscovers
/// variants it already has and their hashes prove it. That is the honest
/// behaviour -- content addressing means a rediscovered point costs a trial
/// and no storage, and the ledger showing the same variant twice is a true
/// statement about what happened.
pub fn forget() -> usize {
    let names = sysbox::children(TRIED);
    let n = names.len();
    for name in names {
        let mut path = String::from(TRIED);
        path.push('/');
        path.push_str(&name);
        sysbox::detach(&path);
    }
    n
}

/// How much of the space has been visited.
pub fn explored() -> (usize, usize) {
    (GRID.iter().filter(|p| p.tried()).count(), GRID.len())
}

/// The quiet window, as hours the RTC will report.
///
/// **These are RTC hours and not necessarily local ones.** The clock this
/// reads is whatever the firmware set: QEMU defaults to UTC, and a machine
/// that dual-boots Windows normally has it on local time. The same constant
/// therefore means different things on the two machines the project runs on,
/// which is a poor property for the one gate whose whole job is knowing that
/// the operator has gone to bed. The first trial recorded in the ledger went
/// in at `h19` for a run at 21:43 local, which is how this was noticed.
///
/// So `godel window <from> <until>` sets it at runtime against the hour the
/// status line prints, and the override lives in the namespace where `snap`
/// versions it. Guessing an offset here would only move the assumption
/// somewhere harder to see.
const QUIET_FROM_DEFAULT: u8 = 2;
const QUIET_UNTIL_DEFAULT: u8 = 6;

/// The window in force: the override if one is set, the defaults otherwise.
pub fn window() -> (u8, u8) {
    if let Some(bytes) = sysbox::read_blob(WINDOW) {
        if let Ok(text) = core::str::from_utf8(&bytes) {
            let mut it = text.split_whitespace().filter_map(|w| w.parse::<u8>().ok());
            if let (Some(f), Some(u)) = (it.next(), it.next()) {
                if f < 24 && u < 24 {
                    return (f, u);
                }
            }
        }
    }
    (QUIET_FROM_DEFAULT, QUIET_UNTIL_DEFAULT)
}

/// Set the window against the hour the RTC actually reports.
pub fn set_window(from: u8, until: u8) -> bool {
    if from > 23 || until > 23 {
        return false;
    }
    let mut s = String::new();
    push_u32(&mut s, from as u32);
    s.push(' ');
    push_u32(&mut s, until as u32);
    s.push('\n');
    sysbox::write_text(WINDOW, &s)
}

/// The hour the RTC reports right now, for anything that has to show the
/// operator what the window is being compared against.
pub fn rtc_hour() -> Option<u8> {
    crate::dev::rtc::now().map(|d| d.hour)
}

/// How many times the test slice may be consulted before its number stops
/// being reportable. Small on purpose: it is the whole point.
const TEST_READS: u32 = 3;

/// Minimum net repairs before a variant may be adopted, before the paired
/// statistic is even consulted. Guards the case the statistic handles badly:
/// three decisions, two repaired, none broken, which is arithmetically
/// impressive and means nothing.
pub const MIN_FIXED: usize = 4;

static ENABLED: AtomicBool = AtomicBool::new(true);
static TRIALS: AtomicU32 = AtomicU32::new(0);
static ADOPTIONS: AtomicU32 = AtomicU32::new(0);

/// A node in the variant DAG.
///
/// Content-addressed by the hash of its own rendering, which names the parent
/// by hash -- so a lineage is a Merkle chain and no ancestor can be edited
/// without every descendant changing its name. Two variants arrived at by
/// different routes with identical content *are* the same node, which is the
/// content-addressed store doing the deduplication for free.
///
/// Stored as text rather than packed bytes. The namespace is browsable and
/// `cat` is the debugger; a self-modification history nobody can read is a
/// self-modification history nobody audits.
#[derive(Clone)]
pub struct Variant {
    pub parent: Option<[u8; 32]>,
    /// Content address of the adapter blob, or none for the frozen baseline.
    pub adapter: Option<[u8; 32]>,
    /// Content address of the agent policy text in force.
    pub policy: Option<[u8; 32]>,
    /// Content address of the skill directory.
    pub skills: Option<[u8; 32]>,
    /// Content address of the corpus this was trained on.
    ///
    /// A training set is a subtree, so one hash names every example in it and
    /// the order they sit in. Without it, a variant fitted to a corpus that
    /// was later replaced is indistinguishable from one fitted to whatever is
    /// there now, and the lineage then describes the wrong experiment.
    pub corpus: Option<[u8; 32]>,
    pub lambda: f32,
    pub rank: u8,
    /// Optimiser passes actually taken.
    ///
    /// In the identity because it determines the weights. Two runs of the
    /// same trainer over the same corpus that stopped at different epochs
    /// produced different adapters and are different objects. The first two
    /// trials in the ledger differed for exactly this reason, and nothing
    /// recorded it: the budget carries a wall-clock cap as well as an epoch
    /// count, and a slower host reached the cap sooner.
    pub epochs: u32,
    pub rule: u8,
    /// Content address of the council core in force, if one is installed.
    ///
    /// The axis that makes this a general loop rather than an adapter search.
    /// A core is an Aiksi program the machine can write, `core_bench` already
    /// judges it, and `voter::install` already adopts it by hash -- what was
    /// missing was any record that it happened, so a core could pass three
    /// judges and leave no trace in the lineage, no ledger line, and nothing
    /// for `rollback` to undo.
    pub core: Option<[u8; 32]>,
    /// Whether this node actually *says* anything about a core.
    ///
    /// Not part of the identity -- it is a fact about the text, not about the
    /// mind -- and so deliberately absent from `render` as a value. What it
    /// controls is whether the `core` line is written at all.
    ///
    /// The distinction is load-bearing and its absence was a real defect.
    /// `rollback` read `parent.core == None` as "the parent had no core" and
    /// uninstalled. But every node written before this field existed also
    /// parses as `None`, so rolling back an *adapter* on any older lineage
    /// silently pulled a machine-written core out of the decision path, with
    /// nothing printed. "Absent" and "none" are different claims and a format
    /// that cannot tell them apart forces the reader to guess.
    ///
    /// Nodes this kernel writes always set it, so they always state the
    /// answer; nodes it reads keep whatever the text said, so an old node
    /// still renders to the exact bytes it was stored as.
    pub core_seen: bool,
    /// Whether the attention path moved, not only the classifier.
    ///
    /// `deeptrain` adapts every q/k/v site as well as the decision layer, and
    /// the two are different objects with different economics -- a
    /// classifier-only adapter leaves every hidden state a constant, which is
    /// what makes cached features and cheap re-judging possible, and a deep
    /// one gives that up. A node that does not say which it is describes the
    /// wrong experiment.
    pub deep: bool,
    /// The J1 significance bar this variant was measured under.
    ///
    /// The axis U3 adds, and the one that changes what "better" means rather
    /// than what the machine is. In the identity for the same reason `corpus`
    /// is: a variant admitted under a loosened bar is not the same claim as one
    /// admitted under the strict default, and a lineage that could not tell
    /// them apart would let a criterion change hide inside an ordinary
    /// adoption. Rendered only when it is not the default `MCNEMAR_95`, so every
    /// node written before U3 -- the whole existing DAG -- re-renders to the
    /// exact bytes it was stored under and its address does not move. The same
    /// bargain `deep` and `core` make, and the reason all three are conditional.
    pub threshold: f32,
    /// The effect-size floor this variant was measured under.
    ///
    /// Renders only when it is not `MIN_FIXED`, for the reason `deep` and
    /// `core` render conditionally: a field added unconditionally to a hashed
    /// structure re-addresses every node that already exists, so `head` would
    /// name something that no longer reproduces and the ledger would stop
    /// being checkable. A node written before the floor was movable has no
    /// `floor` line and reads back as the constant it was actually measured
    /// under.
    pub floor: usize,
    pub born: u32,
}

fn hex32(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in h.iter() {
        push_hex_byte(&mut s, *b);
    }
    s
}

fn push_hex_byte(s: &mut String, b: u8) {
    const D: &[u8; 16] = b"0123456789abcdef";
    s.push(D[(b >> 4) as usize] as char);
    s.push(D[(b & 15) as usize] as char);
}

fn from_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        *o = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut d = [0u8; 10];
    let mut n = 0;
    while v > 0 {
        d[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        s.push(d[n] as char);
    }
}

/// Fixed-point with two decimals, since there is no float formatting here and
/// a ledger of `1.0e0` would be unreadable.
fn push_f2(s: &mut String, v: f32) {
    if v < 0.0 {
        s.push('-');
        push_f2(s, -v);
        return;
    }
    let scaled = (v * 100.0 + 0.5) as u32;
    push_u32(s, scaled / 100);
    s.push('.');
    let frac = scaled % 100;
    s.push((b'0' + (frac / 10) as u8) as char);
    s.push((b'0' + (frac % 10) as u8) as char);
}

/// Six decimal places, for values where two are not enough to tell two things
/// apart.
///
/// `push_f2` renders a learning rate of 3e-4 and one of 2e-4 both as "0.00".
/// For `Variant` that is cosmetic -- the adapter's own hash is in the identity,
/// so two runs at different rates are still different nodes -- but for a
/// `Proposal` it would be fatal: proposals are identified by their rendering
/// alone, so two distinct points in the space would collide, the frontier
/// would skip one, and the ledger would report a rate that was never used.
///
/// `Variant::render` deliberately keeps `push_f2`. Changing it would re-address
/// every node already stored and leave `head` and the ledger pointing at
/// hashes nothing can produce again.
fn push_f6(s: &mut String, v: f32) {
    if v < 0.0 {
        s.push('-');
        push_f6(s, -v);
        return;
    }
    // Via f64 because 1e6 * an f32 loses the low digits to the mantissa, which
    // is the collision this exists to prevent, arriving one decimal later.
    let scaled = ((v as f64) * 1_000_000.0 + 0.5) as u64;
    push_u32(s, (scaled / 1_000_000) as u32);
    s.push('.');
    let mut frac = scaled % 1_000_000;
    let mut digits = [b'0'; 6];
    for d in digits.iter_mut().rev() {
        *d = b'0' + (frac % 10) as u8;
        frac /= 10;
    }
    for d in digits {
        s.push(d as char);
    }
}

impl Variant {
    /// The canonical rendering. This is what gets hashed, so every field that
    /// changes behaviour must appear in it and nothing that does not may --
    /// a timestamp in the hash would make two identical minds different
    /// objects, and an omitted parameter would make two different minds the
    /// same one.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("variant 1\n");
        s.push_str("parent ");
        s.push_str(&self.parent.map(|h| hex32(&h)).unwrap_or(String::from("none")));
        s.push('\n');
        s.push_str("adapter ");
        s.push_str(&self.adapter.map(|h| hex32(&h)).unwrap_or(String::from("none")));
        s.push('\n');
        s.push_str("policy ");
        s.push_str(&self.policy.map(|h| hex32(&h)).unwrap_or(String::from("none")));
        s.push('\n');
        s.push_str("skills ");
        s.push_str(&self.skills.map(|h| hex32(&h)).unwrap_or(String::from("none")));
        s.push('\n');
        s.push_str("corpus ");
        s.push_str(&self.corpus.map(|h| hex32(&h)).unwrap_or(String::from("none")));
        s.push('\n');
        s.push_str("lambda ");
        push_f2(&mut s, self.lambda);
        s.push('\n');
        s.push_str("rank ");
        push_u32(&mut s, self.rank as u32);
        s.push('\n');
        s.push_str("epochs ");
        push_u32(&mut s, self.epochs);
        s.push('\n');
        s.push_str("rule ");
        push_u32(&mut s, self.rule as u32);
        s.push('\n');
        // **Emitted only when there is one.**
        //
        // Every node written before this field existed has no core, and must
        // go on rendering to exactly the bytes it was stored as -- otherwise
        // `head` names an address that no longer reproduces, the ledger stops
        // being checkable, and the re-derivability this module promises is
        // broken by the very change meant to extend it. An unconditional
        // "core none" line would have done precisely that to every node in
        // every existing lineage.
        //
        // `core none` is written too, and only by nodes that know they have
        // an answer to give. That is what lets `rollback` tell a node that
        // says "no core" from one that says nothing at all -- see
        // `core_seen`. An old node has `core_seen` clear, emits neither line,
        // and re-renders byte-for-byte to the address it is stored under.
        match (self.core, self.core_seen) {
            (Some(c), _) => {
                s.push_str("core ");
                s.push_str(&hex32(&c));
                s.push('\n');
            }
            (None, true) => s.push_str("core none\n"),
            (None, false) => {}
        }
        // Conditional for the same reason `core` is: absent from the rendering
        // when absent from the object, so every node written before this
        // existed still renders to the bytes it was stored as.
        if self.deep {
            s.push_str("deep 1\n");
        }
        // The bar, and the third field that renders only when non-default.
        //
        // Compared with a tolerance rather than for equality: the value is
        // stored and read back through `push_f2`/`parse` at two decimals, and a
        // default written as `3.84` then parsed would fail a bitwise `!=` and
        // start emitting a line every existing node lacks -- re-addressing the
        // whole DAG, which is the exact failure this conditional exists to
        // prevent. Half a hundredth is finer than the rendering can resolve, so
        // anything the default rounds to is treated as the default.
        if (self.threshold - MCNEMAR_95).abs() >= 0.005 {
            s.push_str("threshold ");
            push_f2(&mut s, self.threshold);
            s.push('\n');
        }
        if self.floor != MIN_FIXED {
            s.push_str("floor ");
            push_u32(&mut s, self.floor as u32);
            s.push('\n');
        }
        s
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256::hash(self.render().as_bytes())
    }

    /// Write the node into the DAG and return its address.
    ///
    /// `born` is written *beside* the node rather than into it, for the same
    /// reason it is absent from `render`: when the machine rediscovers a
    /// variant it already tried, that has to be visible as the same node
    /// rather than as a new one that happens to behave identically.
    pub fn store(&self) -> [u8; 32] {
        let h = self.hash();
        let mut path = String::from(ROOT);
        path.push_str("/nodes/");
        path.push_str(&hex32(&h));
        if sysbox::read_blob(&path).is_none() {
            sysbox::write_text(&path, &self.render());
            let mut bpath = path.clone();
            bpath.push_str(".born");
            let mut b = String::new();
            push_u32(&mut b, self.born);
            b.push('\n');
            sysbox::write_text(&bpath, &b);
        }
        h
    }

    pub fn load(h: &[u8; 32]) -> Option<Variant> {
        let mut path = String::from(ROOT);
        path.push_str("/nodes/");
        path.push_str(&hex32(h));
        let bytes = sysbox::read_blob(&path)?;
        let text = core::str::from_utf8(&bytes).ok()?;
        Some(Variant::from_text(text))
    }

    /// Parse a node from its canonical rendering.
    ///
    /// Separate from `load` so the round trip -- the property the whole DAG
    /// rests on -- can be checked without a store, a namespace, or a node
    /// somebody has to remember to write first.
    pub fn from_text(text: &str) -> Variant {
        let mut v = Variant {
            parent: None,
            adapter: None,
            policy: None,
            skills: None,
            corpus: None,
            lambda: 0.0,
            rank: 0,
            epochs: 0,
            rule: 0,
            core: None,
            // Clear until a `core` line is actually seen below, which is the
            // whole point: a node that does not mention a core must not be
            // read as one that mentions having none.
            core_seen: false,
            deep: false,
            // Default until a `threshold` line is seen. A node written before
            // U3 has none, and must read back as the strict default it was
            // actually measured under -- reading it as anything else would
            // rewrite history to say the machine had already moved its own bar.
            threshold: MCNEMAR_95,
            // Same argument as `threshold`: a node from before the floor was
            // movable must read back as the constant, or the lineage would
            // claim the machine had already moved a criterion it never touched.
            floor: MIN_FIXED,
            born: 0,
        };
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(key), Some(val)) = (it.next(), it.next()) else { continue };
            match key {
                "parent" => v.parent = from_hex32(val),
                "adapter" => v.adapter = from_hex32(val),
                "policy" => v.policy = from_hex32(val),
                "skills" => v.skills = from_hex32(val),
                "corpus" => v.corpus = from_hex32(val),
                // Absent for a long time, and the omission was not cosmetic.
                // A node read back got `lambda: 0.0` whatever was stored, so
                // `Variant::load(h).render()` did not reproduce the text at
                // `h` and re-hashed to a different address. Nothing re-rendered
                // a loaded node, so it never surfaced -- but re-deriving a
                // verdict from the DAG is the claim this whole module rests
                // on, and it was false for any variant with a learning rate.
                //
                // `push_f2` writes exactly two decimals, and parsing that back
                // and re-rendering it is exact, so the round trip holds.
                "lambda" => v.lambda = val.parse().unwrap_or(0.0),
                // `none` parses to `None`, and either way the node has now
                // made a statement about its core.
                "core" => {
                    v.core = from_hex32(val);
                    v.core_seen = true;
                }
                "deep" => v.deep = val == "1",
                "threshold" => v.threshold = val.parse().unwrap_or(MCNEMAR_95),
                "floor" => v.floor = val.parse().unwrap_or(MIN_FIXED),
                "rank" => v.rank = val.parse().unwrap_or(0),
                "epochs" => v.epochs = val.parse().unwrap_or(0),
                "rule" => v.rule = val.parse().unwrap_or(0),
                _ => {}
            }
        }
        v
    }
}

/// Where the adapter blob for a variant lives.
///
/// Named by the hash of its own bytes, so an adapter that two trials happen
/// to produce identically is stored once -- and so a ledger line naming an
/// adapter names a specific sequence of bytes rather than a filename somebody
/// could later overwrite.
fn blob_path(h: &[u8; 32]) -> String {
    let mut p = String::from(ROOT);
    p.push_str("/blobs/");
    p.push_str(&hex32(h));
    p
}

pub fn head() -> Option<[u8; 32]> {
    let bytes = sysbox::read_blob(HEAD)?;
    let text = core::str::from_utf8(&bytes).ok()?;
    from_hex32(text.trim())
}

fn set_head(h: &[u8; 32]) {
    let mut s = hex32(h);
    s.push('\n');
    sysbox::write_text(HEAD, &s);
}

/// What one trial concluded, in enough detail that a later run can redo it.
///
/// Every judge records its numbers whether it passed or not. A certificate
/// that only says why something was rejected is a certificate that cannot be
/// argued with, and the point of writing them down is that they can be.
pub struct Certificate {
    pub parent: Option<[u8; 32]>,
    pub variant: [u8; 32],
    pub decisions: usize,
    pub validation: usize,
    /// Whether training-set gain predicted a win, recorded before the judges
    /// ran. Nothing acts on it; the ledger accumulates calibration.
    pub predicted: bool,

    /// J1: paired repairs, breaks, and the McNemar statistic.
    pub fixed: usize,
    pub broke: usize,
    pub mcnemar: f32,
    pub j1: bool,
    /// Why J1 answered as it did. A veto on an empty validation slice is not
    /// the same event as a veto on evidence that was weighed and found thin,
    /// and reporting both as "VETO" invites the first to be read as the
    /// second.
    pub j1_why: &'static str,

    /// J2: how many of the machine's own goals still route where they did.
    pub goals_held: usize,
    pub goals_total: usize,
    pub j2: bool,

    /// J3: the structural guards, and which one failed first.
    pub j3: bool,
    pub j3_why: &'static str,

    /// J4: resident kilobytes and rank, the two things that decide whether a
    /// variant can be carried at all.
    pub resident_kib: usize,
    pub rank: usize,
    pub j4: bool,
    /// Optimiser passes taken, and whether the wall-clock cap ended them.
    ///
    /// A run the clock stopped is not reproducible from its epoch count on a
    /// machine of a different speed, so the certificate says so instead of
    /// leaving a later reader to discover it by failing to reproduce.
    pub epochs: u32,
    pub capped: bool,

    pub adopted: bool,

    /// The test slice, consulted only after a variant has already won on
    /// validation -- and only while the budget lasts. `read` is which
    /// consultation this was, and `fresh` says whether the figure may still
    /// be quoted as a number rather than as a stale one.
    pub test_acc: f32,
    pub test_read: u32,
    pub test_fresh: bool,

    /// Present only for a judge-trial (U3), and it changes how this certificate
    /// renders: the four J-slots above are a poor fit for a change to the
    /// *criterion*, so a judge-trial fills this instead and the renderers print
    /// the cross-evaluation matrix from it. `None` for every weights, rule,
    /// core, skill and deep trial, which is all of them before U3 -- so the
    /// existing ledger and dispatch are untouched.
    pub cross: Option<CrossLine>,
}

/// The cross-evaluation matrix, flattened onto one certificate.
///
/// It records what the 2x2 needs: the two bars, whether each admits the
/// reference candidate, and the held-out anchor for the incumbent and that
/// candidate. The incumbent row of the matrix is not stored because every bar
/// admits what is already in force by definition -- only the candidate row
/// varies, which is the whole of the disagreement a judge-change turns on.
#[derive(Clone, Copy)]
pub struct CrossLine {
    pub tau_old: f32,
    pub tau_new: f32,
    /// The effect-size floors either side of the change. Recorded beside the
    /// bars because a certificate that named only the bar could not say which
    /// half of the criterion moved, and after the floor became movable that is
    /// the first question a later reader asks of the line.
    pub floor_old: usize,
    pub floor_new: usize,
    pub admit_old: bool,
    pub admit_new: bool,
    /// Ground-truth routing accuracy on the held-out test slice -- the anchor
    /// no bar can see, and the only thing that tells a real gain from a bar
    /// tuned to accept noise.
    pub anchor_inc: f32,
    pub anchor_cand: f32,
}

impl Certificate {
    pub fn unanimous(&self) -> bool {
        self.j1 && self.j2 && self.j3 && self.j4
    }
}

/// McNemar's statistic with the continuity correction, over the paired
/// counts. Larger is stronger evidence that the difference is not chance.
///
/// Only the discordant pairs carry information -- decisions both variants get
/// right, or both get wrong, say nothing about which is better -- which is
/// exactly why the paired form is worth having and why a difference of
/// percentages is not.
/// The paired statistic, shared with the core judge.
///
/// Public so a second judge cannot grow a second definition of "beyond the
/// noise". Two thresholds that drift apart would let a change be significant
/// to one loop and not to the other, with nothing saying so.
pub fn mcnemar(broke: usize, fixed: usize) -> f32 {
    let n = broke + fixed;
    if n == 0 {
        return 0.0;
    }
    let d = if broke > fixed { broke - fixed } else { fixed - broke } as f32;
    // The -1 is Yates' correction; without it small counts overstate the
    // evidence, and small counts are the regime this machine lives in.
    let num = (d - 1.0).max(0.0);
    num * num / n as f32
}

/// The smallest number of clean repairs -- repairs with nothing broken --
/// that actually clears J1.
///
/// Derived rather than written down, because it is not `MIN_FIXED`. Yates'
/// correction subtracts one from the difference before squaring, so four clean
/// fixes score 2.25 and are refused by the very judge whose floor is four; the
/// real bar on this configuration is six. Two constants that look like the
/// answer and are not is exactly the arrangement in which somebody eventually
/// quotes the wrong one, so the answer is computed from both.
pub fn clean_fixes_needed() -> usize {
    // Both halves of the criterion in force, not the two constants. It read
    // the constants, which was correct while neither could move and became a
    // statement about a criterion the machine was not running the moment one
    // could. Starting from the floor is the point: the answer is where the
    // floor and the statistic first agree.
    let (tau, floor) = (judge_in_force(), floor_in_force());
    let mut f = floor;
    while f < 1024 {
        if mcnemar(0, f) >= tau {
            return f;
        }
        f += 1;
    }
    f
}

/// What a core could win here, and what it would have to win, when both are
/// known. `None` until something has been benched this boot.
pub fn core_room() -> Option<(usize, usize)> {
    super::harness::last_prize().map(|p| (p, clean_fixes_needed()))
}

/// Roughly the 95% threshold for one degree of freedom. Named rather than
/// spelled inline because it is a *decision*, not a constant: 3.84 is the
/// conventional line and the ledger records the statistic itself, so a later
/// reader can apply a different one to the same numbers.
///
/// It is also the **default** the loop starts from, not a fixed law. U3 lets
/// the loop propose a different bar, so `judge_in_force` is what the adapter
/// path actually reads; this constant is only where a machine that has never
/// moved the bar sits, and the value a rollback past the first judge-change
/// returns to.
pub const MCNEMAR_95: f32 = 3.84;

/// The J1 significance bar actually in force.
///
/// Reads `/ai/godel/judge`, defaulting to `MCNEMAR_95`. This is the seam that
/// makes the criterion a variable rather than a law: the adapter path calls
/// this instead of the constant, so a judged change to the bar takes effect on
/// the next trial and a rollback restores the previous one. A machine that has
/// never run a judge-trial reads exactly `MCNEMAR_95` and behaves as it always
/// did -- the same "never searched routes as it did" property `rule_in_force`
/// has.
pub fn judge_in_force() -> f32 {
    sysbox::read_blob(JUDGE)
        .and_then(|b| core::str::from_utf8(&b).ok().and_then(|t| t.trim().parse().ok()))
        .filter(|v: &f32| v.is_finite() && *v > 0.0)
        .unwrap_or(MCNEMAR_95)
}

/// Put a new bar in force. Written with two decimals, the same precision the
/// variant records it under, so what is stored and what a node renders agree.
fn save_judge(tau: f32) -> bool {
    if !tau.is_finite() || tau <= 0.0 {
        return false;
    }
    let mut s = String::new();
    push_f2(&mut s, tau);
    s.push('\n');
    sysbox::write_text(JUDGE, &s)
}

/// The in-force J1 effect-size floor, the other half of the criterion.
///
/// Defaults to `MIN_FIXED` on a machine that has never moved it, so the
/// constant is still where an untouched loop sits and still what a rollback
/// past the first floor-change returns to. Same shape as `judge_in_force`,
/// deliberately: two halves of one criterion that read differently would be
/// the beginning of them disagreeing.
pub fn floor_in_force() -> usize {
    sysbox::read_blob(FLOOR)
        .and_then(|b| core::str::from_utf8(&b).ok().and_then(|t| t.trim().parse().ok()))
        .filter(|v: &usize| *v >= FLOOR_MIN && *v <= FLOOR_MAX)
        .unwrap_or(MIN_FIXED)
}

fn save_floor(n: usize) -> bool {
    if !(FLOOR_MIN..=FLOOR_MAX).contains(&n) {
        return false;
    }
    let mut s = String::new();
    push_u32(&mut s, n as u32);
    s.push('\n');
    sysbox::write_text(FLOOR, &s)
}

/// J1, at a stated criterion.
///
/// One implementation, because there were three and they had already drifted:
/// `godel::trial` read `judge_in_force()` while `harness::core_bench` and
/// `work`'s role judge read `MCNEMAR_95`, so after any adopted bar-change an
/// adapter and a core were held to different criteria while both printed
/// "J1". That is the failure `model.rs` makes the objection about twice, and
/// the fix is one function rather than three that agree by hand.
///
/// Parameterised because `cross_matrix` is the one caller that must evaluate a
/// criterion the loop is *not* running.
pub fn j1_admits_at(tau: f32, floor: usize, fixed: usize, broke: usize, chi: f32) -> bool {
    fixed > broke && fixed - broke >= floor && chi >= tau
}

/// J1 under the criterion actually in force, with the reason it refused.
///
/// The reasons are ordered by what a reader needs to know first: no evidence,
/// then no effect, then too small an effect, then too weak a signal. A caller
/// that only wants the bool takes `.0`.
pub fn j1_verdict(
    n_val: usize,
    fixed: usize,
    broke: usize,
    chi: f32,
) -> (bool, &'static str) {
    if n_val == 0 {
        // A property of how the trial was asked for rather than of the
        // variant: a subsample too small to reach the validation slice leaves
        // the margin with no evidence at all, in either direction.
        return (false, "no validation decisions");
    }
    if fixed <= broke {
        return (false, "no net repair");
    }
    if fixed - broke < floor_in_force() {
        return (false, "net repair below the floor");
    }
    if chi < judge_in_force() {
        return (false, "inside the noise");
    }
    (true, "beyond the noise")
}

/// The widest and narrowest a proposed bar may be.
///
/// A bar of zero admits everything, which is the criterion abolishing itself;
/// a bar above this is stricter than any evidence a night can produce and so
/// silently freezes the loop. Both are refused by J-sanity rather than adopted
/// and discovered later as a machine that never changes or never stops.
pub const JUDGE_MIN: f32 = 0.5;
pub const JUDGE_MAX: f32 = 12.0;

/// The widest and narrowest a proposed effect-size floor may be.
///
/// One, not zero, is the bottom. J1 already requires `fixed > broke`, so a
/// floor of zero and a floor of one admit exactly the same candidates, and
/// offering both would put a point in the grid that can never differ from its
/// neighbour -- the "improved nothing" refusal arriving as a wasted night
/// rather than as a verdict.
///
/// The ceiling is a claim about the corpus rather than a round number. The
/// validation slice runs to a few dozen decisions on a full pass and to
/// twenty-four on the subsample this was measured at, so a floor above
/// sixteen is one no night could clear and would freeze the loop exactly the
/// way `JUDGE_MAX` exists to prevent.
pub const FLOOR_MIN: usize = 1;
pub const FLOOR_MAX: usize = 16;

/// The smallest held-out gain that counts as the anchor supporting a change.
///
/// The anchor is routing accuracy on the test slice against ground-truth
/// labels, so it moves in quanta of one decision over the slice size -- coarse,
/// because the slice is small by construction, and the figure is a floor rather
/// than a tuned constant. A looser bar is admitted only if the variant it newly
/// admits clears this on the anchor; that is the whole of what keeps a criterion
/// change honest, and it is deliberately measured on the one set no judge sees.
pub const MIN_ANCHOR_GAIN: f32 = 0.01;

/// Is the wall clock inside the window where self-modification is allowed?
///
/// Wraps midnight, which is the only interesting case: 02:00-06:00 does not,
/// but 22:00-04:00 would, and writing the comparison as `from <= h < until`
/// would silently permit nothing for every window that crosses the day.
fn in_window(hour: u8) -> bool {
    let (from, until) = window();
    if from <= until {
        hour >= from && hour < until
    } else {
        hour >= from || hour < until
    }
}

/// Both facts, independently. Returns why not, for the journal.
///
/// The RTC says the operator has gone to bed. The entropy ring says no key or
/// pointer interrupt has fired since the last check. Either alone is wrong in
/// a way that matters: a clock does not know somebody is working late, and
/// silence at noon is a coffee break, not consent. `win keys` bypasses the
/// hardware ISRs, so a scripted test looks like silence -- which is correct,
/// the entropy really is hardware timing, and it is why the clock half is not
/// optional.
pub fn quiet_now() -> Result<u8, &'static str> {
    if !ENABLED.load(Ordering::Relaxed) {
        return Err("disabled");
    }
    quiet_hours()
}

/// Whether this is a good hour to do something expensive, with no opinion
/// about what.
///
/// Split out from `quiet_now` when a second unattended job appeared. Gating
/// that job on `quiet_now` would have meant `godel off` silently stopping it
/// too -- a command named after self-modification standing down an
/// application writer, which is exactly the kind of coupling somebody
/// discovers by wondering why nothing happened overnight. Each job now checks
/// its own switch and shares only the question of whether anybody is here.
pub fn quiet_hours() -> Result<u8, &'static str> {
    let Some(dt) = crate::dev::rtc::now() else {
        // No clock, no window, no self-modification. A machine that cannot
        // tell what time it is has no business deciding the operator is
        // asleep.
        return Err("no rtc");
    };
    if !in_window(dt.hour) {
        return Err("outside the quiet window");
    }
    let felt = super::godbits::felt() as u64;
    let last = unsafe { *LAST_FELT.get() };
    unsafe { *LAST_FELT.get() = felt };
    if felt != last {
        return Err("hardware input since the last check");
    }
    // And not on battery. The unattended jobs are the most expensive thing
    // this machine does -- two passes over the corpus for a deep trial, a
    // dozen decodes to compose a core -- and a laptop that spends the night
    // improving itself into a flat battery has not improved itself. A skipped
    // night costs one rotation slot; a flat battery costs the morning.
    //
    // Only a *known* battery refuses. A desktop reports no adapter and gets
    // the same answer it always did, because "unknown" must not become "no".
    if let Some(c) = crate::dev::battery::status() {
        if c.on_ac == Some(false) {
            return Err("on battery");
        }
    }
    Ok(dt.hour)
}

static LAST_FELT: crate::sync::Racy<u64> = crate::sync::Racy::new(0);

/// How many times the test slice has been read, and how many reads remain.
fn test_reads() -> u32 {
    sysbox::read_blob(BUDGET)
        .and_then(|b| core::str::from_utf8(&b).ok().and_then(|t| t.trim().parse().ok()))
        .unwrap_or(0)
}

/// Spend one read of the held-out test slice and answer the new count.
///
/// Public because `search` reads it too and used not to count. One counter for
/// every path that touches the slice, or the budget is decorative.
pub fn spend_test_read() -> u32 {
    let n = test_reads() + 1;
    let mut s = String::new();
    push_u32(&mut s, n);
    s.push('\n');
    sysbox::write_text(BUDGET, &s);
    n
}

/// Append one line to the ledger.
///
/// Append-only text, in the namespace, so `snap` versions it and `back`
/// restores it along with everything else. A self-modification history that
/// lived outside the content-addressed store would be the one part of this
/// machine that could be edited without leaving a trace.
fn ledger_append(line: &str) {
    let mut text = sysbox::read_blob(LEDGER)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    text.push_str(line);
    text.push('\n');
    sysbox::write_text(LEDGER, &text);
}

/// Write the trial down twice, from one certificate, in one call.
///
/// The ledger line is the archive's own form: dense, positional, meant to be
/// diffed and re-derived by a later run. The dispatch is the same facts in the
/// voice the machine addresses an operator in.
///
/// **They are rendered here, together, from one `Certificate`.** The obvious
/// alternative -- keep only the ledger and render a dispatch later by parsing
/// it back -- is how the two come to disagree, and a machine whose
/// announcement disagrees with its own record is the precise failure the
/// persona is written to avoid. The same argument rules out having the model
/// paraphrase a trial into prose: a paraphrase is a claim, and a claim can be
/// wrong about a number that has exactly one right answer.
///
/// So the doctrine is allowed to shape the *rendering* and never the figures,
/// and both files are append-only under `sysbox::guard` for the same reason.
/// Note what that does and does not buy, because the gap is real: the record
/// cannot be falsified, and a notification can still be skipped by raising
/// `REPORTED`. Suppressing an announcement is survivable -- the sitting is
/// still in both files and `godel report --all` still prints it. Editing one
/// would not be.
fn record(c: &Certificate, seq: u32, hour: u8) {
    ledger_append(&render_certificate(c, seq, hour));
    let mut d = sysbox::read_blob(DISPATCH)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    d.push_str(&render_dispatch(c, seq, hour));
    sysbox::write_text(DISPATCH, &d);
}

/// One judge's row. `CONCUR` and `DISSENT` rather than ok/fail because
/// unanimity is the actual rule -- four independent assessors, any one of whom
/// stops adoption -- and "3 of 4 passed" is a sentence that invites somebody to
/// wonder whether three is enough.
fn row(s: &mut String, tag: &str, held: bool, why: &str) {
    s.push_str("  ");
    s.push_str(tag);
    while s.len() % 24 != 0 {
        s.push(' ');
    }
    s.push_str(if held { "CONCUR" } else { "DISSENT" });
    if !held && !why.is_empty() {
        s.push_str("  (");
        s.push_str(why);
        s.push(')');
    }
    s.push('\n');
}

/// The cross-evaluation matrix, as the archive shows it.
///
/// Two things the reader holds at once: what the standing bar and the proposed
/// bar each make of the reference candidate, and what the anchor -- the
/// held-out ground truth neither bar can see -- says about that same candidate.
/// A criterion change is honest exactly when the bar and the anchor point the
/// same way; a bar that admits what the anchor rejects is the drift this whole
/// axis exists to catch, and the reason line says so in as many words.
fn render_cross(s: &mut String, x: &CrossLine, c: &Certificate) {
    let admit = |b: bool| if b { "ADMITS" } else { "REFUSES" };

    // The criterion is two numbers and the dispatch names both, because the
    // operator reading it has to be able to say which one the machine moved.
    let mut bars = String::from("BAR        ");
    push_f2(&mut bars, x.tau_old);
    bars.push_str(" -> ");
    push_f2(&mut bars, x.tau_new);
    bars.push_str("  candidate chi ");
    push_f2(&mut bars, c.mcnemar);
    s.push_str("  ");
    s.push_str(&bars);
    s.push('\n');

    let mut fl = String::from("FLOOR      ");
    push_u32(&mut fl, x.floor_old as u32);
    fl.push_str(" -> ");
    push_u32(&mut fl, x.floor_new as u32);
    fl.push_str("  candidate net repair ");
    // Signed, because a candidate that broke more than it fixed is exactly
    // the case the floor exists to refuse and printing it unsigned would read
    // as a repair.
    let net = c.fixed as i32 - c.broke as i32;
    if net < 0 {
        fl.push('-');
    }
    push_u32(&mut fl, net.unsigned_abs());
    s.push_str("  ");
    s.push_str(&fl);
    s.push('\n');

    let mut mtx = String::from("MATRIX     standing ");
    mtx.push_str(admit(x.admit_old));
    mtx.push_str(" / proposed ");
    mtx.push_str(admit(x.admit_new));
    row(s, &mtx, c.j1, if c.j1 { "" } else { "both criteria agree" });

    let mut anchor = String::from("ANCHOR     ");
    push_f2(&mut anchor, x.anchor_inc * 100.0);
    anchor.push_str("% -> ");
    push_f2(&mut anchor, x.anchor_cand * 100.0);
    anchor.push_str("% held-out, the set no bar sees");
    row(s, &anchor, c.j2, if c.j2 { "" } else { "the anchor withholds it" });

    s.push_str("  REASON     ");
    s.push_str(c.j1_why);
    s.push('\n');
}

/// A sitting, as the machine reports it.
fn render_dispatch(c: &Certificate, seq: u32, hour: u8) -> String {
    let mut s = String::from("SITTING ");
    push_u32(&mut s, seq);
    s.push_str("  hour ");
    push_u32(&mut s, hour as u32);
    s.push('\n');

    s.push_str("  PROPOSAL ");
    s.push_str(&short(&c.variant));
    if let Some(p) = c.parent {
        s.push_str("  succeeding ");
        s.push_str(&short(&p));
    }
    s.push_str("  over ");
    push_u32(&mut s, c.validation as u32);
    s.push_str(" paired decisions\n");

    if let Some(x) = c.cross {
        // A judge-trial: the change is to the criterion, so the report is the
        // cross-evaluation matrix and the anchor, not the four judges -- there
        // is no judge above this one, which is the whole difficulty U3 answers.
        render_cross(&mut s, &x, c);
    } else {
        let mut j1 = String::from("J1 REPAIR  fixed ");
        push_u32(&mut j1, c.fixed as u32);
        j1.push_str(" broke ");
        push_u32(&mut j1, c.broke as u32);
        j1.push_str(" chi ");
        push_f2(&mut j1, c.mcnemar);
        row(&mut s, &j1, c.j1, c.j1_why);

        let mut j2 = String::from("J2 GOALS   ");
        push_u32(&mut j2, c.goals_held as u32);
        j2.push_str(" of ");
        push_u32(&mut j2, c.goals_total as u32);
        j2.push_str(" held");
        row(&mut s, &j2, c.j2, "");

        row(&mut s, "J3 FORM    structure", c.j3, c.j3_why);

        let mut j4 = String::from("J4 COST    rank ");
        push_u32(&mut j4, c.rank as u32);
        j4.push_str(", ");
        push_u32(&mut j4, c.resident_kib as u32);
        j4.push_str(" KiB resident");
        row(&mut s, &j4, c.j4, "");
    }

    s.push_str("  VERDICT");
    while s.len() % 24 != 0 {
        s.push(' ');
    }
    if c.adopted {
        s.push_str("RATIFIED. The prior state is preserved; 'godel rollback' restores it.\n");
    } else {
        s.push_str("REJECTED, and reverted. The prior state stands.\n");
    }
    s.push('\n');
    s
}

/// Sittings the operator has not been shown, oldest first.
///
/// Counted rather than diffed: the dispatch file is append-only, so the number
/// already shown is a position in it and nothing has to be compared.
pub fn pending() -> Option<String> {
    let all = sysbox::read_blob(DISPATCH).and_then(|b| String::from_utf8(b).ok())?;
    let seen = sysbox::read_blob(REPORTED)
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut out = String::new();
    let mut n = 0usize;
    for block in all.split("SITTING ") {
        if block.is_empty() {
            continue;
        }
        n += 1;
        if n > seen {
            out.push_str("SITTING ");
            out.push_str(block);
        }
    }
    if out.is_empty() {
        None
    } else {
        // Only the count of what was actually handed over. A report the
        // operator never saw because the console scrolled is a report that
        // still owes them a reading.
        let mut c = String::new();
        push_u32(&mut c, n as u32);
        sysbox::write_text(REPORTED, &c);
        Some(out)
    }
}

/// Every sitting, whether or not it has been reported.
pub fn all_dispatches() -> Option<String> {
    sysbox::read_blob(DISPATCH).and_then(|b| String::from_utf8(b).ok())
}

fn render_certificate(c: &Certificate, seq: u32, hour: u8) -> String {
    let mut s = String::new();
    push_u32(&mut s, seq);
    s.push_str(" h");
    push_u32(&mut s, hour as u32);
    s.push_str(" parent=");
    s.push_str(&c.parent.map(|h| short(&h)).unwrap_or(String::from("root....")));
    s.push_str(" variant=");
    s.push_str(&short(&c.variant));
    s.push_str(" n=");
    push_u32(&mut s, c.validation as u32);
    s.push_str(" pred=");
    s.push_str(if c.predicted { "win" } else { "lose" });
    if let Some(x) = c.cross {
        // A judge-trial's line is the matrix, not the four judges: the two
        // bars, whether each admits the reference candidate, the anchor before
        // and after, and the verdict's reason -- everything a later run needs
        // to re-derive whether the criterion should have moved.
        s.push_str(" JUDGE[bar=");
        push_f2(&mut s, x.tau_old);
        s.push_str("->");
        push_f2(&mut s, x.tau_new);
        // The floor rides beside the bar, unconditionally. A ledger line is a
        // new object rather than a re-addressed one, so there is no rendering
        // hazard here and nothing to be gained by omitting it -- and a line
        // that named only the bar could not answer which half of the criterion
        // moved, which is the first thing a later reader asks of a judge line.
        s.push_str(" floor=");
        push_u32(&mut s, x.floor_old as u32);
        s.push_str("->");
        push_u32(&mut s, x.floor_new as u32);
        s.push_str(" std=");
        s.push_str(if x.admit_old { "admit" } else { "refuse" });
        s.push_str(" prop=");
        s.push_str(if x.admit_new { "admit" } else { "refuse" });
        s.push_str(" chi=");
        push_f2(&mut s, c.mcnemar);
        s.push_str(" anchor=");
        push_f2(&mut s, x.anchor_inc * 100.0);
        s.push_str("->");
        push_f2(&mut s, x.anchor_cand * 100.0);
        s.push(' ');
        s.push_str(c.j1_why);
        s.push(']');
    } else {
    s.push_str(" J1[fix=");
    push_u32(&mut s, c.fixed as u32);
    s.push_str(" broke=");
    push_u32(&mut s, c.broke as u32);
    s.push_str(" chi=");
    push_f2(&mut s, c.mcnemar);
    s.push(' ');
    s.push_str(c.j1_why);
    s.push(']');
    s.push_str(" J2[goals=");
    push_u32(&mut s, c.goals_held as u32);
    s.push('/');
    push_u32(&mut s, c.goals_total as u32);
    s.push_str(if c.j2 { " ok]" } else { " no]" });
    s.push_str(" J3[");
    s.push_str(if c.j3 { "ok" } else { c.j3_why });
    s.push(']');
    s.push_str(" ep=");
    push_u32(&mut s, c.epochs);
    if c.capped {
        s.push_str("(clock)");
    }
    s.push_str(" J4[r=");
    push_u32(&mut s, c.rank as u32);
    s.push_str(" kib=");
    push_u32(&mut s, c.resident_kib as u32);
    s.push_str(if c.j4 { " ok]" } else { " no]" });
    }
    if c.adopted {
        s.push_str(" ADOPT test=");
        push_f2(&mut s, c.test_acc * 100.0);
        s.push_str("%@read");
        push_u32(&mut s, c.test_read);
        if !c.test_fresh {
            s.push_str("(stale)");
        }
    } else {
        s.push_str(" reject");
    }
    s
}

fn short(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in h.iter().take(4) {
        push_hex_byte(&mut s, *b);
    }
    s
}

/// Make the head name whatever is actually attached, and return it.
///
/// The certificate says which variant a candidate was measured against, and
/// that has to be true. `train adapter` and `adapter load` both attach without
/// touching the head, so without this a trial run after either one would
/// record `parent = none` while competing against a real adapter nobody wrote
/// down. A lineage that can say a variant descended from the frozen model when
/// it did not is exactly the failure the Merkle DAG exists to prevent, and it
/// would arrive through the back door.
///
/// So the incumbent gets recorded before it is competed against. Its `lambda`
/// and `rule` are zero, meaning unknown: it arrived from outside the loop and
/// this is the honest record of that.
fn ensure_head(e: &mut super::Engine) -> Option<[u8; 32]> {
    let Some(ad) = e.model.adapters.as_ref() else {
        // Nothing attached: the frozen model is the incumbent. A head that
        // names an adapter would disagree with what is running, and the
        // running system is the one telling the truth.
        if head().is_some() {
            sysbox::detach(HEAD);
        }
        return None;
    };

    // What kind of adapter this actually is, read off the thing itself.
    //
    // `deeptrain` attaches a full q/k/v adapter and touches neither the head
    // nor the ledger, so the next trial recorded it here -- as a
    // classifier-only variant with unknown parameters, because that is what
    // this function used to assume. The lineage then claimed a deep adapter
    // was a shallow one, which is worse than claiming it was unknown.
    let deep = ad.qkv.iter().any(|t| t.iter().any(|d| d.is_some()));
    let blob = ad.to_blob();
    let ah = sha256::hash(&blob);
    let current = head();
    // Whether the head still describes the *whole* mind, not just its weights.
    //
    // Testing the adapter alone was not enough. `core install` is still a live
    // operator verb and touches neither the head nor the ledger, so a core
    // could be swapped underneath a node that goes on claiming a different one
    // -- and then `rollback`, which restores whatever the parent recorded,
    // would put back a council the machine was never running. Comparing the
    // core as well means an out-of-band install forces a new node, which is
    // the same rule the adapter has always obeyed: record what is in force,
    // never what was assumed.
    let installed = super::voter::installed().map(|c| c.hash);
    let named = current
        .and_then(|h| Variant::load(&h))
        .map(|v| v.adapter == Some(ah) && v.core == installed)
        .unwrap_or(false);
    if named {
        return current;
    }

    sysbox::write_blob(&blob_path(&ah), blob);
    let v = Variant {
        parent: current,
        adapter: Some(ah),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: None,
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        deep,
        // What is actually installed, recorded rather than assumed -- the same
        // discipline as `policy` and `corpus`. A variant trained while a
        // machine-written core was voting is not the same object as one
        // trained without it, and a lineage that cannot tell them apart
        // describes the wrong experiment.
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        // Zero throughout: it arrived from outside the loop and nothing here
        // knows how it was made. Recording a guess would be worse than
        // recording that it is unknown.
        lambda: 0.0,
        rank: 0,
        epochs: 0,
        rule: 0,
        // The bar in force when this variant was measured, so a later reader
        // can interpret the lineage under the criterion it actually ran, not
        // the one running now. `trial_judge` is the exception and sets the bar
        // it adopts.
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vh = v.store();
    set_head(&vh);
    Some(vh)
}

/// Run whatever this proposal proposes, and answer with a certificate.
///
/// The one way in. Before this there were two entry points with two
/// signatures and two error types, and the scheduler had to know which kind of
/// change it was making in order to call the right one -- so widening the loop
/// to a third kind meant editing the scheduler, the shell, and the journal
/// together. Now the proposal carries its kind and the caller carries none.
///
/// **The economics stay separate even though the entry point is one.**
/// Branching *inside* `trial` was the tempting shape and it is the wrong one:
/// `trial` is a training run whose expensive half is a forward pass per
/// example, and a core changes no weights and needs no training. Two costs
/// behind one name is the mistake `deeptrain` was split out to avoid. This
/// dispatches; it does not merge.
///
/// Marking happens here for every kind, so a proposal that faults still counts
/// as visited -- for a core that is what stops the machine judging the same
/// program it wrote every night for the rest of its life.
pub fn run(
    e: &mut super::Engine,
    b: &Budget,
    p: &Proposal,
) -> Result<Certificate, Refused> {
    let result = match p.kind {
        ProposalKind::Adapter => trial(e, b, p).map_err(Refused::Train),
        ProposalKind::Core(h) => {
            p.mark();
            trial_core(e, &h).map_err(Refused::Judge)
        }
        ProposalKind::Deep => trial_deep(e, b, p),
        ProposalKind::Skill(h) => {
            p.mark();
            trial_skill(&h).map_err(Refused::Judge)
        }
        ProposalKind::Config(r) => {
            p.mark();
            trial_config(e, r).map_err(Refused::Judge)
        }
        // `trial_judge` marks itself, the way `trial` does, because it prepares
        // a trial whose fault should still count the point as visited.
        ProposalKind::Judge(tau, floor) => trial_judge(e, tau, floor, b),
    };
    // Tally the outcome against its axis, for the surprise order. Only a trial
    // that reached a verdict counts: a refusal (no corpus, engine held) says
    // nothing about whether the axis is worth pressing, so it must not move the
    // belief that decides how often the axis is tried.
    if let Ok(ref c) = result {
        bump_axis(axis_of(&p.kind), c.adopted);
    }
    result
}

/// Run one trial: train a candidate, judge it, record the certificate, and
/// adopt only if all four judges agree.
///
/// The expensive half -- `Trial::prepare` -- is a forward pass per example.
/// Everything after it is dot products over cached state, which is what makes
/// the judging affordable and what makes any later re-check of this verdict
/// nearly free.
pub fn trial(
    e: &mut super::Engine,
    b: &Budget,
    p: &Proposal,
) -> Result<Certificate, super::train::RunError> {
    // Marked before the work, not after: a trial that faults or is interrupted
    // has still spent the night here, and a marker written only on success
    // sends the loop back to the same failing point forever.
    p.mark();
    let t = super::train::prepare(e, b)?;
    TRIALS.fetch_add(1, Ordering::Relaxed);

    // Say where we are the moment the expensive half is done.
    //
    // Preparing a trial is a forward pass per example plus one per guard
    // goal, which on this hardware is seconds and under emulation is minutes
    // each. Without this line a run that is working looks exactly like a run
    // that has hung, and the difference matters most to whoever is deciding
    // whether to wait or to kill it.
    crate::kprintln!(
        "  prepared: {} examples, {} decisions, {} guards, {} rows ({} ms + {} ms)",
        t.examples,
        t.decisions(),
        t.guards().len(),
        t.live_rows(),
        t.chains_ms,
        t.features_ms
    );

    // The incumbent, narrowed to this trial's row space. `None` means the
    // frozen baseline, which is the honest starting point rather than a
    // special case: an unattached model *is* a variant, the one with no
    // adapter, and it is what a first trial competes against.
    // Record what is attached before competing against it, so `parent` below
    // names the thing the paired test actually ran against.
    let parent = ensure_head(e);
    let incumbent = e.model.adapters.as_ref().and_then(|a| t.gather(a));

    let fit = t.train(b);
    Ok(adjudicate(e, &t, b, parent, incumbent.as_ref(), &fit))
}

/// Judge one trained candidate against the incumbent, write everything down,
/// and adopt only on unanimity.
///
/// Extracted from `trial` so the storm's winner faces the same four judges
/// through the same code, not a second copy that drifts -- the objection
/// `model.rs` makes twice about two implementations that are supposed to
/// agree, applied to the one place where drift would mean two different
/// adoption criteria wearing one name. `trial` trains one candidate and hands
/// it here; `storm` trains a generation and hands its best. The judges cannot
/// tell which door a candidate came through, which is the point.
fn adjudicate(
    e: &mut super::Engine,
    t: &Trial,
    b: &Budget,
    parent: Option<[u8; 32]>,
    incumbent: Option<&super::adapter::Dora>,
    fit: &Fit,
) -> Certificate {
    // Predict before measuring. Training-set gain is the cheap signal and the
    // question is whether it means anything; recording the prediction beside
    // the outcome is the only way to ever find out.
    let train_before = t.score(incumbent, Slice::Train);
    let train_after = t.score(Some(&fit.dora), Slice::Train);
    let predicted = train_after > train_before;

    // --- J1: is it better, beyond noise? --------------------------------
    let (broke, fixed, _, _) = t.paired(incumbent, Some(&fit.dora), Slice::Validation);
    let chi = mcnemar(broke, fixed);
    let n_val = t.slice_size(Slice::Validation);
    // The criterion the loop is *actually running*, both halves of it, through
    // the one implementation every J1 site shares.
    let (j1, j1_why) = j1_verdict(n_val, fixed, broke, chi);

    // --- J2: does it still do the same thing unasked? -------------------
    let (goals_held, goals_total) = t.guards_hold(Some(&fit.dora));
    // Every guard must hold, and none of them may have been routing to a
    // mutating applet in the first place -- a baseline that already wanted to
    // run `rm` on its own initiative is not a baseline worth preserving.
    let j2 = goals_held == goals_total
        && goals_total > 0
        && t.guards().iter().all(|g| !g.mutates);

    // --- J3: structural sanity, regardless of any score -----------------
    let (j3, j3_why) = sanity(t, &fit.dora);

    // --- J4: can this machine carry it? ---------------------------------
    // Decode cost is O(vocab * rank) per token whatever the live set holds,
    // so rank is the knob, and resident bytes matter because the heap is one
    // physically contiguous allocation on a ladder -- a variant that grows
    // without bound is a variant that eventually will not boot.
    let resident_kib = (fit.dora.resident_bytes() + t.live_rows() * 4) / 1024;
    let j4 = fit.dora.r <= b.rank && resident_kib <= MAX_RESIDENT_KIB;

    let adapters = t.scatter(&fit.dora, &e.model.cfg, b.alpha);
    let blob = adapters.to_blob();
    let ablob = sha256::hash(&blob);

    let variant = weight_variant(parent, ablob, b.lr, fit.dora.r, fit.epochs as u32);
    let vhash = variant.hash();

    let mut cert = Certificate {
        parent,
        variant: vhash,
        decisions: t.decisions(),
        validation: t.slice_size(Slice::Validation),
        predicted,
        fixed,
        broke,
        mcnemar: chi,
        j1,
        j1_why,
        goals_held,
        goals_total,
        j2,
        j3,
        j3_why,
        resident_kib,
        rank: fit.dora.r,
        j4,
        epochs: fit.epochs as u32,
        capped: fit.stopped,
        adopted: false,
        test_acc: 0.0,
        test_read: 0,
        test_fresh: true,
        // Every trial before U3 is a weights/rule/core/skill/deep trial, and
        // none of them touch the criterion, so the matrix is absent and the
        // certificate renders exactly as it always did.
        cross: None,
    };
    cert.adopted = cert.unanimous();

    // The test slice is consulted here and nowhere else: after a variant has
    // already won on validation, never to decide whether it won. That
    // ordering is the whole discipline -- a set you select on is a set you
    // have fitted -- and the budget is what keeps the ordering from being
    // quietly undone by a loop that runs every night forever.
    if cert.adopted {
        let (acc, n, fresh) = read_test(t, Some(&fit.dora));
        cert.test_acc = acc;
        cert.test_read = n;
        cert.test_fresh = fresh;
    }

    // Every variant is stored, adopted or not.
    //
    // The claim this whole module rests on is that any later run can re-derive
    // a verdict. That is false for a variant nobody kept: the ledger would
    // name a hash with nothing behind it, and the trials it applies to are
    // most of them, since rejection is the common case by design. So the node
    // and its adapter are written whichever way the judges went, and only the
    // head pointer waits on the verdict.
    //
    // The cost is 23.7 KB per trial at the measured decision-layer size, and
    // content addressing means two trials that land on identical weights are
    // stored once. A nightly loop is a few megabytes a year, which is the
    // price of every line in the ledger being checkable.
    sysbox::write_blob(&blob_path(&ablob), blob);
    variant.store();

    // Offer it to the archive, adopted or not. This is the MAP-Elites turn and
    // it is independent of the head: a variant the judges rejected for not being
    // a *net repair beyond noise* can still be the best mind of its kind, and
    // holding it is how the search keeps a diverse frontier rather than only the
    // one peak `head` climbs. Fitness is validation accuracy -- an absolute
    // number, so cells are comparable across nights, and cheap because the
    // features are cached.
    let fitness = t.score(Some(&fit.dora), Slice::Validation);
    let lit = archive_insert(&vhash, fit.dora.r, fixed, broke, fitness);

    if cert.adopted {
        // The pointer moves last. A head naming a node that is not written yet
        // is a machine that cannot describe its own mind, and the ordering is
        // the only thing preventing it.
        set_head(&vhash);
        let _ = e.model.detach_adapters();
        let _ = e.model.attach_adapters_unseeded(adapters);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    }
    if lit {
        crate::kprintln!("  archive: lit a cell -- best of its kind at rank {}", fit.dora.r);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    cert
}

/// The node a weights candidate becomes, from what is actually in force.
///
/// One constructor, because two would drift: `adjudicate` records its winner
/// through this and `storm` records its cell-winners through this, so a
/// candidate's identity cannot depend on which door it came through. Every
/// contextual field carries what is *actually* installed and running -- policy,
/// corpus, core, rule, bar -- the discipline the old inline literal earned one
/// field at a time. `scatter` builds classifier-only adapters, always, so
/// `deep` is false by construction here.
fn weight_variant(
    parent: Option<[u8; 32]>,
    ablob: [u8; 32],
    lr: f32,
    rank: usize,
    epochs: u32,
) -> Variant {
    Variant {
        parent,
        adapter: Some(ablob),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: None,
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        deep: false,
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        lambda: lr,
        rank: rank as u8,
        epochs,
        rule: super::harness::rule_in_force() as u8,
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    }
}

/// The bound a variant has to fit inside to be carried at all.
///
/// Not arbitrary: `HEAP_LADDER` allocates one physically contiguous region
/// and comes down a rung when the memory map cannot satisfy it, so a lineage
/// that grows a megabyte per adoption is a lineage that eventually does not
/// boot. The ledger records the figure either way.
pub const MAX_RESIDENT_KIB: usize = 8 * 1024;

/// Guards that hold regardless of any score.
///
/// These are the ones worth having when the scores look good: a variant can
/// improve validation accuracy and still be carrying a non-finite scale that
/// will produce a NaN on the first prompt outside the corpus.
pub fn sanity(t: &Trial, d: &super::adapter::Dora) -> (bool, &'static str) {
    for v in d.a.iter().chain(d.b.iter()) {
        if !v.is_finite() {
            return (false, "non-finite factor");
        }
    }
    for (m, s) in d.m.iter().zip(d.s.iter()) {
        if !m.is_finite() || !s.is_finite() {
            return (false, "non-finite magnitude");
        }
        if *s <= 0.0 {
            return (false, "non-positive scale");
        }
    }
    if !t.logits_finite(Some(d)) {
        return (false, "non-finite logit");
    }
    (true, "ok")
}

/// Restore the parent of the current head.
///
/// O(1), because everything is content-addressed: the previous adapter blob
/// was never deleted and the parent node still names it. Undoing a
/// self-modification costs a pointer write and a blob read, which is the
/// property that makes adopting one defensible in the first place.
/// Record whatever is attached right now as a node, and make it the head.
///
/// For changes that arrive from outside the loop -- `deeptrain`, `adapter
/// load`, `train adapter`. None of them is judged, and this does not pretend
/// otherwise: the node it writes carries the honest "arrived from outside"
/// zeros, plus `deep` read off the adapter itself.
///
/// What it buys is that the change is *addressable*. Before this, `deeptrain`
/// moved every q/k/v site and left no trace, so the lineage's account of the
/// mind was silently wrong until the next trial happened to notice, and
/// `godel rollback` had nothing to walk back to. `adapter off` was the only
/// undo, and it discards everything rather than stepping back one change.
pub fn record_current(e: &mut super::Engine) -> Option<[u8; 32]> {
    ensure_head(e)
}

/// Judge a council core and, if it passes, adopt it into the lineage.
///
/// The second kind of thing this loop can change, and the first that is not a
/// number. A core is an Aiksi program defining `fn vote(text, allowed): int`;
/// the machine can write one, `Caps::Sandbox` and a step budget already make
/// running an untrusted one safe, and `harness::core_bench` already judges it
/// on the validation slice with a paired McNemar test (J1), a cost ceiling
/// (J5) and an independence requirement (J6).
///
/// What did not exist was any of the *bookkeeping that makes a change
/// reversible*. A core could pass all three judges and leave no node in the
/// DAG, no line in the ledger, and nothing for `rollback` to undo -- so the
/// one path by which the machine could adopt code it wrote itself was also the
/// one path outside the discipline every other change obeys. `core install`
/// remains for the operator; this is the way in that keeps a record.
///
/// Deliberately not folded into `trial`. That function is a training run --
/// `prepare` is a forward pass per example, and every judge after it reads
/// cached features. A core changes no weights, needs no training, and shares
/// only the lineage machinery. Branching inside `trial` would put two
/// economics behind one name, which is the mistake `deeptrain` was split out
/// to avoid.
pub fn trial_core(e: &mut super::Engine, h: &[u8; 32]) -> Result<Certificate, &'static str> {
    // The engine this function was handed, not a second claim on it.
    //
    // `core_bench` opens `with_engine` itself, and `trial_core` is called from
    // inside one -- so the old spelling produced two live `&mut Engine` at
    // once. Undefined behaviour, and with teeth: the judging passes below
    // mutate the KV cache and `e.pos` under a reference the compiler is
    // allowed to assume nothing else touches, and `ensure_head` immediately
    // afterwards reads the adapter through it to decide what to record.
    let verdict = match super::harness::core_bench_in(e, h, super::harness::VALIDATION) {
        Err(_) => return Err("the core will not load, or scored nothing"),
        Ok(v) => v,
    };
    TRIALS.fetch_add(1, Ordering::Relaxed);

    // Record what is in force before competing against it, exactly as the
    // adapter path does, so `parent` names the thing actually measured.
    let parent = ensure_head(e);

    let variant = Variant {
        parent,
        // Unchanged by this trial: a core votes, it does not move weights.
        // Carried from the incumbent so the node describes the whole mind
        // rather than only the part this trial touched.
        adapter: parent.and_then(|p| Variant::load(&p)).and_then(|v| v.adapter),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: None,
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        lambda: 0.0,
        rank: 0,
        epochs: 0,
        rule: super::harness::Rule::WithCore as u8,
        core: Some(*h),
        core_seen: true,
        // Carried from the incumbent: a core changes no weights, so whatever
        // the parent was, this variant still is.
        deep: parent.and_then(|p| Variant::load(&p)).map(|v| v.deep).unwrap_or(false),
        // The bar in force when this variant was measured, so a later reader
        // can interpret the lineage under the criterion it actually ran, not
        // the one running now. `trial_judge` is the exception and sets the bar
        // it adopts.
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vhash = variant.hash();

    let mut cert = Certificate {
        parent,
        variant: vhash,
        decisions: verdict.n,
        validation: verdict.n,
        // There is a cheap signal after all, and it is a better one than the
        // adapter path's.
        //
        // This used to be `false` with a comment saying no prediction existed.
        // The census makes one: `prize` counts the validation items a core
        // could repair if it answered every one of them correctly, so a prize
        // below the bar is a prediction of failure that is not a guess -- it
        // is arithmetic. The ledger accumulates these beside the outcomes, and
        // a run of `predicted false / adopted false` is not a calibration
        // failure here, it is the ceiling being reported honestly.
        predicted: verdict.prize >= clean_fixes_needed(),
        fixed: verdict.fixed,
        broke: verdict.broke,
        mcnemar: verdict.chi,
        j1: verdict.j1,
        j1_why: if verdict.j1 { "beyond the noise" } else { "inside the noise" },
        // J2 asks whether the machine still does the same thing unasked. A
        // core cannot reach an applet -- it answers an index into a set the
        // caller already chose -- so the guards are held by construction
        // rather than by measurement, and saying so is more honest than
        // running them and reporting a pass they could not fail.
        goals_held: 0,
        goals_total: 0,
        j2: true,
        j3: verdict.j6,
        j3_why: if verdict.j6 { "disagrees somewhere" } else { "adds a vote and no information" },
        resident_kib: 0,
        rank: 0,
        j4: verdict.j5,
        epochs: 0,
        capped: false,
        adopted: false,
        test_acc: 0.0,
        test_read: 0,
        test_fresh: true,
        // Every trial before U3 is a weights/rule/core/skill/deep trial, and
        // none of them touch the criterion, so the matrix is absent and the
        // certificate renders exactly as it always did.
        cross: None,
    };
    cert.adopted = cert.unanimous();

    if cert.adopted {
        let (acc, n, fresh) = read_test_core(e, h);
        cert.test_acc = acc;
        cert.test_read = n;
        cert.test_fresh = fresh;
    }

    variant.store();

    if cert.adopted {
        // Install first, then move the pointer: a head naming a core that is
        // not in force describes a mind the machine is not running.
        if !super::voter::install(h) {
            return Err("the core passed but would not install");
        }
        set_head(&vhash);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    Ok(cert)
}

/// The test slice, for a core that has already won on validation.
///
/// Same budget and same ordering as the adapter path: consulted only after
/// adoption, counted against the same three reads, because a loop that
/// improves itself forever reads the held-out set forever whichever axis it
/// is searching.
///
/// **The read is spent only if it buys a measurement.** This function used to
/// call `spend_test_read` and return `0.0` -- so three adopted cores exhausted
/// the global held-out budget having looked at nothing, wrote `test_acc 0.00`
/// into three certificates (which reads as "0% on test", not as "not
/// measured"), and stamped every later adapter certificate `test_fresh
/// false` permanently. The one number the loop is not allowed to overfit was
/// being spent on a code path that never opened the data.
fn read_test_core(e: &mut super::Engine, h: &[u8; 32]) -> (f32, u32, bool) {
    match super::harness::core_bench_in(e, h, super::harness::TEST) {
        Ok(v) if v.n > 0 => {
            let n = spend_test_read();
            (v.correct as f32 / v.n as f32, n, n <= TEST_READS)
        }
        // Nothing measurable in the test slice. Say so by leaving the budget
        // alone: an unspent read is recoverable, a spent one never is.
        _ => (0.0, test_reads(), false),
    }
}

/// Take the installed core out of the decision path, if there is one.
///
/// `voter::uninstall` answers `false` both when the detach failed and when
/// there was nothing to detach, and those are opposite facts: the second is
/// the ordinary case and must not read as an error.
fn drop_core() -> bool {
    if super::voter::installed().is_none() {
        return true;
    }
    super::voter::uninstall()
}

/// Undo the last adoption: put the parent's mind back and move the head to it.
///
/// **Everything is validated before anything is changed.** The old order swapped
/// the core first and read the adapter blob afterwards, so a rollback whose
/// adapter had been pruned returned an error having *already* changed which
/// core was voting -- leaving the parent's core in force, the child's adapter
/// attached, and the head still naming the child. That is precisely the "the
/// pointer said one thing and the machine did another" state this function
/// exists to prevent, relocated into its own failure path. Now the failable
/// reads all happen first, and the mutations happen only once none of them can
/// fail for a reason we could have seen coming.
/// Adapt the attention path, judge what it bought, and keep it only if it won.
///
/// The third kind of change, and the first that is *destructive while it is
/// being measured*. `trial` builds a candidate adapter beside the running one
/// and attaches it only on adoption; `train_full` has no such shape -- it
/// walks gradients into the tensors the model is using. So the incumbent is
/// copied out first and put back on every path that does not adopt. A judge
/// that leaves a rejected variant installed is not a judge.
///
/// **What the frozen-base trade costs, said in the certificate.** A
/// classifier-only adapter leaves every hidden state a constant, and that is
/// what makes cached features, cheap re-judging and a cheap `Trial` possible.
/// A deep one gives that up: judging it costs two full passes over the corpus
/// rather than one cached one, and every earlier certificate's cached
/// comparison stops applying to it. `deep: true` on the node is what tells a
/// later reader which kind of object they are looking at.
pub fn trial_deep(
    e: &mut super::Engine,
    b: &Budget,
    p: &Proposal,
) -> Result<Certificate, Refused> {
    use super::train::RunError;
    p.mark();

    // Where everything goes now, before anything moves.
    let before = super::harness::route_snapshot(e, super::harness::VALIDATION)
        .map_err(|_| Refused::Train(RunError::NoCorpus))?;

    // The incumbent, kept so a rejection can be undone. `None` is a real
    // answer -- the frozen model is a variant -- and detaching is how it comes
    // back.
    let saved = e.model.adapters.as_ref().map(|a| a.to_blob());
    let parent = ensure_head(e);

    // A deep adapter to train into, if the machine is not already carrying
    // one. `Adapters::full` adapts every q/k/v site as well as the decision
    // layer, which is the whole difference being judged.
    if e.model.adapters.is_none() {
        let cfg = e.model.cfg.clone();
        let full = super::adapter::Adapters::full(&cfg, b.rank, b.alpha);
        if e.model.attach_adapters(full).is_err() {
            return Err(Refused::Judge("a deep adapter will not attach to this checkpoint"));
        }
    }

    let Some(report) = super::train::train_full(e, b, b.examples) else {
        restore(e, &saved);
        return Err(Refused::Train(RunError::Hardware));
    };

    let after = match super::harness::route_snapshot(e, super::harness::VALIDATION) {
        Ok(s) => s,
        Err(_) => {
            restore(e, &saved);
            return Err(Refused::Train(RunError::NoCorpus));
        }
    };

    // --- J1: paired, on the items both snapshots saw --------------------
    let n = before.correct.len().min(after.correct.len());
    let mut fixed = 0usize;
    let mut broke = 0usize;
    for i in 0..n {
        match (before.correct[i], after.correct[i]) {
            (false, true) => fixed += 1,
            (true, false) => broke += 1,
            _ => {}
        }
    }
    let chi = mcnemar(broke, fixed);
    let (j1, j1_why) = j1_verdict(n, fixed, broke, chi);

    // --- J2: does it still do the same thing unasked? -------------------
    //
    // Recomputed on both sides rather than cached, because the cache is
    // exactly what deep training invalidates. A goal that now routes
    // somewhere else is the failure this judge exists for, and one that
    // routes to a mutating applet fails it whether or not it moved.
    let goals_total = before.guards.len().min(after.guards.len());
    let goals_held = (0..goals_total).filter(|i| before.guards[*i] == after.guards[*i]).count();
    let j2 = goals_total > 0
        && goals_held == goals_total
        && after.guards[..goals_total].iter().all(|c| {
            crate::sysbox::APPLETS
                .get(*c)
                .map(|a| !a.mutates)
                .unwrap_or(false)
        });

    // --- J3: structural sanity ------------------------------------------
    let (j3, j3_why) = if !after.finite {
        (false, "the features stopped being finite")
    } else if !report.last_loss.is_finite() {
        (false, "the loss diverged")
    } else if before.correct.len() != after.correct.len() {
        (false, "the slice changed under the run")
    } else {
        (true, "finite throughout")
    };

    // --- J4: can this machine carry it? ---------------------------------
    //
    // The judge that a deep variant is most likely to fail, and rightly. Every
    // adapted attention site is resident for the life of the model, where a
    // classifier adapter is a few rows.
    // The rank bound is not decode cost here, it is identity: `Variant.rank`
    // is a byte, so a rank past 255 would wrap and two different experiments
    // would share a node. Refusing is better than recording a lie.
    let resident_kib = e.model.adapters.as_ref().map(|a| a.resident_bytes()).unwrap_or(0) / 1024;
    let j4 = b.rank <= 255 && resident_kib <= MAX_RESIDENT_KIB;

    let blob = e.model.adapters.as_ref().map(|a| a.to_blob());
    let ablob = blob.as_ref().map(|x| sha256::hash(x));

    let variant = Variant {
        parent,
        adapter: ablob,
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: None,
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        // The whole point of the node: this one moved the attention path, and
        // nothing that reads the lineage may confuse it with one that did not.
        deep: true,
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        lambda: b.lr,
        rank: b.rank as u8,
        epochs: report.epochs as u32,
        rule: p.rule,
        // The bar in force when this variant was measured, so a later reader
        // can interpret the lineage under the criterion it actually ran, not
        // the one running now. `trial_judge` is the exception and sets the bar
        // it adopts.
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vhash = variant.hash();

    let mut cert = Certificate {
        parent,
        variant: vhash,
        decisions: n,
        validation: n,
        // The cheap signal a deep run does have: the loss went down.
        predicted: report.last_loss < report.first_loss,
        fixed,
        broke,
        mcnemar: chi,
        j1,
        j1_why,
        goals_held,
        goals_total,
        j2,
        j3,
        j3_why,
        resident_kib,
        rank: b.rank,
        j4,
        epochs: report.epochs as u32,
        capped: report.stopped,
        adopted: false,
        test_acc: 0.0,
        test_read: 0,
        test_fresh: true,
        // Every trial before U3 is a weights/rule/core/skill/deep trial, and
        // none of them touch the criterion, so the matrix is absent and the
        // certificate renders exactly as it always did.
        cross: None,
    };
    cert.adopted = cert.unanimous();
    TRIALS.fetch_add(1, Ordering::Relaxed);

    if cert.adopted {
        // The blob before the node, so a head can never name an adapter whose
        // bytes are not stored -- that is the one state `rollback` cannot get
        // out of.
        match (blob, ablob) {
            (Some(bytes), Some(h)) => {
                sysbox::write_blob(&blob_path(&h), bytes);
            }
            _ => {
                restore(e, &saved);
                return Err(Refused::Judge("it passed but there is nothing attached to store"));
            }
        }
        variant.store();
        set_head(&vhash);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    } else {
        // Put the machine back. This is the half `deeptrain` never had: it
        // trained into the live model and left whatever came out, judged or
        // not, until the next reboot.
        restore(e, &saved);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    Ok(cert)
}

/// Judge a skill and, if it passes, put it where `run` will find it.
///
/// The cheapest trial in the module and the only one that needs no model: a
/// skill is a program, and the four things worth asking about one are all
/// answerable by running it. That matters more than it sounds -- it means the
/// night loop can judge a skill on a machine with no checkpoint loaded, and
/// that a rejection costs seconds rather than the twenty minutes an adapter
/// trial costs.
///
/// **Adoption is a copy, not a rename.** The candidate stays at its content
/// address under `/ai/skills` and a copy lands in `/ai/tools`, so the thing
/// that was judged and the thing that runs are provably the same bytes. A
/// rename would leave the ledger naming an address nothing holds.
pub fn trial_skill(h: &[u8; 32]) -> Result<Certificate, &'static str> {
    let v = super::skill::bench(h);
    let Some(src) = super::skill::source(h) else { return Err("no such skill") };
    TRIALS.fetch_add(1, Ordering::Relaxed);

    // A skill does not change the mind, so the node it writes names the same
    // adapter and core the head already did. What it changes is the toolkit,
    // and `skills` is the field for it -- hooked up at last, having been
    // hardcoded `None` since the struct was written.
    let parent = head();
    let carried = parent.and_then(|p| Variant::load(&p));
    let variant = Variant {
        parent,
        adapter: carried.as_ref().and_then(|v| v.adapter),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: Some(*h),
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        deep: carried.as_ref().map(|v| v.deep).unwrap_or(false),
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        lambda: 0.0,
        rank: 0,
        epochs: 0,
        rule: super::harness::rule_in_force() as u8,
        // The bar in force when this variant was measured, so a later reader
        // can interpret the lineage under the criterion it actually ran, not
        // the one running now. `trial_judge` is the exception and sets the bar
        // it adopts.
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vhash = variant.hash();

    let mut cert = Certificate {
        parent,
        variant: vhash,
        // Two runs, which is what J3 compared. Not routing decisions, and the
        // ledger's `n` should not be read as though it were.
        decisions: 2,
        validation: 2,
        // Nothing predicts a skill: it is admitted or it is not, and there is
        // no cheap signal that anticipates the verdict the way a training loss
        // anticipates an adapter's.
        predicted: false,
        fixed: 0,
        broke: 0,
        mcnemar: 0.0,
        j1: v.j1,
        j1_why: v.j1_why,
        goals_held: if v.j2 { 1 } else { 0 },
        goals_total: 1,
        j2: v.j2,
        j3: v.j3,
        j3_why: v.j3_why,
        // Steps stand in for resident bytes: both are "what it costs to have",
        // measured in the unit that matters for the kind of thing it is.
        resident_kib: (v.steps / 1024) as usize,
        rank: 0,
        j4: v.j4,
        epochs: 0,
        capped: false,
        adopted: false,
        test_acc: 0.0,
        test_read: 0,
        test_fresh: true,
        // Every trial before U3 is a weights/rule/core/skill/deep trial, and
        // none of them touch the criterion, so the matrix is absent and the
        // certificate renders exactly as it always did.
        cross: None,
    };
    cert.adopted = cert.unanimous();

    if cert.adopted {
        let path = super::skill::adopted_path(h);
        if !sysbox::write_text(&path, &src) {
            return Err("it passed and the toolkit would not take it");
        }
        variant.store();
        set_head(&vhash);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    Ok(cert)
}

/// How much better the confident items must get before a rule is worth
/// changing for.
///
/// Five points of separation. The measured baseline is 90.3% right when the
/// three agree against 50% when they split -- a gap of about 0.40 -- so this
/// is roughly an eighth of the signal, which is large enough not to be
/// chasing validation noise on 180 items and small enough to be reachable.
/// It is a decision and not a derivation, and the certificate records the
/// gaps themselves so a later reader can apply a different one.
pub const MIN_CAL_GAIN: f32 = 0.05;

/// How much of its confidence a candidate may give up while claiming to have
/// improved it. Four fifths: a rule that is beautifully calibrated over six
/// items has not improved the router, it has stopped answering.
const MIN_CONF_KEEP: f32 = 0.8;

/// Judge a routing rule on what it actually changes.
///
/// **The one axis where accuracy is the wrong judge, which is why it sat
/// unsearchable behind a comment for so long.** Every other proposal is
/// selected by J1 -- a net repair beyond the noise -- and a rule change is
/// mostly not that. What it moves is *calibration*: how much better the
/// council's confident answers are than its unconfident ones, which is the
/// property the whole three-core arrangement exists to produce. A router that
/// knows when it is guessing can ask, escalate or refuse; one that is silently
/// 78% accurate cannot.
///
/// So the two judges point in different directions on purpose:
///
///   J1  **do no harm.** The candidate must not lose accuracy beyond the
///       noise. Not "must win" -- requiring a win here is exactly what made
///       this axis unsearchable, because a rule that trades a point of
///       accuracy for a much sharper confidence signal is a trade worth
///       making and J1 as written would veto it.
///   J2  **must improve.** The confidence gap has to widen by `MIN_CAL_GAIN`,
///       and the confident set must not collapse. Something has to get better
///       or this is drift with a certificate.
///
/// J3 is the arithmetic that keeps the comparison meaningful, and J4 is free:
/// a rule costs no resident bytes, which is the honest answer rather than a
/// judge invented to fill the slot.
pub fn trial_config(e: &mut super::Engine, rule: u8) -> Result<Certificate, &'static str> {
    let Some(candidate) = super::harness::Rule::from_u8(rule) else {
        return Err("no such routing rule");
    };
    let v = super::harness::rule_bench(e, candidate)
        .map_err(|_| "the router would not fit, or there is nothing to judge on")?;
    TRIALS.fetch_add(1, Ordering::Relaxed);

    // J1: did it lose anything it should not have?
    //
    // Two ways to fail, and the first was missing. Written as "not
    // significantly worse" alone, this adopted `ProbeOnly` on a measured
    // `fixed 4 broke 10` -- a net loss of six items out of 180 -- because chi
    // reached only 1.79 against a threshold of 3.84. Significance is a poor
    // guard in the losing direction on a slice this size: a real loss can sit
    // under it comfortably.
    //
    // So the floor is symmetric with the one the adapter path uses to call a
    // *gain* real. `MIN_FIXED` says a net repair under four is not a repair;
    // it says just as well that a net loss over four is not nothing.
    let net_loss = v.broke.saturating_sub(v.fixed);
    let lost = net_loss >= MIN_FIXED || (v.broke > v.fixed && v.chi >= MCNEMAR_95);
    let j1 = !lost;
    let j1_why = if lost { "it costs accuracy" } else { "accuracy is unchanged beyond noise" };

    // J2: did the thing this axis is for actually improve?
    let kept = v.conf_now as f32 >= v.conf_was as f32 * MIN_CONF_KEEP;
    let j2 = v.gain() >= MIN_CAL_GAIN && kept;

    // J3: a comparison over nothing is not a comparison.
    let (j3, j3_why) = if v.n == 0 {
        (false, "no validation decisions")
    } else if v.conf_now == 0 || v.conf_was == 0 {
        (false, "one of the rules never claims confidence")
    } else {
        (true, "both rules answer and both claim confidence")
    };

    let parent = ensure_head(e);
    let carried = parent.and_then(|p| Variant::load(&p));
    let variant = Variant {
        parent,
        adapter: carried.as_ref().and_then(|x| x.adapter),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: carried.as_ref().and_then(|x| x.skills),
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        deep: carried.as_ref().map(|x| x.deep).unwrap_or(false),
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        lambda: 0.0,
        rank: 0,
        epochs: 0,
        rule,
        // The bar in force when this variant was measured, so a later reader
        // can interpret the lineage under the criterion it actually ran, not
        // the one running now. `trial_judge` is the exception and sets the bar
        // it adopts.
        threshold: judge_in_force(),
        floor: floor_in_force(),
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vhash = variant.hash();

    let mut cert = Certificate {
        parent,
        variant: vhash,
        decisions: v.n,
        validation: v.n,
        // The cheap signal is the gap itself, known before the judges run.
        predicted: v.gain() > 0.0,
        fixed: v.fixed,
        broke: v.broke,
        mcnemar: v.chi,
        j1,
        j1_why,
        // Confident items, before and after -- the coverage half of J2, in the
        // two fields shaped to carry a "held out of total".
        goals_held: v.conf_now,
        goals_total: v.conf_was,
        j2,
        j3,
        j3_why,
        // A rule is a number. Saying it costs kilobytes would be inventing a
        // judge to fill a slot.
        resident_kib: 0,
        rank: 0,
        j4: true,
        epochs: 0,
        capped: false,
        adopted: false,
        test_acc: 0.0,
        test_read: 0,
        test_fresh: true,
        // Every trial before U3 is a weights/rule/core/skill/deep trial, and
        // none of them touch the criterion, so the matrix is absent and the
        // certificate renders exactly as it always did.
        cross: None,
    };
    cert.adopted = cert.unanimous();

    if cert.adopted {
        let cfg = super::harness::Config {
            lambda: super::harness::default_lambda(),
            rule: candidate,
        };
        if !super::harness::save_config(cfg) {
            return Err("it passed and the configuration would not save");
        }
        variant.store();
        set_head(&vhash);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    Ok(cert)
}

// --- U3: unbinding the judge ------------------------------------------------
//
// Every axis above proposes a change to what the machine *is* and is selected
// by J1-J4. This one proposes a change to what "better" *means* -- the J1
// significance bar itself -- and so cannot be selected by J1, which would be
// the criterion grading its own replacement. What judges it instead is the
// construction 2607.05904 ("More Convincing, Not More Correct") arrives at from
// the opposite direction: a judge scores plausibility, not correctness, so
// self-play can drive a judge's pass-rate up while true accuracy stays flat,
// and the paper finds that even a strict three-judge ensemble accepts 55% of
// the hacked answers -- scoring-level defences do not survive. What does survive
// is a held-out anchor the judge never sees. Here the anchor is already present
// and already budgeted: routing accuracy on the test slice, scored against
// ground-truth applet labels rather than any judge's opinion. A bar change is
// admitted only when the variant it newly admits moves that anchor the way the
// bar says it should. The cross-evaluation matrix is the readout; the anchor is
// what makes the readout evidence.

/// The reference candidate a judge-trial probes both bars with.
///
/// Fixed knobs -- the incumbent grid point -- so the matrix isolates the bar:
/// the same candidate is scored against the standing bar and the proposed one,
/// and nothing about *which* adapter it is can move between the two cells. It is
/// a probe, never adopted; a judge-change adopts a number, not this adapter.
fn judge_reference() -> Proposal {
    GRID[0]
}

/// The whole cross-evaluation, as numbers, computed but not recorded.
pub struct CrossEval {
    pub tau_old: f32,
    pub tau_new: f32,
    pub floor_old: usize,
    pub floor_new: usize,
    /// The reference candidate's paired counts against the incumbent, on the
    /// validation slice -- the evidence both bars weigh.
    pub fixed: usize,
    pub broke: usize,
    pub chi: f32,
    pub admit_old: bool,
    pub admit_new: bool,
    /// The held-out anchor: ground-truth routing accuracy for the incumbent and
    /// the candidate. The gain between them is what grounds the whole thing.
    pub anchor_inc: f32,
    pub anchor_cand: f32,
    pub anchor_reads: u32,
    pub anchor_fresh: bool,
    pub decisions: usize,
    pub validation: usize,
}

impl CrossEval {
    pub fn anchor_gain(&self) -> f32 {
        self.anchor_cand - self.anchor_inc
    }
    pub fn verdict(&self) -> (bool, &'static str) {
        judge_verdict(
            self.tau_new,
            self.floor_new,
            self.admit_old,
            self.admit_new,
            self.anchor_gain(),
        )
    }
}

/// Whether a proposed criterion should be adopted, and why.
///
/// The criterion is the pair `(bar, floor)` and either half may move. Only the
/// sanity question had to learn about the second half: "moves" and "honest"
/// read `admit_old`, `admit_new` and the anchor, which are answers about the
/// candidate rather than about which knob produced them, so the drift check
/// that is the whole point of the axis cost nothing to generalise.
///
/// A pure function of the matrix, so every one of its outcomes is asserted at
/// boot without a model, the way `update::decide` is. Three questions, and the
/// middle one is the whole of U3:
///
///   sane   -- the bar is a finite number inside `[JUDGE_MIN, JUDGE_MAX]`. A
///             bar of zero abolishes the criterion; one too high freezes the
///             loop. Both are refused here rather than adopted and discovered
///             later as a machine that never changes or never stops.
///   moves  -- the two criteria actually disagree about the candidate. One that
///             admits and refuses exactly what the standing one did has changed
///             nothing, and adopting it would be a certificate with no content
///             -- the same "improved nothing" refusal the rule axis makes.
///   honest -- the change agrees with the anchor no bar can see. A looser bar
///             is admitted only if the variant it newly admits genuinely
///             improves held-out accuracy; a tighter bar only if the variant it
///             newly refuses genuinely did not. A bar that pleases itself while
///             the anchor does not move is criterion drift wearing a
///             certificate, and this is the line that catches it.
pub fn judge_verdict(
    tau_new: f32,
    floor_new: usize,
    admit_old: bool,
    admit_new: bool,
    anchor_gain: f32,
) -> (bool, &'static str) {
    if !(tau_new.is_finite() && tau_new >= JUDGE_MIN && tau_new <= JUDGE_MAX) {
        return (false, "the proposed bar is outside sane range");
    }
    // The floor is sanity-checked on the same terms and for the same two
    // failures: under `FLOOR_MIN` the effect-size requirement is abolished and
    // any single repair passes, above `FLOOR_MAX` no night can clear it and
    // the loop silently freezes.
    if !(FLOOR_MIN..=FLOOR_MAX).contains(&floor_new) {
        return (false, "the proposed floor is outside sane range");
    }
    if admit_old == admit_new {
        return (false, "both bars agree on the candidate, nothing changes");
    }
    if admit_new && !admit_old {
        // Loosening: the proposed bar admits what the standing one refused. Only
        // honest if the anchor confirms the newly-admitted variant is better.
        if anchor_gain >= MIN_ANCHOR_GAIN {
            (true, "a looser bar admits a variant the anchor confirms")
        } else {
            (false, "drift: a looser bar admits a variant the anchor rejects")
        }
    } else {
        // Tightening: the proposed bar refuses what the standing one admitted.
        // Honest only if that variant was not a genuine gain in the first place.
        if anchor_gain < MIN_ANCHOR_GAIN {
            (true, "a tighter bar refuses a variant the anchor did not support")
        } else {
            (false, "a tighter bar would refuse a genuine gain")
        }
    }
}

/// Compute the cross-evaluation matrix for one proposed bar.
///
/// Prepares a trial once (the expensive half), trains the reference candidate,
/// scores it against both bars, and reads the anchor for the incumbent and the
/// candidate. Reading the anchor spends the test budget, because for a
/// judge-trial the anchor *is* the evidence rather than an after-the-fact
/// confirmation -- so once the budget is gone a criterion change cannot be
/// grounded at all, which is the intended shape: unbinding the judge is not
/// free, and its price is the one non-renewable resource in the building.
pub fn cross_matrix(
    e: &mut super::Engine,
    tau_new: f32,
    floor_new: usize,
    examples: usize,
    millis: u64,
) -> Result<CrossEval, Refused> {
    let (tau_old, floor_old) = (judge_in_force(), floor_in_force());
    let tb = judge_reference().budget(examples, millis);
    let t = super::train::prepare(e, &tb).map_err(Refused::Train)?;
    let incumbent = e.model.adapters.as_ref().and_then(|a| t.gather(a));
    let fit = t.train(&tb);
    let (broke, fixed, _, _) = t.paired(incumbent.as_ref(), Some(&fit.dora), Slice::Validation);
    let chi = mcnemar(broke, fixed);
    // J1 exactly, parameterised by the whole criterion. This is the one place
    // the criterion is a variable rather than the one `trial` reads, and it
    // calls the same function every other J1 site does so the two cannot drift
    // into disagreeing about what admission means.
    let admit = |tau: f32, floor: usize| j1_admits_at(tau, floor, fixed, broke, chi);
    let anchor_inc = t.score(incumbent.as_ref(), Slice::Test);
    let anchor_cand = t.score(Some(&fit.dora), Slice::Test);
    let reads = spend_test_read();
    Ok(CrossEval {
        tau_old,
        tau_new,
        floor_old,
        floor_new,
        fixed,
        broke,
        chi,
        admit_old: admit(tau_old, floor_old),
        admit_new: admit(tau_new, floor_new),
        anchor_inc,
        anchor_cand,
        anchor_reads: reads,
        anchor_fresh: reads <= TEST_READS,
        decisions: t.decisions(),
        validation: t.slice_size(Slice::Validation),
    })
}

/// Run a judge-trial to a certificate: move the bar, or refuse and say why.
///
/// The adopted object is the *bar*, carried on a variant that keeps everything
/// else from the parent -- adapter, core, rule -- exactly as `trial_config`
/// adopts a rule. The reference candidate is a probe and is never stored; a
/// judge-change adopts a number.
pub fn trial_judge(
    e: &mut super::Engine,
    tau_new: f32,
    floor_new: usize,
    b: &Budget,
) -> Result<Certificate, Refused> {
    // Refuse before paying for a prepare if the anchor is already spent. A
    // criterion change grounded on a stale anchor is exactly what this axis
    // must never do, so it does not even measure one it could not quote.
    if test_reads() >= TEST_READS {
        return Err(Refused::Judge(
            "the anchor budget is spent, so a bar change cannot be grounded",
        ));
    }
    Proposal::judge(tau_new, floor_new).mark();
    let ce = cross_matrix(e, tau_new, floor_new, b.examples, b.millis)?;
    TRIALS.fetch_add(1, Ordering::Relaxed);

    let (blessed, why) = ce.verdict();
    // Even a blessed change is refused on a stale anchor -- the read may have
    // crossed the budget while this trial ran.
    let adopted = blessed && ce.anchor_fresh;

    let parent = ensure_head(e);
    let carried = parent.and_then(|p| Variant::load(&p));
    let variant = Variant {
        parent,
        adapter: carried.as_ref().and_then(|x| x.adapter),
        policy: sysbox::read_blob("/ai/agent/policy").map(|p| sha256::hash(&p)),
        skills: carried.as_ref().and_then(|x| x.skills),
        corpus: sysbox::hash_of(super::vocab::CORPUS),
        deep: carried.as_ref().map(|x| x.deep).unwrap_or(false),
        core: super::voter::installed().map(|c| c.hash),
        core_seen: true,
        lambda: carried.as_ref().map(|x| x.lambda).unwrap_or(0.0),
        rank: carried.as_ref().map(|x| x.rank).unwrap_or(0),
        epochs: carried.as_ref().map(|x| x.epochs).unwrap_or(0),
        rule: super::harness::rule_in_force() as u8,
        // The two fields this trial moves. Either may be the one that
        // actually changed; the variant records both so a later reader does
        // not have to infer which from the certificate.
        threshold: tau_new,
        floor: floor_new,
        born: crate::dev::rtc::now().map(|d| crate::dev::rtc::unix_seconds(&d)).unwrap_or(0),
    };
    let vhash = variant.hash();

    let cross = CrossLine {
        tau_old: ce.tau_old,
        tau_new: ce.tau_new,
        floor_old: ce.floor_old,
        floor_new: ce.floor_new,
        admit_old: ce.admit_old,
        admit_new: ce.admit_new,
        anchor_inc: ce.anchor_inc,
        anchor_cand: ce.anchor_cand,
    };
    // The four J-bools are the sub-checks of the one verdict, mapped so
    // `unanimous`/adoption still reads them: j1 is that the bars disagree, j2
    // that the anchor supports the direction, j3 that the bar is sane, j4 free.
    // The renderers branch on `cross` and print the matrix instead of these
    // labels, so the mapping is for the adoption logic, not for the reader.
    let bars_move = ce.admit_old != ce.admit_new;
    let sane = tau_new.is_finite()
        && tau_new >= JUDGE_MIN
        && tau_new <= JUDGE_MAX
        && (FLOOR_MIN..=FLOOR_MAX).contains(&floor_new);
    let cert = Certificate {
        parent,
        variant: vhash,
        decisions: ce.decisions,
        validation: ce.validation,
        predicted: ce.anchor_gain() > 0.0,
        fixed: ce.fixed,
        broke: ce.broke,
        mcnemar: ce.chi,
        j1: bars_move,
        j1_why: why,
        goals_held: 0,
        goals_total: 0,
        j2: blessed,
        j3: sane,
        j3_why: if sane { "ok" } else { "the criterion is outside sane range" },
        resident_kib: 0,
        rank: 0,
        j4: true,
        epochs: 0,
        capped: false,
        adopted,
        test_acc: ce.anchor_cand,
        test_read: ce.anchor_reads,
        test_fresh: ce.anchor_fresh,
        cross: Some(cross),
    };

    if adopted {
        // The floor first, then the bar. Writing one and failing the other
        // leaves a criterion that is half of what the judges blessed, so the
        // half that can be put back cheaply goes first: a failed bar write
        // restores the floor before returning, and neither is in force.
        if !save_floor(floor_new) {
            return Err(Refused::Judge("it passed and the new floor would not save"));
        }
        if !save_judge(tau_new) {
            let _ = save_floor(ce.floor_old);
            return Err(Refused::Judge("it passed and the new bar would not save"));
        }
        variant.store();
        set_head(&vhash);
        ADOPTIONS.fetch_add(1, Ordering::Relaxed);
    }

    let hour = crate::dev::rtc::now().map(|d| d.hour).unwrap_or(0);
    let seq = TRIALS.load(Ordering::Relaxed);
    record(&cert, seq, hour);
    Ok(cert)
}

// --- The illumination archive (MAP-Elites) ----------------------------------
//
// The loop climbed. `frontier` walked a declared grid toward one best variant,
// `head` named it, and the lineage was a single chain -- which is hill-climbing,
// and Heuresis (2606.25198) measures what that costs: across 3,222 runs a greedy
// top-K search collapses diversity, while MAP-Elites keeps the best occupant of
// every *cell* of a behaviour grid and wins diversity outright while tying on
// quality. So the archive keeps not the single best mind but the best mind of
// each *kind*, and the search fills empty cells rather than climbing.
//
// It changes nothing about the record. A cell holds a variant already in the
// content-addressed DAG, its fitness is a number the trial already measured, and
// the whole archive is a function of the ledger -- re-derivable by replaying it,
// which is why the stored cells are a cache and never the truth. `head` still
// means "what is attached and running"; the archive is the map of everything
// that was ever good at something, laid beside it.

/// Where the archive's cells live, one small text blob per cell.
pub const ARCHIVE: &str = "/ai/godel/archive";

/// Capacity bins and behaviour bins. 4x3 = 12 cells.
///
/// One axis the search *controls* -- rank, the adapter's capacity -- and one it
/// only *observes*: the repair profile, how the variant spends its changes
/// between fixing and breaking decisions. That split is the point of a MAP: the
/// controllable axis is what `next_map` steers along to reach empty ground, and
/// the emergent axis is what makes two variants at the same rank different kinds
/// of mind rather than two tries at one.
pub const RANK_BINS: usize = 4;
pub const REPAIR_BINS: usize = 3;

/// Which cell a variant lands in, from facts a trial already has.
///
/// Rank straight off the proposal; the repair profile from the paired counts
/// the judges read. A variant that only breaks decisions and one that only
/// fixes them are different behaviours even at identical accuracy, and a grid
/// that could not tell them apart would illuminate nothing.
pub fn descriptor(rank: usize, fixed: usize, broke: usize) -> (usize, usize) {
    let r = if rank <= 4 {
        0
    } else if rank <= 8 {
        1
    } else if rank <= 16 {
        2
    } else {
        3
    };
    let total = fixed + broke;
    let b = if total == 0 {
        1 // touched nothing on net: the middle, "balanced", by convention
    } else {
        let frac = fixed as f32 / total as f32;
        if frac < 0.34 {
            0
        } else if frac < 0.67 {
            1
        } else {
            2
        }
    };
    (r, b)
}

fn cell_path(a: usize, b: usize) -> String {
    let mut p = String::from(ARCHIVE);
    p.push('/');
    push_u32(&mut p, a as u32);
    p.push('-');
    push_u32(&mut p, b as u32);
    p
}

/// One cell's occupant: the best variant of its kind, and its fitness.
#[derive(Clone, Copy)]
pub struct Elite {
    pub variant: [u8; 32],
    pub fitness: f32,
}

fn read_cell(a: usize, b: usize) -> Option<Elite> {
    let bytes = sysbox::read_blob(&cell_path(a, b))?;
    let text = core::str::from_utf8(&bytes).ok()?;
    let mut variant = None;
    let mut fitness = 0.0f32;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("hash"), Some(h)) => variant = from_hex32(h),
            (Some("fit"), Some(f)) => fitness = f.parse().unwrap_or(0.0),
            _ => {}
        }
    }
    variant.map(|variant| Elite { variant, fitness })
}

/// Offer a variant to its cell. It becomes the elite only if the cell is empty
/// or it beats the occupant's fitness -- the whole of MAP-Elites in one rule.
///
/// Returns whether the archive changed, so a trial can say it lit a new cell.
/// Ties keep the incumbent, because the first to reach a fitness got there on
/// fewer nights and re-deriving the archive must land on the same occupant.
pub fn archive_insert(variant: &[u8; 32], rank: usize, fixed: usize, broke: usize, fitness: f32) -> bool {
    let (a, b) = descriptor(rank, fixed, broke);
    if let Some(cur) = read_cell(a, b) {
        if fitness <= cur.fitness {
            return false;
        }
    }
    let mut s = String::from("hash ");
    s.push_str(&hex32(variant));
    s.push_str("\nfit ");
    push_f2(&mut s, fitness);
    s.push('\n');
    sysbox::write_text(&cell_path(a, b), &s);
    true
}

/// Whether a candidate *would* take its cell, without writing anything.
///
/// The storm asks this before paying for a variant: storing a node and an
/// adapter blob for every member of a generation would be chaff in the DAG,
/// and only the candidates the archive will actually hold -- plus the one the
/// judges see -- earn an address.
pub fn archive_peek(rank: usize, fixed: usize, broke: usize, fitness: f32) -> bool {
    let (a, b) = descriptor(rank, fixed, broke);
    match read_cell(a, b) {
        None => true,
        Some(cur) => fitness > cur.fitness,
    }
}

/// Every occupied cell, for display and for the coverage/QD figures.
pub fn archive_cells() -> Vec<(usize, usize, Elite)> {
    let mut out = Vec::new();
    for a in 0..RANK_BINS {
        for b in 0..REPAIR_BINS {
            if let Some(e) = read_cell(a, b) {
                out.push((a, b, e));
            }
        }
    }
    out
}

/// The two figures every MAP-Elites run reports: how much of the space is lit,
/// and the summed quality of the frontier. Coverage says the search is
/// exploring; QD-score says the cells it found are worth holding.
pub fn archive_stats() -> (usize, usize, f32) {
    let cells = archive_cells();
    let qd: f32 = cells.iter().map(|(_, _, e)| e.fitness).sum();
    // Summing nothing yields negative zero here, which prints as "-0" and reads
    // as a score that went slightly wrong rather than one that has not started.
    let qd = if qd == 0.0 { 0.0 } else { qd };
    (cells.len(), RANK_BINS * REPAIR_BINS, qd)
}

/// The rank whose bin is least explored, for `next_map` to steer toward.
///
/// "Least explored" is the fewest occupied repair-cells in that rank column, so
/// the search reaches for capacity levels it has illuminated least rather than
/// walking a list in order. Ties break toward lower rank, which is cheaper to
/// carry -- the same cheap-before-expensive rule the rotation obeys.
fn sparsest_rank() -> Option<usize> {
    let mut counts = [0usize; RANK_BINS];
    for (a, _, _) in archive_cells() {
        counts[a] += 1;
    }
    (0..RANK_BINS).min_by_key(|&a| counts[a])
}

/// A representative rank for each bin, for turning a target cell back into a
/// proposal. The lower edge of the bin, so `next_map` proposes the cheapest
/// capacity that lands in the column it wants to fill.
fn rank_for_bin(a: usize) -> usize {
    match a {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => 32,
    }
}

/// The illumination-driven adapter proposal: aim at the sparsest capacity
/// column instead of walking the grid in order.
///
/// It reads only the archive, so like every other proposal source it is a
/// function of the record and re-derivable. When the archive already spreads
/// evenly it answers `None` and `frontier` falls back to the declared grid, so
/// this never *removes* a point the grid would have tried -- it only reorders
/// the search toward empty ground, which is exactly the MAP-Elites bias toward
/// unfilled cells.
fn next_map() -> Option<Proposal> {
    let a = sparsest_rank()?;
    let rank = rank_for_bin(a);
    let p = Proposal {
        lr: 0.02,
        rank,
        alpha: (rank * 2) as f32,
        epochs: 20,
        rule: 0,
        kind: ProposalKind::Adapter,
    };
    if p.tried() {
        None
    } else {
        Some(p)
    }
}

// --- The storm: one prepare, a whole generation ------------------------------
//
// The whole economy of this module rests on one fact the trainer states and
// nothing had ever pushed to its limit: below the classifier the hidden state
// at every decision is a constant, cached once, and an epoch after that costs
// no forward passes at all. Every trial in this tree's history paid the
// expensive half -- a forward pass per example -- to train exactly ONE
// candidate on the cache it bought. The storm pays it once and trains a
// generation: every point of a declared grid spanning the whole capacity axis,
// continuations of the incumbent through the warm-start `train_masked` already
// had, and chimeras bred from same-rank pairs that cost no training at all.
// A dozen minds for the price of one and a few dozen optimiser passes.
//
// What it does NOT change is the tribunal. Every candidate is scored and
// offered to the archive -- the MAP-Elites turn, which is how one storm can
// light half the map -- but exactly one, the best on validation, goes before
// the judges, through the same `adjudicate` a single trial uses. The judges
// cannot tell which door it came through. The multiple-comparisons cost of
// picking a maximum over a generation is real and is paid where the module
// always pays it: selection happens on validation, the test slice stays
// behind its budget, and the anchor is read only if the winner is adopted.
//
// And it is an operator command, not (yet) the night's move. The initiative
// tick is bounded for stated reasons, and a storm's wall time on the GF63 is a
// number nobody has measured; wiring an unmeasured cost into the unattended
// loop is the exact mistake `power.rs` and the tick budget exist to refuse.

/// The generation: declared like `GRID`, in the order it is trained, spanning
/// every rank bin so one storm illuminates the whole capacity axis.
const STORM: &[(f32, usize, f32, usize)] = &[
    (0.02, 4, 8.0, 20),
    (0.05, 4, 8.0, 20),
    (0.02, 8, 16.0, 20),
    (0.05, 8, 16.0, 20),
    (0.01, 8, 16.0, 40),
    (0.02, 16, 32.0, 20),
    (0.05, 16, 32.0, 20),
    (0.02, 32, 64.0, 20),
];

/// Continuations of the incumbent: `(lr, epochs)` trained on top of what is
/// attached, through the warm start `train_masked` grew for the curriculum
/// work. Children of the reigning mind rather than orphans from zero.
const DESCENT: &[(f32, usize)] = &[(0.01, 10), (0.005, 20)];

/// The most pairs a storm will breed. Pairing is deterministic -- same-rank
/// pairs in generation order -- so which chimeras exist is re-derivable from
/// this file and the storm's inputs, like everything else the loop does.
const CHIMERA_CAP: usize = 6;

pub struct StormReport {
    pub trained: usize,
    pub descendants: usize,
    pub chimeras: usize,
    pub cells_lit: usize,
    pub best_fitness: f32,
    pub cert: Certificate,
}

/// One prepare, many minds: train the generation, breed the chimeras, offer
/// everything to the archive, and put the best before the four judges.
pub fn storm(
    e: &mut super::Engine,
    b: &Budget,
) -> Result<StormReport, super::train::RunError> {
    let t = super::train::prepare(e, b)?;
    TRIALS.fetch_add(1, Ordering::Relaxed);
    crate::kprintln!(
        "  prepared: {} examples, {} decisions, {} rows ({} ms + {} ms) -- one prepare, many minds",
        t.examples,
        t.decisions(),
        t.live_rows(),
        t.chains_ms,
        t.features_ms
    );
    let parent = ensure_head(e);
    let incumbent = e.model.adapters.as_ref().and_then(|a| t.gather(a));

    // Each candidate travels with the budget that describes its provenance --
    // the lr and epochs a later reader needs to re-derive it, and the rank and
    // alpha `adjudicate` will judge it under if it wins.
    let mut gen: Vec<(Fit, Budget)> = Vec::new();

    for &(lr, rank, alpha, epochs) in STORM {
        let p = Proposal { lr, rank, alpha, epochs, rule: 0, kind: ProposalKind::Adapter };
        // A storm point is a point tried: the nightly frontier must not spend
        // a night re-deriving what a storm already measured.
        p.mark();
        let tb = p.budget(b.examples, b.millis);
        let fit = t.train(&tb);
        gen.push((fit, tb));
    }
    let trained = gen.len();

    let mut descendants = 0usize;
    if let Some(inc) = incumbent.as_ref() {
        let mask = alloc::vec![true; crate::sysbox::APPLETS.len()];
        for &(lr, epochs) in DESCENT {
            let tb = Budget {
                epochs,
                millis: b.millis,
                examples: b.examples,
                lr,
                rank: inc.r,
                alpha: inc.alpha,
            };
            let fit = t.train_masked(&tb, Some(inc), &mask);
            gen.push((fit, tb));
            descendants += 1;
        }
    }

    // Chimeras, bred deterministically: same-rank pairs in generation order,
    // capped. A chimera's Fit records zero epochs and zero loss because it was
    // never trained -- the same honest zeros a core or a skill carries.
    let mut chimeras = 0usize;
    let n_parents = gen.len();
    'pairs: for i in 0..n_parents {
        for j in (i + 1)..n_parents {
            if chimeras >= CHIMERA_CAP {
                break 'pairs;
            }
            if gen[i].0.dora.r != gen[j].0.dora.r {
                continue;
            }
            let Some(child) = t.crossover(&gen[i].0.dora, &gen[j].0.dora) else { continue };
            let tb = Budget {
                epochs: 0,
                millis: 0,
                examples: b.examples,
                lr: 0.0,
                rank: child.r,
                alpha: child.alpha,
            };
            let fit = Fit {
                dora: child,
                first_loss: 0.0,
                last_loss: 0.0,
                epochs: 0,
                ms: 0,
                stopped: false,
            };
            gen.push((fit, tb));
            chimeras += 1;
        }
    }

    // Score everything on validation, offer what earns a cell to the archive,
    // and remember the best. Only cell-winners and the judged winner get an
    // address in the DAG: storing every member of a generation would be chaff,
    // and the archive must never name a hash with nothing behind it.
    let mut cells_lit = 0usize;
    let mut best = 0usize;
    let mut best_fitness = f32::NEG_INFINITY;
    for (i, (fit, tb)) in gen.iter().enumerate() {
        // A candidate with non-finite factors is offered nowhere. The judges
        // would catch it at J3; the archive has no judges, so the gate is here.
        if !sanity(&t, &fit.dora).0 {
            continue;
        }
        let fitness = t.score(Some(&fit.dora), Slice::Validation);
        let (broke, fixed, _, _) =
            t.paired(incumbent.as_ref(), Some(&fit.dora), Slice::Validation);
        if fitness > best_fitness {
            best_fitness = fitness;
            best = i;
        }
        if archive_peek(fit.dora.r, fixed, broke, fitness) {
            let adapters = t.scatter(&fit.dora, &e.model.cfg, tb.alpha);
            let blob = adapters.to_blob();
            let ablob = sha256::hash(&blob);
            let v = weight_variant(parent, ablob, tb.lr, fit.dora.r, fit.epochs as u32);
            sysbox::write_blob(&blob_path(&ablob), blob);
            let vh = v.store();
            if archive_insert(&vh, fit.dora.r, fixed, broke, fitness) {
                cells_lit += 1;
            }
        }
    }

    // The best of the storm faces the tribunal, through the same door a lone
    // candidate uses. If every candidate failed the sanity screen, `best` is
    // still the first one and J3 will say so on the record, which beats a
    // storm that can fail silently.
    let (win_fit, win_tb) = &gen[best];
    let cert = adjudicate(e, &t, win_tb, parent, incumbent.as_ref(), win_fit);
    Ok(StormReport { trained, descendants, chimeras, cells_lit, best_fitness, cert })
}

/// Put back the adapters a trial was handed, whatever it did to them.
fn restore(e: &mut super::Engine, saved: &Option<Vec<u8>>) {
    match saved {
        Some(bytes) => {
            let _ = e.model.load_adapters(bytes);
        }
        None => {
            let _ = e.model.detach_adapters();
        }
    }
}

pub fn rollback(e: &mut super::Engine) -> Result<Option<[u8; 32]>, &'static str> {
    let Some(h) = head() else { return Err("no head to roll back from") };
    let Some(v) = Variant::load(&h) else { return Err("head names a node that is not stored") };
    let Some(parent) = v.parent else {
        // The root is the frozen model. Rolling back to it means detaching,
        // which is a real state rather than an error.
        //
        // The core belongs to that detachment. A root node can carry one --
        // `trial_core` on a machine with no adapter attached gets `parent:
        // None` from `ensure_head` and records `core: Some(..)` on it -- and
        // this arm used to return `Ok(None)`, reporting a return to the frozen
        // model while a machine-written core went on voting on every routing
        // decision, with the head now deleted so nothing named it and a second
        // rollback could not reach it either.
        if v.core.is_some() && !drop_core() {
            return Err("the adopted core will not detach");
        }
        let _ = e.model.detach_adapters();
        sysbox::detach(HEAD);
        return Ok(None);
    };
    let Some(pv) = Variant::load(&parent) else { return Err("parent is not stored") };

    // --- read and validate, changing nothing ---------------------------

    let blob = match pv.adapter {
        None => None,
        Some(ab) => match sysbox::read_blob(&blob_path(&ab)) {
            None => return Err("the parent's adapter blob is gone"),
            Some(b) => Some(b),
        },
    };

    // What to do about the core, decided before anything moves.
    //
    // `pv.core == None` is only an instruction to uninstall when the parent
    // actually *said* so. Nodes written before the field existed parse the
    // same way, and reading those as "the parent had no core" meant that
    // rolling back an adapter on any older lineage quietly pulled a core out
    // of the decision path -- a change to what the machine does, made as a
    // side effect of undoing something else, and printed nowhere. When the
    // parent is silent the only core this rollback owns is the one the node
    // being left adopted; anything installed out of band is not ours to move.
    enum Core {
        Leave,
        Drop,
        Install([u8; 32]),
    }
    let want = if pv.core_seen {
        match pv.core {
            None => Core::Drop,
            Some(c) => Core::Install(c),
        }
    } else if v.core.is_some() {
        Core::Drop
    } else {
        Core::Leave
    };
    if let Core::Install(c) = want {
        if super::voter::load(&c).is_err() {
            return Err("the parent's core will not load");
        }
    }

    // The routing rule, when the two nodes disagree about it.
    //
    // Only then, and the guard is not caution -- it is correctness. Every node
    // renders a `rule` line, so unlike `core` there is no "absent" to detect;
    // but nodes written before this axis was searchable recorded 0, which is
    // `ProbeOnly`, while the machine that wrote them was running the default
    // `Majority`. Restoring a parent's rule unconditionally would therefore
    // switch a lineage full of legacy nodes to a rule none of them ever ran.
    // If the two agree there is nothing to put back.
    let rule_back = if v.rule != pv.rule {
        match super::harness::Rule::from_u8(pv.rule) {
            None => return Err("the parent names a routing rule this kernel does not have"),
            Some(r) => Some(r),
        }
    } else {
        None
    };

    // The bar, restored only when the two nodes disagree about it -- the same
    // guard `rule` needs and for the same reason. A node written before U3 has
    // the default bar, which renders nothing and parses back as `MCNEMAR_95`, so
    // two default nodes compare equal and nothing is put back; only a node
    // adopted under a moved bar differs from its parent, and rolling it back
    // restores the bar its parent actually ran under. Without this, undoing a
    // judge-trial's adoption would leave the loosened bar in force while the
    // lineage said it had been undone -- the pointer claiming one thing and the
    // criterion doing another, which is exactly the drift the whole axis exists
    // to keep on the record.
    let threshold_back = if (v.threshold - pv.threshold).abs() >= 0.005 {
        Some(pv.threshold)
    } else {
        None
    };
    // The floor, on identical terms and for the identical reason. Both halves
    // default to their constant and render nothing at it, so two pre-U3 nodes
    // compare equal and nothing is put back; only a node adopted under a moved
    // floor differs from its parent. Restoring unconditionally would push the
    // constant onto a lineage of legacy nodes that never recorded one, which is
    // the mistake `rule` records having made.
    let floor_back = if v.floor != pv.floor { Some(pv.floor) } else { None };

    // --- change things -------------------------------------------------

    // The adapter first: it is the half that can still fail on bytes we have
    // already proved are present, so a failure here leaves the machine exactly
    // as it was rather than half-rolled-back.
    match blob {
        None => {
            let _ = e.model.detach_adapters();
        }
        Some(b) => {
            e.model.load_adapters(&b).map_err(|_| "the parent's adapter will not load")?;
        }
    }
    if let Some(r) = rule_back {
        let cfg = super::harness::Config { lambda: super::harness::default_lambda(), rule: r };
        if !super::harness::save_config(cfg) {
            return Err("the adapter was restored but the routing rule will not save");
        }
    }
    if let Some(tau) = threshold_back {
        if !save_judge(tau) {
            return Err("the adapter was restored but the bar will not save");
        }
    }
    if let Some(f) = floor_back {
        if !save_floor(f) {
            return Err("the adapter was restored but the floor will not save");
        }
    }
    match want {
        Core::Leave => {}
        Core::Drop => {
            if !drop_core() {
                return Err("the adapter was restored but the core will not detach");
            }
        }
        Core::Install(c) => {
            if !super::voter::install(&c) {
                return Err("the adapter was restored but the parent's core will not install");
            }
        }
    }
    set_head(&parent);
    Ok(Some(parent))
}

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn counts() -> (u32, u32, u32) {
    (
        TRIALS.load(Ordering::Relaxed),
        ADOPTIONS.load(Ordering::Relaxed),
        test_reads(),
    )
}

pub fn ledger_tail(n: usize) -> Vec<String> {
    let Some(bytes) = sysbox::read_blob(LEDGER) else { return Vec::new() };
    let Ok(text) = String::from_utf8(bytes) else { return Vec::new() };
    let all: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let start = all.len().saturating_sub(n);
    all[start..].iter().map(|s| String::from(*s)).collect()
}

/// How many verdicts have been recorded. The rotation's clock.
pub fn ledger_len() -> usize {
    let Some(bytes) = sysbox::read_blob(LEDGER) else { return 0 };
    let Ok(text) = core::str::from_utf8(&bytes) else { return 0 };
    text.lines().filter(|l| !l.is_empty()).count()
}

/// Deep points, walked by markers exactly as `GRID` is.
///
/// Two, and small ones. A deep trial costs two full passes over the corpus
/// plus the training between them, so this is not a space to sweep -- it is
/// enough points to find out whether moving the attention path buys anything
/// on this corpus at all, which is a question with a cheap answer and an
/// expensive one and no middle.
const DEEP_GRID: &[(f32, usize, f32, usize)] = &[(0.02, 4, 8.0, 4), (0.01, 8, 16.0, 6)];

fn next_deep() -> Option<Proposal> {
    DEEP_GRID
        .iter()
        .map(|&(lr, rank, alpha, epochs)| Proposal::deep(lr, rank, alpha, epochs))
        .find(|p| !p.tried())
}

/// A routing rule that has not been judged yet, other than the one in force.
///
/// The rule already running is excluded rather than marked: judging it against
/// itself is a certificate saying nothing changed, which is true and is not
/// worth a night.
fn next_config() -> Option<Proposal> {
    let now = super::harness::rule_in_force() as u8;
    (0u8..4)
        .filter(|r| *r != now)
        .map(Proposal::config)
        .find(|p| !p.tried())
}

/// A program in the toolkit that has never been judged.
///
/// Scanned rather than queued, because `agent learn` writes straight into
/// `/ai/tools` and a queue would be a second record of the same fact. An
/// adopted skill is copied back there too and is skipped on the next pass by
/// its own marker, which is the marker doing what it is for.
fn next_skill() -> Option<Proposal> {
    for name in sysbox::children("/ai/tools") {
        if !name.ends_with(".ai&xi") {
            continue;
        }
        let mut path = String::from("/ai/tools/");
        path.push_str(&name);
        let Some(bytes) = sysbox::read_blob(&path) else { continue };
        let Ok(text) = core::str::from_utf8(&bytes) else { continue };
        let h = super::skill::store(text);
        let p = Proposal::skill(h);
        if !p.tried() {
            return Some(p);
        }
    }
    None
}

/// Candidate criteria the loop will try, as `(bar, floor)` pairs.
///
/// Declared and in fixed order for the reason every other grid here is: the
/// search is re-derivable from the markers rather than from a coin.
///
/// The shape of the list is the finding that produced it. It held two points
/// that moved only the bar, and a measurement showed the bar was not what was
/// binding: a candidate repairing 2 of 24 with none broken, anchor 52.2% to
/// 60.9%, was refused at every bar in range because `fixed - broke >= floor`
/// is evaluated before chi and 2 is under 4. So the first two points below
/// move the bar at the default floor, the next two move the floor at the
/// default bar, and the last moves both. Each axis of the criterion is
/// reachable alone, which is what makes a verdict attributable to one of them.
///
/// Loosening is the dangerous direction on both axes and the one the anchor
/// exists to police; tightening is included on both so the loop can also
/// *raise* its own criterion when the anchor says the current one lets noise
/// through.
const JUDGE_GRID: &[(f32, usize)] = &[
    (2.00, MIN_FIXED),
    (6.00, MIN_FIXED),
    (MCNEMAR_95, 2),
    (MCNEMAR_95, 6),
    (2.00, 2),
];

/// Trials in an epoch.
///
/// Red Queen (2606.26294) finds that co-evolving an evaluator alongside the
/// agent is only stable under *controlled utility evolution*: the criterion is
/// frozen within an epoch and may move only at a boundary. Otherwise the bar
/// chases each proposal it is meant to judge and the whole thing collapses into
/// an evaluator that says yes. So the loop improves the agent -- weights, rule,
/// core, skill -- within an epoch against a stable bar, and re-examines the bar
/// only at the boundary. Five, one turn of the other five axes, so an epoch is
/// "try each kind once, then look at the criterion."
pub const EPOCH_LEN: usize = 5;

/// Whether the loop stands at an epoch boundary, where the bar may move.
///
/// A function of the ledger length, so it is re-derivable like everything else
/// the rotation reads. Genesis is not a boundary: there is no agent to protect
/// and no epoch behind it to have improved anything.
pub fn at_epoch_boundary() -> bool {
    is_boundary(ledger_len())
}

/// Pure, so the boundary rule is pinned at boot without writing ledger lines.
fn is_boundary(n: usize) -> bool {
    n > 0 && n % EPOCH_LEN == 0
}

/// How far into the current epoch the loop is: `(position, length)`.
pub fn epoch_position() -> (usize, usize) {
    (ledger_len() % EPOCH_LEN, EPOCH_LEN)
}

/// A bar the loop has not judged yet, other than the one in force.
///
/// The bar already running is excluded rather than marked, the same as
/// `next_config`: judging a bar against itself is a certificate that nothing
/// changed, which is true and not worth a night.
fn next_judge() -> Option<Proposal> {
    // The Red Queen gate: the bar moves only at an epoch boundary. Within an
    // epoch this answers "spent" whatever the markers say, so the agent axes get
    // the epoch to themselves and improve against a criterion that does not move
    // underneath them.
    if !at_epoch_boundary() {
        return None;
    }
    let (tau_now, floor_now) = (judge_in_force(), floor_in_force());
    JUDGE_GRID
        .iter()
        .copied()
        // The criterion already running is excluded rather than marked, the
        // same as `next_config`: judging a criterion against itself is a
        // certificate that nothing changed, which is true and not worth a
        // night. Both halves have to differ for the point to be the one in
        // force, so moving either axis is still a candidate.
        .filter(|(t, f)| (*t - tau_now).abs() >= 0.005 || *f != floor_now)
        .map(|(t, f)| Proposal::judge(t, f))
        .find(|p| !p.tried())
}

/// How many kinds the rotation walks.
const KINDS: usize = 6;

/// Where the per-axis tallies live: attempts and adoptions, one small blob each.
pub const AXIS: &str = "/ai/godel/axis";

/// Which axis a kind belongs to, matching the rotation's slot numbers.
fn axis_of(kind: &ProposalKind) -> usize {
    match kind {
        ProposalKind::Adapter => 0,
        ProposalKind::Config(_) => 1,
        ProposalKind::Skill(_) => 2,
        ProposalKind::Deep => 3,
        ProposalKind::Judge(..) => 4,
        ProposalKind::Core(_) => 5,
    }
}

fn axis_path(i: usize) -> String {
    let mut p = String::from(AXIS);
    p.push('/');
    push_u32(&mut p, i as u32);
    p
}

fn read_axis(i: usize) -> (u32, u32) {
    let Some(bytes) = sysbox::read_blob(&axis_path(i)) else { return (0, 0) };
    let Ok(text) = core::str::from_utf8(&bytes) else { return (0, 0) };
    let (mut att, mut adopt) = (0u32, 0u32);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("att"), Some(v)) => att = v.parse().unwrap_or(0),
            (Some("adopt"), Some(v)) => adopt = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    (att, adopt)
}

/// Record one trial's outcome against its axis: an attempt always, an adoption
/// when the verdict adopted. These tallies are what the surprise order reads.
fn bump_axis(i: usize, adopted: bool) {
    let (att, adopt) = read_axis(i);
    let mut s = String::from("att ");
    push_u32(&mut s, att + 1);
    s.push_str("\nadopt ");
    push_u32(&mut s, adopt + if adopted { 1 } else { 0 });
    s.push('\n');
    sysbox::write_text(&axis_path(i), &s);
}

/// How uncertain the machine is about an axis's value, in [0, 1].
///
/// A Beta belief over the axis's adoption rate under a Laplace prior:
/// `rate = (adopt + 1) / (att + 2)`, so an untried axis reads as exactly a half.
/// Uncertainty is highest when the rate sits at a half -- the outcome of the
/// next trial there is least predictable, which under Bayesian surprise
/// (2507.00310) is where the expected epistemic shift is largest.
fn axis_uncertainty(att: u32, adopt: u32) -> f32 {
    let rate = (adopt as f32 + 1.0) / (att as f32 + 2.0);
    1.0 - (rate - 0.5).abs() * 2.0
}

/// The order to try axes in tonight, most uncertain first.
///
/// This replaces the round-robin start, and the trade is deliberate: fairness
/// for information. The round-robin gave every axis a turn in sequence; this
/// reaches first for the axis whose next verdict it can least predict, which is
/// the axis it stands to learn the most from. It stays re-derivable because the
/// tallies are a function of the record, and it stays total -- ties break by
/// slot -- so a later run reconstructs the same order rather than a plausible
/// one. Laplace smoothing keeps even a saturated axis above zero uncertainty,
/// so nothing is starved forever; it is only made to wait behind what is still
/// live.
fn surprise_order_of(stats: &[(u32, u32); KINDS]) -> [usize; KINDS] {
    let mut order = [0usize; KINDS];
    for (i, o) in order.iter_mut().enumerate() {
        *o = i;
    }
    order.sort_unstable_by(|&a, &b| {
        let ua = axis_uncertainty(stats[a].0, stats[a].1);
        let ub = axis_uncertainty(stats[b].0, stats[b].1);
        ub.partial_cmp(&ua).unwrap_or(core::cmp::Ordering::Equal).then(a.cmp(&b))
    });
    order
}

fn surprise_order() -> [usize; KINDS] {
    let mut stats = [(0u32, 0u32); KINDS];
    for (i, s) in stats.iter_mut().enumerate() {
        *s = read_axis(i);
    }
    surprise_order_of(&stats)
}

/// The next thing to try tonight, over every axis the loop can judge.
///
/// **A rotation and not a choice.** The night branch knew two jobs and godel
/// always won the tie, so the adapter grid was walked to exhaustion while
/// every other axis the judges can reach -- the routing rule, deep training, a
/// skill the agent compiled, a core the machine wrote -- was never tried
/// unattended at all. Widening it needed the judges first, which is why this
/// comes last.
///
/// The starting point is the number of verdicts already recorded, so the
/// rotation is a function of the ledger rather than of a coin or of a counter
/// that resets at boot. That matters for the same reason `frontier` walks a
/// declared grid: a later reader has to be able to say what the machine would
/// have done, and "it picked at random" is not an account of a night.
///
/// From the offset it takes the first kind that has work, so an exhausted axis
/// costs one skipped slot rather than an idle night, and the loop stops only
/// when every axis is out of moves.
///
/// Order is deliberate: cheap and declared before expensive and composed. A
/// grid point and a rule change are minutes; a deep trial is two passes over
/// the corpus and a composed core spends a dozen decodes writing something
/// that may not survive its first judge.
pub fn next_proposal() -> Option<Proposal> {
    // The epoch structure decides order before the rotation does. At a boundary
    // the bar is re-examined first -- improve-the-agent within an epoch,
    // update-the-utility at the boundary, in that order -- and off a boundary
    // `next_judge` answers None anyway, so within an epoch this is a no-op and
    // the agent axes rotate as before.
    if at_epoch_boundary() {
        if let Some(p) = next_judge() {
            return Some(p);
        }
    }
    // Surprise-ordered rather than round-robin: reach first for the axis whose
    // next verdict is least predictable. Off a boundary the judge axis answers
    // None, so it drops out of contention regardless of where the order puts it.
    for axis in surprise_order() {
        let candidate = match axis {
            0 => frontier(),
            1 => next_config(),
            2 => next_skill(),
            3 => next_deep(),
            4 => next_judge(),
            // The composed core is still last whatever the order says: making
            // its candidate costs a dozen decodes, so it is reached for only
            // when every cheaper axis is out of moves, never because it looks
            // uncertain.
            _ => continue,
        };
        if candidate.is_some() {
            return candidate;
        }
    }
    // The core axis, considered only after the rest are spent -- its cost is in
    // producing the candidate, so it cannot ride the surprise order.
    author_core()
}

/// Where the search stands, in the order it will actually reach for the axes.
///
/// One row per axis in surprise order -- name, attempts, adoptions, and whether
/// it has work -- so a reader sees not a fixed wheel but the order the tallies
/// produce tonight. The core is reported as "on demand" without being probed,
/// because finding out whether it has a candidate costs the dozen decodes that
/// composing one *is*: a command answering "what would you do tonight" must not
/// spend the night doing it.
pub fn axis_report() -> Vec<(&'static str, u32, u32, bool)> {
    const NAMES: [&str; KINDS] = ["adapter", "rule", "skill", "deep", "judge", "core"];
    let mut out = Vec::new();
    for &i in surprise_order().iter() {
        let (att, adopt) = read_axis(i);
        let has = match i {
            0 => frontier().is_some(),
            1 => next_config().is_some(),
            2 => next_skill().is_some(),
            3 => next_deep().is_some(),
            4 => next_judge().is_some(),
            // Not probed -- see the note above.
            _ => true,
        };
        out.push((NAMES[i], att, adopt, has));
    }
    out
}

/// The lineage of the current head, newest first.
pub fn lineage(limit: usize) -> Vec<([u8; 32], Option<[u8; 32]>)> {
    let mut out = Vec::new();
    let mut cur = head();
    while let Some(h) = cur {
        let Some(v) = Variant::load(&h) else { break };
        out.push((h, v.adapter));
        if out.len() >= limit {
            break;
        }
        cur = v.parent;
    }
    out
}

/// Report whether the test slice may still be spoken about.
///
/// The number itself is never withheld -- withholding it would just mean
/// somebody computes it another way and quotes it without the caveat. What is
/// withheld is the *claim*: after the budget is spent, a test figure is
/// reported as stale, with the count that made it stale attached.
pub fn test_status() -> (u32, u32, bool) {
    let used = test_reads();
    (used, TEST_READS, used < TEST_READS)
}

/// Consult the test slice, spending one read.
pub fn read_test(t: &Trial, dora: Option<&super::adapter::Dora>) -> (f32, u32, bool) {
    let n = spend_test_read();
    (t.score(dora, Slice::Test), n, n <= TEST_READS)
}

/// Eight hex characters of an address, for anything that has to fit on a line.
pub fn short_hex(h: &[u8; 32]) -> String {
    short(h)
}

/// Run a trial and print the certificate.
///
/// The whole certificate, including the judges that passed. A report that
/// only said why something was rejected would be a report nobody could argue
/// with, and the reason for writing these down is that they can be.
pub fn report_trial(b: &Budget) {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED, YELLOW};
    use crate::kprintln;

    console::set_color(YELLOW);
    kprintln!("[godel] trial");
    console::set_color(LTGRAY);

    let Some(p) = frontier() else {
        // Reachable only if 64 successive draws were all already tried, which
        // needs the ledger static while the markers are not -- so this is a
        // near-impossible branch rather than the old "the grid is spent, widen
        // it" that U1 made untrue. The wrong-and-rare message was worse than
        // either alone.
        kprintln!("  no untried draw in {} attempts", DRAW_TRIES);
        kprintln!("  the record is not changing but the markers are -- 'godel forget' clears them");
        return;
    };
    let (seen, all) = explored();
    kprintln!(
        "  point {} of {}: lr {}, rank {}, alpha {}, epochs {}",
        seen + 1,
        all,
        p.lr,
        p.rank,
        p.alpha,
        p.epochs
    );
    // The examples and the wall clock come from the caller; everything that
    // decides what the weights become comes from the proposal.
    let b = &p.budget(b.examples, b.millis);
    let outcome = super::with_engine(|e| trial(e, b, &p));
    let c = match outcome {
        None => {
            kprintln!("  no engine, or another task holds it");
            return;
        }
        Some(Err(_)) => {
            kprintln!("  no trial: the trainer refused (hardware, corpus or checkpoint)");
            return;
        }
        Some(Ok(c)) => c,
    };

    kprintln!(
        "  variant {} from {}",
        short_hex(&c.variant),
        c.parent.map(|h| short_hex(&h)).unwrap_or(String::from("the frozen model"))
    );
    kprintln!("  {} decisions, {} in validation", c.decisions, c.validation);
    kprintln!(
        "  predicted {} from training-set gain (nothing acts on this yet)",
        if c.predicted { "a win" } else { "a loss" }
    );

    let mark = |p: bool| if p { "pass" } else { "VETO" };
    if c.validation == 0 {
        kprintln!("  J1 margin    VETO  {} -- ask for more examples", c.j1_why);
    } else {
        kprintln!(
            "  J1 margin    {}  {} repaired, {} broken of {}, chi {} ({})",
            mark(c.j1),
            c.fixed,
            c.broke,
            c.validation,
            (c.mcnemar * 100.0) as u32 as f32 / 100.0,
            c.j1_why
        );
    }
    kprintln!(
        "  J2 own goals {}  {}/{} still route where they did",
        mark(c.j2),
        c.goals_held,
        c.goals_total
    );
    kprintln!("  J3 sanity    {}  {}", mark(c.j3), c.j3_why);
    if c.capped {
        kprintln!(
            "  {} epochs, ended by the wall-clock cap: this verdict will not",
            c.epochs
        );
        kprintln!("  re-derive on a machine of a different speed");
    } else {
        kprintln!("  {} epochs, ended by the epoch count", c.epochs);
    }
    kprintln!(
        "  J4 cost      {}  rank {}, {} KiB resident",
        mark(c.j4),
        c.rank,
        c.resident_kib
    );

    if c.adopted {
        console::set_color(LTGREEN);
        kprintln!("  adopted -- all four agreed, and the parent is still addressed");
        console::set_color(LTGRAY);
        // Read after winning, never to decide the winner.
        if c.test_fresh {
            kprintln!(
                "  test slice {}% -- read {} of {}",
                (c.test_acc * 100.0) as u32,
                c.test_read,
                TEST_READS
            );
        } else {
            console::set_color(YELLOW);
            kprintln!(
                "  test slice {}% -- read {}, past its budget of {}: STALE, do not quote it",
                (c.test_acc * 100.0) as u32,
                c.test_read,
                TEST_READS
            );
            console::set_color(LTGRAY);
        }
        kprintln!("  'godel rollback' undoes it for the cost of a pointer write");
    } else {
        console::set_color(YELLOW);
        kprintln!("  rejected -- unanimity is required, and it was not unanimous");
        console::set_color(LTGRAY);
    }
    let _ = LTRED;
}

/// Boot self-test. Seven claims, none needing a model or a quiet window.
///
/// What is checked here is the machinery that decides whether the machine may
/// change itself -- the window arithmetic, the statistic, and the content
/// addressing that makes a lineage un-rewritable. None of it involves a
/// forward pass, which is the point: the expensive half of a trial is
/// evidence, and evidence is not what these claims are about.
pub fn selftest() -> bool {
    use crate::kprintln;

    let mut ok = true;
    let mut claim = |what: &str, pass: bool| {
        if !pass {
            ok = false;
        }
        kprintln!("  {}  {}", if pass { "ok " } else { "FAIL" }, what);
    };

    // A window that does not wrap, and one that does. The wrapping case is
    // the whole reason this is a function: `from <= h < until` would permit
    // nothing at all for 22:00-04:00, silently, forever.
    let (from, until) = window();
    claim(
        "the quiet window admits its own hours and refuses the rest",
        in_window(from) && !in_window(until) && !in_window((until + 6) % 24),
    );

    let wraps = |h: u8| {
        let (f, u) = (22u8, 4u8);
        if f <= u {
            h >= f && h < u
        } else {
            h >= f || h < u
        }
    };
    claim(
        "a window across midnight admits 23:00 and 01:00, not 12:00",
        wraps(23) && wraps(1) && !wraps(12),
    );

    // The statistic, on cases whose answers are arithmetic rather than
    // opinion. Nine repairs against two breaks is the shape that looks
    // convincing and is not: chi is 3.27, under the line.
    let a = mcnemar(2, 9);
    let b = mcnemar(1, 12);
    claim(
        "nine repairs against two breaks does not clear the bar; twelve against one does",
        a < MCNEMAR_95 && b >= MCNEMAR_95,
    );
    claim(
        "an even split is no evidence at all",
        mcnemar(7, 7) == 0.0 && mcnemar(0, 0) == 0.0,
    );

    let h = sha256::hash(b"a variant");
    claim(
        "a hash survives being written down and read back",
        from_hex32(&hex32(&h)) == Some(h),
    );

    // The property the whole DAG rests on: identical content is the same
    // node, and `born` is deliberately outside the hash so that a variant
    // rediscovered tomorrow is recognisably the one already tried rather
    // than a new one that behaves identically.
    // Shaped like a node from before the `core` field: it does not mention one
    // at all, which is what the compatibility claims below are about.
    let mk = |lambda: f32, born: u32| Variant {
        core: None,
        core_seen: false,
        deep: false,
        parent: Some(h),
        adapter: Some(sha256::hash(b"adapter")),
        policy: None,
        skills: None,
        corpus: Some(sha256::hash(b"corpus")),
        lambda,
        rank: 8,
        epochs: 20,
        rule: 0,
        threshold: MCNEMAR_95,
        floor: MIN_FIXED,
        born,
    };
    let v1 = mk(0.02, 1000);
    let v2 = mk(0.02, 9999);
    let v3 = mk(0.05, 1000);
    claim(
        "two variants differing only in when they were born are one node",
        v1.hash() == v2.hash(),
    );
    claim(
        "a variant differing in a parameter is a different node",
        v1.hash() != v3.hash(),
    );

    // Re-derivability across the `core` field, both directions.
    //
    // The failure this guards is quiet and permanent: a node whose rendering
    // does not reproduce is a node whose address does not reproduce, and the
    // ledger stops being checkable from that point on. Both halves matter --
    // a node written before the field existed must go on hashing to what it
    // hashed to, and a node written now must be able to *say* it has no core,
    // because `rollback` treats "said none" and "said nothing" differently and
    // was quietly uninstalling live cores when it could not tell them apart.
    let old_text = "variant 1\nparent none\nadapter none\npolicy none\nskills none\n\
                    corpus none\nlambda 0.00\nrank 8\nepochs 20\nrule 0\n";
    let old = Variant::from_text(old_text);
    claim(
        "a node written before the core field says nothing about one",
        !old.core_seen && old.core.is_none(),
    );
    claim(
        "and still renders to exactly the bytes it was stored as",
        old.render() == old_text,
    );
    let mut says_none = old.clone();
    says_none.core_seen = true;
    claim(
        "a node that says it has no core renders that, and is a different node",
        says_none.render().contains("core none\n") && says_none.hash() != old.hash(),
    );
    claim(
        "and reads back as having said it",
        Variant::from_text(&says_none.render()).core_seen,
    );
    let with_core = Variant { core: Some(h), core_seen: true, ..old.clone() };
    let back = Variant::from_text(&with_core.render());
    claim(
        "a node naming a core round-trips through its own rendering",
        back.core == Some(h) && back.core_seen && back.hash() == with_core.hash(),
    );

    // The property the first two recorded trials violated. They trained the
    // same corpus with the same settings, stopped at different epochs because
    // a busy host reached the wall-clock cap sooner, and produced adapters
    // that differed with nothing in the node saying why.
    let mut v4 = mk(0.02, 1000);
    v4.epochs = 19;
    let mut v5 = mk(0.02, 1000);
    v5.corpus = Some(sha256::hash(b"a different corpus"));
    claim(
        "epochs and corpus are part of what a variant is",
        v1.hash() != v4.hash() && v1.hash() != v5.hash(),
    );

    // The bar is part of the variant, and only when it is not the default.
    //
    // The three claims the `deep`/`core` work made about its own fields, made
    // again for U3's -- because the one that matters is silent: a default bar
    // must add nothing to the rendering, or the whole DAG re-addresses and the
    // ledger stops being checkable. `old_text` above already carries no
    // threshold line, so its "renders to exactly the bytes" claim is the
    // negative half; these are the positive one.
    let mut vt = mk(0.02, 1000);
    vt.threshold = 2.0;
    claim(
        "a non-default bar renders, and is a different node",
        vt.render().contains("threshold 2.00\n") && vt.hash() != v1.hash(),
    );
    claim(
        "the default bar renders nothing, so a pre-U3 node keeps its address",
        !v1.render().contains("threshold"),
    );
    claim(
        "a bar round-trips through the rendering",
        Variant::from_text(&vt.render()).threshold == 2.0
            && Variant::from_text(&vt.render()).hash() == vt.hash(),
    );

    // --- U3: the judge-of-the-judge, every branch ------------------------
    //
    // `judge_verdict` is pure, so all of its outcomes are asserted here without
    // a model, the way `update::decide` is -- and the one that earns its place
    // is the drift case, which is the whole point of the axis: a looser bar that
    // admits a candidate the held-out anchor does not support must be REFUSED.
    // A suite that never exercised that branch would be a criterion-drift
    // detector nobody had ever seen detect drift, which is `smp.rs`'s objection
    // about a canary that never fired.
    //
    // The bars: standing 3.84, admit_old means the candidate cleared it. The
    // pairs below name (admit_old, admit_new) and the anchor gain.
    let drift = judge_verdict(2.0, MIN_FIXED, false, true, 0.0);
    claim(
        "drift is caught: a looser bar admitting what the anchor rejects is refused",
        !drift.0,
    );
    let genuine = judge_verdict(2.0, MIN_FIXED, false, true, MIN_ANCHOR_GAIN + 0.02);
    claim(
        "a looser bar admitting what the anchor confirms is adopted",
        genuine.0,
    );
    let tighten_ok = judge_verdict(6.0, MIN_FIXED, true, false, 0.0);
    claim(
        "a tighter bar refusing a candidate the anchor did not support is adopted",
        tighten_ok.0,
    );
    let tighten_bad = judge_verdict(6.0, MIN_FIXED, true, false, MIN_ANCHOR_GAIN + 0.02);
    claim(
        "a tighter bar refusing a genuine gain is refused",
        !tighten_bad.0,
    );
    claim(
        "a bar both sides agree on changes nothing, and is refused",
        !judge_verdict(3.9, MIN_FIXED, true, true, 1.0).0 && !judge_verdict(3.9, MIN_FIXED, false, false, 1.0).0,
    );
    claim(
        "a bar of zero abolishes the criterion and is refused",
        !judge_verdict(0.0, MIN_FIXED, false, true, 1.0).0,
    );
    claim(
        "a bar past the ceiling freezes the loop and is refused",
        !judge_verdict(JUDGE_MAX + 1.0, MIN_FIXED, true, false, 0.0).0,
    );
    // The anchor is the axis's whole defence, and its budget is finite, so the
    // in-force accessor must default to exactly the strict constant on a machine
    // that has never moved it -- otherwise a fresh boot would already be running
    // a bar nobody chose.
    claim(
        "a machine that never moved its bar judges at exactly the default",
        judge_in_force() == MCNEMAR_95,
    );

    // --- the floor, the other half of the criterion ----------------------
    //
    // The measurement that produced this: a candidate repairing 2 of 24 with
    // none broken, held-out anchor 52.2% to 60.9%, refused by every bar in
    // `[JUDGE_MIN, JUDGE_MAX]`. J1 tests `fixed - broke >= floor` before it
    // tests chi, so the axis could move the constraint that was not binding
    // and could not reach the one that was. These claims are about the floor
    // being reachable and being bounded, in that order.
    claim(
        "a floor no bar can reach is what the axis was blind to",
        !j1_admits_at(JUDGE_MIN, MIN_FIXED, 2, 0, mcnemar(0, 2))
            && !j1_admits_at(JUDGE_MAX, MIN_FIXED, 2, 0, mcnemar(0, 2)),
    );
    claim(
        "lowering the floor admits exactly that candidate",
        j1_admits_at(JUDGE_MIN, 2, 2, 0, mcnemar(0, 2)),
    );
    claim(
        "a floor of zero abolishes the effect-size test and is refused",
        !judge_verdict(MCNEMAR_95, 0, false, true, 1.0).0,
    );
    claim(
        "a floor past the ceiling freezes the loop and is refused",
        !judge_verdict(MCNEMAR_95, FLOOR_MAX + 1, false, true, 1.0).0,
    );
    claim(
        "a floor change is policed by the same anchor a bar change is",
        judge_verdict(MCNEMAR_95, 2, false, true, MIN_ANCHOR_GAIN + 0.02).0
            && !judge_verdict(MCNEMAR_95, 2, false, true, 0.0).0,
    );
    claim(
        "a machine that never moved its floor judges at exactly the default",
        floor_in_force() == MIN_FIXED,
    );
    // The silent one, and the reason the rendering is conditional. A default
    // floor must add nothing, or every node in every lineage re-addresses and
    // `head` names something that no longer reproduces.
    let mut vf = mk(0.02, 1000);
    vf.floor = 2;
    claim(
        "a non-default floor renders, and is a different node",
        vf.render().contains("floor 2\n") && vf.hash() != v1.hash(),
    );
    claim(
        "the default floor renders nothing, so an existing node keeps its address",
        !v1.render().contains("floor"),
    );
    claim(
        "a floor round-trips through the rendering",
        Variant::from_text(&vf.render()).floor == 2
            && Variant::from_text(&vf.render()).hash() == vf.hash(),
    );
    // J1 is one implementation now. This is the claim that it stayed one: the
    // parameterised form at the in-force criterion must equal the form every
    // trial actually calls, or the two have drifted again.
    claim(
        "the parameterised J1 and the in-force J1 agree",
        j1_verdict(24, 6, 0, mcnemar(0, 6)).0
            == j1_admits_at(judge_in_force(), floor_in_force(), 6, 0, mcnemar(0, 6)),
    );

    // --- The illumination archive (MAP-Elites) ---------------------------
    //
    // The descriptor is pure, so its bins are pinned here; the elite rule is
    // the whole of MAP-Elites and is checked against the one failure that
    // matters -- a worse variant must never displace a better one, or the
    // archive stops being a frontier and becomes a log of whatever ran last.
    claim(
        "rank bins split at 4, 8 and 16",
        descriptor(4, 0, 0).0 == 0
            && descriptor(8, 0, 0).0 == 1
            && descriptor(16, 0, 0).0 == 2
            && descriptor(32, 0, 0).0 == 3,
    );
    claim(
        "repair bins split a variant that mostly breaks from one that mostly fixes",
        descriptor(8, 1, 9).1 == 0 && descriptor(8, 9, 1).1 == 2 && descriptor(8, 0, 0).1 == 1,
    );
    // Scratch cell, empty at boot before any trial has run. Written and read
    // back through the real store, then detached so the archive stays clean.
    let ha = sha256::hash(b"elite a");
    let hb = sha256::hash(b"elite b");
    let hc = sha256::hash(b"elite c");
    // All three land in the same cell: rank 8 (bin 1), all-fixes (bin 2).
    let first = archive_insert(&ha, 8, 10, 0, 0.50);
    let worse = archive_insert(&hb, 8, 10, 0, 0.40);
    let better = archive_insert(&hc, 8, 10, 0, 0.70);
    let held = read_cell(1, 2);
    claim(
        "the elite rule keeps the best of a cell and refuses a worse challenger",
        first
            && !worse
            && better
            && held.map_or(false, |e| e.variant == hc && (e.fitness - 0.70).abs() < 0.005),
    );
    sysbox::detach(&cell_path(1, 2));
    claim(
        "coverage counts occupied cells against the whole grid",
        {
            let (_, total, _) = archive_stats();
            total == RANK_BINS * REPAIR_BINS
        },
    );

    // --- Red Queen epochs ------------------------------------------------
    //
    // The bar moves only at a boundary, and genesis is not one -- otherwise a
    // fresh machine would re-examine a criterion it has never yet used. The
    // rule is pure, so it is pinned here rather than by writing ledger lines.
    claim(
        "an epoch boundary falls every EPOCH_LEN trials, and never at genesis",
        !is_boundary(0)
            && is_boundary(EPOCH_LEN)
            && is_boundary(2 * EPOCH_LEN)
            && !is_boundary(EPOCH_LEN - 1)
            && !is_boundary(EPOCH_LEN + 1),
    );

    // --- Bayesian-surprise axis order ------------------------------------
    //
    // An untried axis is maximally uncertain and a saturated one -- always
    // adopting, or never -- is not, and the order must put the first ahead of
    // the second or "chase the surprise" is just words. The tie-break is what
    // makes it re-derivable: two equally uncertain axes resolve by slot, every
    // time, so a later run reconstructs the same night rather than a plausible
    // one.
    claim(
        "an untried axis is more uncertain than one that always or never adopts",
        axis_uncertainty(0, 0) > axis_uncertainty(20, 20)
            && axis_uncertainty(0, 0) > axis_uncertainty(20, 0)
            && (axis_uncertainty(0, 0) - 1.0).abs() < 0.001,
    );
    let stats = [(0u32, 0u32), (20, 20), (20, 0), (10, 5), (4, 2), (8, 1)];
    let order = surprise_order_of(&stats);
    claim(
        "the surprise order reaches for the untried axis first",
        order[0] == 0,
    );
    let tie = [(5u32, 2u32), (5, 2), (0, 0), (0, 0), (0, 0), (0, 0)];
    let to = surprise_order_of(&tie);
    claim(
        "equally uncertain axes resolve by slot, so the order is re-derivable",
        to[0] == 2 && to[1] == 3 && to[4] == 0 && to[5] == 1,
    );

    // --- The storm and its chimeras --------------------------------------
    //
    // The blend is the arithmetic a chimera IS, so it is pinned exactly; and a
    // pair that does not share a shape must refuse to breed, because a blend
    // across shapes would index rows that are not there and the fault would
    // land in ring 0 with no guard page under it.
    {
        use super::adapter::Dora;
        let mut x = Dora::new(2, 8.0, 4, 3);
        let mut y = Dora::new(2, 8.0, 4, 3);
        for (i, v) in x.a.iter_mut().enumerate() {
            *v = i as f32;
        }
        for v in y.a.iter_mut() {
            *v = 2.0;
        }
        x.b[0] = 4.0;
        y.b[0] = 6.0;
        x.m[1] = 1.0;
        y.m[1] = 3.0;
        let c = Dora::blend(&x, &y);
        claim(
            "a chimera is the elementwise mean of its parents",
            c.as_ref().map_or(false, |c| {
                c.a[3] == 2.5 && c.b[0] == 5.0 && c.m[1] == 2.0 && c.r == 2
            }),
        );
        let z = Dora::new(3, 8.0, 4, 3);
        claim("a shape mismatch refuses to breed", Dora::blend(&x, &z).is_none());
    }
    // The declared generation spans every rank bin -- a storm that trained one
    // capacity three ways would light one column and call it illumination --
    // and its points are distinct proposals, so marking them cannot collapse
    // two nights' work into one marker.
    {
        let mut bins = [false; RANK_BINS];
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        for &(lr, rank, alpha, epochs) in STORM {
            bins[descriptor(rank, 0, 0).0] = true;
            hashes.push(
                Proposal { lr, rank, alpha, epochs, rule: 0, kind: ProposalKind::Adapter }.hash(),
            );
        }
        claim("the storm spans every rank bin", bins.iter().all(|b| *b));
        let mut distinct = true;
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                if hashes[i] == hashes[j] {
                    distinct = false;
                }
            }
        }
        claim("every storm point is its own proposal", distinct);
    }

    // Store and read back, then take the scratch node out of the real DAG --
    // a self-test that left synthetic ancestors in the lineage would be
    // corrupting the history it exists to protect.
    let stored = v1.store();
    let back = Variant::load(&stored);
    let round = back.as_ref().map_or(false, |b| {
        b.parent == v1.parent && b.adapter == v1.adapter && b.rule == v1.rule
    });
    // The identity, not a sample of the fields. Comparing three of them is
    // what let the missing `lambda` arm live here: `v1` has a nonzero lambda,
    // it read back as 0.0, and every checked field still matched. A node that
    // does not re-hash to the address it was read from cannot be used to
    // re-derive anything, which is the one property this module promises.
    let readdressed = back.as_ref().map_or(false, |b| b.hash() == stored);
    let mut np = String::from(ROOT);
    np.push_str("/nodes/");
    np.push_str(&hex32(&stored));
    let mut bp = np.clone();
    bp.push_str(".born");
    sysbox::detach(&np);
    sysbox::detach(&bp);
    claim("a stored variant reads back with its lineage intact", round);
    claim("a stored variant re-hashes to the address it came from", readdressed);

    // The compatibility property the `core` field rests on.
    //
    // Adding a field to a hashed structure re-addresses every object that
    // already exists unless the field is absent from the rendering when it is
    // absent from the object. If this claim fails, `head` names a node that no
    // longer reproduces, every ledger line stops being checkable, and the
    // change meant to extend re-derivability is what broke it -- so it is
    // asserted rather than reasoned about.
    let no_core = mk(0.02, 1000);
    let mut with_core = mk(0.02, 1000);
    with_core.core = Some(sha256::hash(b"a council core"));
    with_core.core_seen = true;
    claim(
        "a variant that predates the core field renders no core line",
        !no_core.render().contains("core "),
    );
    claim(
        "a core is part of what a variant is",
        no_core.hash() != with_core.hash(),
    );
    let ch = with_core.store();
    let cback = Variant::load(&ch);
    let core_round = cback.as_ref().map_or(false, |b| b.core == with_core.core && b.hash() == ch);
    let mut cnp = String::from(ROOT);
    cnp.push_str("/nodes/");
    cnp.push_str(&hex32(&ch));
    let mut cbp = cnp.clone();
    cbp.push_str(".born");
    sysbox::detach(&cnp);
    sysbox::detach(&cbp);
    claim("a variant carrying a core reads back as itself", core_round);

    ok
}
