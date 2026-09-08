//! Learning which axis to try next, from the record of what trying taught.
//!
//! `godel::next_proposal` reaches for the axis whose next verdict the ledger
//! can least predict, and it decides that with `axis_uncertainty`: a
//! Laplace-smoothed adoption rate folded to a distance from the coin flip. It
//! is a good heuristic and it is hand-written, which means it sees exactly one
//! thing -- how often an axis has said yes -- and cannot see anything else the
//! record holds.
//!
//! This is the machinery for replacing it with something fitted to that
//! record. The loop already spends every night writing down what it tried and
//! what came of it; learning *which trial to attempt* from that history is the
//! literal reading of learning to learn, and the data has been accumulating
//! since the first godel commit.
//!
//! ## The scaffolding is here and the verdict is not, on purpose
//!
//! **A ranker fitted to two ledger lines is noise wearing a coefficient.** A
//! fresh machine's ledger is empty; the loop writes one line a night. So this
//! module deliberately refuses to fit below `MIN_SAMPLES`, and `replay`
//! reports how many samples it actually had rather than returning a verdict
//! computed from three. The honest sequence is to let the loop run, watch
//! `godel drift` while it does, and fit this against history that exists --
//! not to adopt an acquisition function today and discover in a month that it
//! was fitted to nothing.
//!
//! That refusal is the feature. Everything here is written so that when the
//! ledger is long enough, the judge already exists and has not been tuned to
//! whatever the answer turned out to be.
//!
//! ## Features are what was known *before* the trial
//!
//! An acquisition function chooses what to attempt, so it may only see what
//! was on the record before the attempt. Every feature here is computed from
//! the ledger prefix strictly above the line it describes: a post-hoc feature
//! would fit beautifully and rank nothing, because at choosing time it does
//! not exist yet. `samples` walks the ledger forward and emits each line's
//! features from the state before it, which is the only ordering that makes
//! the fitted thing usable as a policy.
//!
//! ## Judging it is a calibration question, not an accuracy one
//!
//! "Did this acquisition function pick better axes" has no ground truth: the
//! trials it did not run were never run. What *is* answerable is whether its
//! probabilities are better calibrated than the incumbent's, and that is
//! sufficient -- `axis_uncertainty` is `1 - |rate - 0.5| * 2`, a monotone
//! transform of how far the estimated rate sits from the coin flip, so the
//! ranking is exactly as good as the rate estimate under it. A better
//! estimator of P(adopt) is a better ranker by construction.
//!
//! So `replay` walks the ledger in time order, fits on the prefix, predicts
//! the next line, and scores both predictors by squared error. The comparison
//! is **paired** -- same line, both predictors, which was closer -- so it
//! reaches `godel::judge_one` as the same kind of evidence every other axis
//! answers to, and refuses on thin evidence for the same reason.

use super::godel;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Bias, attempts, adoption rate, staleness, share.
pub const F: usize = 5;

/// How many samples before a fit means anything.
///
/// Twelve against five features. Not a rule of thumb dressed up: below roughly
/// twice the feature count the normal equations are fitting noise, and this
/// module's whole argument is that a coefficient learned from too little
/// history is worse than the heuristic it would replace, because it carries
/// the authority of having been measured.
pub const MIN_SAMPLES: usize = 12;

/// Ridge penalty. Small, and present so the system is solvable even when a
/// feature never varies across the history seen so far -- which is the
/// ordinary case early on, when one axis has every line.
const LAMBDA: f32 = 0.05;

/// Counts bend towards one over this scale, so an axis with three attempts and
/// one with three hundred are different inputs rather than the same saturated
/// one. Chosen at the order of magnitude a month of nightly trials reaches.
const SOFTEN: f32 = 8.0;

/// One ledger line, as the acquisition function would have seen it beforehand.
#[derive(Clone, Copy)]
pub struct Sample {
    pub x: [f32; F],
    /// Whether the line adopted. What the fit is trying to anticipate.
    pub y: f32,
    /// Which axis, kept for reporting rather than for fitting.
    pub axis: usize,
}

fn soften(n: f32) -> f32 {
    n / (n + SOFTEN)
}

/// The incumbent estimator: the Laplace-smoothed adoption rate that
/// `godel::axis_uncertainty` folds into a distance from the coin flip.
///
/// Written out here rather than imported because what is needed is the *rate*,
/// and `axis_uncertainty` returns the fold of it. Both are the same number
/// seen from two sides, and the fold is not invertible -- 0.2 and 0.8 fold to
/// the same uncertainty -- so a comparison of estimators has to happen before
/// the fold.
pub fn laplace(attempts: u32, adoptions: u32) -> f32 {
    (adoptions as f32 + 1.0) / (attempts as f32 + 2.0)
}

/// Walk the ledger forward, emitting one sample per axis-bearing line.
///
/// Lines with no `axis=` are skipped, for the reason `godel::axis_counts`
/// skips them: they predate the field, so which axis they belong to is not
/// recoverable and guessing would put one axis's history on another's record.
pub fn samples(lines: &[String]) -> Vec<Sample> {
    let n_axes = godel::AXIS_NAMES.len();
    let mut attempts = vec![0u32; n_axes];
    let mut adoptions = vec![0u32; n_axes];
    let mut since = vec![0u32; n_axes];
    let mut total = 0u32;
    let mut out = Vec::new();

    for line in lines {
        let Some(a) = godel::axis_of(line) else { continue };
        let adopted = line.contains(" ADOPT");

        // Features from the state *before* this line. Everything below the
        // push is the update, and nothing above it may read the update.
        let x = [
            1.0,
            soften(attempts[a] as f32),
            laplace(attempts[a], adoptions[a]),
            soften(since[a] as f32),
            if total == 0 { 0.0 } else { attempts[a] as f32 / total as f32 },
        ];
        out.push(Sample { x, y: if adopted { 1.0 } else { 0.0 }, axis: a });

        attempts[a] += 1;
        total += 1;
        if adopted {
            adoptions[a] += 1;
            since[a] = 0;
        } else {
            since[a] += 1;
        }
    }
    out
}

/// Fit weights by ridge regression over the samples.
///
/// `None` below `MIN_SAMPLES`, or when the normal equations are singular --
/// both of which mean "there is not enough here to learn from", and both of
/// which the caller must treat as "keep the heuristic" rather than as a
/// zeroed model that happens to predict a constant.
pub fn fit(s: &[Sample]) -> Option<[f32; F]> {
    if s.len() < MIN_SAMPLES {
        return None;
    }
    // Normal equations: (X'X + lambda I) w = X'y, built here and solved by the
    // same Cholesky the router and the futures model use, so there is one
    // solver in the tree that has been checked against a known-separable fit
    // at every boot.
    let mut g = vec![0.0f32; F * F];
    let mut b = vec![0.0f32; F];
    for sample in s {
        for i in 0..F {
            b[i] += sample.x[i] * sample.y;
            for j in 0..F {
                g[i * F + j] += sample.x[i] * sample.x[j];
            }
        }
    }
    for i in 0..F {
        g[i * F + i] += LAMBDA;
    }
    if !super::probe::ridge_solve(&mut g, F, &mut b) {
        return None;
    }
    let mut w = [0.0f32; F];
    w.copy_from_slice(&b[..F]);
    if w.iter().any(|v| !v.is_finite()) {
        return None;
    }
    Some(w)
}

/// Predicted probability of adoption, clamped to the range a probability has.
///
/// A linear probability model, which is what the router's probe is over its
/// own features. Clamping rather than a logistic because the score is only
/// ever compared and ranked, and a squashing function would add a parameter
/// nothing here can fit.
pub fn predict(w: &[f32; F], x: &[f32; F]) -> f32 {
    let mut s = 0.0;
    for i in 0..F {
        s += w[i] * x[i];
    }
    s.clamp(0.0, 1.0)
}

/// What a walk of the ledger said about the two estimators.
pub struct Replay {
    /// Lines the comparison could be made on: those with enough history above
    /// them to fit anything at all.
    pub judged: usize,
    /// Samples available in total, whether or not they could be judged.
    pub samples: usize,
    /// Lines where the fitted estimator was strictly closer, and where the
    /// Laplace one was. Ties count for neither, which is what makes this a
    /// paired count rather than two averages.
    pub learned_closer: usize,
    pub laplace_closer: usize,
    /// Summed squared error, for a magnitude to go with the count.
    pub learned_err: f32,
    pub laplace_err: f32,
}

impl Replay {
    /// Whether the fitted estimator beat the heuristic beyond the noise, under
    /// the bar every other axis answers to.
    pub fn verdict(&self) -> (bool, &'static str) {
        godel::judge_one(self.judged, self.learned_closer, self.laplace_closer)
    }
}

/// Walk the ledger in time order, fitting on the prefix and predicting the
/// next line, and score both estimators on what they did not see.
///
/// Refitting per line is quadratic in ledger length. That is affordable at the
/// scale this runs -- one line a night, and the fit is five by five -- and it
/// is the only arrangement that never lets a line inform its own prediction.
/// A cached incremental fit would be faster and would need a proof that the
/// cache never leaks forward; this needs none.
pub fn replay(lines: &[String]) -> Replay {
    let s = samples(lines);
    let mut r = Replay {
        judged: 0,
        samples: s.len(),
        learned_closer: 0,
        laplace_closer: 0,
        learned_err: 0.0,
        laplace_err: 0.0,
    };

    let n_axes = godel::AXIS_NAMES.len();
    let mut attempts = vec![0u32; n_axes];
    let mut adoptions = vec![0u32; n_axes];

    for i in 0..s.len() {
        let here = &s[i];
        // The heuristic's own estimate, from the same prefix the fit gets.
        let lap = laplace(attempts[here.axis], adoptions[here.axis]);

        if let Some(w) = fit(&s[..i]) {
            let learned = predict(&w, &here.x);
            let le = (learned - here.y) * (learned - here.y);
            let pe = (lap - here.y) * (lap - here.y);
            r.learned_err += le;
            r.laplace_err += pe;
            if le < pe {
                r.learned_closer += 1;
            } else if pe < le {
                r.laplace_closer += 1;
            }
            r.judged += 1;
        }

        attempts[here.axis] += 1;
        if here.y > 0.5 {
            adoptions[here.axis] += 1;
        }
    }
    r
}

/// Replay the machine's own ledger.
pub fn replay_ledger() -> Replay {
    replay(&godel::ledger_tail(usize::MAX))
}

/// Boot self-test. Pure over synthetic ledger lines -- no store, no model.
///
/// The tie between these lines and the format the ledger actually writes is
/// checked in `godel`'s drift claims, which render real certificates and parse
/// them back. What is checked here is the arithmetic on top of that format:
/// that features cannot see their own outcome, that a fit is refused on thin
/// history, and that a pattern the heuristic structurally cannot represent is
/// one the fitted estimator finds.
pub fn selftest() -> bool {
    use crate::kprintln;
    let mut ok = true;
    let mut claim = |what: &str, pass: bool| {
        if !pass {
            ok = false;
        }
        kprintln!("  {}   {}", if pass { "ok " } else { "FAIL" }, what);
    };

    let line = |axis: &str, adopted: bool| -> String {
        alloc::format!(
            "1 h3 parent=root.... variant=abcdef01 axis={} cell=0 n=180 pred=win \
             J1[fix=12 broke=1 chi=7.69 beyond the noise ok] J2[goals=4/4 ok] J3[ok] \
             ep=20 J4[r=8 kib=24 ok]{}",
            axis,
            if adopted { " ADOPT test=60.00%@read1" } else { " reject" }
        )
    };

    // Features describe the past, never the present. The first line an axis
    // ever has must show no attempts and no adoptions, whatever it went on to
    // do -- otherwise the fit is reading its own answer.
    let first = samples(&[line("adapter", true)]);
    claim(
        "the first line of an axis carries no history of that axis",
        first.len() == 1 && first[0].x[1] == 0.0 && first[0].x[2] == laplace(0, 0),
    );
    claim(
        "and its outcome is recorded as the target, not as a feature",
        first[0].y == 1.0 && !first[0].x.iter().any(|v| *v == 1.0 && first[0].x[0] != *v),
    );

    // A line with no axis is not a sample, for the reason `axis_counts` skips
    // it: which axis it belongs to is not recoverable.
    claim(
        "a line with no axis is not a sample",
        samples(&[String::from("1 h3 n=180 fix=12 broke=1 ADOPT")]).is_empty(),
    );

    // Thin history fits nothing, and says so rather than returning zeroes.
    let few: Vec<String> = (0..MIN_SAMPLES - 1).map(|_| line("adapter", true)).collect();
    claim(
        "a fit is refused below the minimum sample count",
        fit(&samples(&few)).is_none(),
    );
    let enough: Vec<String> = (0..MIN_SAMPLES + 4).map(|_| line("adapter", true)).collect();
    claim(
        "and admitted once there is history to fit",
        fit(&samples(&enough)).is_some(),
    );

    // The demonstration this module exists for. An axis that adopts every
    // other trial has a Laplace rate that converges on one half, so the
    // heuristic predicts 0.5 forever and is wrong by that much every time.
    // Staleness -- trials since the last adoption -- separates the two cases
    // exactly, and it is a feature the heuristic has no way to hold.
    let alternating: Vec<String> =
        (0..40).map(|i| line("adapter", i % 2 == 0)).collect();
    let r = replay(&alternating);
    claim(
        "an alternating axis gives the heuristic nothing to work with",
        r.laplace_err / r.judged.max(1) as f32 > 0.2,
    );
    claim(
        "and the fitted estimator reads the pattern the rate cannot hold",
        r.judged > 0 && r.learned_err < r.laplace_err,
    );
    claim(
        "so the paired count favours it beyond the noise",
        r.verdict().0,
    );

    // And the refusal that matters most: on a ledger too short to fit, the
    // replay judges nothing at all rather than returning a verdict from three
    // lines. This is the state a real machine is in today.
    let short = replay(&[line("adapter", true), line("rule", false)]);
    claim(
        "a ledger too short to fit is judged on nothing, not on three lines",
        short.judged == 0 && !short.verdict().0,
    );

    ok
}
