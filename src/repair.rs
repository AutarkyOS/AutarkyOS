//! Repairs a machine may try on itself, and the judge that says whether one worked.
//!
//! The Windows Troubleshooter's bargain, which was a good one: a fixed set of
//! deterministic actions, one chosen, applied, and then **checked**. It never
//! ran during POST either -- it booted, looked at what was broken, fixed it,
//! and made the fix stick for next time.
//!
//! ### The judge is the check that failed
//!
//! This is the whole reason a repair is allowed to happen unattended. `godel`'s
//! rule is that nothing is adopted without a judge, and for a repair there is
//! an obvious one: apply it and **re-run the selftest that faulted**. Passing
//! is the verdict. That is why `boot_report::Failure` carries a `fn()` rather
//! than the machine merely remembering that something went wrong -- a failure
//! you cannot re-run is a failure you cannot repair.
//!
//! ### The table is an allowlist and starts small
//!
//! Two actions today. That is not a claim that the machine can fix anything;
//! it is the honest size of the set of knobs that exist. Each new one is a
//! deliberate decision to expose a switch, argued at the switch, and the list
//! being visible in one place is the point -- the same reason `eval::BUILTINS`
//! is an allowlist rather than a denylist.
//!
//! Most useful repairs turn something off or down. So did the Troubleshooter's.
//!
//! ### Nothing here chooses with a model
//!
//! Deliberately. The rule is fixed: try each offered action in table order,
//! keep the first whose judge passes. Proving the apply/judge/revert loop
//! somewhere a decode cannot be blamed for is the point of doing it this way
//! first -- if the loop is wrong, it is wrong somewhere legible. The model
//! replaces `choose` and nothing else.

use crate::boot_report::Failure;

pub struct Action {
    pub name: &'static str,
    /// One line, for a person reading the log -- and later for the prompt a
    /// model picks from.
    pub about: &'static str,
    /// Subsystems this is offered for. Empty means any.
    ///
    /// **Narrow on purpose.** An action that pokes a specific register has no
    /// business being offered for a fault in the filesystem, and a chooser
    /// that could pick it would be one bad decode away from a second fault.
    pub offered_for: &'static [&'static str],
    /// Apply it. `false` means it declined, and the loop moves on.
    pub apply: fn() -> bool,
    /// Put it back. Called when the judge did not pass.
    pub revert: fn(),
}

fn retry_apply() -> bool {
    // Nothing to do: the judge re-runs the check, which is the whole action.
    // Worth a row rather than a special case, because "it did not happen the
    // second time" is a real outcome and deserves to be recorded as the repair
    // that worked.
    true
}
fn nothing() {}

fn skip_hwp_apply() -> bool {
    crate::dev::power::skip_hwp(true);
    true
}
fn skip_hwp_revert() {
    crate::dev::power::skip_hwp(false);
}

pub static ACTIONS: &[Action] = &[
    Action {
        name: "retry",
        about: "run the check again, in case the fault was transient",
        offered_for: &[],
        apply: retry_apply,
        revert: nothing,
    },
    Action {
        name: "skip-hwp",
        about: "stop reading the hardware-managed performance registers",
        offered_for: &["power"],
        apply: skip_hwp_apply,
        revert: skip_hwp_revert,
    },
];

/// Which actions are offered for a subsystem, in table order.
pub fn offered(subsystem: &str) -> impl Iterator<Item = &'static Action> + '_ {
    ACTIONS
        .iter()
        .filter(move |a| a.offered_for.is_empty() || a.offered_for.contains(&subsystem))
}

/// Re-run the check that failed, and answer whether it survives now.
///
/// Guarded, because the whole reason it is here is that it faulted once. The
/// panic window is opened for the same reason it is open during the boot
/// selftests: an `assert!` is how most of these fail.
fn judge(f: &Failure) -> bool {
    // Saved and restored rather than closed, because this is callable from
    // inside a selftest -- and a judge that closed the window on its way out
    // would silently take panic recovery away from every check after it.
    let was = crate::cpu::recover::in_selftest();
    crate::cpu::recover::selftest_window(true);
    let verdict = matches!(
        crate::cpu::recover::guarded(f.retry),
        crate::cpu::recover::Caught::Ran
    );
    crate::cpu::recover::selftest_window(was);
    verdict
}

/// What happened to one subsystem.
pub enum Outcome {
    /// An action was applied and the check then passed. The name is the action.
    Repaired(&'static str),
    /// Everything offered was tried and the check still fails.
    Unrepaired,
}

/// Try to repair one failed subsystem.
///
/// **A failed repair is reverted before the next is tried**, so the machine
/// never accumulates a pile of changes that did not help. Whatever is left
/// standing at the end is exactly the one that worked, or nothing.
pub fn attempt(f: &Failure) -> Outcome {
    for a in offered(f.name) {
        if !(a.apply)() {
            continue;
        }
        if judge(f) {
            return Outcome::Repaired(a.name);
        }
        (a.revert)();
    }
    Outcome::Unrepaired
}

/// Try every failed subsystem, and say what happened.
///
/// Table order rather than failure order, because the table is written in
/// dependency order -- there is no point repairing something that reads
/// storage before storage itself.
pub fn attempt_all() {
    use crate::kprintln;
    if crate::boot_report::count() == 0 {
        return;
    }
    crate::gfx::console::set_color(crate::gfx::console::LTGRAY);
    kprintln!("\n[repair] {} subsystem(s) to try", crate::boot_report::count());
    for f in crate::boot_report::failures() {
        match attempt(&f) {
            Outcome::Repaired(action) => {
                crate::gfx::console::set_color(crate::gfx::console::LTGREEN);
                kprintln!("  {:<14} repaired by '{}', and the check now passes", f.name, action);
                crate::boot_report::mark_repaired(f.name, action);
            }
            Outcome::Unrepaired => {
                crate::gfx::console::set_color(crate::gfx::console::LTRED);
                kprintln!("  {:<14} nothing offered fixed it; still unavailable", f.name);
            }
        }
    }
    crate::gfx::console::set_color(crate::gfx::console::LTGRAY);
}

/// Build a `Failure` for a check that is not a real subsystem's.
///
/// The name is deliberately not one in `ACTIONS`, so the only action offered
/// for it is the universal one -- which is what makes the judge claims below
/// about the judge rather than about `skip-hwp`.
fn synthetic(retry: fn()) -> Failure {
    Failure {
        name: "nothing-by-this-name",
        need: crate::boot_report::Need::Optional,
        why: "synthetic",
        rip: 0,
        retry,
        repaired_by: None,
    }
}

fn faults() {
    unsafe { core::ptr::read_volatile(0x0 as *const u64) };
}
fn passes() {}

pub fn selftest() -> bool {
    let mut ok = true;
    fn claim(ok: &mut bool, good: bool, what: &str) {
        crate::kprintln!("  {}   {}", if good { "ok " } else { "FAIL" }, what);
        *ok &= good;
    }

    // ---- the table ---------------------------------------------------------
    //
    // Read out of the table rather than written down here. A claim naming
    // `power` and `skip-hwp` in its own text asserts what the table said on the
    // day it was written, so renaming a row would leave the suite passing while
    // testing something that no longer exists.
    claim(
        &mut ok,
        {
            let mut uniq = true;
            for (i, a) in ACTIONS.iter().enumerate() {
                if ACTIONS[..i].iter().any(|b| b.name == a.name) {
                    uniq = false;
                }
            }
            uniq && ACTIONS.iter().all(|a| !a.name.is_empty() && !a.about.is_empty())
        },
        "every action has a distinct name and something to say about itself",
    );

    claim(
        &mut ok,
        ACTIONS
            .iter()
            .filter(|a| a.offered_for.is_empty())
            .all(|a| offered("nothing-by-this-name").any(|b| b.name == a.name)),
        "an action listing no subsystems is offered for every subsystem",
    );

    // **The misattribution claim.** A narrow action must reach its own
    // subsystem and nothing else, because a chooser that could pick a power
    // register knob for a graphics fault is one decision away from a second
    // fault in a subsystem nobody was repairing. Both halves are derived from
    // the row's own list, so the claim keeps meaning this as the table grows.
    let mut narrow_reaches = true;
    let mut narrow_stays = true;
    for a in ACTIONS.iter().filter(|a| !a.offered_for.is_empty()) {
        for sub in a.offered_for {
            if !offered(sub).any(|b| b.name == a.name) {
                narrow_reaches = false;
            }
        }
        if offered("nothing-by-this-name").any(|b| b.name == a.name) {
            narrow_stays = false;
        }
    }
    claim(&mut ok, narrow_reaches, "a narrow action is offered for each subsystem it names");
    claim(&mut ok, narrow_stays, "and for no other, however the table grows");

    // ---- the judge ---------------------------------------------------------
    //
    // Judged against checks that are nothing to do with any subsystem, so what
    // is measured is the judge and never a particular repair. A judge that
    // answered yes to everything would make every failure look repaired by
    // whatever the table happened to offer first.
    claim(
        &mut ok,
        judge(&synthetic(passes)),
        "a check that runs to the end is judged as passing",
    );
    claim(
        &mut ok,
        !judge(&synthetic(faults)),
        "and one that still faults is not",
    );

    // The window is the panic handler's gate, so a judge that left it open
    // would make a panic anywhere afterwards recoverable, and one that left it
    // shut would take recovery away from the checks that follow.
    let before = crate::cpu::recover::in_selftest();
    let _ = judge(&synthetic(faults));
    claim(
        &mut ok,
        crate::cpu::recover::in_selftest() == before,
        "and judging leaves the selftest window exactly as it found it",
    );

    // ---- apply and revert --------------------------------------------------
    //
    // Found by name: an index would keep passing while testing whichever row
    // had moved into that slot.
    match ACTIONS.iter().find(|a| a.name == "skip-hwp") {
        Some(a) => {
            let before = crate::dev::power::hwp_skipped();
            (a.apply)();
            let during = crate::dev::power::hwp_skipped();
            (a.revert)();
            let after = crate::dev::power::hwp_skipped();
            claim(&mut ok, !before && during, "applying a repair changes the thing it names");
            claim(&mut ok, after == before, "and reverting it puts the value back");
        }
        None => claim(&mut ok, false, "the action this suite reverts is still in the table"),
    }

    // A failed repair must leave nothing behind. `attempt` on a check that
    // cannot be fixed tries everything offered and reverts each one, so the
    // machine after it is the machine before it.
    let before = crate::dev::power::hwp_skipped();
    let outcome = attempt(&synthetic(faults));
    claim(
        &mut ok,
        matches!(outcome, Outcome::Unrepaired) && crate::dev::power::hwp_skipped() == before,
        "a repair that did not work leaves the machine as it was",
    );

    ok
}
