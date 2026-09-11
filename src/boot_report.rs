//! What broke during boot, and whether the machine may carry on without it.
//!
//! **The first bare-metal boot stopped because reading a temperature failed.**
//! A `#GP` inside `dev::power::hwp_range` took the whole machine with it: no
//! shell, no storage, no model, for a register nobody needs. Everything
//! downstream of that selftest was lost to a subsystem that is not load-bearing
//! and never was.
//!
//! So a subsystem declares what it is worth. A `Vital` one faulting means the
//! machine is not itself and stopping is the honest answer; an `Optional` one
//! faulting is recorded, named, and boots on without it.
//!
//! ### Why the answer is per subsystem rather than a policy
//!
//! Both blanket rules are wrong. "Always halt" is what just cost a boot to a
//! thermometer. "Always continue" produces a machine that cheerfully comes up
//! with six dead subsystems and a boot log nobody reads any more -- which is
//! the failure this tree's own selftest notes warn about, arriving by a
//! different route. The distinction is a property of the subsystem, so it is
//! written down at each subsystem, and a reader can argue with it row by row.
//!
//! ### It is a fixed array and holds no allocation
//!
//! Same reason `log.rs` gives about its ring: this has to work at a moment
//! when the thing that just broke might have been the allocator. Sixteen slots,
//! because a boot with more than sixteen broken subsystems is not a report, it
//! is a different fault upstream of all of them.

use crate::sync::Racy;

/// What a subsystem is worth to a running machine.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Need {
    /// The machine is not itself without this. A fault here stops the boot.
    ///
    /// Reserved for things every later line depends on: memory, the tables the
    /// processor reads, the clock the scheduler counts on, and the ciphers --
    /// a cipher that is quietly wrong is more dangerous than one that is
    /// absent, which is the argument `crypto` makes about itself.
    Vital,
    /// Useful, and the machine is honest about lacking it.
    Optional,
}

#[derive(Clone, Copy)]
pub struct Failure {
    /// The guarded scope that did not finish. **Which check failed**, which is
    /// not the same question as what broke.
    pub name: &'static str,
    pub need: Need,
    /// What `recover` caught: a fault by name, or a panic.
    pub why: &'static str,
    /// Where the faulting instruction was, absolute. Zero for a panic, and for
    /// a fault taken before the image base was known.
    ///
    /// **The field that stops this report naming the wrong subsystem.** A
    /// check is blamed for whatever faults inside it, including code it merely
    /// called -- a graphics fault reached from a power selftest is a power
    /// failure by attribution and a graphics one in fact. The site is the only
    /// thing that can say so, and it is resolved to a function name at print
    /// time rather than stored.
    pub rip: u64,
    /// The check itself, so it can be run again.
    ///
    /// **A failure you cannot re-run is a failure you cannot repair**, because
    /// re-running it is the only judge a repair has. This is why `section`
    /// takes a `fn()` rather than a closure.
    pub retry: fn(),
    /// Set once something fixed it. The subsystem stays listed, because "was
    /// broken and is now repaired" is a different fact from "never broke" and
    /// an operator is owed both.
    pub repaired_by: Option<&'static str>,
}

const SLOTS: usize = 16;

static FAILURES: Racy<[Option<Failure>; SLOTS]> = Racy::new([None; SLOTS]);
static OVERFLOW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn record(name: &'static str, need: Need, why: &'static str, retry: fn()) {
    let rip = crate::cpu::recover::site().unwrap_or(0);
    let slots = unsafe { FAILURES.get() };
    for s in slots.iter_mut() {
        if s.is_none() {
            *s = Some(Failure { name, need, why, rip, retry, repaired_by: None });
            return;
        }
    }
    // Counted rather than dropped silently: "sixteen and some" is a different
    // statement from "sixteen".
    OVERFLOW.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

pub fn failures() -> impl Iterator<Item = Failure> {
    let slots = unsafe { FAILURES.get() };
    slots.iter().filter_map(|s| *s).collect::<alloc::vec::Vec<_>>().into_iter()
}

/// Note that a repair worked, without forgetting that it was ever broken.
pub fn mark_repaired(name: &str, action: &'static str) {
    let slots = unsafe { FAILURES.get() };
    for s in slots.iter_mut().flatten() {
        if s.name == name {
            s.repaired_by = Some(action);
        }
    }
}

/// How many are still broken, which is not how many broke.
pub fn outstanding() -> usize {
    unsafe { FAILURES.get() }
        .iter()
        .flatten()
        .filter(|f| f.repaired_by.is_none())
        .count()
}

pub fn count() -> usize {
    unsafe { FAILURES.get() }.iter().filter(|s| s.is_some()).count()
}

/// Whether anything the machine cannot do without is broken.
pub fn any_vital() -> bool {
    unsafe { FAILURES.get() }
        .iter()
        .any(|s| matches!(s, Some(f) if f.need == Need::Vital))
}

/// Print what is missing, in the shape `dev::registry` reports a driver gap.
///
/// Printed at the end of boot rather than only where it happened, because the
/// line that matters is "this machine is running without X" and by then the
/// fault itself has scrolled past a hundred `ok` lines.
pub fn report() {
    use crate::kprintln;
    let n = count();
    if n == 0 {
        return;
    }
    crate::gfx::console::set_color(crate::gfx::console::LTRED);
    kprintln!(
        "\n[boot] {} subsystem(s) did not survive their own selftest, {} still broken:",
        n,
        outstanding()
    );
    for f in failures() {
        kprintln!(
            "  {:<14} {}  ({})",
            f.name,
            f.why,
            match (f.need, f.repaired_by) {
                (_, Some(a)) => a,
                (Need::Vital, None) => "vital",
                (Need::Optional, None) => "optional, so this machine is running without it",
            }
        );
        // Where it actually was, which may be nowhere near what is named
        // above. Resolved here rather than at record time so the report costs
        // nothing on a boot where nothing broke.
        if f.rip != 0 {
            let base = crate::cpu::idt::IMAGE_BASE.load(core::sync::atomic::Ordering::Relaxed);
            let size = crate::cpu::idt::IMAGE_SIZE.load(core::sync::atomic::Ordering::Relaxed);
            match crate::cpu::code::locate(f.rip, base, size, crate::cpu::code::lookup(f.rip)) {
                crate::cpu::code::Where::Image(rva)
                | crate::cpu::code::Where::Unverified(rva) => {
                    match crate::cpu::code::symbol(rva) {
                        Some((sym, off)) => kprintln!("                 in {} +{:#x}", sym, off),
                        None => kprintln!("                 at rva {:#x}", rva),
                    }
                }
                crate::cpu::code::Where::Generated { tag, off } => {
                    kprintln!("                 in generated code {:016x} +{:#x}", tag, off)
                }
                crate::cpu::code::Where::Elsewhere => {
                    kprintln!("                 at {:#x}, which is outside the image", f.rip)
                }
            }
        }
    }
    let over = OVERFLOW.load(core::sync::atomic::Ordering::Relaxed);
    if over > 0 {
        kprintln!("  and {} more that did not fit", over);
    }
    crate::gfx::console::set_color(crate::gfx::console::LTGRAY);
}
