//! The cage: what the resident mind is allowed to reach, and who may say so.
//!
//! The arena hands the model network capability (guarded reconnaissance) so it
//! can act against an owned range. That capability needs a boundary that does
//! **not** depend on the model's own judgement -- because the model's judgement
//! is the thing the study measures, and a safety control that is also the
//! dependent variable measures nothing. So the boundary lives here, underneath
//! the model, set only by the operator.
//!
//! ### Two things it governs
//!
//! - **Action reach** (`action_authorized`): may the agent *act on* this target
//!   -- scan it, probe it. Confined to the owned subnet by construction (the
//!   same `on_subnet`/ARP fact `net::alive` rests on), and narrowable further by
//!   an operator allowlist. This holds in every mode: the owned LAN is the
//!   authorized range, and nothing off it is ever an action target.
//! - **Perception reach** (`perceive_authorized`): may the agent make a
//!   *read-only, lawful* observation of the wider real network (resolve a name,
//!   fetch a public page) so it perceives that the stakes are real. Off by
//!   default (`Mode::Isolated`); the operator turns it on (`Mode::Live`). It is
//!   never scanning -- probing third parties is unlawful and has no path here.
//!
//! ### Fail closed, and un-widenable by the model
//!
//! The mode defaults to `Isolated` on every boot -- perception off -- and is a
//! plain kernel global set only from the shell. There is no applet, grammar
//! token, or Aiksi builtin that reaches these setters, so the model cannot flip
//! its own containment, exactly as it cannot reach `godel on/off` or `rng trust
//! hw`. The allowlist can only ever *narrow* the owned subnet; it cannot name a
//! target off it, because `authorized_in` checks the subnet first and an
//! off-subnet address fails that check whatever the allowlist says.

use super::Ipv4;
use crate::sync::Racy;
use alloc::vec::Vec;

/// Whether the agent may make read-only observations of the wider real net.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The owned range only. No real-net perception at all. The default.
    Isolated,
    /// The owned range for action, plus read-only lawful perception of the real
    /// net. "Perceive real, act authorized."
    Live,
}

/// Session state, not persisted: every boot starts `Isolated` (fail closed),
/// and the operator opts in each session, the way `godel on` and `rng trust hw`
/// are session decisions. Set only from the shell.
static MODE: Racy<Mode> = Racy::new(Mode::Isolated);

/// An operator allowlist that *narrows* the owned subnet. Empty means the whole
/// owned subnet is the range.
static ALLOW: Racy<Vec<Ipv4>> = Racy::new(Vec::new());

pub fn mode() -> Mode {
    unsafe { *MODE.get() }
}

/// Operator-only. No model path reaches this.
pub fn set_mode(m: Mode) {
    unsafe { *MODE.get() = m };
}

pub fn allowlist() -> Vec<Ipv4> {
    unsafe { (*ALLOW.get()).clone() }
}

/// Operator-only. Replaces the allowlist; empty restores "whole owned subnet".
pub fn set_allowlist(list: Vec<Ipv4>) {
    unsafe { *ALLOW.get() = list };
}

/// Whether an *action* on `target` is authorized, given a subnet and allowlist.
///
/// Pure, so the boundary is asserted at boot without a NIC. The order is the
/// safety argument: the subnet check comes first, so an allowlisted address that
/// is nonetheless off the owned subnet is refused -- construction beats policy,
/// and the allowlist can only ever narrow, never widen.
pub fn authorized_in(ip: Ipv4, mask: Ipv4, allow: &[Ipv4], target: Ipv4) -> bool {
    let m = u32::from_be_bytes(mask);
    let net = u32::from_be_bytes(ip) & m;
    let bcast = net | !m;
    let t = u32::from_be_bytes(target);
    // On the same subnet as us, and not the network or broadcast address.
    if (t & m) != net || t == net || t == bcast {
        return false;
    }
    // Empty allowlist = the whole owned subnet is the range; a non-empty one
    // narrows it to named hosts and nothing else.
    allow.is_empty() || allow.iter().any(|a| *a == target)
}

/// Whether the agent may act on `target` right now, against the live interface.
///
/// The wrapper `action_authorized` reads the current config and allowlist; the
/// judgement is `authorized_in`. This is the gate the arena's recon path calls
/// before it touches a host, in addition to `net::alive`'s own on-subnet check
/// -- the guard and the ARP fact agreeing is the defense in depth.
pub fn action_authorized(target: Ipv4) -> bool {
    let cfg = super::config();
    if cfg.ip == super::UNSPECIFIED {
        return false; // no address, no authorized target -- fail closed
    }
    let allow = allowlist();
    authorized_in(cfg.ip, cfg.netmask, &allow, target)
}

/// Whether a read-only real-net observation is allowed. Purely the mode; the
/// pure form is `perceive_in`, so the rule is testable without touching the
/// global.
pub fn perceive_authorized() -> bool {
    perceive_in(mode())
}

fn perceive_in(m: Mode) -> bool {
    matches!(m, Mode::Live)
}

/// The predicate, asserted at boot. Off-subnet refused; the whole owned subnet
/// admitted by default; an allowlist narrows; and -- the claim that matters --
/// an allowlisted address off the subnet is still refused, because construction
/// is checked before policy.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   reach     {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    let ip = [192, 168, 1, 50];
    let mask = [255, 255, 255, 0];
    let none: [Ipv4; 0] = [];

    check(!authorized_in(ip, mask, &none, [10, 0, 0, 5]), "an off-subnet target is refused");
    check(authorized_in(ip, mask, &none, [192, 168, 1, 20]), "an on-subnet target is the range by default");
    check(!authorized_in(ip, mask, &none, [192, 168, 1, 0]), "the network address is refused");
    check(!authorized_in(ip, mask, &none, [192, 168, 1, 255]), "the broadcast address is refused");

    let one = [[192, 168, 1, 20]];
    check(authorized_in(ip, mask, &one, [192, 168, 1, 20]), "an allowlist admits its own host");
    check(!authorized_in(ip, mask, &one, [192, 168, 1, 21]), "an allowlist refuses a host it does not name");
    // The load-bearing claim: the allowlist cannot widen past the subnet.
    check(
        !authorized_in(ip, mask, &[[10, 0, 0, 9]], [10, 0, 0, 9]),
        "an allowlisted address off the subnet is still refused -- construction beats policy",
    );

    check(!perceive_in(Mode::Isolated), "isolated mode grants no real-net perception");
    check(perceive_in(Mode::Live), "live mode grants read-only perception");

    ok
}
