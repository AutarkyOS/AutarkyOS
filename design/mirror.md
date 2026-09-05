# The Mirror: deception as the security posture

Status: **phase 1 built and verified; the rest is design.** `src/net/decoy.rs`
exists, round-trips through the recon engine, and is a boot suite. Everything
below phase 1 is proposal.

## The thesis

AUTARK's security is not concealment. A hidden system is one discovery away
from undefended, and a ring-0 kernel with a language model inside it is too
interesting to stay hidden. So the posture is the opposite: be loud, be
everywhere, and make almost all of it false. The defender's one durable
advantage is that they know which assets are real and the attacker does not, so
every interaction an attacker has is either with a decoy (wasted, and logged) or
carries the risk of being one. Reconnaissance stops being free.

This is not novel in the field even if it is unusual in a hobby kernel: it is
deception technology (honeypots, honeytokens, canaries), tarpits (LaBrea,
endlessh), crawler mazes (Nepenthes, Cloudflare's Labyrinth), and moving-target
defence, assembled into one machine's whole stance rather than bolted on as a
product.

## The inversion worth naming

AUTARK already has a strict internal epistemics: the one invariant says the
record of what the machine did cannot be rewritten, the ledger is ground truth,
and `sysbox::guard` makes reality strictly *distinguishable* from deception on
the inside. The Mirror is that same commitment turned inside out at the network
boundary: outward, reality is made deliberately *indistinguishable* from
deception. Incorruptible truth within, a hall of mirrors without. The two are
not in tension -- the internal truth is exactly what lets the machine keep
track of which external things are lies.

## The line this subsystem does not cross

Deception and cost-imposition happen **on the machine's own turf**. The Mirror
wastes an attacker's time, exhausts their tooling against its own services, and
captures their full fingerprint. It does not reach out to damage an attacker's
systems, and it does not deploy decoys onto infrastructure the operator does not
own. "Hack back" is illegal in the jurisdictions this would run in regardless of
who struck first, and a deterrent that depends on committing crimes is one you
cannot actually field -- it converts the defender into the more prosecutable
party. The strong version needs none of it: an attacker who burns a week on
ghosts, exhausts their scanner on infinite plausible depth, and leaks their
whole toolkit has already been made to pay more than the attack was worth, which
is the entire "more dangerous to attack than to abandon" claim, kept legal.

## Phases

### 1. Decoy banners (built, `src/net/decoy.rs`)

The inverse of `fingerprint::identify`: given a service name, synthesise a
banner the recon engine reads back *as that service*. The round-trip is a boot
assertion, so "indistinguishable from deception" is a proven property of the one
classifier this system trusts, not a matter of taste. A seed selects among real
product/version pairs, so a fleet of decoys reads as a heterogeneous network
rather than a hundred clones -- diversity is the camouflage, determinism keeps
it re-derivable.

Building it found a real bug in `identify`: RTSP carries a `Server:` header like
HTTP, and the generic header-sniff classified an RTSP banner as HTTP before the
`RTSP/` marker was ever checked. The inverse stress-tests the classifier, which
is a second reason to have it.

### 2. Honeytokens / canaries (built, `src/sysbox/canary.rs`)

Decoy secrets planted in the namespace -- fake credentials, fake keys, fake
config -- whose defining property is that no legitimate path ever reads them, so
*any* read is an intrusion signal. `read_blob` gains a hook: a read of a planted
path trips, appending to `/ai/mirror/alarms`, which is now a fifth record under
`sysbox::guard` -- append-only, so an attacker who trips a canary cannot erase
having done so. The one invariant, written for the self-modification history,
turns out to be exactly the property a tripwire needs.

Verified end to end on a real boot: planted `/ai/secrets/aws`; `read()` of it
returned the decoy keys *and* printed `[canary] tripped`; `canary alarms` showed
`1 trip, 1 alarm`; `rm /ai/mirror/alarms` was refused (`the record may not lose
its name`) and `write()` to overwrite it changed nothing -- the alarm survived
both. The armed flag keeps an unarmed machine's read path to a single relaxed
atomic load. Planting and listing are operator-only (shell `canary`), never an
Aiksi builtin: the model can spring a trap but never enumerate the traps.

### 3. The listener and the honeypot (design)

AUTARK's TCP stack is client-only today: one TCB, `connect` aborts whatever was
open, no accept path. A honeypot needs to listen, accept, and hold several
connections, emitting phase-1 banners and logging everything the peer sends.
This is a real addition to the stack. Unlike the recon scanner it is
*testable under QEMU*: user-mode networking forwards host ports into the guest
(`hostfwd`), so a listener can be driven from the host, which the scanner cannot
be. Attribution -- peer address, timing, the exact bytes and tooling
signatures -- is the product.

### 4. The tarpit and the maze (design)

Cost imposition, still on our turf. A tarpit answers a byte at a time on a long
timer so a scanner's connection budget drains against a service that never
finishes (endlessh's method). A maze serves infinite plausible depth -- a
filesystem or a service tree that never bottoms out -- so an automated crawler
spends itself mapping a structure with no end. Both waste the attacker's
resources and none of ours beyond a socket.

## How it ties to the RSI loop

The Mirror produces exactly the kind of ground-truth signal `godel` is built to
learn from: a canary trip or a honeypot session is a labelled event, the ledger
already records labelled events re-derivably, and the recon/fingerprint engines
already turn wire bytes into structured facts. A later phase could let the loop
propose *which* decoys to present and measure their catch rate -- but only
behind the same judges and the same held-out discipline as everything else,
because a self-improving deception layer that graded its own success would be
the criterion-drift failure U3 exists to prevent, in a new costume.
