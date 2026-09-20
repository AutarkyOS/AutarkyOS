# The Mirror: deception as the security posture

Status: **phases 1-4 built and verified; the maze (part of phase 4) is the only
piece left as design.** Decoy banners, honeytokens, the listening honeypot and
the tarpit are all in the tree with boot suites, and the three network-facing
pieces were driven live under QEMU via `hostfwd`.

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

### 3. The listener and the honeypot (built, `src/net/honeypot.rs`)

AUTARK's TCP was client-only: one TCB, `connect` aborts whatever was open, no
accept path. `tcp` gained a passive open -- a `SynRcvd` state and a
`passive_open` that answers an inbound SYN to a listening port with a SYN-ACK
and installs a half-open block, where before `pump` sent a bare RST. On the
handshake completing it serves a phase-1 decoy banner (rotating the identity per
connection) and begins an orderly close, so the single TCB frees for the next
victim through the fully-tested FIN path; the peer's bytes are captured and, at
`Closed`, logged to `/ai/mirror/sessions` -- a sixth `guard` record, so a
captured session cannot be un-captured.

One victim at a time, by the single-TCB design, which for a honeypot is a
feature: a second attacker meets silence, cheaper than a second stack to audit.

**Verified live under QEMU** -- the first Mirror piece that could be, via
`hostfwd` (a `--hostfwd` flag added to `drive.py`). A host socket connected into
the guest and received a real decoy banner (`SSH-2.0-OpenSSH_9.2p1
Debian-2+deb12u3`, then `SSH-2.0-OpenSSH_7.4` on the next connect -- the seed
rotating), and the guest logged both: `10.0.2.2 ssh bytes=14 first=id; uname
-a`. Two bugs fell out of the live run and neither was reachable any other way:
the passive close set `closing` without moving to `FinWait1`, so the machine
served the banner and then stuck in CloseWait, logging nothing (the client
`close()` moves the state; the honeypot path now does too); and the RTSP
Server-header split was asserted wrong in a selftest that only failed on a real
boot, the exact "grep the whole selftest for FAIL" lesson, caught late.

Attribution -- peer address, protocol, the first line of what they sent -- is
the product, and it is the frozen-base argument in a new place: the capture is
data the loop could later learn from, recorded re-derivably.

### 4. The tarpit (built), and the maze (design)

Cost imposition, still on our turf. The **tarpit** (`honeypot tarpit <proto>
<port>`) holds a connection open and dribbles one plausible preamble line per
interval, never a completing banner, so the peer's client blocks reading and its
connection budget drains against a service that never finishes (endlessh's
method). On the single-TCB stack it holds one victim at a time and releases
after a drip cap, logging the count of lines the peer waited through as the cost
imposed -- not a seconds figure, which would be a guess at guest-timer
calibration. Built on the phase-3 passive open: the establish path branches on
`honeypot::is_tarpit()`, and `on_tick` drives the drip and closes the trap when
the peer leaves (a FIN into CloseWait is closed and logged, the same fix the
capture path needed).

Verified live under QEMU: a host client watched the trap dribble 10+ distinct
lines over several seconds with the connection held open, and on a clean client
FIN the guest logged `10.0.2.2 tarpit drips=11`.

The **maze** -- infinite plausible depth, a filesystem or service tree that
never bottoms out so a crawler spends itself mapping nothing -- is not built. It
needs per-connection content generation on top of the listener, which is a
larger addition than the tarpit's timer.

## How it ties to the RSI loop

The Mirror produces exactly the kind of ground-truth signal `godel` is built to
learn from: a canary trip or a honeypot session is a labelled event, the ledger
already records labelled events re-derivably, and the recon/fingerprint engines
already turn wire bytes into structured facts. A later phase could let the loop
propose *which* decoys to present and measure their catch rate -- but only
behind the same judges and the same held-out discipline as everything else,
because a self-improving deception layer that graded its own success would be
the criterion-drift failure U3 exists to prevent, in a new costume.
