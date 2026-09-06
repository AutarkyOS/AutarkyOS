# AUTARK progress

State of the fork as of 2026-09-04, on branch `claude/kernel-distro-ideas-kle4y0`.

Twenty-two commits ahead of `origin/main`, all authored `AUTARK
<autark@autarky.su>`. This file records what is finished and verified, what is
running right now, and what remains. It is written so that a session picking
this up cold can tell measured facts from intentions.

The thesis the fork exists to test:

> Does a certificate-based self-improver stay honest when the space of things
> it may propose is left unenumerated, and when the criterion that judges it is
> allowed to move?

---

## Verification standard used here

There is no `cargo test`. This is a `no_std` UEFI binary, so a claim counts as
verified when it has been through the boot selftests and driven under QEMU, and
counts as unverified otherwise however obviously correct it looks. Several
entries below are marked unverified for exactly that reason.

QEMU here runs under TCG because the container has no `/dev/kvm`, which is
roughly 160x slower than a hypervisor on this workload. A forty-example
`prepare` costs about forty minutes of wall clock. That number governs what is
practical to measure in a session and is the reason some results are at small
sample sizes.

---

## Done and verified

### The fork itself

| commit | what |
|---|---|
| `f0e8c70` | Fork identity, renamed by site rather than by pattern. All 15 on-disk magics and `GLADOS_TYPE_GUID` survive; `\GLADOS\` and `glados-update` do not. Builds as `autark.efi`. |
| `7f045ee` | The persona, and a palette where red carries meaning rather than decoration. |
| `2fa3982` | Registration in place of a setup wizard. The first onboarding this tree has had. |
| `13cc41f`, `0746583` | README rewritten around the distribution. Upstream link corrected to the kernel it actually forks. |
| `d88e594` | The AUTARK mark: a cog and a star, on maroon, drawn once and shared by the boot screen, the desktop wall, the window chrome and the favicon. |

### The invariant

`b850217`. The machine may change anything except the record of what it
changed. `/ai/godel/ledger.txt` is append-only and `/ai/godel/test-budget` is
monotone, enforced at runtime through the ranged NVMe write gate that already
existed for the ESP updater.

Two holes were found while wiring and closed: `rm /ai/godel` unnames the ledger
without the ledger's path ever appearing in the operation, and `mv somedir
/ai/godel` grafts over it. Hence `Change::Graft` distinct from `Change::Write`,
and an ancestor rule. A third was found by the guard's own selftest: `/` fails
the separator test and read as not-above-anything.

The guard lists exact paths and never the `/ai/godel` subtree, which is what
lets the criterion files below be loop-writable while the record is not.

### The conversation surface

`8328e73`, `a7dce42`. A conversation window with a real checkpoint behind it,
driven end to end. `Job::Say` on the existing agent task rather than a second
task, because a second task doing a second kind of work would need a second
entry in the engine's exclusion check.

Recorded negative result: the persona does not take at 135M. `888e4ec` then
measured that it does take at 1.7B, so the boundary is model capacity rather
than prompt design.

### Self-sufficiency

`8b54e50`. The machine can seed its own DRBG and says what that cost. RDRAND
and RDSEED detected in `cpu::Features`, mixed at `reseed` and credited zero by
default, with crediting behind `rng trust hw` as an operator decision. Network
round-trip latency added as a fourth source, which requires trusting nothing.

### Throughput

| commit | what | measured |
|---|---|---|
| `c268dcc` | Prefill split across every core | Tier 1 |
| `6bed94b` | int4 format, producer and host oracle | |
| `2cc54f7` | int4 weights end to end | 0.625 bytes/weight, 1.6x bandwidth cut |

`2cc54f7` surfaced a latent ABI bug that had been in the tree since the SMP
fabric was written. Application processors are entered by `jmp`, not `call`, so
nothing pushes a return address, yet every compiled function assumes it was
called and so entered with `rsp` eight below a 16-byte boundary. int8 never
spilled `xmm6`; int4 did, and took a general protection fault on
`vmovaps %xmm6,0x50(%rsp)`. The fix is a `- 8` on the AP stack top.

### Unbinding, stages U1 and U3

`f35fab3` (U1) removed `GRID` so a proposal became an authored artifact rather
than a point in an enumerated set, with re-derivability restored by
content-addressing the draw instead of listing the space.

`288d032` (U3) unbound the judge: the loop may propose a change to its own
significance bar, judged by a cross-evaluation matrix against a held-out anchor
no bar can see.

`b0056d5` gives the operator the morning dispatch.

### Open-ended search

`a5c799f` and `e1472c9`.

- **MAP-Elites illumination archive.** Twelve cells, four rank bands crossed
  with three repair behaviours, each holding the best variant of its kind.
- **Red Queen epochs.** The criterion is frozen inside an epoch of five trials
  and may move only at a boundary, which is the controlled-utility-evolution
  condition. `is_boundary` is a pure function of ledger length, so where the
  loop stands is re-derivable.
- **Bayesian surprise ordering.** Axes are ordered by a Laplace-smoothed Beta
  posterior, so the loop reaches first for the axis whose next verdict it can
  predict least well. Ties break by slot, so the order is total.
- **The storm.** One prepare, a whole generation: grid points trained against
  cached features, descendants of the incumbent, and chimeras bred by blending
  the low-rank factors of same-rank survivors.

Measured storm run:

```
[storm]  8 trained, 0 descendants of the incumbent, 5 chimeras bred
         archive: 4 cell(s) lit this storm; best validation 0.5
         tribunal: the best was rejected -- no net repair
```

### The loop running unattended

With the RTC inside the quiet window the initiative task fired trials without
being asked, and one of them took an archive cell:

```
prepared: 25 examples, 58 decisions, 4 guards, 140 rows (7675 ms + 1474529 ms)
archive: lit a cell -- best of its kind at rank 8
3 trial(s), 1 adopted
```

### The criterion is a pair, and the axis can reach both halves

`5ff8edc`. This came out of a measurement rather than a design review.

```
[cross-evaluation]
  candidate: fixed 2 broke 0 chi 0.5 over 24 validation
  standing bar 3.84: REFUSES
  proposed bar 2:    REFUSES
  anchor (held-out): incumbent 0.5217391 -> candidate 0.6086956
  verdict: would refuse -- both bars agree on the candidate, nothing changes
```

The anchor said the candidate was genuinely better, by 8.7 points on the set no
bar sees, against a `MIN_ANCHOR_GAIN` of 0.01. `judge_verdict` would have
adopted. It was never asked, because J1 is

```rust
fixed > broke && fixed - broke >= MIN_FIXED && chi >= tau
```

and only the third clause took `tau`. So the axis could move the constraint
that was not binding while being unable to reach the one that was.

`/ai/godel/floor` now sits beside `/ai/godel/judge` on the same terms.
`FLOOR_MIN` is 1 rather than 0, because J1 already requires `fixed > broke` so
zero and one admit the same candidates. `FLOOR_MAX` is 16, which is a claim
about the corpus rather than a round number.

Almost none of the drift machinery moved. `judge_verdict`'s "moves" and
"honest" questions read `admit_old`, `admit_new` and the anchor, which are
answers about the candidate rather than about which knob produced them, so only
the sanity question learned about a second half.

**Found while wiring, and worth more than the feature.** There were three
implementations of J1 and they had already drifted. `godel::trial` read
`judge_in_force()` while `harness::core_bench` and `work`'s role judge read
`MCNEMAR_95` and `MIN_FIXED` directly, so from the first adopted bar change a
core and an adapter were held to different standards while both printed "J1".
There is one `j1_verdict` now and all three call it.

### The judge axis moved the criterion

First adoption this axis has ever produced.

```
the criterion moved -- a looser bar admits a variant the anchor confirms
bar 3.84 -> 0.5, floor 4 -> 2, anchor 0.5217391 -> 0.6086956

1 h12 parent=root variant=4d7a12b4 n=24 pred=win
  JUDGE[bar=3.84->0.50 floor=4->2 std=refuse prop=admit chi=0.50
        anchor=52.17->60.87 a looser bar admits a variant the anchor confirms]
  ADOPT test=60.87%@read1
```

Both halves of the transition, both criteria's decisions, the statistic, the
anchor either side, and which read of the finite budget paid for it.

Note the criterion that admits this candidate is bar 0.5 and floor 2. Lowering
the floor alone does not do it: `chi` is 0.5 and the standing bar is 3.84, so
the third clause refuses as well. Both clauses were binding.

### Rollback of a criterion change

`5dde5e6`. Immediately after that adoption, `godel rollback` printed `back to
the frozen model`, detached the adapter, cleared the head, and left bar 0.5 and
floor 2 in force.

`rollback`'s `parent: None` arm returns early and the criterion restore sits
below that return. A first-ever adoption writes a root node, so that arm is the
only path a criterion change can be rolled back through, and it was the one arm
that did not restore one. The restore's own comment warns about this outcome in
those words, and the code had it anyway through the path that skipped the
restore.

It was unreachable by reading, because the branch that is wrong is the branch
only a first adoption takes, and until that run no judge trial had ever
adopted.

Fixed with one pure function both arms share, `criterion_back`. Four claims,
all passing at boot.

### The rollback record (option B)

*Built and driven live under WHPX this session.* `godel rollback` wrote nothing
to the ledger, so the record showed "adopted X" and never "…then reverted X" --
an incomplete history of what the machine changed, under a machine whose one
invariant is that that history cannot be lost. Now it appends a `revert
variant=<from> to=<to>` line (`root....` when it detaches to the frozen model),
after every restoration has succeeded, so a revert the machine could not honour
never reaches the record.

Chosen over three alternatives (append plainly / dispatch-only / leave it) for
one reason: the ledger is also the search substrate. `record_seed` hashes it to
draw the next proposal (U1) and `ledger_len` counts it to place the epoch
boundary (Red Queen). So both now read *verdict lines only* -- `verdict_bytes`
drops revert lines before the hash and `verdict_count` before the count -- and
the filter is byte-identical to the raw blob when there are no reverts, so every
existing lineage re-derives the seed it always did. The undo is on the
permanent, append-only record but invisible to the search: recording it cannot
redirect what the loop tries next.

Verified live: after `godel judge 0.5 2 40` adopted, `godel ledger` showed the
`ADOPT` line; after `godel rollback`, it showed both that line and `revert
variant=4d7a12b4 to=root....`, while `godel next` still reported `1 verdict(s)
recorded, trial 1 of 5` -- the revert on the record, absent from the clock. Four
pure claims in the godel selftest check the filter on synthetic ledgers, since
the live one is append-only and a test must not write to it.

### Screenshots

Eight `screendump` captures in `docs/screens/`, taken in one boot with the
clock inside the quiet window, referenced from the README.

---

## In progress

Nothing open at the moment. The rollback verification below closed the last
in-flight item.

---

## Verified this session (WHPX host, 2026-09-04)

The container claim in the header -- TCG only, ~160x slower, forty minutes a
prepare -- does not hold on this host. **WHPX works here** (`-accel whpx -cpu
max`), so the whole judge/rollback cycle below is minutes rather than the day
the header budgets for it. Everything in this block was driven on the real
kernel, not reasoned about.

**The judge -> rollback cycle, end to end, and re-derivable.** On a fresh
machine, `godel judge 0.5 2 40` produced, bit-identical to the run that first
found it:

```
the criterion moved -- a looser bar admits a variant the anchor confirms
bar 3.84 -> 0.5, floor 4 -> 2, anchor 0.5217391 -> 0.6086956
```

Status then showed `criterion: bar 0.5 MOVED floor 2 MOVED`, `1 adopted`, and a
lineage node `4d7a12b4`. `godel rollback` returned `back to the frozen model`,
and status restored `criterion: bar 3.84 floor 4 (the default; never moved)`
with `head: none`. One test read spent (`1/3`), as designed. The identical
anchor figures on a machine that had never run it is the re-derivability claim
demonstrated rather than asserted.

**`set_head` returning its result is verified on both paths.** The adoption set
the head (lineage node present); the rollback detached it. No `the head would
not write` line fired because nothing failed, which is the correct silence.

**`1 adopted` beside `head: none` is now the legible case.** The post-rollback
status is exactly that pairing, and it reads correctly: the counter records the
adoption that happened, the head is none because it was rolled back. What was
filed as "not yet chased" is understood and the wording carries it. The one
piece then left open -- `rollback` writing no ledger line -- is now closed;
see "The rollback record (option B)" above.

**A `diag`-array bug the boot caught that compilation did not.** Adding the two
new suites (below) took `SUITES` to 32 and I bumped the guard
`assert!(SUITES.len() == 32)` to match -- but that guard compared against a
literal, not against the `RESULTS` array it was meant to protect, so it passed
while `RESULTS` stayed length 30. `diag fingerprint` then panicked with "len is
30 but the index is 30" on the first boot that ran it. The guard is now
`SUITES.len() == RESULTS.len()`, tying the two arrays so neither can move
alone -- the promise the doc comment had always made and the assert had never
kept. This is the case for booting: compile-green was a false negative.

---

## Goals remaining

### Blocked on someone with push rights

- **The `v1.3.0` release tag.** Every attempt returns HTTP 403 from the
  organisation proxy. It has to be pushed from a machine outside this
  environment. The tag must be exactly `v1.3.0`, because the workflow enforces
  tag equality with `Cargo.toml`, and `UPDATE_SIGNING_KEY` must be set or the
  workflow stops at the signing step.

### Known defects, stated rather than hidden

- **The nightly rotation could not reach the criterion that adopted.** *Closed
  (`c8331e1`).* The most permissive point in `JUDGE_GRID` stopped at `(2.00, 2)`
  while the criterion an operator command proved adoptable was `(0.5, 2)`, so
  the loop was strictly more conservative than the axis and would never have
  found that adoption unattended -- U3 decorative except by hand. `(JUDGE_MIN,
  2)` is in the grid now; the change is reachability only, since `trial_judge`
  still grounds any loosening on the held-out anchor and spends a test read, so
  the loop reaches the point at night only when the anchor confirms it.
  Boot-verified: `godel next` consumes the widened grid, all godel claims pass.
- **`1 adopted` alongside `head: none`.** *Diagnosed and closed; verified on a
  real boot this session (see "Verified this session" above).* The pairing is
  consistent, not a bug in
  itself: `ADOPTIONS` is a per-boot atomic that only rises, and a rollback to
  the frozen model detaches the head without touching it, so the two count
  different things. What was wrong is that the machine could not *tell you
  which* cause produced the pairing, because `set_head` discarded
  `write_text`'s bool -- a failed head write incremented the counter and said
  nothing, looking identical to a normal undo. `set_head` now returns `bool`,
  is `#[must_use]`, and each of its callers reports its own meaning of failure:
  the six adoption sites announce an attached-but-unnamed variant, `ensure_head`
  refuses the trial (a lineage from the wrong parent is worse than none), and
  `rollback` errors (a head naming the child while the parent runs is the worst
  outcome). `godel status` now says `N trial(s) since boot` and, on `head: none`
  with a non-zero count, states plainly it was rolled back since. Still open:
  `rollback` appends nothing to the ledger, so an undo leaves no trace in the
  record -- a real gap under the invariant, but where those entries go is a
  re-derivability decision (`record_seed` hashes the ledger, `is_boundary`
  counts it), left for a decision rather than a tidy-up.
- **Console bleed-through.** Terminal output paints past the window's right
  edge and over the windows behind it, visible in three of the eight
  screenshots. Upstream behaviour, not introduced by this fork.
- **A fault report on the framebuffer.** Painting from inside an interrupt gate
  raises a general protection fault, so a fatal fault on the laptop, which has
  no UART, prints one line and halts. The bug belongs to the console and is now
  visible rather than silent.

### The Mirror -- deception as the posture (new)

The distro's security stance: not concealment but deception and cost-imposition,
on our own turf only. `design/mirror.md` has the four phases and the boundary
(no hack-back, no deploying onto infrastructure we do not own). Two phases built
and boot-verified this session:

- **Phase 1, decoy banners (`net/decoy.rs`).** The inverse of `fingerprint`:
  synthesise a banner the recon engine reads back *as* the named service, proven
  by a boot round-trip through `identify`. Ten protocols, seed-diverse for a
  heterogeneous fleet. Found and fixed a real `identify` ordering bug (RTSP
  misread as HTTP). Suite `decoy`; committed `e9bcc6f`.
- **Phase 2, honeytokens (`sysbox/canary.rs`).** A planted secret nothing
  legitimate reads; any read trips an alarm appended to `/ai/mirror/alarms`,
  now a fifth append-only record under `guard`, so the trip cannot be erased.
  Verified live: read the bait -> got the decoy keys + `[canary] tripped`;
  `rm`/`write` on the alarm log both refused; alarm survived. Suite `canary`;
  operator-only shell verb. The armed flag keeps the read path near-free when
  nothing is planted.

- **Phase 3, the honeypot (`net/honeypot.rs` + a passive open in `tcp`).**
  `tcp` gained a `SynRcvd` state and `passive_open`, turning the client-only
  stack into one that accepts on a listening port, serves a rotating decoy
  banner, captures the peer's bytes, and logs to `/ai/mirror/sessions` (a sixth
  `guard` record). Operator-only `honeypot listen <proto> <port>`. **Verified
  live under QEMU** via a new `drive.py --hostfwd`: a host socket connected in,
  got `SSH-2.0-OpenSSH_9.2p1 ...` (and a different identity on the next
  connect -- the seed rotating), and the guest logged `10.0.2.2 ssh bytes=14
  first=id; uname -a`. Two bugs the live run surfaced and nothing else could:
  the passive close set `closing` without moving to `FinWait1` (stuck in
  CloseWait, banner served but nothing logged); and an RTSP Server-header split
  asserted wrong in a selftest that only fails on a real boot.

- **Phase 4, the tarpit (`honeypot tarpit <proto> <port>`).** Cost imposition:
  holds a connection open and dribbles one plausible preamble line per interval,
  never a completing banner, so the peer's client blocks and its connection
  budget drains (endlessh-style). Built on the phase-3 passive open -- the
  establish path branches on `is_tarpit()`, `on_tick` drives the drip and closes
  the trap when the peer leaves. Releases after a drip cap; logs the line count
  as the exact cost proxy (not a seconds figure -- guest-timer calibration is
  not something to guess at). **Verified live**: a host client watched 10+
  distinct lines dribble with the connection held open, and a clean FIN produced
  `10.0.2.2 tarpit drips=11` in the log. A CloseWait-on-FIN leak (the tarpit
  twin of the capture-mode close bug) was found reviewing the first run and
  fixed before commit.

Not yet built: the **maze** (the other half of phase 4) -- infinite plausible
depth so a crawler spends itself; needs per-connection content generation on the
listener, a larger addition than the tarpit's timer. The doctrine for the eventual
aggressive-security network-stack rewrite and the reverse-engineering-over-
compatibility direction for foreign binaries are recorded in
`design/doctrine.md` (direction, not code).

### Reconnaissance -- a local Shodan (new this session)

*Boot-verified: both selftests pass at boot and under `diag`, and the `recon`
command ran clean end to end under QEMU (found nothing, as its NAT has no hosts
-- the expected empty result, not a failure). The live-host scan is still
GF63-only.*

`src/net/fingerprint.rs` and `src/net/recon.rs`. Shodan's method with its one
internet-scale decision removed: sweep the machine's own subnet, banner-grab
open ports, name each service by banner content. Off-subnet targets refused
(`net::alive` gates on ARP). `recon` in the shell; findings indexed under
`/ai/recon/<ip>/<port>`. Operator-only -- the model reaches Net only through a
trusted Aiksi builtin, not yet exposed.

- **`fingerprint::identify` is pure and verified.** Names SSH/HTTP/FTP/SMTP/
  POP3/IMAP/Redis/MySQL/telnet/RTSP by content not port (SSH-on-80 is still
  SSH). Boot suite `fingerprint`; also run under a host `rustc` harness, which
  caught a bug the compiler passed -- a case-insensitive search silently
  requiring a pre-lowercased needle, so Redis's own refusal did not identify it.
- **`recon::hosts_in` is pure and verified.** Subnet enumeration with network,
  broadcast and self excluded and a wide mask capped at `MAX_HOSTS`. Boot suite
  `recon`; host-harness clean.
- **`recon::scan` is unverified.** QEMU user-mode net is a NAT with no scannable
  hosts, so an ARP sweep finds nothing there -- exercised on the GF63 only,
  same bucket as RTL8168 and WPA2.
- **Next:** the Aiksi builtin surface (`recon_scan`/`recon_hosts`/`recon_host`)
  so the model can query the index -- a Net-class gate change, deliberately held
  until it can be booted.

### A connectome in the kernel (built + verified this session)

*Boot-verified and driven live under WHPX against the real `out/connectome.bin`.*

`design/connectome.md`, `tools/connectome.py`, and now `src/ai/connectome.rs`
plus a `connectome` shell verb. The honest form of "integrate a healthy human
brain": a human synaptic wiring diagram does not exist to download, but *C.
elegans* is a complete one, and at ~84 KB it lives in the kernel heap as an
ordinary graph. The steer was **full + runnable**, and both are done.

- **The loader walks and asserts.** `parse` bounds-checks every field of the
  `GLADOSXN` body and requires landing exactly on the last byte, the same bargain
  `tools/v4.py` makes -- a body with no internal offsets cannot be trusted to a
  reader that seeks. `tools/connectome.py --verify` is the separate second reader.
- **The simulator is a toy, labelled one.** `x_next[i] = tanh(gain * (W x)[i] /
  in_scale[i])`, chemical edges directed and taken excitatory (the dataset has no
  sign), electrical symmetric. It departs from the design sketch in two recorded
  ways: a sparse edge-list walk, not a dense `Mat::matvec` (1.6% density, so sixty
  times less arithmetic and no dense adjacency to materialise); and a per-node
  `in_scale` divisor the sketch lacked, without which a hub like AVAL saturates
  the graph on step one. What the selftest asserts is the machinery -- parse,
  determinism, an excitatory edge driving its target -- never worm behaviour.
- **Wired to nothing that decides.** Loaded on demand from a namespace path
  (`connectome load`), not compiled in; `LOADED`/`STATE` are read by the shell
  and the selftest and by no router, council or `godel`. As far from a decision
  as the Oracle.
- **Suite 36.** Boot selftest line + `diag connectome`; the compile-time
  `SUITES.len() == RESULTS.len()` tie was bumped 35 -> 36.

Live: `load` -> 448 neurons / 7379 connections (4681 chemical, 2698 electrical);
`neigh AVAL` -> its 132 outgoing synapses; `stim AVAL 100` then `step 1 4` lights
the VA/DA/AS motor neurons AVAL is known to drive, and `step 4 4` reaches the
body-wall muscles (dBWM/vBWM) and D-class motor neurons -- the backward-locomotion
motor pathway traced through the loaded graph, which is the biology and not luck.

### Tooling: environment notes for a hypervisor host

- **WHPX works here** (`-accel whpx -cpu max`), so the ~160x TCG penalty this
  file assumes elsewhere does not apply on this machine. Boots and trials are
  minutes, not tens of minutes.
- **`drive.py` hardcoded ports 45454/45455.** A second checkout of this kernel
  on the same host (a sibling fork, `Projects\sanctum`) binds the same pair, and
  because `-serial ...,wait=on` strands a QEMU, the second run attaches to the
  *other* project's kernel and captures its boot log -- reads as this tree's
  binary having reverted. Now overridable via `AUTARK_PORT` (monitor takes the
  next number); default unchanged.
- **`tokenizer.py --verify` needs UTF-8 output.** The Windows console is cp1252
  and the verify cases include non-Latin-1 text, so it dies on
  `UnicodeEncodeError` mid-run; `PYTHONUTF8=1` fixes it. Belongs in the tooling
  section of CLAUDE.md.

### Unbinding, stage U2

Not started. The unbound target for this tree is native code the machine writes
and adopts itself. The substrate exists: `src/cpu/code.rs` emits into a
page-aligned `Exec` and calls through a pinned `sysv64` pointer, `src/aiksi/jit.rs`
compiles the integer subset, and `code::locate` names an rip inside generated
code so a fault report stops lying. `diag differ` is the gate and was written
before the code generator on purpose. What is missing is letting the loop adopt
what comes out of it.

### Measurement at a sample size that means something

Every judge-axis figure in this file is from a 40-example subsample producing
24 validation decisions. That establishes the machinery composes and
establishes nothing about how much it helps. A full-corpus run is roughly
twenty-two minutes with a hypervisor and days under TCG, so it needs hardware
this environment does not have.

### Carried over from the plan, still open

- An authored application reaching adoption. The machine writes drafts and
  adopts none of them.
- `aixi`'s plan is stringified to a report rather than gating how much the loop
  attempts.
- Real tasks on more than one core. The machinery is proven and the `Racy`
  audit is missing. Every task is pinned to core 0, `unpin` exists, and nothing
  calls it.
- Wireless. The supplicant is complete and checked against IEEE 802.11i vectors
  at every boot, and has never had hardware to run on.

### Declined

- Tier 3, AVX-VNNI with quantized activations. Explicitly declined.
