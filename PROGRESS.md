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

### Screenshots

Eight `screendump` captures in `docs/screens/`, taken in one boot with the
clock inside the quiet window, referenced from the README.

---

## In progress

**End-to-end verification of the rollback fix.** A fresh machine is running
`godel judge 0.5 2 40` right now, after which `godel rollback` must return the
criterion to `bar 3.84 floor 4`. About forty minutes of prepare under TCG.

The re-run doubles as a re-derivability check. Nothing in the training path is
random, so the second run should produce a bit-identical matrix: `fixed 2 broke
0 chi 0.5` with the same anchor figures. Anything else is a finding on its own.

Boot on the fixed build is already confirmed clean: 288 selftest claims, zero
failures, all four rollback claims passing.

---

## Goals remaining

### Blocked on someone with push rights

- **The `v1.3.0` release tag.** Every attempt returns HTTP 403 from the
  organisation proxy. It has to be pushed from a machine outside this
  environment. The tag must be exactly `v1.3.0`, because the workflow enforces
  tag equality with `Cargo.toml`, and `UPDATE_SIGNING_KEY` must be set or the
  workflow stops at the signing step.

### Known defects, stated rather than hidden

- **The nightly rotation cannot reach the criterion that adopted.** The most
  permissive point in `JUDGE_GRID` is `(2.00, 2)`, and `chi` of 0.5 is under a
  bar of 2.00. So the grid is more conservative than the axis, and unattended
  running would never have found the adoption an operator command did. Either
  the grid widens or that gap is documented as deliberate.
- **`1 adopted` alongside `head: none`.** Observed during the unattended run.
  An adoption should move the head. Either `adopted` counts something the head
  does not track, such as an archive cell win, or a head write did not happen.
  Not yet chased.
- **Console bleed-through.** Terminal output paints past the window's right
  edge and over the windows behind it, visible in three of the eight
  screenshots. Upstream behaviour, not introduced by this fork.
- **A fault report on the framebuffer.** Painting from inside an interrupt gate
  raises a general protection fault, so a fatal fault on the laptop, which has
  no UART, prints one line and halts. The bug belongs to the console and is now
  visible rather than silent.

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
