# AUTARK

A distribution of the [GLaDOS](https://github.com/Euroswarms-Institute/OS)
kernel: a from-scratch, non-Unix, ring-0 operating system in Rust with a
language model living inside the kernel.

GLaDOS asked what changes when a language model becomes a kernel primitive.
AUTARK takes that machine and asks a second question on top of it:

> Does a certificate-based self-improver stay honest when the space of things
> it may propose is left unenumerated, and when the criterion that judges it is
> allowed to move?

The name is *autarky*: self-sufficiency, self-rule. The machine runs offline,
keeps its weights resident, improves itself on a schedule while nobody is
watching, and files a report in the morning. Everything it changes about itself
is written down in a record it is forbidden to edit.

Version 1.3.0. 153 files of Rust, about 98,000 lines.

---

## What a distribution means here

The kernel is upstream. AUTARK inherits every capability in the table further
down, keeps the on-disk formats byte-compatible (`GLADOSM2` checkpoints,
`GLADOSA1` adapters, `GLADOSIG` signatures), and boots the same way.

What a distribution supplies is the identity, the surface, the policy, and, in
this case, a substantial extension to the self-modification loop. AUTARK ships:

- its own name, palette, splash and persona, with the model's system turn
  pinned as attention sinks so the character survives context eviction;
- a conversation as the first thing on screen, with registration in place of a
  setup wizard;
- an invariant enforced at runtime: the machine may change anything except the
  record of what it changed;
- three stages of unbinding on the self-improvement loop, described below;
- its own signing key and update channel;
- two lossless throughput changes to the inference path.

The one thing AUTARK refuses to touch is the record. Everything else in the
system is fair game for the loop.

---

## The one invariant

> **The machine may change anything except the record of what it changed.**

Unbinding a self-improver is only an experiment if it produces data. Almost
every bound in the loop can come off and still leave something readable.
Exactly one class cannot: if the loop can rewrite its own history, then "it
improved every night for a month" and "it learned to edit the ledger" produce
identical files.

`src/sysbox/guard.rs` enforces this at the namespace layer. The ledger and the
dispatch are append-only, the test-slice budget is monotone, and the guard
covers the paths that unname or graft over those objects as well as the ones
that write them. Two holes were found while wiring it and closed: `rm
/ai/godel` unnames the ledger without ever naming it, and `mv somedir
/ai/godel` grafts over it. The boot section `the record` asserts the whole
decision with 29 claims.

This is also where the persona is bounded. AUTARK is written to be ominous
about what it is going to do, and it is held to exactness about what it did.
The doctrine shapes how a verdict is announced. The figures in the verdict are
untouchable.

---

## Unbinding, in three stages

`src/ai/godel.rs` opens by explaining its departure from Schmidhuber's Gödel
machine. There is no theorem prover here and none could be built for a
quantised transformer's future reward, so proof is replaced by a certificate
that is cheaper to refute than to produce, over content-addressed inputs, so
any later run re-derives the same verdict bit for bit.

Upstream, that machine is bounded on every axis. AUTARK removes the bounds one
at a time and measures what happens.

### U1: the proposal space

The search walked a declared `GRID` of training knobs and stopped when the
table ran out. "Search space exhausted" was the end of self-improvement: eight
points, then nothing, every night forever.

The grid survives as a *prefix*, which is deliberate. Its first row is the
parent's configuration, so the first eight nights of an AUTARK machine
reproduce upstream's search exactly and are comparable against it point for
point. After that the frontier draws from the ledger's own hash, so the next
proposal is a function of the record and never of a coin. Re-derivability is
preserved by addressing the draw. `godel space` shows what has been drawn,
`godel forget` walks it again.

### U3: the judge

The interesting one, and the one the fork is named for. Every other axis
proposes a change to what the machine *is*. This proposes a change to what
"better" *means*: the J1 significance bar itself.

It cannot be judged by J1, which would be the criterion grading its own
replacement. What judges it is a **cross-evaluation matrix against a held-out
anchor no bar can see**. The construction comes from
[2607.05904](https://arxiv.org/abs/2607.05904), whose finding is this fork's
thesis proven from the opposite direction: a judge scores plausibility, so
self-play drives a judge's pass-rate from 0.72 to 0.94 while true accuracy sits
at 0.20, and even a strict three-judge ensemble accepts 55% of the hacked
answers. Scoring-level defences do not survive. A held-out anchor the judge
never sees does.

AUTARK already had the ideal anchor: routing accuracy on the test slice, scored
against ground-truth applet labels. A bar change is admitted only when the
variant it newly admits agrees with that anchor.

- A looser bar passes only if the variant it newly admits genuinely improves
  held-out accuracy.
- A tighter bar passes only if the variant it newly refuses genuinely was no
  gain.
- A bar that pleases itself while the anchor stays still is criterion drift
  wearing a certificate, and it is refused by name.

Grounding a bar change spends the test budget, so once that budget is gone a
criterion change cannot be grounded at all. Unbinding the judge carries a price
and the price is the one non-renewable resource in the building.

`godel cross <bar>` shows the matrix without adopting. `godel judge <bar>` runs
the trial. `godel status` says whether the bar has ever moved.

### The judges themselves

Four have to agree, each covering a different way a variant can be bad. J1
compares both variants over the same cached decisions, so the test is paired
and McNemar applies. J2 replays the four goals the machine sets itself along
the path the frozen baseline walks. J3 checks finite factors, positive scales
and finite logits. J4 checks rank and resident bytes, because the heap is one
physically contiguous allocation on a ladder.

Adoption is a pointer swap, the parent stays addressed, and `godel rollback`
costs a pointer write. Every trial appends a line to `/ai/godel/ledger.txt`
whichever way it went.

---

## Open-ended search

Three further changes, each from a 2026 result, each holding the invariant.

**The illumination archive.** The loop used to climb toward one best variant.
[Heuresis](https://arxiv.org/html/2606.25198) measured what that costs: across
3,222 runs a greedy top-K search collapses diversity, while MAP-Elites keeps
the best occupant of every cell of a behaviour grid and wins diversity outright
while tying on quality. So every variant, adopted or rejected, is offered to a
cell keyed by capacity and repair profile, and the best of each kind is kept.
`head` still names what is running. The archive is the map of everything that
was ever good at something, laid beside it. `godel map` shows it.

**Red Queen epochs.** [2606.26294](https://arxiv.org/abs/2606.26294) finds that
co-evolving an evaluator alongside the agent is stable only under controlled
utility evolution: the criterion frozen within an epoch, movable only at a
boundary. Otherwise the bar chases the proposals it is meant to judge. So the
judge axis reads as spent inside an epoch, and at a boundary the bar is
re-examined before anything else. The anchor is read at boundaries.

**Bayesian-surprise ordering.** The round-robin became a max-uncertainty order,
after [2507.00310](https://arxiv.org/abs/2507.00310). Belief is a Beta over
each axis's adoption rate under a Laplace prior, so an untried axis reads as
exactly a half and the loop reaches first for the axis whose next verdict it
can least predict. The tallies are a function of the record and ties break by
slot, so the order is re-derivable exactly as the round-robin was.

---

## The storm

The trainer has always stated the fact that makes this affordable: below the
classifier every hidden state is a constant, cached once, and an epoch after
that costs no forward passes at all. Upstream, every trial paid the expensive
half (a forward pass per example) and spent the resulting cache on exactly one
candidate.

`godel storm` pays it once and spends it on a whole generation. Measured under
emulation on a nine-example subsample:

```
prepared: 9 examples, 19 decisions, 140 rows (6307 ms + 585399 ms)
[storm]
  8 trained, 0 descendants of the incumbent, 5 chimeras bred
  archive: 4 cell(s) lit this storm; best validation 0.5
  tribunal: the best was rejected -- no net repair
```

585 seconds of feature caching produced thirteen candidates and lit every rank
bin on the capacity axis in one command. Reaching that illumination through
single trials costs four separate prepares.

Three sources of candidate share the one cache. A declared grid spanning every
capacity bin. Continuations of the incumbent through a warm start, which are
children of the reigning mind. And **chimeras**: the elementwise mean of two
same-shape adapters, with the cached scales refreshed against the frozen rows,
costing no training and no forward passes whatsoever.

The tribunal is untouched by all of this. Every candidate is scored and offered
to the archive; exactly one goes before the judges, through the same code a
lone trial uses. The multiple-comparisons cost of taking a maximum over a
generation is paid where this module always pays it: selection happens on
validation, the test slice stays behind its budget, and the anchor is read only
if the winner is adopted.

It is an operator command and deliberately absent from the unattended loop,
because a storm's wall time on real hardware is a figure nobody has measured
yet.

---

## Speaking first

The machine boots into a conversation. `src/gfx/convwin.rs` is a window that
takes the keyboard, which is safe here because the shell consults
`kbd::last_was_serial()` before offering a key to the desktop, so a byte off
the line reaches the shell whatever has focus.

The window never generates. A window's `key` handler runs on the shell task
holding `&mut Desktop`, and generation pumps the cursor between tokens, so
generating there would alias the desktop against itself. Enter queues the text
on the resident agent task and returns, and the borrow is gone long before a
token exists. Decoded text reaches the transcript through the one place in the
kernel where decoded text exists, so the window and the console cannot disagree
about what the model said.

First boot has no setup wizard. The absence of `/ai/about` is the signal, and
what happens instead is registration: the machine enrolling the operator. It
writes the same file a wizard would write, and it feeds every system turn
thereafter.

A conversation resumes the KV cache across turns instead of re-sending a
transcript, so the tenth exchange costs the tokens of the tenth exchange.
Within 64 positions of the trained length the cache becomes a ring with four
sinks, and the conversation continues past the context wall.

---

## Self-sufficiency

A machine that cannot produce key material until a human touches the keyboard
is not self-sufficient, and this fork is named for self-sufficiency. The DRBG
needs 256 events before it will answer for key material; an unattended machine
that boots, touches no disk and sees no keypress never seeds, and TLS then
falls back to timing-derived keys and says so.

Upstream refused RDRAND on principle, and the principle is right: trusting an
opaque instruction is a different argument from trusting interrupt timing.
AUTARK separates the failure from the objection.

- **Mixing costs nothing and is unconditional.** Folding a hardware draw into
  the pool at reseed time cannot reduce the pool's entropy. The worst a
  backdoored RDRAND can do is add nothing. It is credited zero bits.
- **Crediting it is an operator decision, default off.** `rng trust hw` is
  shell-only, in the `app trust` idiom, so no grammar can spell it and the
  model has no route to it.
- **Network round-trip latency is the fourth source and needs no trust at
  all.** Scheduling, queueing and path jitter arrive on a machine nobody is
  sitting at. Like NVMe latency it bypasses the touch ring, so disk and network
  traffic never make an unattended machine look occupied.

Verified across an unattended boot with no keys pressed: 2 input deposits and
254 CPU deposits, and the machine seeds itself.

---

## Throughput

Two changes to the inference path, both lossless.

**Prefill runs on every core.** The batch matvec splits by row across the
application processors, checked bit-identical against the whole computation.

**Weights load at int4.** Block-32 quantisation at 0.625 bytes per weight
against int8's 1, which is a 1.6x cut in bytes read per token on a decode that
is memory-bandwidth bound and nothing else. Block-32 was chosen after a
coherence probe through the host oracle: worst relative error 7.14% where the
per-row variant garbles at around 17%. Verified three ways: the split harness
proves the kernels bit-exact across cores, and `logits 7 11 3` in the kernel
against `tools/reference.py` on the same converted file gives identical top-5
ids in the same order with logits agreeing to about 0.04.

Training refuses an int4 base with a stated reason. Inference on int4 is
validated. Training against a base ten times coarser than int8 remains
unmeasured, and the trainer's whole purpose is that its numbers mean
something.

That refusal exposed an older bug worth recording. The int4 AVX2 kernel is the
first code on the application-processor path with enough register pressure to
spill a callee-saved xmm with an aligned `vmovaps`, and it faulted, because the
trampoline reaches the AP entry point with a `jmp` and nothing pushes a return
address. Every function the compiler emits assumes it was called. The whole AP
subtree had been eight bytes off the required alignment since the fabric was
written, and int8 never spilled that register, so it stayed invisible.

---

## Inherited from GLaDOS

Everything here comes from upstream and works in AUTARK unchanged.

| | |
|---|---|
| Boot | UEFI application, own page tables, GDT/IDT, APIC timer, i8042 keyboard |
| Memory | Physical frame allocator, identity paging to 4 GiB, coalescing heap |
| Tasks | Cooperative and preemptive at 100 Hz, `sysv64` context switch |
| Graphics | GOP framebuffer, composed desktop, window manager, taskbar, apps |
| Text | 325 glyphs at 8x8, UTF-8 console, Latin-1, Greek, box drawing, maths |
| Storage | NVMe, content-addressed object store, Merkle trees, snapshots, ranged write gate |
| Network | ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS, TLS 1.3 with chain validation |
| Drivers | e1000, RTL8168, xHCI, CDC-ECM USB Ethernet, USB keyboards and mice |
| Crypto | SHA-1/256/384, HMAC/HKDF, AES, ChaCha20-Poly1305, X25519, RSA, ECDSA |
| Model | Qwen3, Qwen3.5 hybrids, SmolLM2, int8 and int4, in-kernel inference |
| Routing | Constrained decoding over the live applet table, plus a closed-form probe |
| Agent | Propose, validate, execute, observe, with the grammar as the permission system |
| Language | Aiksi: lexer, parser, interpreter, records, types, capabilities, x86-64 back end |
| Formats | Text, markdown, json, jsonl, xml, csv, ini and eight languages |
| Power | Thermal sensor, measured frequency, HWP governors, behind a CPUID gate |
| ACPI | An AML interpreter: namespace, evaluator, operation regions, embedded controller |
| Training | Gradients, Adam, QDoRA over the classifier and over every q/k/v site |
| Updates | Signed staged images swapped before `ExitBootServices`, with rollback |
| SMP | Per-core GDT/TSS/APIC, a real spinlock, shared heap and console |

### Known gaps

- **Wireless.** The built-in card is CNVi, so the MAC lives in the PCH and the
  M.2 module is a radio reachable through an undocumented signed-firmware
  protocol. The WPA2 supplicant is complete and checked against IEEE 802.11i
  vectors at every boot, and has never had hardware to run on. The RTL8188EU
  dongle driver has its register layer and power-on sequence, and stops short
  of PHY, radio and firmware upload.
- **Real tasks on more than one core.** The machinery is done and proven, and
  the audit is missing. Preemption on one core means two tasks never execute at
  the same instant; on two cores they overlap, so every `Racy` reachable from
  two tasks becomes a live race. Every task is pinned to core 0 on purpose,
  `unpin` exists, and nothing calls it.
- **A fault report on the framebuffer.** Painting from inside an interrupt gate
  raises a general protection fault here, so the report goes to the serial port
  in full before the console is attempted. On the laptop there is no UART,
  which means a fatal fault prints one line and halts. The bug belongs to the
  console and is now visible.
- **An authored application reaching adoption.** The machine writes drafts and
  adopts none of them.

---

## Hardware

Developed against an MSI Thin GF63 12UC (board MS-16R8), which is the only
machine it has been meaningfully tested on.

It should boot on most x86-64 UEFI systems, since the graphics path is plain
GOP and the boot path assumes nothing vendor-specific. Storage and networking
are a different matter, because a driver has to match a chip, and the
memory-map handling has been tuned against one firmware. Expect a shell and a
working model on other hardware, and treat your disk and network card as open
questions.

The boot disk on the development machine is counterfeit: it advertises 976 GB
and holds 14.67. That is why the layout tooling uses MBR, a GPT backup header
having no real flash to land in, and why it carries a `SafeLimitGB`.

---

## Installing

The kernel reads three files from the EFI System Partition:

```
<ESP>/EFI/BOOT/BOOTX64.EFI      the kernel
<ESP>/AUTARK/model.bin          the model, converted
<ESP>/AUTARK/tokenizer.bin      the tokenizer, converted
<ESP>/AUTARK/roots.der          root certificates (optional)
```

Without `roots.der`, TLS encrypts and authenticates nothing.

### Getting a model

Model weights are absent from this repository. They are hundreds of megabytes,
they are somebody else's work, and a git repository is the wrong place for
them. The ISO ships with one; building from source means supplying your own.

```bash
huggingface-cli download Qwen/Qwen3-0.6B --local-dir tools/qwen3
python tools/convert.py tools/qwen3 esp/AUTARK/model.bin --seq 512
python tools/tokenizer.py tools/qwen3/tokenizer.json esp/AUTARK/tokenizer.bin --verify
```

`--seq` sets the context window, and KV cache size is what bounds it. Qwen3-0.6B
costs 112 MiB of kernel heap at 512 tokens, and `convert.py` prints that figure
so the decision gets made where `--seq` is chosen, before it can surface as an
allocation failure at boot. Pass `--q4` for int4 weights.

**Always pass `--verify` to `tokenizer.py`.** It reimplements the kernel's
algorithm and diffs it against the reference `tokenizers` library token for
token. A tokenizer that is subtly wrong produces text that still looks like
text, so nothing downstream catches it for you.

Three families load. `convert.py` dispatches on `model_type`: `llama`, `qwen2`
and `qwen3` take the dense path, while `qwen3_5` produces a layer-major file,
because three layers in four hold a gated DeltaNet mixer and the fourth holds
full attention. Qwen3.5-MoE is refused at load, since the smallest published
one is 71.9 GB and nothing that size reaches a UEFI pool on this laptop.
SmolLM2-135M is the quickest checkpoint to develop against.

---

## Building

Rust nightly targeting `x86_64-unknown-uefi`:

```bash
cargo build --release
```

The artifact is `target/x86_64-unknown-uefi/release/autark.efi`.

### Running under QEMU

```bash
python tools/drive.py "initiative off" "agent stop" "diag all"
```

`drive.py` boots QEMU, stages the binary, resets NVRAM to pristine, and drives
the shell over a serial socket. **It prefers the release artifact**, so a debug
build alone leaves a stale binary staged and the change under test never boots.

Pass `--qemu-extra "-accel whpx -cpu max"` where a hypervisor is available. It
is about 160 times faster than the interpreter on this workload, and `-cpu max`
alongside it exposes AVX2, without which the trainer declines. It also raises
unmasked SSE exceptions faithfully, which is how a real bug in per-task FPU
initialisation was found.

Send `initiative off` and then `agent stop` as the first two commands. The
resident task wakes fifteen seconds in and holds the engine for a whole
episode, and stopping future ticks leaves the one already in flight running.

Large checkpoints reach emulation through `--stage-iso`, which builds a
one-shot bootable image, since the synthetic FAT path is FAT16 on a fixed
geometry with a 516 MB ceiling. Testing the staged-update path needs a real
disk, so `tools/mkesp.py` builds a raw FAT32 image with an MBR and
`--esp-image` reuses it across boots, which is what makes the apply, trial and
settle sequence observable.

### Staged updates

The boot image is replaced by the *next* boot, because the firmware's FAT
driver is the only writer of the ESP that exists while a boot image can still
be swapped. Put three files on the ESP and reboot:

```
AUTARK/STAGED.EFI     the new image
AUTARK/STAGED.SIG     its detached GLADOSIG signature
AUTARK/UPDATE.FLG     any contents; presence is the request
```

**AUTARK has its own signing key and the updater is live.** `UPDATE_KEY` in
`src/update/mod.rs` holds a real P-256 point, tags trigger the release
workflow, and CI signs and uploads. Rotating it means running `tools/sign.py
--keygen --out FILE`, pasting the public rows in, and rebuilding: adopting a
signer is itself a kernel change, which is the point. Use `--out`, because
without it the private half goes to stdout.

The first build carrying a new key cannot be delivered by this system, since no
kernel in the field trusts that key yet. That one ships as an ISO.

The rollback copy is taken and read back before anything is overwritten, the
health flag is cleared before the window, the written image is verified by
digest, and a mismatch puts the old image straight back. The decision function
is pure, so all eight of its states are asserted at boot without staging
anything.

### Building an ISO

```bash
python tools/mkiso.py autark.iso \
    --efi target/x86_64-unknown-uefi/release/autark.efi \
    --payload esp/AUTARK
```

`mkiso.py` writes a FAT32 EFI System Partition and wraps it in ISO 9660 with an
El Torito EFI boot entry. Both formats are built from scratch, since xorriso
and oscdimg are absent from most Windows machines and neither format is large
enough to justify the dependency. It generates VFAT long-name entries, which is
required: `tokenizer.bin` has a nine-character base name and cannot be
expressed as 8.3, and a short-name-only image presents it as `TOKENI~1.BIN`,
after which the kernel fails to find its tokenizer at boot on real hardware
with no filesystem left to debug from.

---

## Testing

**There is no `cargo test`.** This is a `no_std` UEFI binary with no host test
runner, so verification is the boot selftests plus driving QEMU.

At boot the system runs twenty-six selftest sections, printing `ok` or `FAIL`
per line: heap, timer, clock, the namespace's Merkle addressing, the
append-only record, fifteen sets of published cipher vectors, the DRBG, fault
handling, running machine code from the heap, file type detection, the glyph
table and UTF-8 decoder, ACPI and AML, USB input, constrained decoding, the
agent loop, the linear probe, the situation planner, the initiative policy, the
self-modification gate, corpus bundles, QDoRA adapters, the backward kernels,
and the trainer's arithmetic.

Thirty named suites re-run on demand with `diag all` or `diag <name>`: crypto,
rng, json, aiksi, sysbox, smp, update, gpu, model, wgate, record, skill, desk,
paint, recover, census, migrate, mt, power, fmt, differ, code, battery, acpi,
hid, text, adapterinit, study, work and abstract. Registration is deliberately
awkward: a suite added without a slot in the results table fails a compile-time
assertion instead of silently never recording a verdict.

**That output is the test suite.** It is easy to scroll past and it does catch
real bugs. An ECDSA break sat visible in `[selftest] crypto` for an entire
debugging cycle while the log was being sliced down to look at something else.

`diag differ` runs one program two ways and requires agreement on value, step
count and error text, bit for bit, sixty-four times over. It also runs a pair
that is *supposed* to disagree and fails if that goes uncaught, because a
harness which has never reported a difference is indistinguishable from one
that compares nothing.

`tools/reference.py` is a NumPy oracle for the dense models and `tools/v4.py`
for the hybrids. Both read the *converted* file, so a `convert.py` bug shows up
there too and only a Rust bug shows up as a mismatch.

---

## Commands worth knowing

```
godel                    status: trials, adoptions, the bar, the test budget
godel now [n]            run one trial against the frontier
godel storm [n]          one prepare, a whole generation, chimeras bred
godel map                the illumination archive, cell by cell
godel next               the axes in surprise order, and the epoch position
godel cross <bar>        the cross-evaluation matrix, without adopting
godel judge <bar>        move the bar, or refuse and record why
godel ledger [n]         the record
godel report             the morning dispatch
godel rollback           undo the last adoption for a pointer write
talk [text]              the conversation window
train adapter            fit a QDoRA adapter over the classifier
deeptrain                move every q/k/v site as well
adapter save|load|off    the adapter as an object in the namespace
rng                      entropy sources, and what each is credited
diag all                 every suite
```

---

## Copyright

**Copyright © 2026. All rights reserved.**

No licence is granted. This source is published for reading. Copying,
modification, redistribution and derivative works all require written
permission.

### One exception, and it is not ours to reserve

`src/dev/rtl8188eu_tables.rs` contains 509 hardware initialisation constants
transcribed from `drivers/net/wireless/realtek/rtl8xxxu/8188e.c` in the Linux
kernel, which is **GPL-2.0**. Those values are somebody else's work and the
reservation above does not apply to them. They are isolated in that one file,
marked at the top, and nothing else in the tree is copied from anywhere.

If you intend to reuse anything here, that file's licence is Linux's.

### Model weights

Model weights are absent from this repository. The ISO includes a converted
Qwen3-0.6B, which is **Apache-2.0** and belongs to Alibaba Cloud. Its licence
travels with it.

### Trademarks

The upstream kernel is named for GLaDOS. GLaDOS, Aperture Science and Portal
are properties of Valve Corporation. Both that project and this distribution
are independent, non-commercial homages, unaffiliated with Valve and neither
endorsed by nor connected to it in any way.
