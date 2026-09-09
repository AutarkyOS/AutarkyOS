# Mining many coins at once, and which ones

Status: yespower is implemented in ring 0 and measured; see "Measured" below.
No coin has been mined. Every *network* figure is still absent on purpose
rather than guessed at, for the reason the last section gives. What is settled
here is the shape of the problem, the licence gate, and which algorithm family
the arithmetic points at.

## The idea

GLaDOS stays on x86-64 and mines several coins simultaneously, carving itself
into slices sized to what the low-power devices those networks are made of
actually have. The point is not to beat ASIC farms; it is to take a meaningful
share of a dozen small networks at once rather than a negligible share of one
large one. Monero is out by decision: it is the crowded one.

A GLaDOS-only pool aggregates all of it, converts, and pays out in $GLADOS, so
a miner sees one token rather than twelve coins.

**Owning the pool is what makes the kernel side small, and that is the
non-obvious part.** The pool speaks every upstream dialect -- Bitcoin's
`mining.notify` with coinb1/coinb2/merkle_branch to one coin, Monero's
`login`/`getjob` blob shape to another -- and GLaDOS speaks one protocol to us.
The right shape for that protocol is Monero's rather than Bitcoin's: the pool
pre-builds a blob, the kernel mutates a nonce inside it and hashes. **The
kernel then never learns what a coinbase or a merkle branch is, for any coin.**

The Stratum V1 client already in `src/mine/` is not wasted by that. It moves to
the pool as its *upstream* client, host-side, where it is ordinary code.

| | work |
|---|---|
| Kernel | N hash algorithms, one blob protocol, a supervisor with real resource budgets |
| Pool | N stratum dialects, N upstream connections, share accounting, conversion, payout |

## The budget being spent is L3, not cores and not RAM

Three limits, in the order they bite.

**Task slots bite first and are the easiest to design around.** `MAX_TASKS` is
24, `MAX_CPUS` is 16, every application processor takes a slot through
`adopt_idle`, and slots are never reclaimed. On the GF63 roughly twenty of the
twenty-four are spoken for before any mining starts, and a `mine off` / `mine
on` cycle burns more. So the unit is **a job per slice, with one supervisor
rotating which coin each slice works** -- never a task per coin, which caps out
in the low single digits and then bricks the machine.

**Heap is not the limit.** Boot reports `heap 320 MiB` plus `+1020 MiB across 1
more regions (1340 MiB total)`. At yespower's 8 MiB that is over a hundred
jobs' worth. Memory is not what runs out.

**L3 cache is the limit, and it is the interesting one.** yespower is built to
hammer L2 -- that is precisely the mechanism that makes it GPU-unfriendly --
and its 2 to 16 MiB working set exceeds any single core's L2 by design.
Concurrent jobs therefore contend in L3. Upstream's own PERFORMANCE file says
so directly:

> running 8 threads results in substantial slowdown

The GF63's i5-12450H has roughly 12 MB of L3. At the 2 MiB setting that is
**about four to six concurrent jobs** before they steal from each other; at
8 MiB, one or two.

**That figure is arithmetic and not a measurement**, and `mine sweep` is the
command that would settle it. Under QEMU it cannot:

    [mine sweep] yespower 1.0 N=2048 r=8
      1 slice(s)  387 H/s  (100% of one)
      2 slice(s)  704 H/s  (181%)
      3 slice(s)  992 H/s  (256%)
      4 slice(s)  993 H/s  (256%)

The curve bends hard at three and goes perfectly flat after it -- and that is
**core count rather than cache**. The guest has four vCPUs and core 0 is
carrying the shell and the clock, so three is all there ever was. An emulator
with four cores cannot find a wall that only appears when jobs outnumber the
cache, so this measurement belongs on the GF63 and is in the hardware runbook
(`todo`) accordingly.

What the sweep *does* settle here is that the slices genuinely run in parallel:
2.56x on three of them is impossible for tasks sharing one core, which would
sum to 1x however many there were.

## yespower, measured upstream

Memory is `128 * N * r` bytes. Upstream's recommended settings:

| setting | N, r | memory |
|---|---|---|
| 1 MiB | 1024, 8 | 1 MiB |
| 2 MiB | 2048, 8 | 2 MiB |
| 4 MiB | 1024, 32 | 4 MiB |
| 8 MiB | 2048, 32 | 8 MiB |
| 16 MiB | 4096, 32 | 16 MiB |

Throughput, from upstream's PERFORMANCE file, on an i7-4770K (2013) with four
threads:

| version | N=2048, r=8 (2 MiB) | N=2048, r=32 (8 MiB) |
|---|---|---|
| yespower 0.5 | 3700-3800 H/s | ~803 H/s |
| yespower 1.0 | ~3995 H/s | ~831 H/s |

Roughly 1,000 H/s per core at 2 MiB and 200 at 8 MiB, on hardware a decade
older than the GF63. Those are four-thread figures on a four-core part, so they
already include some contention.

## Measured, in ring 0

`mine bench <ms>` hashes flat out with no pool and no network. QEMU under WHPX,
`-smp 4`, best of one, five-second samples:

| algorithm | H/s | working set |
|---|---|---|
| sha256d | 88,297 | 0 |
| yespower 1.0, N=2048 r=8 | **125** | 2,146 KiB |
| yespower 0.5, N=2048 r=8 | 97 | 2,058 KiB |
| yespower 1.0, N=2048 r=32 | 33 | 8,296 KiB |

Two internal consistency checks fall out and both hold. **r=32 is 3.8x slower
than r=8**, where upstream's own figures give 4.8x -- the same shape, since `r`
scales the blockmix work linearly. And **0.5 is slower than 1.0 at identical
parameters**, which it must be: 0.5 runs salsa20/8 with PWXrounds=6 where 1.0
runs salsa20/2 with PWXrounds=3, so 1.0 is simply less work per hash. A build
where those two came out the other way round would have the versions swapped
somewhere.

The working set is what `128 * N * r` predicts plus the S-boxes, so
`Hasher::footprint` is telling the truth and the slice budget can be trusted to
it.

**Against upstream, we are about 8x slow**, and that is expected rather than
alarming: upstream's ~1000 H/s per core is `yespower-opt.c` on bare metal, and
this is `yespower-ref.c` under an emulator. The reference is what the vectors
are checked against; speed is a later change with them still passing.

### The number that matters is not the bench one

The same algorithm, measured **inside the mining loop** rather than flat out:

    mine bench   125 H/s   over 632 hashes in 5039 ms, 5 tasks
    mine (loop)   40 H/s   over 240 hashes in 5955 ms, 7 tasks

**Three times less, on the same machine and the same algorithm.** The bench
runs on the shell task while everything else is blocked; the miner is one
runnable task among seven and gets a round-robin share of one core.

Both numbers are honest and they answer different questions. The bench says
what the algorithm costs, which is what a comparison against upstream or
against another algorithm needs. The loop says what a slice actually delivers,
which is what the supervisor's accounting and every expected-value figure must
use. **Quoting the bench number in an EV calculation would overstate earnings
by 3x**, and `mine ev` therefore reads the loop's counter and prints the task
count beside it.

### And a pinned slice is not an unpinned one

Those two figures were taken with the miner pinned to core 0 like every other
task this kernel has ever spawned. A slice on a core of its own reads **387
H/s** -- three times the bench and nearly ten times the pinned loop.

Two things changed at once there and it would be dishonest to credit one: the
slice was unpinned *and* the sweep rests the shell on `hlt` rather than letting
it poll. So the honest statement is that a slice with a core to itself and
nothing competing does about 387 H/s under emulation, and how that splits
between the two causes has not been measured.

**Every rate in this section is a QEMU rate.** The kernel says so itself now:
anything printing a hash rate asks `dev::power::virtualised()` and appends a
note when a hypervisor is present, because a figure that does not say what it
is worth gets quoted as though it were hardware.

## Many coins at once, which is now a thing the kernel does

`src/mine/work.rs` is the table: four slots, each with its own label, its own
algorithm and its own job, and a supervisor saying which slice works which slot.
`mine coin <n> <label> <algo...>` installs one, `mine coin <n> off` removes it,
`mine coins` prints the table.

Measured under QEMU with three slices over two coins, which is the whole claim
of this section in one command:

    slot  label       slices  source   rate            algorithm
    1     zeny        2       fixture  676 H/s         yespower 1.0 N=2048 r=8
    2     bitcoin     1       fixture  238759 H/s      sha256d

Two different proof-of-work functions, on two different cores, at the same
instant. Clearing the second put all three slices back on the first and it read
968 H/s, against 676 on two -- so the supervisor's re-spread is visible in the
figures rather than only in the table.

**The aggregate hashrate had to be abandoned, and that is the interesting
part.** One `HASHES` counter was a fair summary while every slice computed the
same function. Sum those two rows and the answer is 239,435 "H/s", which is
238,759 with rounding: the yespower work -- the work that is actually scarce and
actually worth something -- disappears entirely into a number dominated by the
cheap algorithm. So there is a counter per slot and the report prints a row per
coin with no total anywhere. `client::HASHES` survives only as the *sweep's*
counter, where one coin is in the table by construction.

**A slot's figures are forgotten whenever what produced them changes** -- the
algorithm, or its share of the slices. That was found rather than designed:
clearing a coin took slot 1 from two slices to three and it reported 792 H/s,
which is neither the two-slice rate nor the three-slice one and looks perfectly
plausible as either.

**Assignment is sticky, and that is a memory decision rather than a policy.** A
slice keeps its hasher across batches because `Yespower` owns up to 8 MiB of
working set and a batch at that setting is eight hashes; rotating a slice
between coins per batch would throw that allocation away and take it again
several times a second, spending more time in the allocator than in the
algorithm. So a slice stays on a coin until the table changes.

**A share carries its slot and is checked twice.** Only slot 0 has a connection
behind it. A fixture slot exists to be measured and its target is one nothing
meets -- but the day one does, through a mistyped difficulty or a target of all
ones, submitting it would send the pool a share for a header it never issued,
which is how a worker gets banned. The miner declines to queue it and
`drain_shares` declines to send it.

**What this is not yet.** Every slot but the pool's is fed by a *fixture* job,
because there is one Stratum connection and no protocol that can carry several
coins down it. That is not a stopgap to be replaced by four connections -- four
socket tasks do not fit in `MAX_TASKS` beside four slices -- it is the shape
that waits for the pool in the table at the top of this file to exist and speak
one protocol with a coin field in it. The kernel half of "mine many coins at
once" is done; the half that makes the coins real is Part B.

## The licence gate

This decides where implementations may come from, and it is a gate rather than
a preference. The reasoning is the one `mkiso.py` already applies to Xash3D:
a GPL source read to write a kernel this project does not GPL is an obligation
nobody has decided to take on.

| source | licence | usable |
|---|---|---|
| [openwall/yespower](https://github.com/openwall/yespower) | **2-clause BSD** (Colin Percival, Alexander Peslyak) | **yes** |
| [tevador/RandomX](https://github.com/tevador/RandomX) | BSD-3 (tevador, Monero Project) | yes |
| [JayDDee/cpuminer-opt](https://github.com/JayDDee/cpuminer-opt) | **GPL-2** | **no** |

That last row is the trap. cpuminer-opt is where reference implementations of
most niche algorithms live, including yespower, GhostRider and dozens more, and
it is the first thing anybody searching for "how do I implement X" will find.

**The rule: go to each algorithm's own upstream, never to the multi-algo
miner.** yespower has its own BSD repository. RandomX has its own. Where an
algorithm exists *only* inside a GPL miner it costs a clean-room implementation
from the specification, or it does not get done -- and that cost belongs in the
candidate table beside the algorithm, not discovered afterwards.

BSD-2 needs the copyright notice retained, which is exactly the arrangement
`src/doom/` already has with room4doom's MIT: one file, marked at the top,
saying where it came from.

## Candidates, ranked by what they cost us

| algorithm | coins | cost | notes |
|---|---|---|---|
| SHA-256d | many | **done** | in ring 0, pinned by block 125552 |
| BLAKE2s | several | **~done** | written in `exp/xpu`, `algocheck.py` oracles it |
| kHeavyHash | Kaspa family | **~done** | written in `exp/xpu`, oracle exists |
| **yespower / yescrypt** | **BitZeny, Yenten, Koto, WAVI, Veco, PRiVCY** | **low** | BSD upstream, scrypt-derived, 1-16 MiB |
| VerusHash | Verus | low-moderate | Haraka512 over AES-NI |
| Argon2d | Nimiq | moderate | well specified, memory-hard |
| AstroBWT | Dero | moderate | Burrows-Wheeler + Salsa20 + SHA3 |
| CryptoNight family | Conceal, others | heavy | five hash functions, 2 MB scratchpad |
| GhostRider | Raptoreum | **heavy** | x16r *plus* CryptoNight family, and the reference is GPL |
| RandomX | Monero, Zephyr, SAL | **heaviest** | a VM with a JIT; 2 GB fast mode does not fit the heap ladder, 256 MB light mode is ~10x slower |

**yespower wins on five axes at once**, which is why it goes first: cheapest to
implement, smallest working set so the most jobs fit, licence-clean at source,
CPU-only by construction rather than merely ASIC-unfriendly, and attached to
the smallest networks in the table. Nothing else scores well on all five.

Three algorithms are already most of the way there. Porting a hash kernel from
the CUDA in `exp/xpu` to CPU Rust is far cheaper than writing one, and
`tools/algocheck.py` transfers unchanged as the oracle.

## What is deliberately absent, and how to get it

**No network hashrates, no prices, no coins-per-day.** miningpoolstats, poolbay
and bitinfocharts all render those in JavaScript and none of them yielded a
figure. Inventing them would be worse than the gap, and they would be stale
within days regardless.

**The kernel already reads the real number off the wire.** `mine probe` pulls
`nbits` out of a live `mining.notify`, and `nbits` *is* the network target;
`ev::coinbase_value` sums the block's own outputs; `mine ev` turns those plus a
measured hashrate into coins per day. That is a measurement against the live
network rather than a table somebody typed.

So the way to score a coin is to point `mine probe` at its pool and read what
prints. The catch is circular and worth stating: a pool will not hand out work
a miner cannot do, so the algorithm has to exist before the coin can be scored.
Which fixes the order.

## Sequencing

1. ~~**yespower in ring 0.**~~ **Done.** `tools/yespower.py` came first and
   carries upstream's own thirteen TESTS-OK vectors; `src/mine/yespower.rs`
   matches three of them, one verbatim. Wired to the loop and measured above.
2. **Score the six coins with `mine probe` and `mine ev`.** Real targets, real
   coinbase values, real hashrate. This is the calibration set for everything
   after, and the first honest answer to whether the premise holds.
3. ~~**Measure the concurrency curve.**~~ **`mine sweep` exists and runs.**
   The measurement itself is a GF63 job and is in the hardware runbook, because
   a four-vCPU guest plateaus on cores before it can reach cache. Still the
   largest unmeasured claim in this document.
4. **The supervisor**, allocating slices against that measured budget rather
   than against core count. Slices exist and are unpinned; what does not exist
   is anything that gives them *different coins*, which is the whole idea.
5. **The pool**, which is independent of all of the above and could start in
   parallel: proxy first, device-agnostic, `xmrig` on somebody's Pi as its
   first client.

Items 1 to 4 are kernel work and item 5 is not, so they do not block each
other. The pool can exist and take miners before GLaDOS is a useful client at
it, and that is the right order rather than a compromise: a pool needs miners,
and xmrig users exist today.

## The question none of this answers

Who mines there. A pool with no miners is a server bill, and the recruitment
story -- market-rate payouts in the mined coin, plus $GLADOS and RWA on top,
funded by the operator's fee rather than by passing miner proceeds through --
is an offer that still needs somebody to hear it. That is not a technical
problem and nothing in this document addresses it.
