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

**That figure is arithmetic and not a measurement.** It is the first thing to
check once one algorithm runs: sweep concurrent job count against total
hashrate and find where the curve bends. Until then it is a prediction, and
this tree's own record on predictions of this kind is poor.

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
3. **Measure the concurrency curve.** Jobs against total hashrate, to find
   where L3 bends. Replaces the arithmetic above with a number, and it is now
   the largest unmeasured claim in this document. Needs the supervisor, since
   nothing today can run two jobs at once.
4. **The supervisor**, allocating slices against that measured budget rather
   than against core count.
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
