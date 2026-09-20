# Eight hundred entrants, in waves, over 36 hours

`design/live36.md` sized a launch at the connection ceiling. Eight hundred
people arriving in timezone waves is a different problem, and it moves three
answers. Two of the three are not about the server at all.

Everything here is measured on the deployed host or read off a chain.

## The gate is impossible at 1,000,000, and that is arithmetic rather than an opinion

Total supply is **1,000,000,000**, read on-chain. The pool holds **130.5M**, or
13.1% of it. So:

- 800 entrants at 1,000,000 each need **800M tokens**.
- The AMM can supply **130 gates**, and long before that the price goes vertical
  -- the hundredth costs $968 on average and the hundred-and-twentieth $2,807.
- The other 869.5M sit in wallets that are not the pool. Whether 800 strangers
  can each end up holding 1M is a question about who those holders are, not
  about the pool, and it is not a question the AMM can answer.

**800 people cannot buy a 1M gate at any price.** If the event is to have 800
participants the gate has to come down, and what it comes down to is a real
choice with a computable answer:

| gate | at spot | total cost | avg/entrant | % of pool bought |
|---:|---:|---:|---:|---:|
| 1,000,000 | $225.63 | impossible | | |
| 250,000 | $56.41 | impossible | | |
| 100,000 | $22.56 | $46,774 | $58.47 | 61.3% |
| **50,000** | **$11.28** | **$13,053** | **$16.32** | **30.6%** |
| 25,000 | $5.64 | $5,345 | $6.68 | 15.3% |
| 10,000 | $2.26 | $1,929 | $2.41 | 6.1% |

At 50,000 the whole event buys $13,053 of GLADOS -- which is **7,769 times**
the $1.68 the fee-conversion loop produces. The gate is the mechanism. It always
was; at 800 people it stops being arguable.

And it makes the event humane. Per participant at that gate:

    entry, with price impact   $16.32
    round-trip tax 1% + 3%      $0.65
    electricity, 36 hours       $0.54
    mined, after a 2% fee      +$0.10
    ---
    net                        -$1.09      across 800 people, -$872

A dollar to take part, rather than $226 and a five-fold electricity loss. That
is the difference between an event people can be invited to honestly and one
that cannot be.

## PPLNS is the wrong payout scheme for this, and the reason is specific

Three conditions hold at once here, and PPLNS assumes none of them:

1. **The pool is a proxy, so there are no block events.** `payouts()` is a
   report, not a trigger -- it says "if we paid now, this is the split". PPLNS
   is defined by paying the last N work *when a block is found*, and no block is
   ever found here.
2. **The payout is computed once, at the end.**
3. **Participants are separated in time by timezone.**

Put together: a payout taken at hour 36 reads a window holding the last N units
of work. At the current setting that window is **five seconds wide**. Wave one
mined for twelve hours and stopped at hour twelve; it gets **nothing** -- not a
smaller share, nothing. So does wave two.

There are two fixes and one of them is free.

**Size the window to span the event.** At 800 miners on two coins at 45 s per
share and 16 bits, the whole 36 hours is 3.0e11 work, comfortably inside `u64`
(1.8e19). Set `--window` above that and PPLNS becomes proportional-over-the-event,
which is what is wanted.

**Or pay from the cumulative tally instead.** `Tally.work` is already the
all-time work per `(worker, coin)`, already persisted across restarts, already
published in the ledger, and already re-derived independently by
`tools/ledgercheck.py`. For a single time-boxed event it is exactly the right
basis and it cannot be misconfigured, which the window demonstrably can.

**The anti-hopping argument for PPLNS does not apply here**, and that is the
part worth being clear about rather than defending the existing choice out of
habit. Pool-hopping is jumping between *rounds* of a round-based scheme. A
36-hour event with one payout at the end is one round, and it is the whole
event: you either did work or you did not, more work gets proportionally more,
and early versus late does not change anything. The property PPLNS is bought for
is not being used.

Recommendation: **pay from the tally, and start the event with a fresh ledger**
so nothing before it is included.

## The server holds it, and that was measured rather than hoped

850 concurrent connections against the deployed binary on the 2012 i3:

    852 threads   21,040 KiB resident   854 descriptors   load average 1.25

The soak running beside it was untouched. Twenty-one megabytes and a load
average of 1.25 is not a machine in difficulty.

Two things had to change for that to be reachable and both are now in:

- **`--max-connections`**, because 256 was a `const`. It was the right number
  while the only question was whether a stranger could exhaust the box; it is
  the wrong one the moment an event is planned, and a ceiling that turns away
  the fourth wave is an outage to the people in it.
- **`ulimit -n`**, raised in `run-pool.sh` before the pool starts. The login
  default on that host is 1024 and the hard limit is 524288, and raising the
  soft limit to the hard one **needs no privilege** -- which makes it the one
  resource question on this box where root was never the answer. The daemon
  reads `/proc/self/limits` and clamps its own ceiling to what it actually has,
  so a `--max-connections` above the descriptor limit is refused at startup with
  a line rather than discovered as `EMFILE` in the middle of a wave.

## Validation is the real capacity limit, and `--share-seconds` is the lever

Offered validation is `connections x coins / seconds-per-share`. Measured costs
per share on that host: sha256d 2.3 us, blake2s 0.5 us, neoscrypt 504 us,
yespower 2 MiB 7.15 ms, yespower 8 MiB 19.4 ms.

At 800 concurrent on two coins, what one core has to give:

| seconds/share | offered | sha256d | neoscrypt | yespower 2 MiB | yespower 8 MiB |
|---:|---:|---:|---:|---:|---:|
| 10 | 160/s | ~0% | 8% | **114%** | **310%** |
| 30 | 53/s | ~0% | 3% | 38% | 103% |
| 45 | 36/s | ~0% | 2% | 25% | 69% |
| 60 | 27/s | ~0% | 1% | 19% | 52% |

So at ten seconds a share, yespower cannot be served to eight hundred people on
one core. At forty-five it fits inside the 25% budget already deployed, and
sha256d and neoscrypt were never in question.

`--share-seconds` was a `const` too. It costs information to raise -- a rate
estimate settles more slowly and a departed miner takes longer to notice -- so
the default does not move; but for an event it is the largest single lever on
what an expensive algorithm costs, and having it fixed left "defer a third of
the traffic" as the only available answer.

**Recommended for this event: `--share-seconds 45`, and no yespower-8MiB coin.**

## Waves, specifically

Each wave arrives as a burst of new connections. Three things are worth knowing:

- **First-time entrants converge slowly and returning ones do not.** VarDiff
  needs eight accepted shares or sixty idle seconds to move, so a fresh miner
  spends its first minute or two at the configured start. A miner that has been
  here before resumes at its remembered difficulty, which is the fix made
  earlier today -- without it, every phone that sleeps its radio between waves
  would restart at the operator's guess forever and be credited nothing.
- **The tally holds 4,096 records** and 800 workers is well inside it. Eviction
  only ever drops records with zero credited work, so a wave of arrivals cannot
  displace an earlier wave that actually mined.
- **The log is bounded at 8 MB** by live rotation. At 800 concurrent and 45 s a
  share it would otherwise reach roughly 220 MB over the event.

## What to set

    --max-connections 900        measured at 850: 852 threads, 21 MB, load 1.25
    --share-seconds 45           makes yespower affordable, or drop yespower
    --cpu-percent 25             unchanged; it is sufficient at 45 s a share
    --window <span the event>    or pay from the tally instead, which is better

    entry gate 50,000 GLADOS     1,000,000 is unreachable for 800 people
    fresh ledger at the start    so the tally covers the event and nothing else

And the thing to say out loud before anybody joins: it costs about a dollar to
take part, the mining earns ten cents, and the electricity is fifty-four. The
numbers are the interesting part of this project, not the embarrassing part.
