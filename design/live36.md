# What happens if it goes live for everybody, for 36 hours

A mechanism analysis of this project's own system, from measurements taken this
session. Not advice, and not a projection about price -- every figure is either
read off a chain, benchmarked on the deployed host, or arithmetic over those.

## The short version

Three separate economies run at once and they differ by **five orders of
magnitude**. Ranked by size:

| | over 36 hours, at 256 miners |
|---|---|
| Entry: GLADOS bought to meet the 1M gate | **$57,000+** |
| Electricity burned by participants | **$138** |
| All coin mined, gross | **$26.88** |
| Operator fee, and therefore the GLADOS payout loop | **$0.54** |

The fee loop that Part C was designed around is the smallest number on the page.
The entry gate is a hundred thousand times larger than it. **If this event does
anything to the token, the gate does it and the payout loop is a rounding
error on a rounding error.**

## What one miner gets

A GF63-class machine, measured: $0.07/day gross against 1.4 kWh/day.

    mined, gross          $0.1050
    after a 2% pool fee   $0.1029
    electricity           $0.5397
    net                  -$0.4368     5.2x underwater

That is the honest headline and it does not improve with scale, because it is
per-device. A phone earns proportionally less and burns proportionally less; a
desktop with a real GPU earns more and burns more. The ratio is a property of
mining a competitive algorithm on general-purpose hardware, not of this pool.

`mine ev` prints this on every run, which is the whole reason it exists.

## The tokenomics, which are not where the plan was looking

Entry requires holding **1,000,000 GLADOS**. At the pool price read on-chain
(block 59,460,321) that is **$225.63** -- and the interesting part is what
happens when more than one person does it, because a constant-product pool
prices the *next* buyer off what the last one took.

    entrants        total spent     average each
           1              $228             $228
          10            $2,451             $245
          25            $6,998             $280
          50           $18,342             $367
          65           $29,304             $451
         100           $96,780             $968
         120          $336,890           $2,807

**The pool holds 130.5M GLADOS, which is 131 whole gates.** So there is a hard
ceiling on participation that has nothing to do with `MAX_CONNECTIONS`: past
about a hundred entrants the cost per gate goes vertical, and at 131 it is
unbounded. A public launch that attracted 256 miners could not sell 256 gates at
any price.

Two consequences worth being blunt about:

- **The gate is the demand mechanism.** Not the fee conversion. If the intent is
  buy pressure, this is where it comes from, and it is already built and already
  enforced on-chain.
- **It is also a queue with a rising price.** The first fifty entrants pay $367
  each on average and the hundredth pays into a pool that has already tripled.
  That is what a fixed token-count gate against a thin AMM does, and it is not a
  design choice anybody made -- it falls out of the arithmetic.

### The part that has to be said plainly

Round-tripping the gate costs **1% buy tax + 3% sell tax + slippage both ways**.
An entrant who buys in, mines for 36 hours and sells out pays roughly 4-8% of
$226 to $450 in friction, burns $0.54 of electricity, and receives $0.10 of
mined coin plus a share of a $0.54 GLADOS distribution -- about **two tenths of
a cent** each at 256 participants.

So a 36-hour open event, if it is presented as a way to earn, is a mechanism
where **every participant loses money with near-certainty**, the entry buying
lifts the price during the event, and the exits push it back down afterwards
into a pool that the sell tax has thinned. That shape is not made honest by the
code being correct or the pool being non-custodial. It is made honest, if at
all, by saying all of the above *before* anybody joins -- which is the one thing
this project is actually well set up to do, since the miner already prints its
own terrible expected value on every run.

If the event is framed as "come look at an operating system that mines from ring
0, here is exactly what it earns and exactly what it costs you", the numbers
above are the point rather than the problem.

## What breaks operationally, and what already got fixed

Measured against the deployed binary this session.

**Capacity is 256 concurrent connections**, one thread and one descriptor and
28 KiB each -- 258 threads and 8.2 MB resident at the ceiling, verified by
holding 300 open. The 257th is refused with a log line and the count recovers
cleanly. A public launch that draws more than 256 turns the rest away.

**The validation budget binds on yespower and nowhere else.** At 25% of one
core, against measured per-share costs:

    sha256d          2.3 us   107,000 shares/s
    blake2s          0.5 us   480,000 shares/s
    neoscrypt      504   us       496 shares/s
    yespower 2 MiB   7.2 ms        35 shares/s
    yespower 8 MiB  19.4 ms        13 shares/s

256 connections on two coins at one share per ten seconds offers **51.2
shares/s**. So sha256d, blake2s and neoscrypt are untroubled, yespower 2 MiB
defers about a third of shares, and yespower 8 MiB defers three quarters.
`--cpu-percent` is the knob and 25% is conservative on a borrowed four-thread
box; the deferral is graceful rather than a failure, but it should be a decision
rather than a surprise.

**Wildly varying devices are the case VarDiff is for**, and one failure mode was
found and fixed today: VarDiff needs eight accepted shares or sixty idle seconds
to move, and its state used to be per-connection -- so a phone that sleeps its
radio and reconnects every forty-five seconds restarted at the operator's guess
every time and was credited **nothing**, forever. Measured: 30-minute
connections eased 24 bits to 8 and got paid; 45-second connections ran 19 cycles
and accepted zero shares. Difficulty is now remembered per `(worker, slot)`
across reconnects. Without that fix, a public launch would have silently paid
mobile devices nothing while the logs looked healthy.

**The log would have reached 664 MB.** 51.2 accepted-share lines a second over
36 hours. Rotation existed but was only checked when the pool restarted, and a
pool that does not crash never restarts -- so on a machine that is not ours it
would have grown until something else broke. Now rotated live, bounded at 8 MB.

**The ledger is fine**: 256 rows is 32 kB against a 4,096-row cap, rewritten
every sixty seconds.

## The one thing that must change first

**The payout window is set to 5 seconds of mining.**

`run-pool.sh` passes `--window 268435456`. At 256 miners with VarDiff settled
around 20 bits, the pool credits 5.4e7 work per second, so that window covers
**five seconds**. PPLNS pays the last N units of work; everyone who mined for 36
hours and stopped six seconds before a block found gets nothing at all.

    vardiff settles at 12 bits  the window is 1280 seconds of mining
                        16 bits                  80 seconds
                        20 bits                   5 seconds
                        24 bits                   0.31 seconds

That figure looked perfectly large as a bare integer, which is exactly what a
number with no unit does. For a small coin the right window is a couple of
blocks of expected work:

    difficulty 1e4    one block = 4.3e13     a 2-block window = 8.6e13
    difficulty 1e6    one block = 4.3e15     a 2-block window = 8.6e15
    difficulty 1e8    one block = 4.3e17     a 2-block window = 8.6e17

All comfortably inside `u64` (1.8e19). The deployed value is between **32
million and 3 billion times too small**, depending on the coin.

Nothing else on this page is a blocker. This one is: a 36-hour event on the
current setting would take everybody's work and pay almost none of it.

## Before going live, in order

1. **Set `--window` from the coin's actual difficulty.** Two blocks of work.
   Everything else is secondary to this.
2. **Decide `--cpu-percent` deliberately** if any yespower coin is served, or
   accept a third of shares deferred at full load.
3. **Decide whether 256 concurrent is the ceiling you want**, knowing the pool
   can only sell about 131 entry gates anyway -- so 256 may already be past the
   real limit.
4. **Publish the share log from the start**, because it is what a miner has
   instead of a wallet to audit, and retrofitting it after an event is worthless.
5. **Say the electricity number up front.** It is the most credible thing this
   project can put on a landing page and it costs nothing to be right about.
