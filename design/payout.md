# The GLADOS payout loop, sized

The plan for Part C argued about custody, routing and slippage. All three were
real questions and none of them is the binding one. **The binding one is
magnitude, and nobody had multiplied it out.**

## The number

Everything here is measured rather than assumed. A GF63-class machine earns
**$0.07 a day** gross (`payrate.py`, against live pool quotes). The
GLADOS/WETH pool is **$58,901** deep (read on-chain at block 59,460,321). A
swap on Robinhood Chain costs **$0.048** of gas at 0.132 gwei. Operator fee
taken at a conventional 2%.

|  miners | gross $/day | fee $/day | fee $/year | % of pool depth per year |
|--------:|------------:|----------:|-----------:|-------------------------:|
|       1 |        0.07 |    0.0014 |       0.51 |                   0.001% |
|      10 |        0.70 |    0.0140 |       5.11 |                   0.009% |
|     100 |        7.00 |    0.1400 |      51.10 |                   0.087% |
|   1,000 |       70.00 |    1.4000 |     511.00 |                   0.868% |
|  10,000 |      700.00 |   14.0000 |   5,110.00 |                   8.676% |

To move **ten percent of pool depth in a year** takes **11,527** GF63-class
machines mining continuously. That is the whole result. Every other question in
Part C is downstream of it.

## Three things this overturns

**The slippage caps are unnecessary.** The research that measured the pool
recommended capping conversions at $250 to $500 a day, which is correct
arithmetic about the pool and irrelevant here: at a hundred miners the *annual*
conversion is $51 and slips 0.17%. The cap sits three orders of magnitude above
anything this loop can produce. Building a scheduler with size caps would be
building a governor for an engine that cannot reach the speed.

**What actually binds is gas as a fraction of a small swap**, which is a much
smaller problem and points the other way:

    at 100 miners, $51.10/year
      monthly    $ 4.26 per swap   gas is 1.13% of it
      quarterly  $12.78 per swap   gas is 0.38%
      yearly     $51.10 per swap   gas is 0.09%

So the rule is "batch until the amount is worth the gas", which is one
comparison and no schedule.

**And the route does not need automating yet.** At $51 a year the conversion is
a thing a person does occasionally. Writing a daemon to walk four legs
non-custodially, for an amount that size, is the same mistake as the size caps
one layer up. The legs should be *known to work* and executed by hand until the
number justifies otherwise.

## What the route actually is now

The plan had `XMR -> THORChain -> USDC -> Across -> USDG -> Uniswap V3 ->
GLADOS`. Three of those five hops turned out not to exist as described: native
Monero is not live on THORChain, there is no GLADOS/USDG pool, and the pool is
Uniswap V2 rather than V3.

What replaces it is shorter, and the first leg was already solved by a decision
made for an unrelated reason:

    mined altcoin
      -> the upstream pool sells it and pays BTC     already true
      -> BTC to ETH, non-custodially                 the one open leg
      -> Across delivers WETH into 4663              verified live
      -> one Uniswap V2 swap, WETH to GLADOS         verified on-chain

**`payrate.py` reads auto-exchange pools**, and its own header says what
`estimate_current` means: what a unit of hashrate earned per day, *in BTC, after
the pool sold whatever it mined*. So the altcoin-to-liquid-asset problem --
which is what THORChain was in the plan to solve -- is not this project's
problem at all. It was solved by choosing that class of upstream, for reasons
that had nothing to do with payouts.

The WETH leg is better than the USDG one it replaces, and for a reason worth
stating: **WETH is the pool's own quote token**. Bridging WETH rather than USDC
deletes the USDG hop *and* one of the two swaps, so the route lost a hop by
being measured rather than by being optimised.

**The one open leg is BTC to ETH.** THORChain is the obvious venue and BTC and
ETH are its two oldest pools, but that could not be verified from here --
`thornode.ninerealms.com` and `thornode.thorchain.info` have no A record from
this network and `thorswap` is behind a bot challenge. It is recorded as
unverified rather than assumed, and at these amounts it is also not urgent.

## So what is Part C for

If it cannot move the price, and the arithmetic above says it cannot at any
scale this project will reach, then buy pressure was never the thing worth
building. What is left is worth more and costs less:

- **A mechanism that visibly works**, with every conversion transaction hash
  published. For a pool whose only asset is being checkable, a small loop that
  anybody can audit end to end beats a large one nobody can.
- **The 1,000,000 gate in the claim contract**, which is the one part of this
  that is enforced by something other than a promise -- and which answers the
  objection `docs/token/index.html` makes about itself, that a balance check
  compiled into a ring-0 kernel is one edit away from being deleted.
- **A reason to hold that is not a yield claim.** Miners are paid in what they
  mined, at the market rate, directly. GLADOS on top is a bonus whose size is
  honestly small, and saying so is better than implying otherwise.

That is a smaller claim than the plan's and it is one that survives contact with
the numbers. The alternative -- shipping the loop and letting somebody work out
for themselves that it converts fifty dollars a year -- is the failure this
whole file exists to avoid.

## What to build, in order

1. **Nothing on the conversion leg.** It is four hops, three verified, and it is
   worth $51 a year at a hundred miners. Do it by hand, publish the hashes.
2. **The distributor and the 1M gate**, because that is the part that is
   enforced rather than promised, and it is the same amount of work whatever the
   amount flowing through it.
3. **Publishing the share log** (B4), which is what a miner has instead of a
   wallet to audit and is the only thing standing in for trust.

And the honest note for the announcement: the mechanism is real, the amounts are
small, and the page should say the second as plainly as the first.
