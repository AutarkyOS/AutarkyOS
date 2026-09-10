# The GLADOS payout loop, sized

> **Superseded in its premise, kept for its arithmetic.** This document was
> written against the design where GLADOS came out of the *operator's fee* and
> arrived as a bonus on top of a coin payout. The decision since taken is
> different and larger: **the mining reward itself converts**, so the payout
> *is* GLADOS, bought on the market with the proceeds of what was mined. See
> "The decision" below. The numbers in the rest of this file are correct for
> what they measure and are a 50x understatement of the flow that will actually
> run.

## The decision

Four choices, taken deliberately, and the contract already supports all of them
because the gate and the mode are per-epoch rather than global.

**The reward is the whole mining proceeds, not the fee.** What a miner earned is
converted and comes back as GLADOS. That is 50x the fee-only figure this
document sizes: $84 over a 36-hour event at 800 miners against $1.68, and a
claim worth $0.105 rather than $0.0021.

**Two epochs, and only the second has a gate.** The payout epoch is ungated, so
everybody who mined is paid -- which is what makes 800 participants possible at
all, since the pool holds only about 130 whole 1,000,000-token gates and gating
the payout would strand most of a crowd. A second, gated epoch pays a bonus on
top to holders. One mechanism, two configurations, no code.

**One hundred percent converts, for now.** Deliberately "for now": nothing in
the contract requires it, the split is a property of how the tree is built, and
a later epoch can pay part in something else without redeploying anything.

**`Mode.Market`: each claim is the claimant's own buy.** Chosen on visibility,
after the two candidates were measured against each other rather than argued.

### Why Market, given the arithmetic says Direct converts more

Because the first answer was optimising the wrong axis, and the correction is
worth keeping.

**Total price impact is identical**, which is the fact that removes the usual
reason to prefer one. One $84 buy against the real pool yields 370,115 GLADOS;
eight hundred buys of $0.105 yield 370,113. Constant product is path-independent
for a given total input, and both the 0.3% pool fee and the 1% buy tax are
proportional. "Many small buys are gentler on the pool" is simply false. All
that differs is the share-out: first claimant 464 GLADOS, last 461, a 0.57%
spread.

So the choice came down to four other things:

| | Market | Direct |
|---|---|---|
| gas, per miner | $0.048, **46%** of their $0.105 | $0.029, **28%** |
| converted at a 40% claim rate | $33.60 | $84.00 |
| operator touches the trade | no | yes, and must be believed on rate |
| **buys on the chart** | **up to 800** | **1** |
| **unique buyers** | **up to 800** | **1** |

The first recommendation here was Direct, on the claim-rate row. That was wrong
for this project's purpose. **Under Direct the eight hundred payouts are
invisible to the market**: they are wallet-to-wallet transfers, untaxed, they
never touch the pair, and no chart shows them. The screener reads one buy from
one address. Under Market it reads eight hundred buys from eight hundred
addresses, for the same $84. Unique buyers is the one figure on those pages
that is hard to fake, and the difference is categorical rather than marginal.

**And the claim-rate objection has an answer that costs nothing.** `reclaim`
returns the *unclaimed quote token* to the operator after the deadline -- a
deliberate line, since a Market epoch holds WETH and sending it back as GLADOS
would be sending what it does not have. So the operator converts the tail
themselves and the whole pot still reaches the market, after eight hundred real
buyers have already been on the chart.

One honest caveat about the candles: **claims cluster.** They are front-loaded,
a burst then a long tail, not an even drip across 36 hours. Direct-tranched is
the opposite -- perfectly schedulable, and perfectly obviously one wallet.

---

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

    mined altcoin                                  yespower, neoscrypt, blake2s
      -> the upstream sells it and pays you          already true
      -> that payout to ETH, non-custodially         the one open leg
      -> Across delivers WETH into 4663              verified live
      -> one Uniswap V2 swap, WETH to GLADOS         verified on-chain

**Nothing here mines BTC**, and the second line is deliberately not spelled
"BTC" any more. zpool's API denominates everything in BTC -- `estimate_current`
is BTC per day per unit of hashrate, after they sold what you mined -- so BTC is
the *accounting unit of that class of pool* rather than anything in the mining
path. On a yiimp pool the payout coin is inferred from the address you mine
with, and their currency list carries 219 of them: LTC, DOGE and RVN would all
do, and the route would be identical.

### Which payout coin, measured rather than assumed

Liquidity is the wrong criterion at this size. A payout is tens of dollars, so
the *fixed* costs decide and BTC is the worst of the candidates on the one that
matters. Measured at the time of writing, a 1-in-2-out transaction on each
chain, priced through CoinGecko:

    BTC    1 sat/vB x 141 vB          $0.1090      an empty mempool
    LTC    9,443 per kB x 0.25 kB     $0.0012
    DOGE   59,811,274 per kB x 0.25   $0.0126

**LTC is 91x cheaper than BTC at BTC's cheapest.** And BTC's cheapest is the
whole problem: 1 sat/vB is the floor, and the same transaction at an ordinary
busy-day 50 sat/vB is **$5.45**, which makes LTC 4,542x cheaper. Against $25.55
of annual mining revenue:

    cadence      BTC (quiet)   BTC (busy)      LTC
    monthly            5.12%      255.97%    0.056%
    quarterly          1.71%       85.32%    0.019%
    yearly             0.43%       21.33%    0.005%

Monthly withdrawals in BTC on a busy day cost **two and a half times what the
mining earned**. LTC's fee is not merely lower, it is *stable* -- it does not
have a congestion mode -- and at this size that predictability is worth more
than the depth BTC brings.

zpool's own fee is a flat 1% on all 219 currencies, so the pool is not a
differentiator; only the chain is.

**Cadence and coin multiply, and both are free to choose.** Yearly withdrawals
in LTC cost 0.005% of revenue. Monthly in BTC on a bad day costs 256%. That is
a factor of fifty thousand between two arrangements of the same mining.

**What is not measured here** is the swap from the payout coin to ETH, because
no THORChain endpoint was reachable from this network -- three have no A record
and one is behind a bot challenge. The reasoning that it also favours LTC is
that THORChain's outbound fee is derived from the source chain's own fee, so
BTC's congestion would carry through; but that is reasoning, not a measurement,
and it is the largest single cost in the chain. Nor is the per-coin minimum
payout threshold, which zpool publishes on its site rather than in its API and
which decides how long until any of this happens at all.

**ETH is not among them and cannot be**, which is the constraint underneath the
whole leg. Ethereum has not been mineable since the merge, so no mining pool
pays in it. GLADOS lives on an EVM L2 and nothing mineable is native there, so
there is always a swap between what was mined and what buys the token. The only
question is how many hops, and BTC is simply the most liquid place to start.

**`payrate.py` reads auto-exchange pools**, and its own header says what
`estimate_current` means: what a unit of hashrate earned per day, *in BTC, after
the pool sold whatever it mined*. So the altcoin-to-liquid-asset problem --
which is what THORChain was in the plan to solve -- is not this project's
problem at all. It was solved by choosing that class of upstream, for reasons
that had nothing to do with payouts.

What remains is only the hop from *whatever the upstream pays* to ETH, and that
is one swap rather than the three the plan had.

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

Revised against the decision at the top of this file.

1. **The conversion leg still does not need automating.** Four hops, three
   verified, and $84 an event. Do it by hand and publish the hashes. What
   changed is only the amount, and $84 is not the threshold at which a daemon
   becomes cheaper than a person.
2. **The distributor exists.** `contracts/GladosDistributor.sol`, sixty claims,
   and the whole pipeline runs locally in one command. What it needs is a
   deploy, an operator address, and somebody who did not write it reading it.
3. **A gated bonus epoch needs one thing the builder does not do yet**: filter
   the tree to addresses that actually hold the gate. Without it, a
   non-holder's allocation sits in the tree unclaimable and dilutes everybody
   who can claim, until the deadline reclaims it. That is one balance query per
   address at build time.
4. **Publishing the share log** (B4), which is what a miner has instead of a
   wallet to audit and is the only thing standing in for trust.

And the honest note for the announcement: the mechanism is real, the amounts are
small, and the page should say the second as plainly as the first.
