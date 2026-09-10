# The GLADOS payout loop, sized

## Read this first: three corrections, all found by being told it felt too expensive

**1. The granularity is the cost, not the route.** This is the large one and it
was never examined. At an 800-miner 36-hour event the pot is $84 and a share is
$0.105, and *every* way of paying that on chain costs more than the pot:

    Market: the miner claims and swaps       $455.96    543% of the pot
    Direct: the miner claims a transfer      $195.41    233%
    Push:   the operator sends, one by one   $108.56    129%
    Push:   batched, ~25k gas per recipient   $54.28     65%

No amount of bridge-shopping touches that. A claim pays for its own gas only
when a share clears it:

    36 hours   each $0.1050   market gas 543%   direct gas 233%
    weekly     each $0.4900   market gas 116%   direct gas  50%
    monthly    each $2.1000   market gas  27%   direct gas  12%
    quarterly  each $6.3000   market gas   9%   direct gas   4%

**So the event may run for 36 hours and the paying must accumulate and settle
quarterly.** Two cadences, only the second constrained. Visible buying comes
from the operator converting in tranches on whatever schedule it likes;
distribution comes from claims, which have to be rare to be worth making.

**2. Ethereum L1 was never required, and is not the dominant cost either.**
Sixteen chains are Across origins into 4663 -- Base, Arbitrum, Optimism, Linea,
Polygon, zkSync among them. And a *measured* Across deposit on L1 is **$0.027**
across 37 real transactions at a 0.10 gwei base fee, against $0.0022 from Base.
The dominant costs are two flat fees, not gas: THORChain's ~$0.25 outbound and
Across's ~$0.20 destination fill.

**3. THORChain was never down; this network could not see it.** Recorded
because the mistake is instructive. Every `thornode.*` subdomain under
`ninerealms.com` returns NODATA -- the records are withdrawn, confirmed against
an off-network resolver -- so four endpoint failures read as a dead protocol.
It is running v3.20.1 with 87 active nodes and no halt flags, reachable at
`thorchain.ibs.team/api`. An unreachable endpoint is not evidence about a
protocol, and this document said it was.

## The two routes, both now priced

Neither touches Ethereum mainnet.

**A. Fastest, and the operator is not trustworthy.** unMineable pays **POL
directly to a `0x` address on Polygon PoS**, minimum **3 POL, about $0.28**,
"sent automatically once a day with no network fees" -- read from
`unmineable.com/coins/POL`. Then one cheap Polygon swap and Across from Polygon.

    mine -> POL on Polygon (4 days) -> swap -> Across 137->4663 -> WETH

**B. Slower, better-run counterparties.** zpool to LTC, then THORChain to ETH
**on Base**, then Across from Base.

    mine -> LTC (37 days) -> THORChain -> BASE.ETH -> Across 8453->4663 -> WETH

Measured for route B, at 18:07 UTC:

    $10   THORChain $0.2750 (2.750%) + Across $0.09-0.28   = $0.48   4.80%
    $100  THORChain $0.4523 (0.452%) + Across $0.10-0.45   = $0.65   0.65%
    $500  THORChain $1.2492 (0.250%) + Across $0.17-0.47   = $1.45   0.29%

**Batching dominates everything else here**: five $100 trips cost $3.27 against
$1.45 for one $500 trip. The cost is nearly all flat fees, so the only lever
that matters is trip size.

Against route A at $100 the totals are close -- roughly 1.5% against 1.65% --
so **A buys nine times faster settlement and one fewer hop, and B buys
counterparties worth trusting.** They are independent and cost nothing to run
side by side, which is also the only way to learn what unMineable's real take
is.

### unMineable is the cheap route and is not a trusted one

Its terms reserve fees "up to 10%" and say payouts "may be subject to fees,
including network fees", contradicting the "no network fees" on every coin page.
Trustpilot is 55% one-star. A balance with no reward activity for six months is
forfeited. **The mitigation is the same fact that makes it attractive**: a $0.28
threshold paid daily means exposure at any moment is about one day of earnings.
Tolerable here, and not at scale.

Kryptex is the trustworthy alternative -- **USDC on Polygon**, 1.5 USDC minimum,
flat 0.5 USDC fee, so 33% at the minimum and 5% if allowed to reach 10.

### NiceHash is out, and the reason is the best cautionary tale here

Worth a paragraph because the failure is not a fee, it is a mechanism that
destroys the balance, and nothing about it is visible from the fee schedule.

NiceHash has restructured into a Bitcoin-only platform: **ETH is delisted**, the
order-book exchange is dead -- all 112 markets read `REMOVED`, last trade 2024 --
and of 79 currencies exactly three are live, BTC plus USDT and USDC **on
Ethereum and Solana only**. No L2 at any size. Mining pays USDT for exactly one
of 21 algorithms and it is a Bitcoin-ASIC one.

But the thing that actually kills it is the **60-day rule**. Funds unused for 50
days are swept, and in NiceHash's own words: *"if the inactive balance is less
than 20,000 satoshis or 10 USDT/USDC ... it will be deducted as a 60-Day Rule
Non-Transferable Amount Fee instead."* Below threshold, **the whole balance is
taken as the fee**.

At $0.07 a day you accrue $3.43 in fifty days. The BTC sweep threshold is
$15.43 and the USDT one is $10.00. **The balance can never outrun the clock**,
so the account loses essentially all revenue on a rolling basis. And the
withdrawal minimum for USDT is *the same 10 units* as the confiscation
threshold, which is not a coincidence: the documentation says the confiscation
happens precisely because the balance is below the minimum transfer amount. The
balance is destroyed at the exact moment it would first become withdrawable.

Full KYC -- ID, proof of address, liveness check, beneficial-owner declaration --
is required before earning a single satoshi of that.

The general lesson is the one this whole section is about: **a venue's fee table
is not its cost.** Nothing in NiceHash's fee schedule is unreasonable. The
dormancy rule, in a different document, takes everything.

### Two things to check before trusting any of this with money

**Nobody has observed a completed Across fill on 4663.** The SpokePool bytecode
is deployed and the API prices routes into it, but a priced route is not a
delivered one. Do one $10 trip before believing the table.

**The Across fee moved 5x in nine minutes** -- $0.09 to $0.47, same route, same
size, 97% of it destination fill gas -- and it is flat in dollars regardless of
transfer size. Quote it live per trip rather than reading a number from here.

---


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
path. Their currency list carries 219 of them and LTC, DOGE and RVN would all do,
with the route identical.

**How the payout coin is chosen was written wrongly here and it matters.** It
is not inferred from the address you mine with. zpool takes `c=<SYMBOL>` in the
*password* field, and with no `c=` the currency is "randomly chosen from any
matching coins we have used" and cannot be changed once a balance has posted.
So the LTC route needs an explicit `c=LTC`, and a rig configured with only an
LTC address gets whatever the pool felt like.

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

### The threshold, which was the biggest unknown and is now the clearest number

zpool carries an undocumented `minimum_payout` in `/api/currencies` -- 219 coins,
202 of them at 0.05 of whatever the coin is -- and it decides how long until a
first payout exists at all. At this machine's measured $0.0703 a day net:

    BTC     0.00075 BTC   $58.00    825 days     the default, and the worst
    LTC     0.05 LTC       $2.62     37 days
    DOGE    5 DOGE         $0.42      6 days     the fastest
    RVN     0.05 RVN       $0.0001    same day

**LTC wins on both axes at once**, which is the useful part: 22x faster to a
first payout than BTC *and* the smallest withdrawal fee as a fraction of that
payout, 0.05% against DOGE's 3.00%. DOGE reaches a payout six times sooner and
gives up sixty times more of it in fees.

All three are `only_direct: 0` and `conversion_disabled: 0`, checked, so they
can be paid from mining a different algorithm rather than requiring you to mine
that coin. That was worth checking: 158 of the 219 have conversion disabled and
would have looked available while refusing the one thing needed.

**The swap is measured now** and the earlier reasoning here was wrong twice
over. It guessed that THORChain's cost would favour LTC because the outbound fee
derives from the source chain's own fee. Measured, **LTC, DOGE and BTC cost
within $0.004 of each other on THORChain** -- the real differences are the
minimum swap ($0.91 / $1.00 / $6.23) and the speed, not the fee. So the payout
coin should be chosen on threshold and withdrawal fee, which is where LTC
genuinely wins, and not on what the swap costs. Nor is the per-coin minimum
payout threshold, which zpool publishes on its site rather than in its API and
which decides how long until any of this happens at all.

**ETH is not among them**, which is the constraint underneath the whole leg --
though the reason given here was wrong, and the correction is worth keeping
because it was a category error. This said ETH "cannot be" a payout currency
because Ethereum stopped being mineable at the merge. That conflates *mineable*
with *payable*: an auto-exchange pool sells whatever you mined and credits you
in something else, which is exactly how it pays in 219 coins nobody mined on it.
zpool's refusal is **policy, not physics** -- its own site says "ETH style (0x*)
wallets are not supported", and the API corroborates it with zero of 219
currencies matching ether, usd, tether, polygon, arbitrum, base or optimism.

Which means a pool that settled to an EVM address is not impossible, merely
absent from this one, and finding one would delete the most expensive leg of
the design. GLADOS lives on an EVM L2 and nothing mineable is native there, so
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
