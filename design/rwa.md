# Paying miners in tokenized stock, and why it does not work yet

Robinhood Chain (id 4663) is an Arbitrum Orbit L2 built for tokenized real-world
assets, and $GLADOS already lives on it. So the question is a fair one: if the
chain the token is on was built to carry tokenized equities, why is the payout
denominated in anything else?

This file records what was **measured on the chain** rather than what the
marketing says, because the two disagree in one important place.

## What is actually deployed

Robinhood's own contracts page lists exactly two addresses, **WETH and USDG**.
No stock token is documented anywhere the issuer publishes. They are there
regardless -- found by scanning `Transfer` logs and reading `symbol()` and
`name()` off every contract that emitted one:

| contract | transfers | symbol | name |
|---|---:|---|---|
| `0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec` | 33,539 | NVDA | NVIDIA . Robinhood Token |
| `0x2e0847e8910a9732eb3fb1bb4b70a580adad4fe3` | 19,459 | GOOGL | Alphabet Class A . Robinhood Token |
| `0x1b0e319c6a659f002271b69db8a7df2f911c153e` | 16,123 | GME | GameStop . Robinhood Token |
| `0x4a0e65a3eccec6dbe60ae065f2e7bb85fae35eea` | 13,016 | SPCX | Space Exploration Technologies Corp. |
| `0x12f190a9f9d7d37a250758b26824b97ce941bf54` | 9,817 | AMZN | Amazon . Robinhood Token |
| `0x117cc2133c37b721f49de2a7a74833232b3b4c0c` | 7,090 | SPY | SPDR S&P 500 ETF Trust |

**The undocumented half is the interesting half.** SPCX is SpaceX, which is a
private company: there is no public market for it at all, and its presence says
the chain is carrying more than a mirror of a brokerage's listed inventory.

## They are permissionlessly transferable, which was not the expectation

Every tokenized-equity design published anywhere gates transfers -- ERC-3643,
an identity registry, a whitelist, a transfer agent. So the first question was
which of those NVDA carries. **The answer is none of them.**

    paused()            -> false
    owner()             reverts (absent)
    identityRegistry()  reverts (absent)
    compliance()        reverts (absent)
    transferAgent()     reverts (absent)
    isWhitelisted()     reverts (absent)
    isVerified()        reverts (absent)
    isFrozen()          reverts (absent)

An absent function is weak evidence on its own -- a gate can be spelled a
hundred ways and probing for seven names proves nothing about the eighth. So
the check that settles it is a simulated transfer rather than a survey of
selectors: `transfer` of 0.35 NVDA **from a real holder** (`0xd01d…2257`, whose
balance is 35.27) **to an address that has never been used** (`0x…beef`).

It succeeds.

That is the whole finding. A never-seen address can receive the token, so
nothing on the contract asks who the recipient is, and paying a stranger in
NVDA is mechanically possible today.

## The depth figure in the first version of this file was wrong

It said about ten dollars, from reading `getPair` on four pairs. **The factory
carries 41,741 pairs**, and asking it properly -- `PairCreated` logs filtered on
the indexed `token0`/`token1` -- finds **62 pairs involving these six tokens**,
not four. Four of 41,741 is a sample, and it was reported as a fact about the
chain.

Most of those 62 are not usable for acquisition. The counterparty is a memecoin
somebody launched against a stock ticker -- `MVDA`, `NVDAs`, `Stockcoin`,
`GAMECOIN`, `dont'buy`, `NVTEST963` -- and buying `NVDA` with `HODL` requires
already holding `HODL`, which has the same problem one level down. **Seven of
the 62 have a quote asset that can be arrived at from outside**, and this is
their whole depth:

    AMZN / WETH    0.01177828 WETH     $28.99
    GME  / WETH    0.00903404 WETH     $22.23
    NVDA / WETH    0.00394343 WETH      $9.70
    NVDA / USDG    0.18623300 USDG      $0.19
    SPY  / USDG    0.00065300 USDG      $0.00
    SPCX / USDG, SPCX / WETH           dust
                                     -------
                                       $61.11     at ETH $2,460.90

So the real figure is **$61, six times what this file first said**, and two of
the three pairs that carry it were not in the original spot check at all.

**And the chain has no working stablecoin market underneath any of it.** The
`WETH`/`USDG` pair is `175.24 WETH` against `0.00000043 USDG`: a degenerate pool
nobody can trade through, which is why ETH had to be priced off-chain to value
the table above.

## Slippage, which depends only on one ratio

Worth writing down because it makes the basket question answerable without
knowing a single stock price. On a constant-product pool, spending `x` of the
quote against reserve `R` returns, valued at the pool's own pre-trade price,

    x * R / (x + R)

Efficiency is `R/(x+R)` and **depends only on `x/R`** -- not on the price, not on
which stock, not on how the basket is composed. Spreading `x` across several
pairs in proportion to their reserves gives every pair the same ratio, so the
basket behaves exactly like one pool of the summed depth. That is the honest
version of "split it across a basket": it works, and what it buys is `R = $61`
instead of `R = $9.70`.

Against the 36-hour pot, and against the quarterly settlements the cadence
argument in `payout.md` actually implies:

    spend $84    receive $35.37    42.1% efficiency    57.9% lost
    spend $250   receive $49.11    19.6%               80.4%
    spend $630   receive $55.71     8.8%               91.2%

    to keep 99%, one clip may be at most $0.62
    to keep 95%,                          $3.22
    to keep 90%,                          $6.79

## But depth is a stock and the thing that matters is a flow

**This is the correction that mattered**, and the first version of this file did
not make it. A pool is not a budget that gets spent once. Buying pushes the
price up, an arbitrageur with a cheaper source sells into it, and both the price
and the stock-side reserve come back. So a $9.70 pool can pass far more than
$9.70 through itself, and the question is not how deep it is but **how fast it
refills**.

That is measurable, so it was measured -- every `Swap` event on the seven pairs,
bucketed by day, quote side only and in its own units:

    day        d0      d1      d2      d3      d4      d5      d6
    AMZN     2.71    0.40   18.95   12.34   49.22    0.00    0.00
    GME      0.81   29.91    0.07    0.00    0.13    0.75    0.71
    NVDA   488.67   16.26    0.22    5.42    0.00    0.00    0.00
    total  492.18   46.57   19.24   17.75   49.34    0.75    0.71

    14-day total $683.93    mean $48.85/day    median $12.89/day

**The first day is 72% of the fortnight**, which is exactly why one reading is
not a rate -- and why the $492 that showed up in the first 24-hour window would
have been a second wrong number reported confidently, had it not been bucketed.

## The verdict, on the flow rather than on the depth

$84 is **12% of everything the entire RWA basket has traded in two weeks**, and
at the median day it is six and a half days of the basket's whole turnover --
turnover being two-directional, so the one-way buying required is a larger share
still. A quarterly settlement of $250 to $630 is five to thirteen months of it.

So the route does not work, and the reason is now a defensible one rather than a
spot check: **not that the pools are shallow, which they can survive, but that
the flow through them is one to two orders of magnitude below what a settlement
needs.**

The number to watch is therefore a rate and not a reserve, which is a better
trigger than the one this file carried before: **sustained basket throughput
around $5,000 a day**, at which point a $250 settlement is 5% of daily flow and
can be clipped in under the 95% line without moving anything. Nothing here is
within two orders of magnitude of that, and the measurement takes about a minute
to repeat -- `PairCreated` for the pair set, `Swap` bucketed by day for the flow.

## The legal question was being chased and it does not bind

It was, and the chase is called off. The argument against it is good and worth
recording, because it is a correction to how this file was framed rather than to
anything it measured.

**A tokenized RWA is not the RWA.** The thing on chain is an ERC-20 whose value
rests entirely on an issuer's promise to track something; the share itself is
somewhere else, in a custodian's book, and no amount of holding the token
reaches it. Every measurement above says the same thing from the other end: no
identity registry, no whitelist, no transfer agent, and a transfer to a
never-used address that simply works. **Mechanically, `NVDA` on 4663 is
indistinguishable from any other ERC-20 launched by a private entity**, which is
to say it is indistinguishable from a memecoin. Treating it as though the
securities weight of NVIDIA stock travels with the token is a category error,
and this file was drifting toward making it.

Where the reasoning stops, stated once so nobody has to re-derive it: the
distinction that would matter is not what the token *is* but what it is *sold
as*. A thing that names itself "NVIDIA . Robinhood Token" is representing a
relationship, which is a different position from a token representing nothing
and claiming nothing. That is a fact about the **issuer's** conduct, though, not
about a downstream holder's -- and this pool would be a downstream holder buying
on a market like anyone else.

**Either way it changes no decision here**, and that is the reason to stop
rather than resolve it. The route died on ten dollars of depth. A legal finding
in either direction leaves it dead, and one that came back permissive would
change nothing about a pair that cannot fill an $84 order. The one number to
watch is still depth, and the legal question is worth reopening exactly when
that number moves and not before.
