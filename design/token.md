# Part C research -- five open questions

Kept for the same reason `design/papers.md` is kept: most of what it establishes
is that things this project had already written down are **wrong**, and the
wrongness is worth more than a note saying the questions are answered. Four of
the five had a confident answer in the plan and three of those did not survive
contact with the chain.

The headline, before the detail: **there is no GLADOS/USDG pool**, it is
GLADOS/WETH on Uniswap **V2** at about $59k, so a $1,000 conversion costs 5% and
the design needs size caps rather than a schedule. **The Stocks Vault story is
false** -- `dividendToken()` is GLADOS itself -- and it is a good thing nobody
wrote it onto the token page first. And **native Monero on THORChain is not
live**, which means the first leg of the C1 route does not currently exist; the
May-2026 story traces to a press release marked as sponsored.

## What was re-verified here rather than taken from the note

The tax figures were going onto a public page, so they were read again
independently, with the function selectors derived from `keccak256` rather than
looked up in a 4-byte directory (`scratchpad/selectors.py`, checked against the
empty-string vector first). At block 59,463,301:

    symbol()       0x95d89b41  -> "GLADOS"
    decimals()     0x313ce567  -> 18
    buyTaxRate()   0x691f224f  -> 0x64  = 100 = 1.00%
    sellTaxRate()  0x24024efd  -> 0x12c = 300 = 3.00%
    owner()        0x8da5cb5b  -> the zero address

Those five are on `docs/token/index.html` now, with the command that produces
them, run verbatim from the page before it was published.

**The dividend figures were not re-verified and are not on the page.**
`minimumShareBalance()`, `dividendToken()` and `totalDividendsDistributed()` all
**revert on the token contract** -- they live on a separate tracker this note
reached and a direct probe did not (`dividendTracker()`, `distributor()`,
`rewardToken()`, `dividendDistributor()` all revert too). So the 1,000,000
threshold and the 96.8M distributed are believed and unconfirmed here, and the
page says neither. The block explorer that would settle it is behind a bot
challenge.

Read-only. No wallet connected, no transaction attempted, no credential entered.
Every on-chain figure below came from `eth_call` / `eth_getLogs` against public RPC.

**Chain snapshot used for all pool arithmetic:** Robinhood Chain (4663), block
**59,460,321** (`0x38b4ae1`), **2026-09-10T14:04:16Z**. Read via
`https://rpc.mainnet.chain.robinhood.com`, which answered `eth_chainId` = `0x1237`
= 4663.

---

## Provenance

| # | Question | Best source obtained | Confidence |
|---|---|---|---|
| 1 | GLADOS pool, depth, slippage | **Primary -- on-chain.** Pool read directly; price cross-checked against an on-chain WETH/USDG pool at the same block and against CoinGecko (0.02% apart). Tax behaviour verified against two real settled trades. Corroborated independently by flap.sh's own site ($59,445.71 vs my $58,901). | **High** |
| 2 | Launchpad tax rate readable on-chain | **Primary -- on-chain + flap docs.** Selectors extracted from implementation bytecode, values read from the proxy, function names confirmed verbatim in docs.flap.sh. | **High** |
| 3 | Stocks Vault / dividend asset | **Primary -- on-chain + flap docs.** `dividendToken()` read directly; `VaultPortal.getVault()` reverts; docs.flap.sh read in full (59 pages). | **High** |
| 4a | THORChain → Arbitrum L2 | **Primary -- THORChain live API + own blog.** | **High** |
| 4b | Across on 4663, USDC→USDG | **Primary -- Across live API (I re-verified myself), Across GitHub, Robinhood's own docs.** | **High** |
| 5 | Native XMR on THORChain | **Primary -- live API (4 endpoints) + THORChain's own blog.** Contradicts a sponsored press release. | **High** |
| -- | Verified *source code* for `0x7777…3333` | **Not obtained.** Blockscout sits behind Cloudflare; I worked from bytecode instead. This did not block the answer. | n/a |

Two independent lines of evidence agree on every material on-chain fact
(my own RPC reads, and a separate agent's reads via a different RPC endpoint at a
different block). Where they differ it is only because the pool traded between blocks.

---

# 1. GLADOS liquidity -- **there is no GLADOS/USDG pool. It is GLADOS/WETH, on Uniswap V2, ~$58.9k.**

Three corrections to the plan, in descending order of importance.

### 1a. The pair is WETH, not USDG

`quoteToken()` on the token returns `0x0bd7d308f8e1639fab988df18a8011f41eacad73`,
whose `symbol()` is **WETH** -- the canonical WETH named in Robinhood's own docs
(`https://docs.robinhood.com/chain/contracts`).

A GLADOS/USDG V2 pair *does* exist at `0x6c90d0373db912bc971a4027b562b05605eda65e`,
and it is **dust: 703.13 GLADOS against 0.1443 USDG -- a total of $0.29.** It is not
a venue. Treat it as nonexistent.

flap's docs are explicit that this is structural, not a choice:
> "Native ETH (`address(0)`) is currently the only enabled quote token on Robinhood
> Chain, for both token types."

**So the plan's final hop `USDG → Uniswap V3 → GLADOS` cannot execute as written.**

### 1b. It is Uniswap **V2**, not V3

`mainPool()` = `0x93f777932d98d15b351d1bce8c76b34381eede5b`. It answers
`getReserves()` and `MINIMUM_LIQUIDITY()`; `slot0()`, `fee()`, `liquidity()` and
`tickSpacing()` all **revert**. Its `symbol()` is `UNI-V2`. Its factory is
`0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f`, which HoodScan independently
identifies as the Uniswap **v2 factory** on this chain.

flap's docs state the rule:
> "**When a token is a tax token, it can only be migrated to Uniswap V2 or its forks.**"
> "Both supported token types (Non-Tax, Tax V3) migrate exclusively to **Uniswap V2**
> via `V2_MIGRATOR` -- no other migrator type is accepted on this chain."

I confirmed the empirical fee is exactly 0.30% by calling the router's own
`getAmountsOut` and matching it against a 997/1000 constant-product model to
**0.000 ppm**.

**There is no V3 or V4 liquidity, and this is tested rather than assumed:**

- Uniswap V3 factory `0x1f7d7550b1b028f7571e69a784071f0205fd2efa`:
  `getPool(GLADOS, WETH|USDG, fee)` returns the zero address for all of
  100 / 500 / 3000 / 10000.
- Uniswap V4 is a singleton, so pools are not addressable -- but the PoolManager
  holds every pool's tokens. `balanceOf(0x8366a39c…40951)` = **0 GLADOS**. There is
  no V4 liquidity.
- V3 NonfungiblePositionManager, UniversalRouter and SwapRouter02 all hold 0 GLADOS.

**130,521,682 of the 131,225,000 GLADOS in any venue sit in that one V2 pair.**

### 1c. Depth and slippage

At block 59,460,321:

| | |
|---|---|
| Reserves | **12.106205 WETH / 130,521,681.72 GLADOS** |
| ETH price | **$2,432.69** (on-chain WETH/USDG pair, same block; CoinGecko said $2,432.11 at 13:55:10Z -- 0.02% apart) |
| GLADOS price | **$0.0002256381** |
| **Pool TVL** | **~$58,901** (2 × WETH side) |
| FDV | ~$225,638 |
| Pool holds | 13.05% of the 1,000,000,000 supply |

flap.sh's own page reported liquidity **$59,445.71** and market cap $226,669 at
13:56:51Z -- an independent number agreeing to within 1%.

**Realistic all-in cost, USDG in → GLADOS held.** The route is two V2 hops
(USDG→WETH in an $857k pool, then WETH→GLADOS in the $58.9k pool) plus the token's
own 1% buy tax:

| Size | hop-1 loss | hop-2 price impact | LP fees | buy tax | **TOTAL** |
|---|---|---|---|---|---|
| **$10** | 0.30% | 0.03% | 0.60% | 1.00% | **1.63%** |
| **$100** | 0.32% | 0.34% | 0.60% | 1.00% | **1.95%** |
| **$1,000** | 0.53% | 3.25% | 0.60% | 1.00% | **5.02%** |
| $2,500 | 0.88% | 7.72% | 0.60% | 1.00% | 9.73% |
| $5,000 | 1.45% | 14.25% | 0.60% | 1.00% | 16.63% |
| $10,000 | 2.57% | 24.73% | 0.60% | 1.00% | 27.68% |
| $25,000 | 5.78% | 44.23% | 0.60% | 1.00% | **48.26%** |

Selling is worse, because the sell tax is 3%:

| Size | sell tax | impact | LP fees | **TOTAL** |
|---|---|---|---|---|
| $10 | 3.00% | 0.01% | 0.60% | **3.61%** |
| $100 | 3.00% | 0.32% | 0.60% | **3.92%** |
| $1,000 | 3.00% | 3.25% | 0.60% | **6.85%** |
| $5,000 | 3.00% | 14.37% | 0.60% | **17.97%** |
| $10,000 | 3.00% | 25.03% | 0.60% | **28.63%** |

Round trip (buy, then immediately sell the same notional): **5.15% at $100,
5.42% at $1,000, 6.66% at $5,000.**

**What actually trades here.** Nine `Swap` events in the last 20,000 blocks
(~35 minutes); the five buys were 0.020-0.102 WETH, i.e. **$50 to $250**. flap
reported 24h volume of $103,238 and 398 holders. A $1,000 conversion is roughly
4-20× the size of a typical trade on this pool.

**Sizing conclusion for C5.** The 3% band is at about **$600**; the 5% band at
about **$1,000**. A daily conversion cap of **$250-$500** keeps all-in cost near
2-3%. Above ~$2,500 per conversion the price impact exceeds the fee revenue
plausibly being converted. This is a hard size cap, not a preference.

### 1d. A design improvement that falls out of this

Across supports **WETH → WETH into 4663** on 13 routes, and the destination token
is `0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73` -- *exactly the GLADOS pool's quote
token*. (I re-read `https://app.across.to/api/available-routes` myself at
2026-09-10T14:05:52Z: 37 routes into 4663 -- 13 WETH→WETH, 12 USDC→USDG,
11 ETH→ETH, 1 USDG-MAINNET→USDG.)

So bridge **WETH, not USDC**. That removes the USDG→WETH hop entirely, saving
~0.30-0.53% and one transaction, and it makes the final leg a single V2 swap.
Gas on 4663 is ETH, so ETH is needed anyway
(`https://docs.robinhood.com/chain/gas-and-fees`: *"Robinhood Chain uses ETH as its
native gas token."*).

---

# 3. Stocks Vault -- **refuted. GLADOS has no vault, and its dividends pay in GLADOS itself.**

Do **not** write the tokenized-equity story down. It is false for this token.

**Primary, on-chain, decisive:**

```
GLADOS.dividendContract()            = 0x86b4e8a64082fe5b04d99aca0f81faccaec95c2c
  (an EIP-1167 proxy -> 0x56b3b7b02751da9f58162a52f0cf10cbe57aa8df)
dividendContract.dividendToken()     = 0x3d609ecafc6aa7dba67dd7ad1d10b49c52d57777
                                       ^^^ GLADOS itself
VaultPortal.getVault(GLADOS)         -> reverts, custom error 0xc02219d9
flap.sh page payload, "vault"        -> null
```

flap's docs describe exactly this configuration as one of three non-vault dividend
modes: the launching token itself -- *"Holders earn more of the same token."*

**The Stocks Vault is real, but it is a different, opt-in launch path** that GLADOS
did not take. flap's launch form has a *"Select Vault (Optional)"* section with an
*"Enable Vault"* toggle; the docs distinguish `Portal` (no vault features) from
`VaultPortal`. GLADOS went through the plain `Portal`.

Three further corrections to the C6 claim, worth recording so it is not
half-repaired later:

1. **The ticker list is wrong.** flap's docs say *"tokenized equities such as
   NVDAon, AAPLon, TSLAon, **MSFTon**"* -- not SPY. And there is no fixed list:
   `supportedAssets()` "returns the immutable subset baked in at creation", chosen
   per vault.
2. **Even a Stocks Vault does not pay the stocks directly** on the version deployed
   here. Docs: *"For v3, dividends are paid in the vault's own `IndexBasketToken`
   (an ERC-20 basket), **not directly in the underlying stocks**."*
3. **The $4 auto-distribution claim is true but misattributed.** Docs:
   *"Once a holder's pending rewards cross a **$4 USD-equivalent threshold**, the bot
   calls the withdraw-for-user function on their behalf… **The bot pays the gas** for
   that transaction."* This is in the generic dividend chapter and applies to
   **every** flap tax token with dividends, vault or not. **So it does apply to
   GLADOS** -- just not for the reason C6 gives.

**What the token page should say instead.** The page's "40% -- Dividends to holders"
is *correct* and can now be made specific from the chain rather than softened:

- Dividends pay in **GLADOS**.
- The eligibility floor is on-chain: `minimumShareBalance()` = **1,000,000 GLADOS**
  -- the page's 1M threshold, readable rather than asserted.
- **96,841,041.96 GLADOS has actually been distributed** (~$21,850 at the snapshot
  price), against `totalShares()` of 806,476,916 GLADOS. This is a live mechanism,
  not a promise.
- A further 11,116,932 GLADOS sits in the dividend contract pending distribution.

One caveat the page must not skip if it makes this claim: `setDividendToken(address)`
exists and the dividend contract's `owner()` is `0x26605f322f7ff986f381bb9a6e3f5dab0beaeb09`
-- flap's own Portal contract. The dividend asset **is** GLADOS today and flap retains
the ability to change it. The token contract's own `owner()` is the zero address
(renounced); the dividend contract's is not.

---

# 2. Tax rate -- **yes, fully readable on-chain, and the 40/30/25/5 split is confirmed**

The implementation at `0x7777c8743c88b3aff3cf262135bef2c8b2e83333` is **19,020 bytes**
and I could not obtain verified source (Blockscout is behind Cloudflare). I did not
need it: I extracted all 43 dispatch selectors from the bytecode and resolved them
against the openchain.xyz signature database. flap's docs then name the same three
functions verbatim, and the docs list `0x7777c8743c88b3aff3cf262135bef2c8b2e83333`
by name as **"Tax Token V3 Impl (`TOKEN_TAXED_V3`)"**.

**Read live from the proxy:**

| Call | Raw | Meaning |
|---|---|---|
| `buyTaxRate()` | `0x64` = 100 | **1.00% buy** |
| `sellTaxRate()` | `0x12c` = 300 | **3.00% sell** |
| `taxRate()` | `0x12c` = 300 | 3.00% |
| `taxExpirationTime()` | 4941832675 | **2126-08-08** -- i.e. never |
| `antiFarmerExpirationTime()` | 1790047075 | 2026-09-22T03:17:55Z (21-day window, still active) |
| `state()` | 2 | graduated / listed |
| `owner()` | `0x0` | renounced |

Docs confirm the semantics: *"`taxRate()` always returns `max(buyTaxRate, sellTaxRate)`…
they will always see the worst-case value and will never under-report the tax."*

**The split**, read from flap's documented Tax Token Helper
(`0xb10bD2672aE63735d677164A54B573a016f0203C`, `getTaxTokenInfo`):
`dividendBps` **4000**, `marketBps` **3000**, `lpBps` **2500**, `deflationBps` **500**.

**The token page's 40/30/25/5 table is exactly right.** One attribution fix: it is
**not "the launchpad's split"**. flap fixes nothing -- any launcher picks four
basis-point buckets summing to 100%, and buy/sell rates in 0-10% each. The page
currently implies the launchpad imposes it ("split four ways by the launchpad
contract"). It is GLaDOS's own configuration, chosen at launch. That is a *stronger*
statement, not a weaker one, and it is the accurate one.

**How the tax actually lands -- verified against two real settled trades**, because
this changes the slippage arithmetic and a docs reading alone would not settle it:

```
tx 0xbe5dea76…72064   pool amount1Out = 219,472.4000 GLADOS
    pool ->  token contract      2,194.7240   (exactly 1.0000%)
    pool ->  buyer             217,277.6760   (99.0000%)

tx 0x20d304be…e5f1f   pool amount1Out = 443,530.4300 GLADOS
    pool ->  token contract      4,435.3043   (exactly 1.0000%)
    pool ->  buyer             439,095.1247   (99.0000%)
```

The buy tax is taken out of the tokens leaving the pool, at exactly `buyTaxRate`.
The 1.00% column in the Q1 table is measured, not modelled.

Cumulative to date, from the helper: 11,172,125 GLADOS burnt, 96,841,042 to
dividends, 28,125,415 GLADOS + 1.15 WETH added to liquidity, 2.76 WETH to the
creator wallet (`0x6ef4fa01…527d`).

---

# 4. THORChain → Arbitrum L2 -- **no. And Across on 4663 -- yes.**

### 4a. THORChain reaches no Arbitrum-stack chain

Supported chains, live at 2026-09-10 13:53 UTC from `/thorchain/inbound_addresses`
and `/thorchain/lastblock`:

> BTC, ETH, BSC, AVAX, **BASE**, DOGE, LTC, BCH, XRP, TRON, GAIA *(halted)*,
> SOL *(halted)*, plus native THOR.

**Arbitrum One is not supported. No Arbitrum-stack chain is.** Robinhood Chain is
an Arbitrum Orbit chain (Across's own `networks.ts` tags it `family: ORBIT`), so
**the Across hop is mandatory** -- the plan's assumption here is correct, and now
verified rather than assumed.

BASE *is* supported, but it is OP-stack, and its USDC pool is only ~**$31,826**
deep. The only USDC pool with real depth is **ETH.USDC at ~$2.02M**. So the
realistic path is THORChain → **Ethereum L1** → Across → 4663, not via Base.

### 4b. Across is live on 4663 and the USDC→USDG claim is right

- SpokePool `0xD29C85F15DF544bA632C9E25829fd29d767d7978`, in
  `across-protocol/contracts/broadcast/deployed-addresses.json` under `"4663"`;
  `chainId()` on it returns `0x1237`.
- Docs: `https://docs.across.to/reference/supported-chains` lists Robinhood / 4663.
  (Note the plan-era URL `docs.across.to/introduction/supported-chains` now 404s.)
- Robinhood's own docs name Across in their bridging table: *"Across | Intents-based
  bridge | **Seconds**"*.
- Live quote API returns `outputToken` USDG `0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`
  with `estimatedFillTimeSec: 2`.
- A real settled fill confirms it end to end: tx
  `0xe333654c…6fee6`, block 59,455,986 -- 241.878016 USDC in (Ethereum) →
  241.607757 USDG out (4663), fee 0.1117%.

**Two corrections and one hard limit:**

1. **It is 12 chains, not 13.** 13 *routes* arrive as USDG; the 13th is
   USDG→USDG from Ethereum. The 12 USDC origins are chains
   1, 10, 130, 137, 143, 480, 999, 8453, 42161, 43114, 57073, 59144.
   (I re-read the route list myself at 14:05:52Z and got exactly this.)
2. **USDG is Paxos "Global Dollar", 6 decimals**, not 18 -- worth knowing before
   writing any conversion arithmetic.
3. **Per-transfer ceiling: `maxDeposit` = 13,824.178 USDC (~$13.8k)** at 13:54 UTC.
   Well above any conversion size the GLADOS pool can absorb, so not binding here --
   but it bounds the design.

Also: **there is no MulticallHandler on 4663.** Across's supported-chains table
shows `--` in that column, unlike almost every other chain. **Bridge-and-execute is
not available**, so the bridge and the swap cannot be one atomic action. The
conversion leg is necessarily at least two transactions with price risk between them.

---

# 5. Native Monero on THORChain -- **the plan is wrong on both the date and the outcome. XMR is not live.**

The claim under review: *"THORChain 3.20 added native Monero swaps in May 2026."*

**XMR is not a supported chain today (2026-09-10).** Four independent primary
endpoints agree:

| Endpoint | Result |
|---|---|
| `/thorchain/inbound_addresses` | 12 chains, **no XMR** |
| `/thorchain/pools` | no XMR pool, no ZEC pool |
| `/thorchain/mimir` | **no `HALTXMRCHAIN` key exists at all** |
| `/thorchain/pool/XMR.XMR` | **HTTP 400** |

Midgard, a separate indexing service, returned the same asset list. The node
queried self-reports version **3.20.1** at height 27,773,048, so this is a current
3.20 node and not a stale one.

**What actually happened.** The code merged -- `XMRChain = Chain("XMR")` exists in
`thornode/common/chain.go` -- but *a constant in that file is not live support*; the
same file also defines NOBLE, SUI, ADA, TAO and DOT, none of which are live either.
The chain was never activated. THORChain's own blog, 27 Aug 2026:

> "Zcash and Monero are waiting… The message is deliberately cautious: **$XMR and
> Zcash are delayed, not abandoned.**"

And in April 2026 it was still unbuilt -- blog, 10 Apr 2026: *"Monero ($XMR) is
**targeting** mainnet in 1-2 months."* v3.20 activated **25 August 2026**, not May.

The "May 2026 / native XMR swaps live" story traces to a **Chainwire press release**
carried by Decrypt and marked *"sponsored by our commercial partners"*, written in
the present tense about a capability the chain data contradicts. This is worth
noting as a pattern: the plan's error came from a paid announcement, not journalism.

**Consequence: the first leg of the C1 route does not exist.** No date is committed
for it. A pool was planned to open at only ~$10k with the treasury as primary LP,
so even at activation it would not initially support size.

---

## What this changes in Part C

The route in C1 is `XMR → THORChain → USDC → Across → USDG → Uniswap V3 → GLADOS`.
**Three of its five hops are wrong.**

| Hop | Plan | Reality |
|---|---|---|
| XMR → THORChain | native, live May 2026 | **does not exist**, delayed indefinitely |
| THORChain → USDC | ✓ | ✓ (ETH L1 ~$2.02M; Base only ~$32k) |
| USDC → Across → USDG | ✓, "13 chains, ~2s" | ✓, **12** chains, ~2s, cap ~$13.8k, no multicall |
| USDG → GLADOS | Uniswap **V3** | **Uniswap V2**, and there is **no USDG pair** |
| pool | "GLADOS/USDG" | **GLADOS/WETH, ~$58.9k** |

**The corrected route is shorter, not longer:**

```
<mined coin> → THORChain → WETH (Ethereum L1)
             → Across → WETH on 4663   [same address as the pool's quote token]
             → Uniswap V2 → GLADOS
```

Monero specifically must be replaced or the leg done off-THORChain, and that
decision cannot be deferred -- it is the input to the whole loop.

**Sizing, which was the point of asking:** the pool is ~$58.9k. Convert **$250-$500
per day** and pay ~2-3% all-in. **$1,000 costs 5%. $5,000 costs 17%. $25,000 costs
48%.** Size caps are mandatory, and they should be denominated against live reserves
read at conversion time rather than a constant, since the pool is small enough that
its own depth moves.

**One thing that argues in the design's favour.** The pool's 1% buy tax means every
conversion the pool operator makes already routes 40% of that 1% straight back to
holders as GLADOS dividends, and 25% into liquidity -- which slightly deepens the
pool the mechanism depends on. The buy tax is not purely a cost.

---

## Gaps, stated plainly

- **No verified source for `0x7777…3333`.** Blockscout (`robinhoodchain.blockscout.com`,
  the explorer named in both Robinhood's and Across's docs) is behind Cloudflare and
  refused automated access. Everything about the implementation here comes from
  bytecode-derived selectors plus flap's docs, which agree -- but I have not read the
  Solidity.
- **`liqExpectedOutputAmount()` = 0.2 ETH and `liquidationThreshold()` = 400,000 GLADOS**
  are read but I have not established exactly what triggers a tax liquidation. It
  matters if a large conversion would trip one mid-swap.
- **Whether the 24h volume figure ($103,238) is real or partly wash** is not something
  I checked. Nine swaps in 35 minutes at $50-$250 each does not obviously extrapolate
  to $103k/day, and that discrepancy is worth resolving before the volume number is
  used for anything.
- **The 2-second Across fill time is an API estimate**, not a measured latency and
  not an SLA. Measuring it would require sending a transaction.
- **THORChain's official 3.20 release notes** could not be read verbatim (GitLab
  releases page 404s / is JS-rendered). The 25 Aug activation date rests on secondary
  reporting; the *delay* is primary from THORChain's own blog.
- **Legal review (C5, third bullet) is untouched** -- it was not in scope here.
- HoodScan (`hoodscan.co`), used for the DEX contract directory, is an independent
  third-party explorer **not named in Robinhood's own documentation**. Its Uniswap
  factory addresses were each confirmed by direct RPC call before being relied on;
  treat the rest of its content as secondary.
