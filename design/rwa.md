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

## And it still cannot be a payout, because there is nowhere to buy it

Mechanical possibility is not availability. The pool would have to **acquire**
the token before it could distribute it, and on-chain there is nothing to
acquire it from. Reading `getPair` off the factory at
`0x8bceaa40b9acdfaedf85adf4ff01f5ad6517937f`:

    NVDA/WETH    0.0039 WETH of depth   (about $10)
    NVDA/USDG    ~0
    SPY/USDG     ~0
    SPCX/USDG    ~0

**About ten dollars of liquidity across the whole venue.** The 36-hour event's
entire pot is $84, so a single epoch's conversion is eight times the depth of
the only pair that has any. There is no size at which this works, and it is not
a matter of slippage tolerance: the pair cannot fill the order at any price.

So the acquisition path is not a DEX. It is Robinhood's own app, which means an
account, an identity check, and an operator holding equities on behalf of
people who are owed a payout -- which is precisely the custody shape the whole
design was arranged to avoid (see `payout.md`, and the P2Pool argument in the
plan). The chain being permissionless does not make the *on-ramp*
permissionless, and the on-ramp is the part that binds.

## What this changes about the design: nothing yet, and that is worth saying

The RWA route is **recorded and not adopted**. It fails on availability rather
than on mechanism, and availability is the kind of fact that changes: a pair
with $10 in it today is one liquidity provider away from having $100,000.

The thing to watch is therefore a single number -- **depth in NVDA/WETH or any
stock/USDG pair on 4663** -- and the threshold is easy to state. A payout venue
needs depth of at least an order of magnitude above one epoch's conversion, so
against a quarterly settlement of a few hundred dollars that is roughly $5,000
of two-sided depth. Nothing on the chain is within two orders of magnitude of
it.

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
