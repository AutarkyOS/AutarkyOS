#!/usr/bin/env python3
"""The whole financial model, with every input labelled by where it came from.

    economics.py                 the model at current measurements
    economics.py --live          re-measure everything measurable first
    economics.py --sensitivity   which unknowns actually move the answer
    economics.py --selftest

### Why this exists

Because the alternative is answering one question at a time and discovering a
new gap with each answer. This enumerates every input the design depends on,
says for each one whether it was **measured**, **quoted** or **assumed**, and
then shows which of them the conclusion is actually sensitive to.

That last part is the point. An unknown that does not move the answer is not a
problem to be solved, it is a number to stop worrying about; an unknown that
moves it by an order of magnitude is the only thing worth spending a day on.
Without the sensitivity pass, both feel equally annoying.

### The rule about sources

Every figure carries a `src`. `MEASURED` means this repository read it, from a
chain or a benchmark, on the date given. `QUOTED` means an API or a document
said so. `ASSUMED` means somebody chose it and nothing has checked it -- and
those are listed separately at the end, because an assumed number that nobody
flags becomes a measured one in the retelling.
"""
import argparse
import json
import sys
import urllib.request

MEASURED, QUOTED, ASSUMED = "measured", "quoted", "assumed"
UA = {"User-Agent": "glados-pool/economics (+https://aperture.institute)"}


class Input:
    def __init__(self, key, value, unit, src, note):
        self.key, self.value, self.unit, self.src, self.note = key, value, unit, src, note

    def __repr__(self):
        return "%s=%s" % (self.key, self.value)


# --------------------------------------------------------------- the inputs
#
# Dates are when this repository last read the figure. Anything volatile is
# marked in its note, because a volatile number measured once is an assumption
# with a timestamp on it.

INPUTS = [
    # -- mining
    Input("gross_per_machine_day", 0.07, "$/day", MEASURED,
          "payrate.py against live pool quotes, 2026-09-10. A GF63: RTX 3050 + i7."),
    Input("power_per_machine_day", 0.36, "$/day", MEASURED,
          "1.4 kWh/day at EU domestic rates. The machine's own draw."),
    Input("pool_fee", 0.01, "fraction", MEASURED,
          "zpool /api/currencies: a flat 1% on all 219 currencies, 2026-09-10."),

    # -- getting paid
    Input("withdraw_ltc", 0.0012, "$/tx", MEASURED,
          "blockcypher medium_fee_per_kb x 0.25 kB at $52.39/LTC, 2026-09-10."),
    Input("withdraw_btc_quiet", 0.109, "$/tx", MEASURED,
          "mempool.space 1 sat/vB x 141 vB at $77,334/BTC. This is the FLOOR."),
    Input("withdraw_btc_busy", 5.45, "$/tx", MEASURED,
          "the same transaction at 50 sat/vB, an ordinary busy day."),
    Input("payout_threshold_pol", 0.28, "$", MEASURED,
          "3 POL on Polygon PoS at unMineable, read from unmineable.com/coins/POL. "
          "4 days at this machine's rate, and the only sub-week option that "
          "lands on an EVM chain Across reaches from."),
    Input("payout_threshold_doge", 0.42, "$", MEASURED,
          "5 DOGE at zpool, from the undocumented minimum_payout field. 6 days, "
          "and zpool pays the chain fee itself."),
    Input("payout_threshold_ltc", 2.62, "$", MEASURED,
          "0.05 LTC, from an undocumented `minimum_payout` field in zpool's "
          "/api/currencies, at $52.39/LTC. 37 days at this machine's rate."),
    Input("payout_threshold_btc", 58.00, "$", QUOTED,
          "0.00075 BTC, from zpool's site rather than its API: BTC is not among "
          "the 219 payout currencies the API lists. 825 days, which is why the "
          "default is the worst option available."),

    # -- moving it
    Input("l1_gas_gwei", 0.105, "gwei", MEASURED,
          "ethereum-rpc.publicnode.com, 2026-09-10. Near an all-time low and "
          "historically 10-50x this. Treat as a range, never a point."),
    Input("l2_gas_gwei", 1.10, "gwei", MEASURED,
          "Robinhood Chain eth_gasPrice, 2026-09-10. **Not stable**: read 0.131 "
          "and 1.19 gwei hours apart the same day, a 9x spread, though steady to "
          "within 12% across thirty seconds. This file first said 'stable, being "
          "an L2' and measured the opposite an hour later."),
    Input("eth_usd", 2468.56, "$", QUOTED, "CoinGecko, 2026-09-10."),
    Input("swap_fee", None, "fraction", ASSUMED,
          "UNKNOWN. The LTC->ETH leg. No THORChain endpoint was reachable."),
    Input("bridge_fee", None, "fraction", ASSUMED,
          "UNKNOWN. Across relayer fee for a small ETH transfer into 4663."),

    # -- the token
    Input("pool_depth_usd", 58901.0, "$", MEASURED,
          "GLADOS/WETH V2 reserves on chain, block 59,460,321. Moves with every "
          "trade; read 11.54 WETH later the same day against 12.106 earlier."),
    Input("buy_tax", 0.01, "fraction", MEASURED, "buyTaxRate() = 100 bps, on chain."),
    Input("sell_tax", 0.03, "fraction", MEASURED, "sellTaxRate() = 300 bps, on chain."),
    Input("lp_fee", 0.003, "fraction", MEASURED, "Uniswap V2's constant."),
    Input("total_supply", 1e9, "tokens", MEASURED, "totalSupply() on chain."),
    Input("claim_rate", None, "fraction", ASSUMED,
          "UNKNOWN. What fraction of miners claim. Airdrop rates vary hugely and "
          "no figure here is this project's own."),

    # -- gas amounts, from the compiled contracts
    Input("gas_open", 130_000, "gas", ASSUMED, "openEpochOnMarket, estimated not measured."),
    Input("gas_claim", 210_000, "gas", ASSUMED, "claimOnMarket with a swap, estimated."),
    Input("gas_bridge", 120_000, "gas", ASSUMED, "an Across deposit, estimated."),
]

I = {x.key: x.value for x in INPUTS}
SRC = {x.key: x for x in INPUTS}


def usd(gas, gwei):
    return gas * gwei * 1e-9 * I["eth_usd"]


# ------------------------------------------------------------------ measure

def live():
    """Re-read everything this machine can actually reach."""
    def rpc(url, method):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={**UA, "content-type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=20))["result"]

    def get(u):
        return json.load(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=20))

    changed = []
    try:
        g = int(rpc("https://ethereum-rpc.publicnode.com", "eth_gasPrice"), 16) / 1e9
        changed.append(("l1_gas_gwei", I["l1_gas_gwei"], g)); I["l1_gas_gwei"] = g
    except Exception as e:
        print("  l1 gas: unreachable (%s)" % type(e).__name__, file=sys.stderr)
    try:
        g = int(rpc("https://rpc.mainnet.chain.robinhood.com", "eth_gasPrice"), 16) / 1e9
        changed.append(("l2_gas_gwei", I["l2_gas_gwei"], g)); I["l2_gas_gwei"] = g
    except Exception as e:
        print("  l2 gas: unreachable (%s)" % type(e).__name__, file=sys.stderr)
    try:
        p = get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd")
        v = p["ethereum"]["usd"]
        changed.append(("eth_usd", I["eth_usd"], v)); I["eth_usd"] = v
    except Exception as e:
        print("  eth price: unreachable (%s)" % type(e).__name__, file=sys.stderr)
    return changed


# -------------------------------------------------------------- the model

def cycle_cost(l1_gwei=None, swap_fee=None, bridge_fee=None):
    """What one full trip costs: withdraw, swap, bridge. Fractions where known."""
    l1 = I["l1_gas_gwei"] if l1_gwei is None else l1_gwei
    fixed = I["withdraw_ltc"] + usd(I["gas_bridge"], l1)
    return fixed, (swap_fee, bridge_fee)


def model(miners, days, epochs, l1_gwei=None, swap_fee=0.0, bridge_fee=0.0, claim_rate=1.0):
    """The whole stack, end to end, for one event or period."""
    gross = miners * I["gross_per_machine_day"] * days
    after_pool = gross * (1 - I["pool_fee"])

    fixed, _ = cycle_cost(l1_gwei)
    trips = 1                                   # bridge once per period, not per epoch
    after_move = after_pool - trips * fixed
    after_move *= (1 - swap_fee) * (1 - bridge_fee)

    open_gas = epochs * usd(I["gas_open"], I["l2_gas_gwei"])
    distributed = max(0.0, after_move - open_gas)

    # What a claimant nets: their slice, less the LP fee and buy tax the swap
    # takes, less the gas they pay to claim.
    claimants = max(1, int(miners * claim_rate))
    per_claim = distributed * claim_rate / claimants
    claim_gas = usd(I["gas_claim"], I["l2_gas_gwei"])
    net_per_claim = per_claim * (1 - I["lp_fee"]) * (1 - I["buy_tax"]) - claim_gas

    return {
        "gross": gross, "after_pool": after_pool, "after_move": after_move,
        "distributed": distributed, "per_claim": per_claim,
        "claim_gas": claim_gas, "net_per_claim": net_per_claim,
        "power": miners * I["power_per_machine_day"] * days,
        "buy_pressure": distributed * claim_rate,
    }


def show(miners, days, epochs, **kw):
    m = model(miners, days, epochs, **kw)
    print("  %-26s %12s" % ("gross mined", "$%.2f" % m["gross"]))
    print("  %-26s %12s" % ("after the 1% pool fee", "$%.2f" % m["after_pool"]))
    print("  %-26s %12s" % ("after withdraw + bridge", "$%.2f" % m["after_move"]))
    print("  %-26s %12s" % ("after %d epoch(s) of gas" % epochs, "$%.2f" % m["distributed"]))
    print("  %-26s %12s" % ("per claimant, before gas", "$%.4f" % m["per_claim"]))
    print("  %-26s %12s" % ("their gas to claim", "-$%.4f" % m["claim_gas"]))
    print("  %-26s %12s" % ("what a miner nets", "$%.4f" % m["net_per_claim"]))
    print("  %-26s %12s" % ("their electricity", "-$%.2f" % (m["power"] / max(1, miners))))
    print("  %-26s %12s" % ("buy pressure created", "$%.2f" % m["buy_pressure"]))
    return m


def breakeven(gas_gwei=None):
    """How long one miner must mine before claiming is worth the gas.

    **The cleanest result in this file, and it removes most of the anxiety.**
    A claimant's share is `gross_per_day x days` however many miners there are,
    because the pot and the head count scale together -- so the break-even is a
    number of *days per miner* and is independent of the size of the event, the
    swap fee, the bridge fee and the claim rate. All of those were unknowns
    being chased; none of them is in this equation.
    """
    g = I["l2_gas_gwei"] if gas_gwei is None else gas_gwei
    claim_gas = usd(I["gas_claim"], g)
    per_day = I["gross_per_machine_day"] * (1 - I["pool_fee"]) * (1 - I["lp_fee"]) * (1 - I["buy_tax"])
    return claim_gas, claim_gas / per_day


def breakeven(gas_gwei=None):
    """How long one miner must mine before claiming is worth the gas.

    **The cleanest result in this file, and it removes most of the anxiety.**
    A claimant's share is their own mining -- `gross_per_day x days` -- however
    many miners there are, because the pot and the head count scale together.
    So the break-even is a number of *days per miner*, and it does not depend on
    the size of the event, the swap fee, the bridge fee or the claim rate. Those
    were the unknowns being chased. None of them is in this equation.
    """
    g = I["l2_gas_gwei"] if gas_gwei is None else gas_gwei
    claim_gas = usd(I["gas_claim"], g)
    per_day = I["gross_per_machine_day"] * (1 - I["pool_fee"]) * (1 - I["lp_fee"]) * (1 - I["buy_tax"])
    return claim_gas, claim_gas / per_day


# --------------------------------------------------------- sensitivity

def sensitivity(miners=800, days=1.5, epochs=1):
    """Which unknowns move the answer, and by how much.

    The whole reason this file exists. An unknown that changes the result by a
    percent is not worth another day of research; one that changes it by ten is
    the only thing worth doing next.
    """
    base = model(miners, days, epochs)["net_per_claim"]
    print("  baseline: a miner nets $%.4f over %.1f days at %d miners\n" % (base, days, miners))
    print("  %-34s %14s %10s" % ("if this unknown turns out to be", "miner nets", "change"))

    cases = [
        ("L1 gas at 30 gwei (an ordinary day)", dict(l1_gwei=30.0)),
        ("L1 gas at 100 gwei (a bad one)", dict(l1_gwei=100.0)),
        ("the swap costs 1%", dict(swap_fee=0.01)),
        ("the swap costs 5%", dict(swap_fee=0.05)),
        ("the swap costs 15%", dict(swap_fee=0.15)),
        ("the bridge costs 0.5%", dict(bridge_fee=0.005)),
        ("only 20% of miners claim", dict(claim_rate=0.2)),
        ("only 50% claim", dict(claim_rate=0.5)),
    ]
    for label, kw in cases:
        v = model(miners, days, epochs, **kw)["net_per_claim"]
        d = (v - base) / base * 100 if base else float("nan")
        print("  %-34s %14s %9.1f%%" % (label, "$%.4f" % v, d))


def unknowns():
    print("\nWhat is still assumed rather than known:\n")
    for x in INPUTS:
        if x.src == ASSUMED:
            print("  %-22s %s" % (x.key, x.note))


def selftest():
    fails = 0

    def claim(c, w):
        nonlocal fails
        print(("ok    " if c else "FAIL  ") + w)
        if not c:
            fails += 1

    m = model(1, 365, 12)
    claim(m["gross"] > 0, "a year of one machine grosses something")
    claim(m["after_pool"] < m["gross"], "the pool fee reduces it")
    claim(m["distributed"] <= m["after_move"], "gas reduces what is distributed")
    # The case that matters: at tiny scale the costs can exceed the revenue,
    # and the model must say so rather than going negative quietly.
    tiny = model(1, 1, 30)
    claim(tiny["distributed"] == 0.0, "thirty epochs on one day of one miner distributes nothing")
    big = model(800, 1.5, 1)
    claim(big["buy_pressure"] > 0, "an 800-miner event creates buy pressure")
    # **This asserted `net_per_claim > 0` and failed the moment gas was
    # re-measured**, which is the model working rather than breaking: at 1.10
    # gwei a claim costs $0.55 against a $0.10 share, so the claimant is
    # genuinely underwater and the model says so. The claim now checks the
    # *relationship* -- that a claim is worth making exactly when the share
    # clears the gas -- which is true at any gas price and is the thing the
    # design actually depends on.
    gas, days = breakeven()
    short = model(800, days * 0.5, 1)
    long_ = model(800, days * 2.0, 1)
    claim(short["net_per_claim"] < 0, "below the break-even a claimant nets less than nothing")
    claim(long_["net_per_claim"] > 0, "and above it they net something")
    claim(abs(model(800, days, 1)["net_per_claim"]) < gas * 0.05,
          "with the break-even itself landing within a twentieth of the gas")
    # **Approximately independent of head count, and the approximation is
    # where the interesting part is.** The pot and the claimants scale
    # together, so the variable part cancels -- but the *fixed* costs of an
    # event (one bridge, one epoch) do not, and they fall on a smaller pot
    # harder. So a small pool needs longer per miner, not the same. Asserted as
    # an ordering rather than an equality, which is what is actually true.
    claim(model(10, days, 1)["net_per_claim"] < model(800, days, 1)["net_per_claim"],
          "a ten-miner pool is worse off than an eight-hundred one at the same days")
    claim(model(10, days * 3, 1)["net_per_claim"] > 0,
          "but gets there too, given three times as long")
    # Sensitivity must actually vary.
    a = model(800, 1.5, 1, swap_fee=0.0)["net_per_claim"]
    b = model(800, 1.5, 1, swap_fee=0.15)["net_per_claim"]
    claim(b < a, "a 15% swap fee makes a claimant worse off than a free swap")
    print("\n%s" % ("selftest passed" if fails == 0 else "%d FAILED" % fails))
    return 0 if fails == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="re-measure what is reachable")
    ap.add_argument("--sensitivity", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--miners", type=int, default=800)
    ap.add_argument("--days", type=float, default=1.5)
    ap.add_argument("--epochs", type=int, default=1)
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if a.live:
        print("re-measuring:")
        for k, was, now in live():
            print("  %-16s %s -> %s" % (k, was, now))
        print()

    print("== one machine, one year ==")
    show(1, 365, 12)
    print("\n== a 36-hour event, %d miners, one epoch ==" % a.miners)
    show(a.miners, a.days, a.epochs)
    print("\n== the same event, an epoch every hour ==")
    show(a.miners, a.days, 36)

    print("")
    print("== when is a claim worth making ==")
    print("")
    print("  A claimant's share is their own mining, so this is days per")
    print("  miner and is nearly independent of how many there are -- the pot")
    print("  and the head count scale together. A small pool needs longer,")
    print("  because one bridge and one epoch fall on a smaller pot.")
    print("")
    for label, g in (("gas at 0.131 gwei (today's low)", 0.131),
                     ("gas at 1.10 gwei (today's high)", 1.10),
                     ("gas at 5 gwei", 5.0)):
        c, d = breakeven(g)
        print("  %-32s claim costs $%.4f -> %5.1f days of mining" % (label, c, d))

    if a.sensitivity:
        print("\n== sensitivity ==")
        sensitivity(a.miners, a.days, a.epochs)
    unknowns()
    return 0


if __name__ == "__main__":
    sys.exit(main())
