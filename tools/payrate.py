#!/usr/bin/env python3
"""What this machine would actually be paid, asked of a pool that pays it.

    payrate.py                    price every algorithm we can compute
    payrate.py --all              include the ones we cannot
    payrate.py --power 0.36       against a different daily electricity cost
    payrate.py --selftest         check the unit convention against Bitcoin

### Why this replaces the arithmetic it was going to be

`market.rs` says an expected value is `price x reward / (2^256 / network
target)` and records why it was not written: a coinbase output is in the
chain's own base unit, how many of those make a coin is not on the wire, and
writing 1e8 because Bitcoin uses it is an invented figure.

**A multi-coin auto-exchange pool publishes the answer directly.** yiimp's
`/api/status` gives `estimate_current` per algorithm -- what a unit of hashrate
earned per day, in BTC, after the pool sold whatever it mined. Price, network
difficulty, block reward and the decimals constant are all already inside it,
because the pool did the selling and is quoting the proceeds.

That also dissolves a conclusion this project reached twice.
`design/mining.md` ranked coins by whether *the coin* could be sold. On an
auto-exchange pool the coin's own liquidity is the pool's problem, not the
miner's: it pays in BTC whatever it mined. What matters is revenue per unit of
**our** hardware, which is this number and nothing else.

### The unit convention is derived, so it is checked

zpool documents none of it. Read off the data: `estimate_current` is BTC per
day per `mbtc_mh_factor` MH/s, and `actual_last24h` is the same in mBTC. That
is a guess about somebody else's API and a wrong one would move every figure
here by three orders of magnitude while still printing plausible pennies.

So `--selftest` checks it against a quantity nobody in this exchange controls:
zpool's own SHA-256 farm is a known fraction of Bitcoin's hashrate, and
Bitcoin's daily issuance is a published constant, so the two must agree. They
do, within the slop of the round numbers used.
"""

import argparse
import json
import sys
import urllib.request

UA = {"User-Agent": "glados-pool/payrate.py (+https://aperture.institute)"}

DEFAULT_POOL = "https://zpool.ca/api/status"

# What this machine computes, in hashes a second, and where each figure comes
# from. Measured rather than rated: every one of these is a number this project
# printed, not a specification.
#
# The GPU figures are through the pool on a *busy* host -- the pool daemon
# running beside the miner on the same laptop -- which `design/xpu.md` records
# as costing about a fifth. They are therefore conservative.
OURS = [
    # algo on the pool   our H/s      what it is
    ("sha256",    0.63e9,   "RTX 3050, cuda/xpu.cu, through the pool"),
    ("blake2s",   1.28e9,   "RTX 3050, cuda/xpu.cu, through the pool"),
    ("heavyhash", 0.383e9,  "RTX 3050, cuda/kheavy.cu heavy step only -- an upper bound"),
    ("yespower",  342.0,    "one kernel mining slice, ring 0"),
    ("yespower",  1368.0,   "four kernel slices, which measured 256% of one"),
]

# A laptop drawing ~60 W flat out is ~1.4 kWh a day; EU domestic is around
# EUR 0.26/kWh. Stated as an assumption and overridable, because it is the one
# number here that is not measured and it is the one the conclusion rests on.
DEFAULT_POWER_USD_DAY = 0.36


def get(url):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30))


def btc_per_day(entry, hashes_per_second, field="estimate_current"):
    """The derived convention, in one place so the selftest checks what runs.

    The quoted unit is `mbtc_mh_factor` megahashes a second. `estimate_current`
    is BTC per that per day; `actual_last24h` is the same in milli-BTC.
    """
    factor = float(entry["mbtc_mh_factor"])
    if factor <= 0:
        return None
    rate = float(entry[field])
    if field == "actual_last24h":
        rate /= 1000.0
    return (hashes_per_second / 1e6 / factor) * rate


def btc_price():
    """Spot BTC, from the source `prices.py` already cross-checks.

    One source is enough here and would not be in `prices.py`: this figure
    scales every row identically, so it cannot change which algorithm wins, and
    an error in it is visible as every number being wrong together.
    """
    u = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
    return float(get(u)["bitcoin"]["usd"])


def selftest(offline=False):
    """The unit convention against Bitcoin's own issuance.

    Nothing here controls either side: the pool reports its own SHA-256
    hashrate and its own payout rate, Bitcoin issues a published amount per
    day, and the pool's share of the network must be the pool's share of the
    issuance. A convention wrong by the usual factor -- 1e3, 1e6 -- fails this
    by the same factor and could not be mistaken for noise.
    """
    ok = True

    def claim(name, cond, detail=""):
        nonlocal ok
        print("%-4s  %s%s" % ("ok" if cond else "FAIL", name, ("  [%s]" % detail) if detail else ""))
        ok = ok and cond

    # The arithmetic claims come first and need nothing. `--offline` stops
    # here, which is what CI runs: a step that fetched a third party's API
    # would fail on their uptime rather than on a defect here, and that is the
    # objection `prices.py` records about its own selftest.
    if not offline:
        d = get(DEFAULT_POOL)
        sha = d["sha256"]
        pool_hs = float(sha["hashrate"])
        claim("the pool reports a sha256 farm at all", pool_hs > 0, "%.4g H/s" % pool_hs)
        mine = btc_per_day(sha, pool_hs)
        # Round numbers on purpose. Bitcoin's hashrate moves and its issuance
        # is 3.125 BTC per block at ten minutes; both are quoted coarsely
        # because the claim is about a factor of a thousand, not a percent.
        network_hs = 1.0e21
        issuance = 3.125 * 6 * 24
        expected = pool_hs / network_hs * issuance
        ratio = mine / expected if expected else 0.0
        claim(
            "the derived unit agrees with Bitcoin's issuance within 10x",
            0.1 < ratio < 10.0,
            "%.4f BTC/day derived against %.4f expected, ratio %.2f" % (mine, expected, ratio),
        )

    # A synthetic entry, so the arithmetic is checked without the network.
    fake = {"mbtc_mh_factor": 1000.0, "estimate_current": "0.002", "actual_last24h": "4.0"}
    claim("one unit of hashrate earns one rate", abs(btc_per_day(fake, 1e9) - 0.002) < 1e-12)
    claim("ten units earn ten times", abs(btc_per_day(fake, 1e10) - 0.02) < 1e-12)
    claim(
        "actual is read as milli-BTC and estimate as BTC",
        abs(btc_per_day(fake, 1e9, "actual_last24h") - 0.004) < 1e-12,
    )
    claim("a zero factor is refused rather than dividing", btc_per_day({"mbtc_mh_factor": 0}, 1e9) is None)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool", default=DEFAULT_POOL, help="a yiimp-style /api/status (default %(default)s)")
    ap.add_argument("--power", type=float, default=DEFAULT_POWER_USD_DAY,
                    help="assumed electricity, USD a day (default %(default)s)")
    ap.add_argument("--all", action="store_true", help="also list algorithms we cannot compute")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--offline", action="store_true",
                    help="with --selftest, run only the claims that need no network")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest(a.offline) else 1

    d = get(a.pool)
    btc = btc_price()
    print("%-11s %-11s %-11s %-12s %s" % ("algo", "ours H/s", "USD/day", "USD/day 24h", "what it is"))

    best = 0.0
    for algo, hs, note in OURS:
        e = d.get(algo)
        if e is None:
            print("%-11s %-11.4g %s" % (algo, hs, "-- this pool does not serve it"))
            continue
        # A pool that serves an algorithm nobody mines and that pays nothing is
        # not the same as one that does not serve it, and neither is a rate.
        if float(e["estimate_current"]) == 0 and float(e["actual_last24h"]) == 0:
            print("%-11s %-11.4g %s" % (algo, hs, "-- served, but it pays nothing and has no miners"))
            continue
        est = btc_per_day(e, hs) * btc
        act = btc_per_day(e, hs, "actual_last24h") * btc
        best = max(best, act)
        print("%-11s %-11.4g $%-10.6f $%-11.6f %s" % (algo, hs, est, act, note))

    if a.all:
        print()
        print("what this pool serves that we cannot compute, by what it pays:")
        rows = []
        for k, v in d.items():
            if k in {x[0] for x in OURS}:
                continue
            r = float(v["actual_last24h"]) * float(v["mbtc_mh_factor"])
            rows.append((r, k, v))
        for r, k, v in sorted(rows, reverse=True)[:10]:
            print("  %-16s %6s workers   %.4g H/s" % (k, v["workers"], float(v["hashrate"])))

    print()
    print("best measured: $%.4f a day, against $%.2f a day of electricity assumed." % (best, a.power))
    if best < a.power:
        print("That is %.0fx underwater. The premise does not hold on this hardware," % (a.power / best if best else float("inf")))
        print("and no arrangement of the algorithms above changes it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
