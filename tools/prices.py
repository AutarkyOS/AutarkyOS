#!/usr/bin/env python3
"""What a mined coin is worth, from two sources that do not talk to each other.

`design/mining.md` recorded "no prices" as a gap and gave the reason: every
site that renders one does it in JavaScript. That was true of the *sites* and
not of the market -- CoinGecko and CoinPaprika both answer plain JSON with no
key and no account. This is the fetcher, and it writes a file the pool reads.

    prices.py                    print the table
    prices.py --write PATH       write it as JSON for the pool
    prices.py --selftest         check the reader against the writer

### The field that decides whether any of this is honest

**A dead coin still has a price, and the API will hand it to you.** Ask
CoinGecko for BitZeny and it answers `0.00023968` with no error and no
qualification; the number is from August 2022. `last_updated_at` is what says
so, it is *opt-in* (`include_last_updated_at=true`), and without it the reply
for a coin nobody has traded in four years is byte-for-byte the shape of a
reply for Bitcoin.

That is the exact failure this repository keeps writing down. So: the age is
requested, it is printed beside every figure, and a price past `--max-age` is
written to the file **marked unusable rather than omitted**. Omitting it would
read as "nobody asked", which is a different fact.

### Two sources, and how far apart they are is itself the measurement

The same bargain `tokenizer.py --verify` and `differ.rs` make. Averaging two
prices produces a third number neither source will confirm, and an average is
also how one source being broken becomes invisible.

**A gap has two causes and they need telling apart**, which the first live run
demonstrated by producing one of each. Verge came back 2.0% apart -- two
sources averaging different exchange sets on a coin with a six-million-dollar
day, which is what an illiquid market looks like and is not an error. Veco came
back a factor of 4.6 apart, which is not a spread: it is two sources quoting
two different assets that share a ticker, and it is exactly the mis-mapping a
second source exists to catch.

So there are three bands, not two. Inside `--tolerance` the two agree and the
mean is quoted. Between that and `--spread-max` they are apart and the
**lower** is quoted with the gap recorded -- lower because under-promising is
the safe direction for an expected value, and recorded because a reader must
be able to see that the number has a range behind it. Past `--spread-max`
nothing is quoted at all, because at that distance the likeliest explanation is
that the two sources are not describing the same coin.

**A coin one source does not list at all is a finding, not an error.** Three of
the yespower coins this project ranked first are 404 at CoinPaprika, which is
what a delisting looks like from the outside.

### Volume is not decoration

A price is what the last trade cleared at, so a coin with no volume has a
quoted price and no way to realise it. Zero volume voids the price here, and
the threshold is an argument rather than a constant because what counts as
tradeable depends on how much is being sold.
"""

import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

UA = {"User-Agent": "glados-pool/prices.py (+https://aperture.institute)"}

# The coins this project can mine or has ranked, and what each source calls
# them. Written out rather than searched for, because a fuzzy match on a ticker
# is how "VECO" becomes some other VECO -- and the whole point of two sources
# is that they are quoting the same asset.
#
# `algo` is what GLaDOS would mine it with, and `None` means the algorithm is
# not implemented here. It is in the table anyway: a coin worth mining that we
# cannot mine is the most useful row in it.
COINS = [
    # label        algo             coingecko        coinpaprika
    ("bitcoin",    "sha256d",       "bitcoin",       "btc-bitcoin"),
    ("verge",      "blake2s",       "verge",         "xvg-verge"),
    ("kaspa",      "kheavyhash",    "kaspa",         "kas-kaspa"),
    ("digibyte",   "sha256d",       "digibyte",      "dgb-digibyte"),
    ("monero",     None,            "monero",        "xmr-monero"),
    ("bitzeny",    "yespower",      "bitzeny",       "zny-bitzeny"),
    ("koto",       "yespower",      "koto",          "koto-koto"),
    ("yenten",     "yespower",      "yenten",        "ytn-yenten"),
    ("veco",       "yespower",      "veco",          "veco-veco"),
    ("privcy",     "yespower",      "privcy",        "prv-privcy"),
    ("wavi",       "yespower",      "wavi",          "wavi-wavi"),
]

# Beyond this a price is history rather than a quote. Six hours is generous for
# a liquid market and still refuses everything the survey found stale, which
# was measured in hundreds of days rather than hours -- there is nothing near
# the boundary, so the exact figure is not load-bearing.
MAX_AGE_HOURS = 6.0
# Two sources quoting one asset differ by the exchanges they average and by
# when they sampled. Two percent covers that on a liquid coin; past it the gap
# is worth printing rather than hiding, which is what the middle band is for.
TOLERANCE = 0.02
# Past this the two are not describing one asset. Measured: Veco's two quotes
# are a factor of 4.6 apart, and no exchange spread is 360%.
SPREAD_MAX = 0.25
# Below this a price cannot be realised, whatever it says. Not zero, because a
# single wash trade is not a market either.
MIN_VOLUME_USD = 1000.0


def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def from_coingecko(ids):
    """`{id: (price, volume, unix)}`, and a missing id is simply absent.

    One request for every coin, because the free tier is rate limited and
    eleven requests is eleven chances to be told to come back later.
    """
    url = (
        "https://api.coingecko.com/api/v3/simple/price"
        "?ids=%s&vs_currencies=usd"
        "&include_24hr_vol=true&include_last_updated_at=true" % ",".join(ids)
    )
    out = {}
    for k, v in get(url).items():
        if "usd" not in v:
            continue
        out[k] = (
            float(v["usd"]),
            float(v.get("usd_24h_vol") or 0.0),
            int(v.get("last_updated_at") or 0),
        )
    return out


def from_coinpaprika(ids):
    """The same, one request per coin because there is no batch endpoint.

    A 404 is recorded as an absence rather than raised. It is the answer for a
    delisted coin, and it is information.
    """
    out = {}
    for pid in ids:
        try:
            d = get("https://api.coinpaprika.com/v1/tickers/" + pid)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
        q = d["quotes"]["USD"]
        # An ISO 8601 Z stamp. `strptime` rather than `fromisoformat`, which
        # did not accept a trailing Z before 3.11 and this venv is not pinned.
        try:
            when = int(time.mktime(time.strptime(d["last_updated"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone)
        except (KeyError, ValueError):
            when = 0
        out[pid] = (float(q["price"]), float(q.get("volume_24h") or 0.0), when)
    return out


def survey(max_age_hours=MAX_AGE_HOURS, tolerance=TOLERANCE, min_volume=MIN_VOLUME_USD,
           spread_max=SPREAD_MAX):
    """Every coin in `COINS`, with a verdict and the reason for it."""
    gecko = from_coingecko([c[2] for c in COINS])
    paprika = from_coinpaprika([c[3] for c in COINS])
    now = time.time()

    rows = []
    for label, algo, gid, pid in COINS:
        g = gecko.get(gid)
        p = paprika.get(pid)
        row = {
            "coin": label,
            "algo": algo,
            "usd": None,
            "volume_24h_usd": None,
            "age_hours": None,
            "usable": False,
            # Why the price cannot be quoted. Empty when it can.
            "why": "",
            # Something a reader of a quotable figure still needs to know.
            # Separate from `why` on purpose: a caveat is not a refusal, and
            # collapsing the two means either losing caveats or losing coins.
            "note": "",
            "sources": [],
        }
        if g:
            row["sources"].append("coingecko")
        if p:
            row["sources"].append("coinpaprika")

        if not g and not p:
            row["why"] = "neither source lists it"
            rows.append(row)
            continue
        if not p:
            # Kept rather than dropped: one source is a price and is not a
            # cross-check, and saying which is missing is the point.
            row["why"] = "only coingecko lists it, so nothing checks it"
        elif not g:
            row["why"] = "only coinpaprika lists it, so nothing checks it"

        best = g or p
        row["usd"] = best[0]
        row["volume_24h_usd"] = best[1]
        # The *older* of the two, because the claim is only as fresh as its
        # weakest support.
        stamps = [x[2] for x in (g, p) if x and x[2]]
        row["age_hours"] = (now - min(stamps)) / 3600.0 if stamps else None

        if g and p:
            hi = max(g[0], p[0])
            lo = min(g[0], p[0])
            gap = (hi - lo) / hi if hi > 0 else 1.0
            row["spread"] = gap
            if gap > spread_max:
                row["why"] = (
                    "the sources are a factor of %.1f apart (%.10g against %.10g), "
                    "which is a different asset rather than a spread"
                    % (hi / lo if lo > 0 else float("inf"), g[0], p[0])
                )
                rows.append(row)
                continue
            if gap > tolerance:
                # The lower of the two, because under-promising is the safe
                # direction for an expected value and the caveat carries the
                # rest.
                row["usd"] = lo
                row["note"] = "the sources are %.1f%% apart; the lower is quoted" % (gap * 100.0)
            else:
                # Both agree, so quote the mean of two numbers already within
                # the tolerance. Not an average standing in for a disagreement:
                # a disagreement took one of the two branches above.
                row["usd"] = (g[0] + p[0]) / 2.0
            # The smaller volume for the same reason the lower price is taken.
            row["volume_24h_usd"] = min(g[1], p[1])

        if row["age_hours"] is None:
            row["why"] = "no source said when it was priced"
        elif row["age_hours"] > max_age_hours:
            row["why"] = "last priced %.0f days ago" % (row["age_hours"] / 24.0)
        elif (row["volume_24h_usd"] or 0.0) < min_volume:
            row["why"] = "24h volume is $%.0f, so the price cannot be realised" % (
                row["volume_24h_usd"] or 0.0
            )
        elif row["why"]:
            pass  # only one source has it, and that is already recorded
        else:
            row["usable"] = True
        rows.append(row)
    return rows


def render(rows):
    print("%-10s %-11s %-14s %-14s %-10s %s" % ("coin", "algo", "usd", "24h vol usd", "age", "verdict"))
    for r in rows:
        age = "--" if r["age_hours"] is None else (
            "%.1f h" % r["age_hours"] if r["age_hours"] < 48 else "%.0f d" % (r["age_hours"] / 24.0)
        )
        print(
            "%-10s %-11s %-14s %-14s %-10s %s"
            % (
                r["coin"],
                r["algo"] or "--",
                "--" if r["usd"] is None else "%.10g" % r["usd"],
                "--" if r["volume_24h_usd"] is None else "%.0f" % r["volume_24h_usd"],
                age,
                (r["note"] or "usable") if r["usable"] else r["why"],
            )
        )
    usable = [r for r in rows if r["usable"]]
    print()
    print("%d of %d coins have a price this can quote." % (len(usable), len(rows)))
    mineable = [r for r in usable if r["algo"]]
    print(
        "%d of those run an algorithm this project has: %s"
        % (len(mineable), ", ".join(r["coin"] for r in mineable) or "none")
    )


def document(rows):
    return {
        "version": 1,
        "fetched_at": int(time.time()),
        "max_age_hours": MAX_AGE_HOURS,
        "min_volume_usd": MIN_VOLUME_USD,
        "tolerance": TOLERANCE,
        "spread_max": SPREAD_MAX,
        "coins": rows,
    }


def selftest():
    """The reader against the writer, on a document with every verdict in it.

    Deliberately offline. What this checks is the shape of the file the pool
    parses and the rule it applies, and a check that needed the network would
    be a check nobody could run when the network is what broke.
    """
    ok = True

    def claim(name, cond):
        nonlocal ok
        print("%-4s  %s" % ("ok" if cond else "FAIL", name))
        ok = ok and cond

    rows = [
        {"coin": "a", "algo": "blake2s", "usd": 1.0, "volume_24h_usd": 5e6,
         "age_hours": 0.5, "usable": True, "why": "", "note": "",
         "sources": ["coingecko", "coinpaprika"]},
        {"coin": "b", "algo": "yespower", "usd": 2.0, "volume_24h_usd": 0.0,
         "age_hours": 9000.0, "usable": False, "why": "last priced 375 days ago",
         "note": "", "sources": ["coingecko"]},
        # The middle band, which is the one a two-verdict file cannot express:
        # quotable, and carrying something the reader has to know.
        {"coin": "c", "algo": "blake2s", "usd": 3.0, "volume_24h_usd": 6e6,
         "age_hours": 1.0, "usable": True, "why": "",
         "note": "the sources are 2.0% apart; the lower is quoted",
         "sources": ["coingecko", "coinpaprika"]},
    ]
    doc = document(rows)
    text = json.dumps(doc, indent=2, sort_keys=True)
    back = json.loads(text)

    claim("the document round-trips", back["coins"] == rows)
    claim("a usable coin is marked usable", back["coins"][0]["usable"])
    claim("an unusable coin is present rather than omitted", len(back["coins"]) == 3)
    claim("and it carries the reason", back["coins"][1]["why"] != "")
    # The one property the pool depends on and cannot recover if it is wrong.
    claim(
        "every unusable coin has a reason",
        all(r["usable"] or r["why"] for r in back["coins"]),
    )
    claim(
        "no coin is both usable and reasoned against",
        all(not (r["usable"] and r["why"]) for r in back["coins"]),
    )
    # The distinction the first live run forced. A caveat that had to be a
    # refusal would have thrown away Verge, which is the only live market whose
    # algorithm this project can already compute.
    claim(
        "a caveat does not make a coin unusable",
        back["coins"][2]["usable"] and back["coins"][2]["note"],
    )
    claim("the fetch time is recorded", back["fetched_at"] > 1_700_000_000)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", metavar="PATH", help="write the survey as JSON")
    ap.add_argument("--max-age", type=float, default=MAX_AGE_HOURS,
                    help="hours past which a price is history (default %(default)s)")
    ap.add_argument("--min-volume", type=float, default=MIN_VOLUME_USD,
                    help="USD of 24h volume below which a price cannot be realised")
    ap.add_argument("--tolerance", type=float, default=TOLERANCE,
                    help="fractional disagreement between sources that is still agreement")
    ap.add_argument("--spread-max", type=float, default=SPREAD_MAX,
                    help="fractional gap past which the sources are quoting different assets")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    rows = survey(a.max_age, a.tolerance, a.min_volume, a.spread_max)
    render(rows)
    if a.write:
        d = os.path.dirname(os.path.abspath(a.write))
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with io.open(a.write, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document(rows), f, indent=2, sort_keys=True)
            f.write("\n")
        print("\nwrote %s" % a.write)
    return 0


if __name__ == "__main__":
    sys.exit(main())
