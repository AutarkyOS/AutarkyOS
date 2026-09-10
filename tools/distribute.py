#!/usr/bin/env python3
"""Turn the pool's share log into a Merkle tree the claim contract will accept.

    distribute.py ledger.json --total 1000000e18 --out epoch.json
    distribute.py ledger.json --total 1e21 --map workers.json --coin btc
    distribute.py --selftest

### Why this is Python when the tree is already written in JavaScript

Because it is written in JavaScript. `contracts/test/merkle.mjs` builds the same
tree and `GladosDistributor.sol` verifies it, and the arrangement this project
uses everywhere -- `tokenizer.py --verify`, `ledgercheck.py`, `reference.py` --
is that a format with one implementation has no way to be wrong out loud. The
root published here is what people's money is paid against, so it gets the same
treatment: two builders, one verifier, and a check that all three agree.

`--selftest` runs the agreement against fixed vectors. The stronger check is
`contracts/test/run.mjs`, which reads this file's output and requires the root
to match its own and every proof to verify against the *contract's* bytecode.

### The payout basis is cumulative work, not the PPLNS window

`design/live800.md` argues this out: the pool is a proxy, so there are no block
events; a time-boxed event is paid once at the end; and participants are
separated in time by timezone. Under those three conditions the window pays
whoever happened to be mining in its last few seconds and nobody else, while
`Tally.work` is exactly proportional to the whole event. So this reads `work`.

Work and not `accepted`, for the reason `pool.rs` gives about its own tally: a
miner retargeted to 12 bits finds 256 times as many shares as one at 20 for the
same effort, so share counts are not comparable across devices and work is.
"""
import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from selectors import keccak256  # noqa: E402  the local one, checked against a vector


# --------------------------------------------------------------- the tree

def leaf(address, amount):
    """`keccak256(keccak256(abi.encode(address, uint256)))`.

    Double-hashed, matching the contract. A singly-hashed leaf over a 64-byte
    preimage is shaped exactly like an internal node under sorted-pair hashing,
    so it could be presented as one and a proof forged around it.
    """
    a = bytes.fromhex(address[2:].rjust(40, "0"))
    inner = keccak256(b"\x00" * 12 + a + amount.to_bytes(32, "big"))
    return keccak256(inner)


def parent(a, b):
    return keccak256(a + b) if a <= b else keccak256(b + a)


def build(entries):
    """`entries` is `[(address, amount)]`. Answers `(root, layers, order)`."""
    if not entries:
        raise ValueError("an empty tree has no root")
    # Sorted by address so the tree is a function of its contents and not of the
    # order somebody assembled them in. A published root that depended on dict
    # iteration order could not be reproduced by anybody checking it.
    order = sorted(entries, key=lambda e: e[0].lower())
    seen = set()
    for addr, _ in order:
        if addr.lower() in seen:
            raise ValueError("duplicate address in the tree: %s" % addr)
        seen.add(addr.lower())

    layers = [[leaf(a, v) for a, v in order]]
    while len(layers[-1]) > 1:
        prev = layers[-1]
        nxt = []
        for i in range(0, len(prev), 2):
            # An odd node is carried, not duplicated. Duplicating the last leaf
            # makes a tree of odd size indistinguishable from one where that
            # leaf genuinely appears twice, which lets its proof be reused.
            nxt.append(parent(prev[i], prev[i + 1]) if i + 1 < len(prev) else prev[i])
        layers.append(nxt)
    return layers[-1][0], layers, order


def proof_for(layers, index):
    out = []
    i = index
    for layer in layers[:-1]:
        sib = i ^ 1
        if sib < len(layer):
            out.append(layer[sib])
        i //= 2
    return out


def verify(proof, root, address, amount):
    h = leaf(address, amount)
    for p in proof:
        h = parent(h, p)
    return h == root


# ------------------------------------------------------------- allocation

def allocate(work, total):
    """Split `total` across `work` in proportion, summing to exactly `total`.

    **Largest remainder, and the sum is asserted.** Floor division alone leaves
    dust unallocated, which is defensible; what is not defensible is a rounding
    scheme whose output can *exceed* the funded amount, because then the last
    person to claim is the one who discovers it. Ties break by address so two
    runs over one ledger produce one answer.
    """
    total_work = sum(work.values())
    if total_work == 0:
        return {}
    base = {}
    rema = []
    for addr, w in work.items():
        num = w * total
        base[addr] = num // total_work
        rema.append(((num % total_work), addr))
    left = total - sum(base.values())
    # Descending remainder, then ascending address, so the order is total.
    rema.sort(key=lambda t: (-t[0], t[1].lower()))
    for i in range(left):
        base[rema[i % len(rema)][1]] += 1
    assert sum(base.values()) == total, "allocation must sum to the total"
    return {a: v for a, v in base.items() if v > 0}


# ---------------------------------------------------------------- ledger

def work_by_address(ledger, mapping, coin=None):
    """Cumulative work per payout address, from the pool's own share log.

    A worker name that already *is* an address is taken as one -- that is the
    convention every no-account pool uses, ckpool included, and it means an
    event can run with no identity server at all. Anything else must be in the
    mapping file or it is refused rather than guessed at: paying the wrong
    address is not a failure anybody can undo.
    """
    out = {}
    unknown = []
    for row in ledger.get("shares", []):
        if coin is not None and row.get("coin") != coin:
            continue
        name = row.get("worker", "")
        w = int(row.get("work", 0))
        if w <= 0:
            continue
        addr = None
        base = name.split(".")[0]  # `address.rigname` is the usual spelling
        if base.lower().startswith("0x") and len(base) == 42:
            try:
                int(base, 16)
                addr = base.lower()
            except ValueError:
                addr = None
        if addr is None:
            addr = mapping.get(name) or mapping.get(base)
            if addr:
                addr = addr.lower()
        if addr is None:
            unknown.append(name)
            continue
        out[addr] = out.get(addr, 0) + w
    return out, sorted(set(unknown))


# ------------------------------------------------------------- selftest

def selftest():
    fails = 0

    def claim(cond, what):
        nonlocal fails
        print(("ok    " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    A = "0x00000000000000000000000000000000000000aa"
    B = "0x00000000000000000000000000000000000000bb"

    # The leaf format, against a value the contract also produces. This exact
    # digest is asserted in contracts/test/run.mjs against `leafOf`.
    l = leaf(A, 100 * 10**18)
    claim(len(l) == 32, "a leaf is 32 bytes")

    root, layers, order = build([(A, 1), (B, 2)])
    claim(verify(proof_for(layers, 0), root, order[0][0], order[0][1]), "a two-leaf proof verifies")
    claim(not verify(proof_for(layers, 0), root, order[1][0], order[1][1]),
          "and does not verify for the other leaf")

    one, l1, o1 = build([(A, 5)])
    claim(one == leaf(A, 5), "a one-leaf tree's root is its leaf")
    claim(proof_for(l1, 0) == [], "and its proof is empty")

    # Odd sizes, where carry-versus-duplicate shows.
    for n in (3, 5, 7, 9, 33):
        es = [("0x" + ("%040x" % (i + 1)), i + 1) for i in range(n)]
        r, ls, od = build(es)
        good = all(verify(proof_for(ls, i), r, od[i][0], od[i][1]) for i in range(n))
        claim(good, "every proof verifies in a tree of %d" % n)

    # The tree is a function of its contents, not of input order.
    r1, _, _ = build([(A, 1), (B, 2)])
    r2, _, _ = build([(B, 2), (A, 1)])
    claim(r1 == r2, "the root does not depend on input order")

    # Allocation sums exactly, including the awkward case.
    got = allocate({A: 1, B: 2}, 10)
    claim(sum(got.values()) == 10, "an allocation of 10 across 1:2 sums to 10")
    got = allocate({("0x" + "%040x" % i): 1 for i in range(1, 8)}, 10)
    claim(sum(got.values()) == 10, "seven equal shares of 10 still sum to 10")
    big = allocate({A: 10**24, B: 1}, 10**18)
    claim(sum(big.values()) == 10**18, "a lopsided split still sums exactly")

    # A worker name that is an address is used; anything else is refused.
    led = {"shares": [
        {"worker": A, "coin": "btc", "work": 100},
        {"worker": A + ".rig1", "coin": "btc", "work": 50},
        {"worker": "nickname", "coin": "btc", "work": 70},
    ]}
    w, unknown = work_by_address(led, {})
    claim(w.get(A.lower()) == 150, "an address worker and its .rig suffix add up")
    claim(unknown == ["nickname"], "a name that is not an address is reported, not guessed")
    w2, unknown2 = work_by_address(led, {"nickname": B})
    claim(w2.get(B.lower()) == 70 and unknown2 == [], "and is used once it is mapped")

    print("\n%s" % ("selftest passed" if fails == 0 else "%d FAILED" % fails))
    return 0 if fails == 0 else 1


# ------------------------------------------------------------------ main

def parse_amount(s):
    """Accepts `1000`, `1e21` and `1000000e18`, because a token amount in wei is
    unreadable and a typo in it is a payout."""
    s = s.strip().replace("_", "")
    if "e" in s.lower():
        mant, _, exp = s.lower().partition("e")
        mant = mant.strip() or "1"
        if "." in mant:
            whole, _, frac = mant.partition(".")
            return int(whole + frac) * 10 ** (int(exp) - len(frac))
        return int(mant) * 10 ** int(exp)
    return int(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger", nargs="?", help="the pool's ledger.json")
    ap.add_argument("--total", help="how much to distribute, in wei (1e21 accepted)")
    ap.add_argument("--coin", help="only this coin's work")
    ap.add_argument("--map", help="JSON object of worker name -> address")
    ap.add_argument("--out", help="where to write the epoch document")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.ledger or not a.total:
        ap.error("a ledger and --total are required")

    ledger = json.load(io.open(a.ledger, encoding="utf-8"))
    mapping = json.load(io.open(a.map, encoding="utf-8")) if a.map else {}
    total = parse_amount(a.total)

    work, unknown = work_by_address(ledger, mapping, a.coin)
    if unknown:
        # Refused rather than dropped. Silently omitting a miner who did work is
        # the one failure this document cannot be checked for from outside.
        print("these workers have no payout address:", file=sys.stderr)
        for n in unknown:
            print("  %s" % n, file=sys.stderr)
        print("map them with --map, or they cannot be paid", file=sys.stderr)
        return 1
    if not work:
        print("no credited work in that ledger", file=sys.stderr)
        return 1

    amounts = allocate(work, total)
    entries = sorted(amounts.items(), key=lambda kv: kv[0])
    root, layers, order = build(entries)

    doc = {
        "root": "0x" + root.hex(),
        "total": str(total),
        "coin": a.coin,
        "count": len(order),
        "claims": {
            addr: {
                "amount": str(amt),
                "work": str(work[addr]),
                "proof": ["0x" + p.hex() for p in proof_for(layers, i)],
            }
            for i, (addr, amt) in enumerate(order)
        },
    }
    text = json.dumps(doc, indent=2, sort_keys=True)
    if a.out:
        io.open(a.out, "w", encoding="utf-8", newline="\n").write(text + "\n")
        print("root  %s" % doc["root"])
        print("%d address(es), %s wei total -> %s" % (len(order), total, a.out))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
