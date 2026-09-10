#!/usr/bin/env python3
"""Ask a pool to prove what it pays, and check the proof.

This is the miner's side of the bargain in `design/pool.md`. A job is a finished
80-byte header, so the coinbase is inside a merkle root and a root is a hash:
there is nothing to read. A pool willing to show its working sends `proof`, and
rebuilding it and requiring the same merkle root is a complete check -- a
matching root proves the coinbase you were *shown* is the coinbase that was
*committed to*, and a pool cannot show one and mine another without breaking it.

The kernel does this in ring 0 (`mine::proto::proves`). This does it in Python
so it can be run against any pool, by anybody, before pointing hardware at one
-- and so CI can check it without booting QEMU.

**What it cannot tell you** is whether any chain wants that header at all. A
pool free-running its own template passes perfectly. That is what the `source`
column in the pool's own report is for, and it is not something a miner can
verify from the outside.

    python tools/prooftest.py --port 3334
    python tools/prooftest.py --port 3334 --expect-fail   # for a pool that lies

Exit status is 0 when the outcome matched what was expected.
"""

import argparse
import hashlib
import json
import socket
import sys
import time


def d2(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def root_of(proof):
    """Rebuild the merkle root the coinbase in this proof commits to."""
    coinbase = (bytes.fromhex(proof["coinb1"])
                + bytes.fromhex(proof["extranonce"])
                + bytes.fromhex(proof["coinb2"]))
    root = d2(coinbase)
    for sib in proof.get("branch", []):
        # Order is load-bearing: a branch folded the other way produces
        # thirty-two perfectly plausible bytes that commit to nothing.
        root = d2(root + bytes.fromhex(sib))
    return root, coinbase


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def bech32_encode(hrp, witver, prog):
    """Just enough bech32/bech32m to name a v0 or v1 witness output.

    Written out rather than pulled from a library because this file is meant to
    be runnable by a miner with nothing installed -- the whole point of it is
    that somebody can check a pool before pointing hardware at it, and a
    dependency is a reason not to bother.
    """
    data = [witver] + [b for b in convertbits(prog, 8, 5)]
    const = 1 if witver == 0 else 0x2bc830a3
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in data + checksum)


def convertbits(data, frm, to):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if bits:
        out.append((acc << (to - bits)) & maxv)
    return out


def script_address(spk):
    """Name a coinbase output's script, or say what shape it is.

    **This is the question a non-custodial pool has to answer** and the one the
    value alone does not: a miner can verify that the coinbase committed to is
    the coinbase it was shown, and still have no idea whose address it pays.
    Only P2WPKH, P2WSH, P2TR and P2PKH are named, because those cover what a
    pool actually emits; anything else is reported by its shape rather than
    guessed at, since an address printed wrong is worse than none.
    """
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return bech32_encode("bc", 0, spk[2:])
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return bech32_encode("bc", 0, spk[2:])
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return bech32_encode("bc", 1, spk[2:])
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and spk[2] == 0x14:
        return "p2pkh:" + spk[3:23].hex()
    if len(spk) >= 2 and spk[0] == 0x6a:
        # The witness commitment, and every block after segwit has one. Named
        # rather than listed as an unknown, or every run reports a mystery.
        return "op_return (witness commitment)"
    return "unrecognised script, %d bytes" % len(spk)


def coinbase_value(cb):
    """Sum the coinbase outputs, or None if it does not parse exactly.

    Walks and must land on the last byte, which is the same bargain
    `ev::coinbase_value` makes: a transaction that *nearly* parses is one this
    has misread, and a plausible number from a misread is worse than none.

    Answers `(total, [(value, script)])` so the caller can say *who* is paid
    and not only how much.
    """
    try:
        i = 4                                     # version
        if cb[i] == 0x00:                         # segwit marker
            return None
        n_in = cb[i]; i += 1
        if n_in >= 0xfd:
            return None
        for _ in range(n_in):
            i += 32 + 4                           # outpoint
            ln = cb[i]; i += 1
            if ln >= 0xfd:
                return None
            i += ln + 4                           # script + sequence
        n_out = cb[i]; i += 1
        if n_out >= 0xfd:
            return None
        total = 0
        outs = []
        for _ in range(n_out):
            v = int.from_bytes(cb[i:i + 8], "little"); i += 8
            total += v
            ln = cb[i]; i += 1
            if ln >= 0xfd:
                return None
            outs.append((v, cb[i:i + ln])); i += ln
        i += 4                                    # locktime
        return (total, outs) if i == len(cb) else None
    except IndexError:
        return None


def first_job(host, port, seconds):
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(2)
    sock.sendall((json.dumps({
        "id": 1, "method": "glados.hello",
        "params": {"v": 1, "worker": "prooftest", "agent": "prooftest.py"},
    }) + "\n").encode())
    buf = b""
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("method") == "glados.job":
                    return msg["params"]
    finally:
        sock.close()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3334)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--expect-paid", metavar="ADDRESS",
                    help="require this address among the coinbase outputs; "
                         "the check a miner actually wants before pointing "
                         "hardware at a pool")
    ap.add_argument("--expect-fail", action="store_true",
                    help="require the proof NOT to verify, for checking a pool "
                         "that is deliberately lying")
    ap.add_argument("--allow-absent", action="store_true",
                    help="a job with no proof is not a failure. A local coin "
                         "has no chain and so no coinbase worth showing.")
    a = ap.parse_args()

    job = first_job(a.host, a.port, a.seconds)
    if job is None:
        print("no job arrived within %gs" % a.seconds)
        return 2

    proof = job.get("proof")
    if proof is None:
        if a.allow_absent:
            print("%s on %s: no proof offered (allowed)" % (job["job"], job["coin"]))
            return 0
        print("%s on %s: the pool offered no proof of what it pays"
              % (job["job"], job["coin"]))
        return 1

    root, coinbase = root_of(proof)
    header = bytes.fromhex(job["header"])
    ok = root == header[36:68]

    if ok:
        parsed = coinbase_value(coinbase)
        if parsed is None:
            print("%s on %s: proof VERIFIES, coinbase did not parse exactly"
                  % (job["job"], job["coin"]))
        else:
            value, outs = parsed
            print("%s on %s: proof VERIFIES, pays %d.%08d"
                  % (job["job"], job["coin"], value // 100_000_000,
                     value % 100_000_000))
            # **Who, and not only how much.** A miner can verify that the
            # coinbase committed to is the coinbase it was shown and still have
            # no idea whose address it pays, which for a pool whose whole claim
            # is that it never holds your coins is the question.
            for v, spk in outs:
                if v == 0:
                    continue
                print("  %d.%08d to %s" % (v // 100_000_000, v % 100_000_000,
                                           script_address(spk)))
            if a.expect_paid:
                names = [script_address(spk) for v, spk in outs if v > 0]
                if a.expect_paid not in names:
                    print("  FAIL: nothing pays %s" % a.expect_paid)
                    return 1
                print("  and %s is among them" % a.expect_paid)
    else:
        print("%s on %s: proof DOES NOT match the header it came with"
              % (job["job"], job["coin"]))
        print("  committed: %s" % header[36:68].hex())
        print("  rebuilt  : %s" % root.hex())

    if a.expect_fail:
        # Inverted deliberately, so a pool built to lie can be checked as
        # rigorously as one built to be honest. A check that can only pass is
        # not a check.
        return 0 if not ok else 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
