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


def coinbase_value(cb):
    """Sum the coinbase outputs, or None if it does not parse exactly.

    Walks and must land on the last byte, which is the same bargain
    `ev::coinbase_value` makes: a transaction that *nearly* parses is one this
    has misread, and a plausible number from a misread is worse than none.
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
        for _ in range(n_out):
            total += int.from_bytes(cb[i:i + 8], "little"); i += 8
            ln = cb[i]; i += 1
            if ln >= 0xfd:
                return None
            i += ln
        i += 4                                    # locktime
        return total if i == len(cb) else None
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
        value = coinbase_value(coinbase)
        paid = ("pays %d.%08d" % (value // 100_000_000, value % 100_000_000)
                if value is not None else "coinbase did not parse exactly")
        print("%s on %s: proof VERIFIES, %s" % (job["job"], job["coin"], paid))
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
