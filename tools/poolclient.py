#!/usr/bin/env python3
"""A miner that speaks the GLaDOS pool protocol, for driving a pool without a kernel.

`design/pool.md` has the protocol. This is a third implementation of it -- the
kernel's is `src/mine/proto.rs` and the pool shares that same file, so without
something written separately the encoder and the decoder are the same code
agreeing with itself.

It exists mostly for iteration speed. Booting the kernel under QEMU to check a
change in the pool costs three minutes; this costs a second, and the kernel run
stays the thing that settles anything about the kernel.

**sha256d and blake2s only.** `hashlib` has both. yespower it does not have, and
a Python transliteration of it here would be a fourth implementation of the one
algorithm this tree is most careful about -- `tools/yespower.py` already exists
for that and is checked against upstream's own vectors. A job for an algorithm
this client cannot compute is skipped and said out loud rather than failed.

    python tools/poolclient.py --host 127.0.0.1 --port 3334 --worker probe.rig
    python tools/poolclient.py --port 3334 --shares 5 --seconds 30
"""

import argparse
import hashlib
import json
import socket
import sys
import time


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def blake2s(b):
    return hashlib.blake2s(b, digest_size=32).digest()


def hasher_for(algo):
    """The function a job's algorithm names, or None if we cannot compute it."""
    name = algo.get("name")
    if name == "sha256d":
        return sha256d
    if name == "blake2s":
        return blake2s
    return None


def meets(digest, target):
    """Is this digest at or below the target.

    **The digest is little-endian and the target is big-endian**, and that
    asymmetry is the whole of this function. A block hash is a 256-bit integer
    stored least-significant byte first, which is why a Bitcoin block id is
    displayed reversed and why `hash::below_target` reverses before comparing.
    Comparing both as big-endian is not close to right: it accepts and rejects
    an unrelated set of shares.

    Got wrong here first. Every share this client found was refused by the pool
    and the pool was correct -- an entire connection's worth of "bad", which the
    pool's abuse limiter then quite properly dropped.

    Not a count of leading zeros either: a target that is not a power of two
    cannot be expressed that way. `src/mine/hash.rs` makes the same point.
    """
    return int.from_bytes(digest, "little") <= int.from_bytes(target, "big")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3334)
    ap.add_argument("--worker", default="poolclient.rig")
    ap.add_argument("--shares", type=int, default=4,
                    help="stop after this many accepted shares")
    ap.add_argument("--seconds", type=float, default=60.0,
                    help="stop after this long regardless")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    sock = socket.create_connection((a.host, a.port), timeout=5)
    sock.settimeout(0.5)
    buf = b""

    def send(obj):
        sock.sendall((json.dumps(obj) + "\n").encode())

    send({"id": 1, "method": "glados.hello",
          "params": {"v": 1, "worker": a.worker, "agent": "poolclient.py"}})

    jobs = {}          # job id -> (algo fn, header, target)
    done = 0
    skipped = set()
    deadline = time.time() + a.seconds
    nonce = 0

    while time.time() < deadline and done < a.shares:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                print("pool closed the connection")
                break
            buf += chunk
        except socket.timeout:
            pass

        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue

            if msg.get("method") == "glados.job":
                p = msg["params"]
                fn = hasher_for(p["algo"])
                if fn is None:
                    if p["algo"].get("name") not in skipped:
                        skipped.add(p["algo"].get("name"))
                        print("skipping %s: this client cannot compute it"
                              % p["algo"].get("name"))
                    continue
                jobs[p["job"]] = (fn, bytes.fromhex(p["header"]),
                                  bytes.fromhex(p["target"]), p["coin"])
                if not a.quiet:
                    print("job %s on %s (%s)" % (p["job"], p["coin"], p["algo"]["name"]))
            elif "result" in msg and isinstance(msg["result"], dict):
                r = msg["result"]
                if "slots" in r:
                    print("welcomed, %d slot(s)" % r["slots"])
                elif "verdict" in r:
                    print("  share %s" % r["verdict"])
                    if r.get("ok"):
                        done += 1

        # Mine whatever is in hand. Newest first, since an older job is more
        # likely to have been replaced.
        for jid in list(jobs)[::-1]:
            fn, header, target, _coin = jobs[jid]
            found = None
            # A bounded slice per pass, so incoming jobs and replies are still
            # read promptly -- the same reason the kernel's hash loop works in
            # batches rather than until it finds something.
            for _ in range(200_000):
                nonce = (nonce + 1) & 0xFFFFFFFF
                h = header[:76] + nonce.to_bytes(4, "little")
                if meets(fn(h), target):
                    found = nonce
                    break
            if found is not None:
                send({"id": 2, "method": "glados.submit",
                      "params": {"job": jid,
                                 "nonce": found.to_bytes(4, "big").hex(),
                                 "echo": {}}})
                break

    print("accepted %d share(s)" % done)
    sock.close()
    return 0 if done > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
