#!/usr/bin/env python3
"""A deliberately gentle miner, to keep the soak honest without cooking the box.

The pool has never run for hours. What a soak is looking for is a trend --
memory that climbs, descriptors that are never closed, a ledger that grows
without bound -- and none of that needs the machine driven hard. It needs the
code paths *exercised*: connect, take a job, submit, be answered, reconnect.

So this hashes on one core at a low duty cycle, sleeping most of every second.
On a four-thread i3 that is also serving Jellyfin and Immich to a household,
the test that tells you the most is the one nobody notices is running.

It also reconnects deliberately every `--cycle` seconds. A pool that leaks a
descriptor or a thread per connection shows it as a slope rather than as a
crash, and only a test that keeps connecting can find it.
"""
import argparse
import hashlib
import json
import os
import random
import socket
import struct
import sys
import time


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def below(digest, target_be):
    # The digest is read little-endian and the target big-endian, which is the
    # convention `below_target` uses and the one it is easy to get backwards.
    return int.from_bytes(digest, "little") <= int.from_bytes(target_be, "big")


def run_once(host, port, worker, cycle, duty):
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(2.0)
    f = s.makefile("rwb")
    nid = [1]

    def send(o):
        f.write((json.dumps(o) + "\n").encode())
        f.flush()

    send({"id": nid[0], "method": "glados.hello",
          "params": {"v": 1, "worker": worker, "agent": "soak/1"}})
    nid[0] += 1

    jobs = {}
    accepted = bad = other = 0
    end = time.time() + cycle
    nonce = random.getrandbits(32)

    while time.time() < end:
        # Drain whatever is waiting, without blocking the hash loop.
        try:
            while True:
                line = f.readline()
                if not line:
                    return accepted, bad, other, "closed"
                v = json.loads(line.decode(errors="replace"))
                if v.get("method") == "glados.job":
                    p = v["params"]
                    if p["algo"]["name"] == "sha256d":
                        jobs[p["slot"]] = (p["job"], bytes.fromhex(p["header"]),
                                           bytes.fromhex(p["target"]))
                r = v.get("result")
                if isinstance(r, dict) and "verdict" in r:
                    vd = r["verdict"]
                    if vd == "accepted":
                        accepted += 1
                    elif vd == "bad":
                        bad += 1
                    else:
                        other += 1
                break
        except socket.timeout:
            pass
        except (ValueError, OSError):
            pass

        if not jobs:
            time.sleep(0.2)
            continue

        slot = sorted(jobs)[0]
        job, header, target = jobs[slot]
        # A short burst, then sleep: `duty` is the fraction of a second spent
        # hashing, so 0.05 is one core at five percent.
        t0 = time.time()
        found = None
        while time.time() - t0 < duty:
            for _ in range(2000):
                nonce = (nonce + 1) & 0xFFFFFFFF
                h = header[:76] + struct.pack("<I", nonce)
                if below(sha256d(h), target):
                    found = nonce
                    break
            if found is not None:
                break
        if found is not None:
            send({"id": nid[0], "method": "glados.submit",
                  "params": {"job": job,
                             # Big-endian hex, not an integer. `proto::parse_share`
                             # wants a string and answers None otherwise, and a
                             # submit that will not parse is dropped with no reply
                             # -- so an integer here is a miner that mines
                             # perfectly and is never credited, silently.
                             "nonce": "%08x" % found, "echo": {}}})
            nid[0] += 1
        time.sleep(max(0.0, 1.0 - duty))

    try:
        s.close()
    except OSError:
        pass
    return accepted, bad, other, "cycled"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.66.66.1")
    ap.add_argument("--port", type=int, default=3334)
    ap.add_argument("--worker", default="soak")
    ap.add_argument("--hours", type=float, default=5.0)
    ap.add_argument("--cycle", type=float, default=300.0,
                    help="seconds per connection before reconnecting")
    ap.add_argument("--duty", type=float, default=0.05,
                    help="fraction of a second spent hashing")
    ap.add_argument("--log", default=os.path.expanduser(
        "~/.local/state/glados-pool/soakminer.log"))
    a = ap.parse_args()

    end = time.time() + a.hours * 3600
    tot_a = tot_b = tot_o = cycles = fails = 0
    with open(a.log, "a", buffering=1) as log:
        log.write("# soak start %s host=%s port=%d duty=%.2f cycle=%.0fs\n"
                  % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     a.host, a.port, a.duty, a.cycle))
        while time.time() < end:
            try:
                acc, bad, oth, why = run_once(a.host, a.port, a.worker, a.cycle, a.duty)
                tot_a += acc; tot_b += bad; tot_o += oth; cycles += 1
                log.write("%s cycle=%d accepted=%d bad=%d other=%d why=%s totals=%d/%d/%d\n"
                          % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             cycles, acc, bad, oth, why, tot_a, tot_b, tot_o))
            except Exception as e:
                fails += 1
                log.write("%s connect/run failed (%d so far): %s: %s\n"
                          % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             fails, type(e).__name__, str(e)[:120]))
                time.sleep(10)
        log.write("# soak done cycles=%d accepted=%d bad=%d other=%d failures=%d\n"
                  % (cycles, tot_a, tot_b, tot_o, fails))
    return 0


if __name__ == "__main__":
    sys.exit(main())
