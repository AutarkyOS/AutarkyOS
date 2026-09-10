#!/usr/bin/env python3
"""Ask the pool to refuse things, and check that it does.

Every bound in `server.rs` is a number in a comment until something has
actually gone past it. These are the four that were never driven:

  MAX_BAD             32 bad shares and the connection is dropped
  MAX_SUBMITS_PER_SEC 20 submits a second and the rest are ignored
  MAX_LINE            128 KiB without a newline desynchronises the stream
  MAX_CONNECTIONS     256 open connections and the next is refused

and the total validation budget, which is the only one of the five that is a
*pool-wide* bound rather than a per-connection one -- and therefore the only
one a reconnecting attacker cannot walk around.

Run against a throwaway instance on its own port with its own ledger. It sends
garbage on purpose and the share log it leaves behind is worthless.
"""
import argparse
import json
import socket
import sys
import threading
import time
from collections import Counter


class Conn:
    def __init__(self, host, port, worker, timeout=20.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        self.nid = 1
        self.worker = worker

    def send(self, obj):
        self.s.sendall((json.dumps(obj) + "\n").encode())
        self.nid += 1

    def hello(self, agent="abuse/1"):
        self.send({"id": self.nid, "method": "glados.hello",
                   "params": {"v": 1, "worker": self.worker, "agent": agent}})

    def line(self, timeout=None):
        """One line, or None at EOF. Raises socket.timeout if nothing comes."""
        if timeout is not None:
            self.s.settimeout(max(0.05, timeout))
        while b"\n" not in self.buf:
            b = self.s.recv(65536)
            if not b:
                return None
            self.buf += b
        i = self.buf.index(b"\n")
        out, self.buf = self.buf[:i], self.buf[i + 1:]
        return json.loads(out.decode(errors="replace"))

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def collect_jobs(c, want=1, timeout=8.0):
    """Read until `want` jobs have arrived. Returns {slot: (id, header, target)}."""
    jobs = {}
    end = time.time() + timeout
    while len(jobs) < want and time.time() < end:
        try:
            v = c.line(timeout=end - time.time())
        except socket.timeout:
            break
        if v is None:
            break
        if v.get("method") == "glados.job":
            p = v["params"]
            jobs[p["slot"]] = (p["job"], bytes.fromhex(p["header"]),
                               bytes.fromhex(p["target"]))
    return jobs


# ---------------------------------------------------------------- MAX_BAD

def t_badshares(a):
    """33 bad shares should end the connection, and the 33rd is the last."""
    c = Conn(a.host, a.port, "abuse-bad")
    c.hello()
    jobs = collect_jobs(c, want=1)
    if not jobs:
        return fail("no job arrived; is the pool serving a coin?")
    job = jobs[sorted(jobs)[0]][0]

    verdicts = []
    # Deliberately under MAX_SUBMITS_PER_SEC, so what ends this is the bad
    # counter and not the rate limit -- two bounds that would otherwise be
    # indistinguishable from the client side.
    for i in range(60):
        try:
            c.send({"id": c.nid, "method": "glados.submit",
                    "params": {"job": job, "nonce": "%08x" % (0xF0000000 + i), "echo": {}}})
        except OSError:
            break
        time.sleep(0.1)
        try:
            while True:
                v = c.line(timeout=0.4)
                if v is None:
                    c.close()
                    return report("MAX_BAD", verdicts, "connection dropped")
                r = v.get("result")
                if isinstance(r, dict) and "verdict" in r:
                    verdicts.append(r["verdict"])
                    break
        except socket.timeout:
            pass
        except OSError:
            c.close()
            return report("MAX_BAD", verdicts, "connection dropped")
    c.close()
    return report("MAX_BAD", verdicts, "never dropped")


# --------------------------------------------------- MAX_SUBMITS_PER_SEC

def t_ratelimit(a):
    """Sixty submits inside one second; twenty should be answered."""
    c = Conn(a.host, a.port, "abuse-rate")
    c.hello()
    jobs = collect_jobs(c, want=1)
    if not jobs:
        return fail("no job arrived")
    job = jobs[sorted(jobs)[0]][0]

    t0 = time.time()
    for i in range(60):
        c.send({"id": 1000 + i, "method": "glados.submit",
                "params": {"job": job, "nonce": "%08x" % (0xE0000000 + i), "echo": {}}})
    burst = time.time() - t0

    answered = []
    end = time.time() + 3.0
    while time.time() < end:
        try:
            v = c.line(timeout=end - time.time())
        except socket.timeout:
            break
        if v is None:
            break
        r = v.get("result")
        if isinstance(r, dict) and "verdict" in r:
            answered.append(v.get("id"))

    # Still alive? A rate limit that dropped the connection would be a
    # different (and worse) bound than the one the comment describes.
    alive = False
    try:
        c.send({"id": 9999, "method": "glados.work", "params": {"slot": 0}})
        end = time.time() + 4.0
        while time.time() < end:
            v = c.line(timeout=end - time.time())
            if v is None:
                break
            if v.get("method") == "glados.job":
                alive = True
                break
    except (socket.timeout, OSError):
        pass
    c.close()
    out({"test": "MAX_SUBMITS_PER_SEC", "cap": 20, "offered": 60,
         "burst_s": round(burst, 3), "answered": len(answered),
         "still_open": alive})
    return 0


# -------------------------------------------------------------- MAX_LINE

def t_bigline(a):
    """A quarter of a megabyte with no newline in it."""
    c = Conn(a.host, a.port, "abuse-line")
    c.hello()
    collect_jobs(c, want=1)
    sent = 0
    write_failed_at = None
    blob = b'{"method":"glados.submit","params":{"job":"' + b"A" * 65536
    try:
        for _ in range(4):
            c.s.sendall(blob)
            sent += len(blob)
            time.sleep(0.3)
    except OSError:
        write_failed_at = sent
    # Whether the write succeeded or not, the read side says whether the
    # server is done with us.
    eof = False
    try:
        v = c.line(timeout=5.0)
        eof = v is None
    except socket.timeout:
        eof = False
    except OSError:
        eof = True
    c.close()
    out({"test": "MAX_LINE", "max_line": 128 * 1024, "sent": sent,
         "write_failed_at": write_failed_at, "server_closed": eof})
    return 0


# ------------------------------------------------------- MAX_CONNECTIONS

def t_conns(a):
    """Open more connections than the ceiling and see where it lands."""
    conns = []
    welcomed = refused = errors = 0
    t0 = time.time()
    for i in range(a.n):
        try:
            c = Conn(a.host, a.port, "abuse-c%d" % i, timeout=8.0)
            c.hello()
            conns.append(c)
        except OSError:
            errors += 1
    opened = time.time() - t0

    # A refused connection is accepted and closed at once, so the tell is the
    # welcome rather than the connect.
    for c in conns:
        try:
            v = c.line(timeout=10.0)
            if v is None:
                refused += 1
            else:
                welcomed += 1
        except socket.timeout:
            errors += 1
        except OSError:
            refused += 1

    # Held open on purpose. The ceiling is a bound on *threads* as much as on
    # miners, and a run that opened and closed inside two seconds measured
    # nothing -- the first attempt sampled Threads: 2 throughout, which is not
    # a pool serving 256 connections, it is a sampler that missed the window.
    if a.hold > 0:
        time.sleep(a.hold)
    for c in conns:
        c.close()
    time.sleep(3.0)

    # And the count comes back down: a ceiling that leaked would refuse
    # everybody afterwards, which reads exactly like being under attack.
    recovered = False
    try:
        c = Conn(a.host, a.port, "abuse-after", timeout=10.0)
        c.hello()
        v = c.line(timeout=10.0)
        recovered = v is not None
        c.close()
    except OSError:
        pass
    out({"test": "MAX_CONNECTIONS", "ceiling": 256, "attempted": a.n,
         "welcomed": welcomed, "refused": refused, "connect_errors": errors,
         "open_s": round(opened, 2), "accepts_after": recovered})
    return 0


# ------------------------------------------------------------- the budget

def flood_worker(a, idx, stop, stats):
    """Reconnect-and-flood.

    MAX_BAD caps one connection at 33 validations, so the sustained cost an
    attacker can impose is per *connection* and nothing bounds how fast
    connections may be made. The total budget is the only thing left.
    """
    offered = answered = conns = 0
    while not stop.is_set():
        try:
            c = Conn(a.host, a.port, "abuse-flood%d" % idx, timeout=10.0)
            c.hello()
            jobs = collect_jobs(c, want=1, timeout=6.0)
            if not jobs:
                c.close()
                continue
            conns += 1
            job = jobs[sorted(jobs)[0]][0]
            n = 0
            dead = False
            while not stop.is_set() and n < 40 and not dead:
                for _ in range(20):
                    n += 1
                    offered += 1
                    c.send({"id": n, "method": "glados.submit",
                            "params": {"job": job,
                                       "nonce": "%08x" % (((idx << 24) ^ (n * 2654435761)) & 0xFFFFFFFF),
                                       "echo": {}}})
                t1 = time.time() + 1.05
                while time.time() < t1:
                    try:
                        v = c.line(timeout=t1 - time.time())
                    except socket.timeout:
                        break
                    if v is None:
                        dead = True
                        break
                    r = v.get("result")
                    if isinstance(r, dict) and "verdict" in r:
                        answered += 1
            c.close()
        except OSError:
            time.sleep(0.5)
    stats[idx] = (offered, answered, conns)


def t_flood(a):
    stop = threading.Event()
    stats = {}
    ts = [threading.Thread(target=flood_worker, args=(a, i, stop, stats))
          for i in range(a.conns)]
    t0 = time.time()
    for t in ts:
        t.start()
    time.sleep(a.seconds)
    stop.set()
    for t in ts:
        t.join(timeout=20)
    took = time.time() - t0
    off = sum(v[0] for v in stats.values())
    ans = sum(v[1] for v in stats.values())
    cn = sum(v[2] for v in stats.values())
    out({"test": "budget-flood", "threads": a.conns, "seconds": round(took, 1),
         "connections": cn, "offered": off, "answered": ans,
         "offered_per_s": round(off / took, 1),
         "answered_per_s": round(ans / took, 1)})
    return 0


def report(name, verdicts, note):
    out({"test": name, "cap": 32, "answered": len(verdicts),
         "verdicts": dict(Counter(verdicts)), "note": note})
    return 0


def out(d):
    print(json.dumps(d))


def fail(msg):
    out({"error": msg})
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3335)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("badshares")
    sub.add_parser("ratelimit")
    sub.add_parser("bigline")
    p = sub.add_parser("conns")
    p.add_argument("-n", type=int, default=300)
    p.add_argument("--hold", type=float, default=0.0,
                   help="seconds to hold every connection open before closing")
    p = sub.add_parser("flood")
    p.add_argument("--conns", type=int, default=6)
    p.add_argument("--seconds", type=float, default=30.0)
    a = ap.parse_args()
    return {"badshares": t_badshares, "ratelimit": t_ratelimit,
            "bigline": t_bigline, "conns": t_conns, "flood": t_flood}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
