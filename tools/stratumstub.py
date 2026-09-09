#!/usr/bin/env python3
"""A Stratum V1 server that exists to be wrong at the kernel in controlled ways.

Pointing the miner at a real pool to test it has two problems: the pool decides
what shapes it sends, so the cases worth testing are the ones it happens not to
produce, and a client that is wrong submits garbage to somebody else's server.
This is the `mkelf.py` bargain -- a fixture that differs from the positive case
in exactly one field, which no real server will produce on request.

    stratumstub.py                       serve one session on :3333 and exit
    stratumstub.py --port 3333 --forever stay up across reconnects
    stratumstub.py --flat                a flat subscribe result, not nested
    stratumstub.py --difficulty 0.001    the fractional case that reads as 0
    stratumstub.py --short-notify        eight parameters, which must be refused

Under QEMU the guest reaches the host at 10.0.2.2, so:

    mine pool 10.0.2.2:3333
"""

import argparse
import hashlib
import json
import socket
import sys
import time

# Block 125552's own fields, so the kernel's job parsing is checked against the
# same block its header claims already use. prevhash is in stratum word order.
PREV = "ab02cd818b9e567ee21793cddef299feb29ad444a41b85b8000008a300000000"
VERSION = "00000001"
NBITS = "1a44b9f2"
NTIME = "4dd7f5c7"

# A real coinbase transaction, split around the extranonce the way a pool
# splits it. The halves are chosen so coinb1 + extranonce1 + extranonce2 +
# coinb2 is a transaction that parses exactly to its last byte, because the
# kernel's expected-value block reads the block subsidy out of the coinbase
# outputs rather than from a hardcoded constant that would go stale across a
# halving -- and a coinbase that is not a transaction makes it omit the line.
#
# The script length byte accounts for the eight extranonce bytes that land in
# the middle, which is the one field that has to agree with EXTRANONCE2_SIZE.
COINB1 = ("0100000001" + "00" * 32 + "ffffffff" + "10" + "03010203")
COINB2 = "040a0b0cffffffff0200f2052a0100000001514e61bc0000000000026a0000000000"
# 50.12345678, so a reader can tell it apart from a plain 50 that might have
# come from somewhere else.
COINB_VALUE = 5012345678
EXTRANONCE1 = "08000002"
EXTRANONCE2_SIZE = 4


def send(conn, obj):
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    conn.sendall(line.encode())
    print("  -> %s" % line.strip(), flush=True)


def serve_one(conn, args):
    conn.settimeout(60)
    buf = b""
    subscribed = False
    while True:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            print("  (timeout waiting for the client)", flush=True)
            return
        except OSError as e:
            # The guest going away is the ordinary end of a driven test, not a
            # failure of the stub. Reporting it as a traceback loses the log.
            print("  (connection reset: %s)" % e, flush=True)
            return
        if not chunk:
            print("  (client closed)", flush=True)
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            print("  <- %s" % line.decode(errors="replace"), flush=True)
            try:
                msg = json.loads(line)
            except ValueError:
                print("  !! not JSON", flush=True)
                continue
            method = msg.get("method")
            mid = msg.get("id")

            if method == "mining.subscribe":
                if args.flat:
                    # The shape that breaks a parser which walks result[0].
                    result = ["deadbeef", "1a2b3c4d", 8]
                else:
                    result = [
                        [["mining.set_difficulty", "b4b6"], ["mining.notify", "ae6812"]],
                        EXTRANONCE1,
                        EXTRANONCE2_SIZE,
                    ]
                send(conn, {"id": mid, "result": result, "error": None})
                subscribed = True

            elif method == "mining.authorize":
                send(conn, {"id": mid, "result": True, "error": None})
                # Difficulty and the first job go out *before* some pools answer
                # authorize, and always after. Sending them here checks that the
                # client does not discard notifications while awaiting an id.
                send(conn, {"id": None, "method": "mining.set_difficulty",
                            "params": [args.difficulty]})
                params = ["job1", PREV, COINB1, COINB2, branch_hex(args),
                          VERSION, NBITS, NTIME, True]
                if args.short_notify:
                    params = params[:8]
                send(conn, {"id": None, "method": "mining.notify", "params": params})

            elif method == "mining.submit":
                if not args.verify:
                    # Accept nothing. In this mode the stub is only for the
                    # connection path, and a share it accepted would be a share
                    # nobody checked.
                    send(conn, {"id": mid, "result": None,
                                "error": [21, "Job not found", None]})
                    continue

                # Verify it, which is a different thing from accepting it and is
                # the whole reason this mode exists.
                #
                # The stub sent coinb1, coinb2, the branch and the extranonce1;
                # the client sends back extranonce2, ntime and the nonce. That
                # is everything, so the header can be rebuilt here from an
                # implementation that shares no code with the one under test --
                # this is Python and hashlib against Rust. A pool that assembles
                # a header wrongly produces shares that are perfectly valid
                # arithmetic about a block that does not exist, and nothing but
                # a second implementation catches it.
                try:
                    _w, jid, e2h, ntimeh, nonceh = msg["params"][:5]
                    ok, why = verify_share(jid, e2h, ntimeh, nonceh, args)
                except Exception as exc:               # noqa: BLE001
                    ok, why = False, "malformed submit: %s" % exc
                if ok:
                    print("  share verified: %s" % why, flush=True)
                    send(conn, {"id": mid, "result": True, "error": None})
                else:
                    print("  share REFUSED: %s" % why, flush=True)
                    send(conn, {"id": mid, "result": None,
                                "error": [23, why, None]})

            elif method is not None:
                send(conn, {"id": mid, "result": None,
                            "error": [20, "Unsupported method", None]})

        if subscribed and args.hangup_after_subscribe:
            print("  (hanging up on purpose)", flush=True)
            return


def swap_words(b):
    """The prevhash transform: eight words keep their order, each one flips.

    Not a whole-string reversal and not a no-op, which are the two things
    somebody writes instead. `src/mine/header.rs` has the same table and this
    is deliberately a separate expression of it.
    """
    out = bytearray(32)
    for w in range(8):
        for i in range(4):
            out[w * 4 + i] = b[w * 4 + 3 - i]
    return bytes(out)


def d2(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def verify_share(jid, e2h, ntimeh, nonceh, args):
    """Rebuild the header from what we sent plus what came back, and hash it."""
    if jid != "job1":
        return False, "unknown job %r" % jid
    e2 = bytes.fromhex(e2h)
    if len(e2) != EXTRANONCE2_SIZE:
        return False, ("extranonce2 is %d bytes, this pool asked for %d"
                       % (len(e2), EXTRANONCE2_SIZE))

    coinbase = (bytes.fromhex(COINB1) + bytes.fromhex(EXTRANONCE1)
                + e2 + bytes.fromhex(COINB2))
    root = d2(coinbase)
    for sib in branch_bytes(args):
        root = d2(root + sib)

    # `mining.submit` sends ntime and nonce big-endian; the header holds them
    # little-endian. Reversing here rather than reinterpreting is the same rule
    # `submit_hex` follows in the other direction.
    header = (bytes.fromhex(VERSION)[::-1]
              + swap_words(bytes.fromhex(PREV))
              + root
              + bytes.fromhex(ntimeh)[::-1]
              + bytes.fromhex(NBITS)[::-1]
              + bytes.fromhex(nonceh)[::-1])
    if len(header) != 80:
        return False, "rebuilt header is %d bytes" % len(header)

    digest = d2(header)
    # Displayed reversed, the way a block id is shown everywhere.
    shown = digest[::-1].hex()

    # The stub's own target, from the difficulty it announced. diff-1 is
    # 0x00000000FFFF << 208, which is the number every Bitcoin-family pool
    # divides.
    diff1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    target = int(diff1 / float(args.difficulty))
    value = int.from_bytes(digest[::-1], "big")
    if value > target:
        return False, "hash %s does not meet difficulty %s" % (shown[:16], args.difficulty)
    return True, "%s meets difficulty %s" % (shown[:16], args.difficulty)


def branch_bytes(args):
    """The merkle branch this stub advertises, as bytes.

    Non-empty when asked for, because an empty branch never runs the fold loop
    at all -- so a client whose fold is wrong passes every test built on the
    default. `algocheck.py` makes the same point about its eleven-leaf tree.
    """
    return [bytes.fromhex(h) for h in branch_hex(args)]


def branch_hex(args):
    if args.branch <= 0:
        return []
    # Derived rather than random, so two runs of the stub agree and a failure is
    # reproducible. Nothing about these has to be a real transaction: a merkle
    # branch is 32-byte siblings and the fold does not care where they came from.
    return [hashlib.sha256(b"glados stub branch %d" % i).hexdigest()
            for i in range(args.branch)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3333)
    ap.add_argument("--difficulty", default="1",
                    help="sent verbatim, so 0.001 really is a JSON number")
    ap.add_argument("--flat", action="store_true")
    ap.add_argument("--short-notify", action="store_true")
    ap.add_argument("--hangup-after-subscribe", action="store_true")
    ap.add_argument("--forever", action="store_true")
    ap.add_argument("--branch", type=int, default=0,
                    help="emit a merkle branch this many levels deep; an empty "
                         "one never runs the fold loop at all")
    ap.add_argument("--verify", action="store_true",
                    help="rebuild each submitted header here and check its hash, "
                         "so accepting a share means something")
    args = ap.parse_args()

    # The difficulty must reach the wire as a number and not a string, or the
    # kernel's Json::Num branch is never exercised.
    try:
        args.difficulty = json.loads(args.difficulty)
    except ValueError:
        print("difficulty must be a JSON number", file=sys.stderr)
        return 2

    s = socket.socket()
    # **No SO_REUSEADDR.** On Windows that flag does not mean "reuse a socket in
    # TIME_WAIT", it means a second process may bind a port the first is still
    # listening on, and connections then go to whichever the stack feels like.
    # Six of these accumulated during one session and the guest kept reaching an
    # old one with a different difficulty, which read as the kernel ignoring a
    # set_difficulty it had actually never been sent. Failing to bind is the
    # correct outcome and it is loud.
    try:
        s.bind(("0.0.0.0", args.port))
    except OSError as e:
        print("cannot bind :%d -- is another stub still running? (%s)"
              % (args.port, e), file=sys.stderr)
        return 2
    s.listen(4)
    print("stratum stub on :%d, difficulty %r" % (args.port, args.difficulty), flush=True)
    while True:
        conn, addr = s.accept()
        print("session from %s:%d" % addr, flush=True)
        try:
            serve_one(conn, args)
        finally:
            conn.close()
        if not args.forever:
            return 0
        time.sleep(0.1)


if __name__ == "__main__":
    sys.exit(main())
