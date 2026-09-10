"""Drive the pool's roster refusal for real, over a socket.

    python tools/poolroster.py [path-to-glados-pool]

Four names against one running pool: an unregistered nickname, a registered
one, the same name in capitals with a rig suffix, and a bare 0x address.

**The last is the one worth watching.** It must be admitted with no roster
lookup at all, because an address-shaped name is its own payout address and
that is the rule `tools/distribute.py` pays on. If those two rules drift, the
pool admits names the distributor cannot pay -- which is the silent loss the
roster exists to prevent, arriving by another route.

The refusal path cannot be reached from `--selftest`: `roster::checks` is pure
functions over a struct, and what this adds is that a refusal actually reaches
a socket, carrying the registration URL, before any work is done.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

DEFAULT = os.path.join("pool", "target", "release",
                       "glados-pool.exe" if os.name == "nt" else "glados-pool")
EXE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
if not os.path.exists(EXE):
    print("no pool binary at %s" % EXE, file=sys.stderr)
    print("build one, or pass the path:", file=sys.stderr)
    print("  cargo build --release --manifest-path pool/Cargo.toml", file=sys.stderr)
    sys.exit(2)

WORK = tempfile.mkdtemp(prefix="poolroster-")
ROSTER = os.path.join(WORK, "roster.json")
PORT = int(os.environ.get("POOLROSTER_PORT", "45599"))
REGISTER = "https://pool.example/register"

# The document `/worker/map` serves. Written in that shape rather than as a
# flat file so this exercises the parser the real deployment uses.
json.dump({"workers": {"alice": "0x00000000000000000000000000000000000000aa"},
           "updated_at": {"alice": "2026-09-01T00:00:00Z"}},
          open(ROSTER, "w"))

proc = subprocess.Popen(
    [EXE, "--listen", "127.0.0.1:%d" % PORT, "--roster", ROSTER,
     "--roster-url", REGISTER, "--require-roster"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
time.sleep(2.5)


def greet(name):
    """One connection, one `glados.hello`, one line of answer.

    A fresh socket per name because the pool holds one worker per connection
    on purpose -- re-greeting under a second name is its own refusal, and
    reusing the socket here would test that instead of this.
    """
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    msg = json.dumps({"id": 1, "method": "glados.hello",
                      "params": {"v": 1, "worker": name, "agent": "poolroster"}})
    s.sendall((msg + "\n").encode())
    s.settimeout(4)
    buf = b""
    try:
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.close()
    return buf.decode(errors="replace").split("\n")[0]


fails = 0


def claim(cond, what):
    global fails
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        fails += 1


# A welcome carries `"error":null`, so "no error" is not a substring test for
# the absence of the word. Getting that wrong reported three passing cases as
# failures the first time this ran.
r = greet("mallory")
claim('"error":"' in r and "no payout address" in r,
      "an unregistered name is refused at the greeting")
claim(REGISTER in r, "and the refusal says where to register")

claim('"error":null' in greet("alice") , "a registered name is welcomed")
claim('"error":null' in greet("ALICE.rig4"),
      "and so is the same name in capitals with a rig suffix")
claim('"error":null' in greet("0x00000000000000000000000000000000000000bb"),
      "an address is welcomed without being in the roster at all")

proc.terminate()
try:
    out, _ = proc.communicate(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()
    out = ""

print("\n--- pool log ---")
for line in (out or "").splitlines():
    if "roster" in line or "refused" in line or "hello" in line:
        print(" ", line)

print("\n%s" % ("roster drive passed" if fails == 0 else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
