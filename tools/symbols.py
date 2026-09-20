"""Turn the linker's map into a symbol table the kernel can read at a fault.

    cargo build --release                      # emits target/glados.map
    python tools/symbols.py target/glados.map --emit src/cpu/symbols.rs

### Why this exists

A fault reporter that prints `rva 0xaa013` has said everything it knows and
nothing anybody can act on. Turning that offset into a function name took a
second computer, the `.efi`, and `llvm-objdump` -- on a machine whose entire
diagnostic channel is a framebuffer with no serial port. The first bare-metal
boot on the GF63 cost exactly that, for a one-line bug.

So the names travel with the kernel. `rva 0xaa013` becomes
`dev::power::hwp_range +0x13`, which is a sentence somebody can act on without
leaving the room.

### Provenance, and why a map rather than the PDB

The `.efi` is stripped: its COFF symbol table has four entries. A 41 MB PDB is
produced beside it, and parsing PDB in Python would be a project. `lld-link`
takes MSVC's `/MAP` and writes a plain text table of every public symbol with
its `Rva+Base`, which is the same information for none of the effort. Same
bargain `tools/rtlconv.py` and `tools/doominfo.py` make: extract rather than
retype, and state where it came from.

### The demangler is a heuristic and says so

Rust's v0 mangling is a grammar, and a complete demangler for it is a real
piece of work. What a fault report needs is much less: the path components, so
a person knows which file to open. This walks the length-prefixed runs and
joins them, which is exact for plain functions and approximate for impl methods
on generic types -- `Governor::parse` comes back as `power::Governor::parse`,
while a deeply generic instantiation may come back with a component missing.

**It never invents a name.** Anything it cannot parse is emitted mangled, which
is ugly and correct, rather than pretty and wrong. A fault report that names
the wrong function is worse than one that names none.
"""

import argparse
import io
import os
import re
import sys

# A crate disambiguator: `Cs` then a base-62 hash then `_`. Always noise here.
DISAMBIG = re.compile(r"Cs[0-9A-Za-z]{8,}_")
# A back-reference to an earlier path, `B` then optional base-62 then `_`.
# Left in place these are read as length-prefixed components and produce
# components like `_8` in the middle of a real name.
BACKREF = re.compile(r"B[0-9a-zA-Z]*_")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def demangle(sym):
    """Path components of a v0 symbol, joined. See the module note."""
    if not sym.startswith("_R"):
        # C symbols and the hand-written assembly entry points, which are
        # already the name somebody would search for.
        return sym
    s = BACKREF.sub("", DISAMBIG.sub("", sym))
    out, i, n = [], 2, len(s)
    while i < n:
        if s[i].isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            ln = int(s[i:j])
            if ln and j + ln <= n and IDENT.match(s[j:j + ln]):
                out.append(s[j:j + ln])
                i = j + ln
                continue
            i = j
        else:
            i += 1
    if not out:
        return sym
    # The crate name leads every path and says nothing: every symbol in this
    # table is in this kernel.
    if out[0] == "glados" and len(out) > 1:
        out = out[1:]
    return "::".join(out)


def parse_map(path):
    """`(rva, name)` for every public symbol, sorted, deduplicated by address.

    The `Publics by Value` section is what is wanted; the section table above it
    has the same shape and would otherwise be read as symbols at address zero.
    """
    rows = []
    started = False
    with io.open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Publics by Value" in line:
                started = True
                continue
            if not started:
                continue
            parts = line.split()
            # ` 0001:00000000  <name>  0000000140001000  <lib:object>`
            if len(parts) < 3 or ":" not in parts[0]:
                continue
            try:
                addr = int(parts[2], 16)
            except ValueError:
                continue
            rows.append((addr, parts[1]))
    if not rows:
        raise SystemExit("no 'Publics by Value' rows in %s -- is this a /MAP file?" % path)
    rows.sort()
    # One entry per address. Aliases at the same address are the same code, and
    # a fault can only be in one of them.
    out, last = [], None
    for addr, name in rows:
        if addr != last:
            out.append((addr, name))
            last = addr
    return out


def emit(path, base, rows, stamp=0):
    names, offsets, blob = [], [], 0
    for _, sym in rows:
        d = demangle(sym)
        names.append(d)
        offsets.append(blob)
        blob += len(d)

    # FNV-1a over what the table actually says. See BUILD_STAMP's note: the
    # linker timestamp cannot answer "which table produced this name", because
    # it changes on every link and belongs to the pass before this one.
    h = 0x811C9DC5
    for (addr, _), name in zip(rows, names):
        for b in ("%x" % (addr - base)).encode() + name.encode():
            h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    stamp = h

    L = []
    a = L.append
    a("//! Function names by address, generated. Do not edit.")
    a("//!")
    a("//! Emitted by `tools/symbols.py` from the linker's `/MAP` output, which")
    a("//! is produced by the `link-arg=/MAP` in `.cargo/config.toml`. The")
    a("//! image itself is stripped -- its COFF symbol table has four entries --")
    a("//! so this is the only way a fault report can name the function it is in.")
    a("//!")
    a("//! **Sorted by address, and `lookup` binary-searches it.** A fault")
    a("//! handler runs with interrupts off on a machine that is about to halt,")
    a("//! so this allocates nothing and takes no lock.")
    a("//!")
    a("//! Names are demangled by a heuristic that is exact for plain functions")
    a("//! and approximate for impl methods on generic types. Anything that")
    a("//! would not parse is left mangled rather than guessed at.")
    a("")
    a("/// Identifies this symbol table, and therefore the code layout it describes.")
    a("///")
    a("/// **Printed beside a resolved name, because a table is only valid for its")
    a("/// own build.** An rva photographed off one machine and resolved against a")
    a("/// later image names whatever now lives at that offset, confidently and")
    a("/// wrongly -- which happened twice while building this: 0xaa013 was")
    a("/// `dev::power::hwp_range` before a one-line fix and `mine::checks` after.")
    a("///")
    a("/// A hash of the table's own contents rather than the linker's timestamp.")
    a("/// The timestamp was the first attempt and it cannot work: every link")
    a("/// produces a new one, so the value never converges, and the table is")
    a("/// generated from the map of the *previous* link -- so it named a build")
    a("/// that was not the one running. Hashing the contents means two builds of")
    a("/// the same code carry the same stamp, which is the question being asked.")
    a("pub const BUILD_STAMP: u32 = 0x%X;" % stamp)
    a("")
    a("/// Where the image was linked to load. An address below this is not ours.")
    a("pub const IMAGE_BASE: u64 = 0x%X;" % base)
    a("")
    a("/// `(rva, offset into NAMES, length)`, ascending by rva.")
    a("pub static SYMBOLS: &[(u32, u32, u16)] = &[")
    for (addr, _), off, name in zip(rows, offsets, names):
        a("    (0x%X, %d, %d)," % (addr - base, off, len(name)))
    a("];")
    a("")
    a("pub static NAMES: &str = \"%s\";" % "".join(names).replace("\\", "\\\\").replace("\"", "\\\""))
    a("")
    io.open(path, "w", encoding="utf-8", newline="\n").write("\n".join(L))
    return blob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("map", nargs="?", default="target/glados.map")
    ap.add_argument("--emit", help="where to write the Rust table")
    ap.add_argument("--lookup", help="resolve one address or rva, for checking")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    rows = parse_map(a.map)
    base = 0x140000000
    with io.open(a.map, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Preferred load address" in line:
                base = int(line.split()[-1], 16)
                break

    if a.lookup is not None:
        want = int(a.lookup, 16)
        if want < base:
            want += base
        best = None
        for addr, sym in rows:
            if addr <= want:
                best = (addr, sym)
            else:
                break
        if best is None:
            print("below every symbol")
            return 1
        print("%s +0x%x" % (demangle(best[1]), want - best[0]))
        return 0

    print("%d symbol(s), base 0x%X" % (len(rows), base))
    stamp = 0
    with io.open(a.map, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Timestamp is" in line:
                try:
                    stamp = int(line.split()[2], 16)
                except (IndexError, ValueError):
                    stamp = 0
                break

    if a.emit:
        blob = emit(a.emit, base, rows, stamp)
        size = os.path.getsize(a.emit)
        print("names %d bytes, table %d bytes, source %d bytes -> %s"
              % (blob, len(rows) * 10, size, a.emit))
    return 0


def selftest():
    fails = 0

    def claim(cond, what):
        nonlocal fails
        print(("ok    " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    claim(demangle("_RNvNtCs1nq6ahSYcz8_6glados4mine6checks") == "mine::checks",
          "a plain function demangles to its path")
    claim(demangle("_RNvNtNtCs1nq6ahSYcz8_6glados3dev5power9hwp_range")
          == "dev::power::hwp_range",
          "and so does the one that faulted on the GF63")
    claim(demangle("_RNvMNtNtCs1nq6ahSYcz8_6glados3dev5powerNtB2_8Governor5parse")
          == "dev::power::Governor::parse",
          "an impl method keeps its type, the backref having been stripped")
    claim(demangle("ap_tramp_start") == "ap_tramp_start",
          "a hand-written assembly symbol is left alone")
    # The honesty claim: something this cannot parse comes back mangled rather
    # than as a plausible wrong answer.
    claim(demangle("_RQQQnonsense") == "_RQQQnonsense",
          "and something unparseable is left mangled rather than guessed at")
    claim(demangle("_R") == "_R", "an empty body does not panic")

    print("\n%s" % ("selftest passed" if fails == 0 else "%d FAILED" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
