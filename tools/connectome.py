#!/usr/bin/env python3
"""Fetch the C. elegans connectome and flatten it into one file the kernel can index.

Why this animal, and why this is the honest version of "integrate a brain"
--------------------------------------------------------------------------
There is no dataset you can download that is a healthy human brain in any sense
a kernel could run. A human structural scan is diffusion MRI: millimetre voxels
and statistically-inferred fibre bundles, not neurons and not synapses, and no
project has ever traced one human's synaptic wiring -- the largest mapped human
fragment as of 2024 is a cubic millimetre. "Integrate a human brain" is not a
scoping question, it is a category error, and this tool does not pretend
otherwise.

What *does* exist, complete, is one nervous system, mapped synapse by synapse:
Caenorhabditis elegans, the hermaphrodite, 302 neurons and roughly 7,000
connections, first traced by White et al. (1986) and reconstructed since. It is
the only connectome of a whole animal that is finished, it is public, and it is
small enough to live in a kernel heap as an ordinary graph. So this is the
real, runnable form of the idea: not a metaphorical brain but an actual, entire
one, at the only scale where "the wiring diagram, complete" is a fact rather
than an aspiration.

What the kernel would do with it is a separate, unbuilt question (see
docs/connectome.md). This tool's job is only to turn the published edge list
into a compact, self-describing file, and to check it read back exactly.

Source
------
OpenWorm's ConnectomeToolbox, `cect/data/herm_full_edgelist.csv`, which is the
Cook/White hermaphrodite edge list as columns Source,Target,Weight,Type. The
data is the community's, not ours; its provenance is in that repository.

Usage
-----
    python tools/connectome.py esp/AUTARK/connectome.bin
    python tools/connectome.py esp/AUTARK/connectome.bin --verify
    python tools/connectome.py out/c.bin --src path/to/herm_full_edgelist.csv

The GLADOSXN format, defined here and nowhere else yet
-----------------------------------------------------
Little-endian throughout.

    magic     8   b"GLADOSXN"
    version   u32 = 1
    n_nodes   u32
    n_edges   u32
    reserved  u32 = 0
    names         n_nodes x (u8 length + ASCII bytes), in id order
    edges         n_edges x (u32 src, u32 dst, u16 weight, u8 kind)
                  kind: 0 = chemical synapse, 1 = electrical gap junction

Node ids are the index into the sorted, de-duplicated set of names, so a name's
id is a function of the data and not of file order -- the same property the
namespace's zero-padded blob names buy, and for the same reason: a later run
must land on the same ids or the edges point at different neurons.

Like tools/v4.py, the reader walks and never seeks and asserts it lands on the
last byte, because a body with no internal lengths turns one wrong field into
valid-looking garbage for everything after it.
"""

import argparse
import struct
import sys
import urllib.request
from pathlib import Path

MAGIC = b"GLADOSXN"
VERSION = 1
DEFAULT_URL = (
    "https://raw.githubusercontent.com/openworm/ConnectomeToolbox/"
    "main/cect/data/herm_full_edgelist.csv"
)


def load_edges(csv_text):
    """Parse Source,Target,Weight,Type rows into (src, dst, weight, kind).

    Names carry trailing spaces in the source file; they are stripped, because
    'I2L' and 'I2L    ' are one neuron and treating them as two would split its
    degree in half and invent a node.
    """
    edges = []
    lines = csv_text.splitlines()
    header = [c.strip().lower() for c in lines[0].split(",")]
    try:
        si, ti, wi, ki = (
            header.index("source"),
            header.index("target"),
            header.index("weight"),
            header.index("type"),
        )
    except ValueError:
        raise SystemExit(f"unexpected header: {header!r}")

    for ln in lines[1:]:
        if not ln.strip():
            continue
        cols = ln.split(",")
        src = cols[si].strip()
        dst = cols[ti].strip()
        weight = int(cols[wi].strip())
        kind_s = cols[ki].strip().lower()
        if not src or not dst:
            continue
        # chemical vs electrical is the one distinction the wiring makes and the
        # dynamics care about: a gap junction is bidirectional and a synapse is
        # not, so the kind is kept rather than flattened to a plain edge.
        kind = 1 if kind_s.startswith("electr") or "gap" in kind_s else 0
        edges.append((src, dst, weight, kind))
    return edges


def build(edges):
    """Edges over names -> (sorted names, edges over integer ids)."""
    names = sorted({n for e in edges for n in (e[0], e[1])})
    idx = {n: i for i, n in enumerate(names)}
    idedges = [(idx[s], idx[d], w, k) for (s, d, w, k) in edges]
    return names, idedges


def write(path, names, idedges):
    out = bytearray()
    out += MAGIC
    out += struct.pack("<IIII", VERSION, len(names), len(idedges), 0)
    for n in names:
        b = n.encode("ascii")
        if len(b) > 255:
            raise SystemExit(f"neuron name too long: {n!r}")
        out += struct.pack("<B", len(b)) + b
    for (s, d, w, k) in idedges:
        # Synapse counts fit u16 with room to spare; the densest pair in the
        # data is well under a hundred. Assert rather than truncate.
        if w > 0xFFFF:
            raise SystemExit(f"weight {w} overflows u16")
        out += struct.pack("<IIHB", s, d, w & 0xFFFF, k)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(out)
    return len(out)


def verify(path):
    """Walk the file the way the kernel loader must, and land on the last byte.

    A separate reader from the writer on purpose: a writer and reader that share
    a bug agree with each other and disagree with reality. This one only knows
    the format, not the data that produced it.
    """
    b = Path(path).read_bytes()
    if b[:8] != MAGIC:
        raise SystemExit("bad magic")
    version, n_nodes, n_edges, reserved = struct.unpack_from("<IIII", b, 8)
    if version != VERSION:
        raise SystemExit(f"version {version}, expected {VERSION}")
    off = 24
    names = []
    for _ in range(n_nodes):
        ln = b[off]
        off += 1
        names.append(b[off : off + ln].decode("ascii"))
        off += ln
    edges = []
    for _ in range(n_edges):
        s, d, w, k = struct.unpack_from("<IIHB", b, off)
        off += 11
        if s >= n_nodes or d >= n_nodes:
            raise SystemExit(f"edge references node {max(s, d)} of {n_nodes}")
        edges.append((s, d, w, k))
    if off != len(b):
        raise SystemExit(f"walked to {off} of {len(b)} -- the format is out of step")
    return names, edges


def summarise(names, idedges):
    chem = sum(1 for e in idedges if e[3] == 0)
    elec = len(idedges) - chem
    deg = [0] * len(names)
    for (s, d, _w, _k) in idedges:
        deg[s] += 1
        deg[d] += 1
    top = sorted(range(len(names)), key=lambda i: deg[i], reverse=True)[:8]
    print(f"  {len(names)} neurons, {len(idedges)} connections "
          f"({chem} chemical, {elec} electrical)")
    print("  most-connected neurons:")
    for i in top:
        print(f"    {names[i]:<8} degree {deg[i]}")


def main():
    ap = argparse.ArgumentParser(description="Fetch and flatten the C. elegans connectome.")
    ap.add_argument("out", help="output .bin path")
    ap.add_argument("--src", help="local edge-list CSV instead of downloading")
    ap.add_argument("--url", default=DEFAULT_URL, help="edge-list URL")
    ap.add_argument("--verify", action="store_true", help="read the written file back and check it")
    args = ap.parse_args()

    if args.src:
        csv_text = Path(args.src).read_text(encoding="utf-8")
        print(f"  read {args.src}")
    else:
        print(f"  fetching {args.url}")
        with urllib.request.urlopen(args.url, timeout=60) as r:
            csv_text = r.read().decode("utf-8")

    edges = load_edges(csv_text)
    names, idedges = build(edges)
    size = write(args.out, names, idedges)
    print(f"  wrote {args.out}  {size:,} B")
    summarise(names, idedges)

    if args.verify:
        vn, ve = verify(args.out)
        ok = vn == names and ve == idedges
        print("  verify: " + ("read back byte-exact" if ok else "MISMATCH"))
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
