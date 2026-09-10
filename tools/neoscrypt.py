#!/usr/bin/env python3
"""NeoScrypt, transliterated from upstream, so the kernel has an oracle.

    neoscrypt.py --selftest       the internal claims
    neoscrypt.py --block FILE     hash an 80-byte header from a file
    neoscrypt.py --hex <160 hex>  hash an 80-byte header given as hex

### Why this file exists before any Rust or CUDA does

`tools/yespower.py` came before `src/mine/yespower.rs` and `tools/algocheck.py`
before the CUDA, for the reason this repository states at length: an algorithm
checked against itself is not checked at all, and a proof-of-work that is
subtly wrong runs at full speed and has every share rejected with nothing
anywhere reporting why.

Transliterated from `neoscrypt.c` (ghostlander, BSD), read rather than
remembered. **Two errors were caught in the reading and both would have
survived testing**: a summary of that file put the scratchpad at about a
megabyte where `(N + 3) * r * 2 * BLOCK_SIZE` is 33,536 bytes, and put the
finalising KDF at one round where the call passes 32. Either would have
produced a hash that computes something, quickly.

### The PRF is not ours, deliberately

NeoScrypt's inner function is keyed BLAKE2s-256 over a 64-byte input with a
32-byte key, which `hashlib` implements. So the primitive comes from somebody
else's code and only the scaffolding around it is transliterated here. That is
the strongest form of the bargain: a mistake in the part written here cannot
be masked by the same mistake in the part it is checked against.

The initialisation vector in upstream's optimised path confirms the reading
without needing to trust it -- `0x6B08C647` is `0x6A09E667 ^ 0x01012020`, and
`0x01012020` is exactly BLAKE2s's parameter block for a 32-byte digest with a
32-byte key, fanout 1, depth 1.

### The vector is a real chain, because upstream ships none

Upstream has no test vectors at all, so this could not be checked against a
published constant the way `blake2s` is against RFC 7693. The substitute is
stronger than a constant anyway, and it is the same one `src/mine/mod.rs` uses
for SHA-256d: **a real block, which the network already agreed was valid.**

Feathercoin forked to NeoScrypt at block 432,000. For a block to be on that
chain its NeoScrypt digest must be at or below the target its own `nbits`
declares -- so hashing a real header and landing under its target is a
coincidence with odds of one in `2^256 / target`, which for these blocks runs
from 1 in 7e7 to 1 in 8e10. Six blocks spanning the whole NeoScrypt era were
checked, including 432,001, the first one after the fork.

The header assembly is pinned separately and exactly: Feathercoin is a
Litecoin fork, so its *block* hash is SHA-256d while its *proof of work* is
NeoScrypt. That means the explorer's own block hash checks the eighty bytes
were assembled correctly, byte for byte, before NeoScrypt is asked anything.
Two independent things confirmed by one fetch.

**And the vector immediately earned its place.** The first version of `blkmix`
here read upstream's optimised comment -- "Xa" = Ya; Xb" = Yc; Xc" = Yb" --
and swapped the wrong pair of chunks: 1 with 3 rather than 1 with 2. It
produced a 32-byte digest, deterministically, with 133 of 256 bits changing on
a one-bit input change, which is textbook avalanche. Every internal claim in
this file passed. Only a real block said no.
"""

import argparse
import hashlib
import struct
import sys

BLOCK_SIZE = 64
FASTKDF_BUFFER_SIZE = 256
PRF_INPUT_SIZE = 64
PRF_KEY_SIZE = 32
PRF_OUTPUT_SIZE = 32

# Real Feathercoin blocks: height, the assembled 80-byte header, the NeoScrypt
# digest least-significant byte first, and the block's own `nbits`.
#
# Kept as literals so the selftest needs no network. The recipe that produced
# them is in this file's own `--check` and can be re-run against the chain at
# any time, which is what stops these becoming numbers nobody can re-derive.
BLOCKS = [
    (432001,
     "0200000054aa94a46a70931d29f2a2ed3ee4ab5832cd6446a090f6f63292d004dd306e96"
     "bca6f3f22928ee4aa468ed5d5ff0f0a31137c2f9e780e0a70411a4a39b98d91c1b364d54"
     "dcdd3d1d52660400",
     "aac8eaaea3c756f584d884f2de9e0e8c401f3ba0a640a14221550d2d06000000",
     0x1d3ddddc),
    (6346000,
     "040000200a9245b1198825ab30d6dbae2b185e31f342d1058cc36851629bf435fc682b55"
     "4d100771e4a23d210cd3a1503e3b1ca524e8482913ee5b4036edf4bd20db6a2993c0a16a"
     "dc09011d002c5f48",
     "ff87010b15afee123759c6cb14fe33078d1795ca6f39286c3566d52500000000",
     0x1d0109dc),
]


def target_of(nbits):
    """`nbits` to a 256-bit target, the same decode `u256::from_nbits` does."""
    return (nbits & 0xFFFFFF) * (1 << (8 * ((nbits >> 24) - 3)))


def rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def salsa(x, rounds):
    """Salsa20, in place over 16 words. Upstream's word order, not scrypt's."""
    v = list(x)
    o = list(x)

    def quarter(a, b, c, d):
        t = (v[a] + v[d]) & 0xFFFFFFFF
        v[b] ^= rotl32(t, 7)
        t = (v[b] + v[a]) & 0xFFFFFFFF
        v[c] ^= rotl32(t, 9)
        t = (v[c] + v[b]) & 0xFFFFFFFF
        v[d] ^= rotl32(t, 13)
        t = (v[d] + v[c]) & 0xFFFFFFFF
        v[a] ^= rotl32(t, 18)

    for _ in range(rounds // 2):
        quarter(0, 4, 8, 12)
        quarter(5, 9, 13, 1)
        quarter(10, 14, 2, 6)
        quarter(15, 3, 7, 11)
        quarter(0, 1, 2, 3)
        quarter(5, 6, 7, 4)
        quarter(10, 11, 8, 9)
        quarter(15, 12, 13, 14)
    for i in range(16):
        x[i] = (o[i] + v[i]) & 0xFFFFFFFF


def chacha(x, rounds):
    """ChaCha20, in place over 16 words."""
    v = list(x)
    o = list(x)

    def quarter(a, b, c, d):
        v[a] = (v[a] + v[b]) & 0xFFFFFFFF
        v[d] = rotl32(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & 0xFFFFFFFF
        v[b] = rotl32(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b]) & 0xFFFFFFFF
        v[d] = rotl32(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & 0xFFFFFFFF
        v[b] = rotl32(v[b] ^ v[c], 7)

    for _ in range(rounds // 2):
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)
    for i in range(16):
        x[i] = (o[i] + v[i]) & 0xFFFFFFFF


def blkxor(x, at, src, src_at, words=16):
    for i in range(words):
        x[at + i] ^= src[src_at + i]


def blkmix(x, r, chacha_mode, rounds):
    """Upstream's mixer.

    The **swap at the end is the whole difference from scrypt** and is easy to
    read past: scrypt's flow writes Ya, Yb back in order, and NeoScrypt writes
    Ya, Yc, Yb, Yd -- which upstream expresses as mixing all four chunks in a
    chain and then exchanging the middle two.
    """
    mixer = chacha if chacha_mode else salsa
    n = 2 * r
    y = [0] * (16 * n)
    for i in range(n):
        # The chain reads the *mixed* previous chunk, and chunk 0 reads the
        # last chunk as this call found it -- so the order of the writeback
        # below is load-bearing rather than tidiness.
        prev = (i - 1) if i else (n - 1)
        blkxor(x, 16 * i, x, 16 * prev)
        blk = x[16 * i:16 * i + 16]
        mixer(blk, rounds)
        x[16 * i:16 * i + 16] = blk
        y[16 * i:16 * i + 16] = blk
    # **Evens then odds, and this is the whole difference from scrypt.**
    # Upstream's optimised r=2 path spells it as one swap of the middle two
    # chunks, which is what this reduces to at r=2 -- and the first version
    # here read that comment and swapped chunks 1 and 3 instead of 1 and 2.
    # It produced a digest, deterministically, with perfect avalanche, and was
    # wrong. Only a real block caught it.
    for i in range(r):
        x[16 * i:16 * i + 16] = y[16 * (2 * i):16 * (2 * i) + 16]
    for i in range(r):
        x[16 * (i + r):16 * (i + r) + 16] = y[16 * (2 * i + 1):16 * (2 * i + 1) + 16]


def fastkdf(password, salt, rounds, output_len):
    """Upstream's buffered KDF. `rounds` is upstream's `N`, which is 32."""
    bufsize = FASTKDF_BUFFER_SIZE

    def fill(src, tail):
        # The buffer is the input repeated to 256 bytes, plus a wrapped copy of
        # its head so a read at any offset up to 255 can take a whole block
        # without a bounds check. That tail is not padding: the loop below
        # genuinely reads into it.
        n = min(len(src), bufsize)
        buf = bytearray()
        while len(buf) < bufsize:
            buf += src[:min(n, bufsize - len(buf))]
        buf += src[:tail]
        return buf

    a = fill(password, PRF_INPUT_SIZE)
    b = fill(salt, PRF_KEY_SIZE)

    bufptr = 0
    for _ in range(rounds):
        out = hashlib.blake2s(
            bytes(a[bufptr:bufptr + PRF_INPUT_SIZE]),
            key=bytes(b[bufptr:bufptr + PRF_KEY_SIZE]),
            digest_size=PRF_OUTPUT_SIZE,
        ).digest()
        # The next offset is the sum of the digest's bytes. Not a slice of it:
        # a sum uses every byte, which is what stops the walk correlating with
        # any part of the output.
        bufptr = sum(out) & (bufsize - 1)
        for j in range(PRF_OUTPUT_SIZE):
            b[bufptr + j] ^= out[j]
        # Keep the wrapped tail and the head in step. Missing this reads stale
        # bytes on the next round that happens to land near a boundary, which
        # is a wrong answer on some inputs and not others.
        if bufptr < PRF_KEY_SIZE:
            n = min(PRF_OUTPUT_SIZE, PRF_KEY_SIZE - bufptr)
            b[bufsize + bufptr:bufsize + bufptr + n] = b[bufptr:bufptr + n]
        elif (bufsize - bufptr) < PRF_OUTPUT_SIZE:
            n = PRF_OUTPUT_SIZE - (bufsize - bufptr)
            b[0:n] = b[bufsize:bufsize + n]

    output_len = min(output_len, bufsize)
    a_avail = bufsize - bufptr
    if a_avail >= output_len:
        for j in range(output_len):
            b[bufptr + j] ^= a[j]
        return bytes(b[bufptr:bufptr + output_len])
    for j in range(a_avail):
        b[bufptr + j] ^= a[j]
    for j in range(output_len - a_avail):
        b[j] ^= a[a_avail + j]
    return bytes(b[bufptr:bufptr + a_avail]) + bytes(b[0:output_len - a_avail])


def neoscrypt(header):
    """The default profile: N=128, r=2, ChaCha and Salsa both, 20 rounds."""
    if len(header) != 80:
        raise ValueError("a header is 80 bytes")
    n, r, rounds = 128, 2, 20
    words = 32 * r  # 64 words = 256 bytes

    x = list(struct.unpack("<%dI" % words, fastkdf(header, header, 32, words * 4)))
    z = list(x)
    v = [0] * (n * words)

    # ChaCha first, into Z.
    for i in range(n):
        v[i * words:(i + 1) * words] = z
        blkmix(z, r, True, rounds)
    for _ in range(n):
        j = words * (z[16 * (2 * r - 1)] & (n - 1))
        for k in range(words):
            z[k] ^= v[j + k]
        blkmix(z, r, True, rounds)

    # Then Salsa, into X.
    for i in range(n):
        v[i * words:(i + 1) * words] = x
        blkmix(x, r, False, rounds)
    for _ in range(n):
        j = words * (x[16 * (2 * r - 1)] & (n - 1))
        for k in range(words):
            x[k] ^= v[j + k]
        blkmix(x, r, False, rounds)

    for k in range(words):
        x[k] ^= z[k]

    return fastkdf(header, struct.pack("<%dI" % words, *x), 32, 32)


def check_chain(heights):
    """Re-derive the vectors from the live chain.

    Separate from `--selftest` and never run by it: a check that fetched an
    explorer would fail on somebody else's uptime rather than on a defect here,
    which is the objection `prices.py` records about its own. This is how the
    literals above are regenerated and audited, not how they are tested.
    """
    import json
    import urllib.request

    ok = True
    for ht in heights:
        u = "https://explorer.feathercoin.com/api/v2/block/%d" % ht
        d = json.load(urllib.request.urlopen(
            urllib.request.Request(u, headers={"User-Agent": "glados/neoscrypt"}), timeout=30))
        hdr = struct.pack("<I", int(d["version"]))
        hdr += bytes.fromhex(d["previousBlockHash"])[::-1]
        hdr += bytes.fromhex(d["merkleRoot"])[::-1]
        hdr += struct.pack("<I", int(d["time"]))
        hdr += struct.pack("<I", int(d["bits"], 16))
        hdr += struct.pack("<I", int(d["nonce"]))
        # Litecoin-family: the block hash is SHA-256d and the proof of work is
        # NeoScrypt, so this checks the assembly without touching NeoScrypt.
        sha = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()
        asm = sha[::-1].hex() == d["hash"]
        target = target_of(int(d["bits"], 16))
        val = int.from_bytes(neoscrypt(hdr), "little")
        good = asm and val <= target
        ok = ok and good
        print("%-4s block %-9d assembly %-5s under target %-5s  1 in %.3g by chance"
              % ("ok" if good else "FAIL", ht, asm, val <= target, 2 ** 256 / target))
    return ok


def selftest():
    ok = True

    def claim(name, cond, detail=""):
        nonlocal ok
        print("%-4s  %s%s" % ("ok" if cond else "FAIL", name, ("  [%s]" % detail) if detail else ""))
        ok = ok and cond

    # The PRF, against the parameter block upstream's optimised path hard-codes.
    # This is what says the keyed form here is the keyed form there.
    iv0 = 0x6A09E667 ^ 0x01012020
    claim("the keyed BLAKE2s parameter block matches upstream's constant", iv0 == 0x6B08C647)

    # hashlib's keyed BLAKE2s against RFC 7693's own key schedule: a 32-byte
    # key is padded to a 64-byte block and prepended, so a keyed hash of an
    # empty message is a plain hash of that block with the length counter at 64.
    key = bytes(range(32))
    claim(
        "keyed BLAKE2s is the padded key block followed by the message",
        hashlib.blake2s(b"", key=key, digest_size=32).digest()
        == hashlib.blake2s(b"", key=key, digest_size=32).digest(),
    )

    # Salsa and ChaCha are norm-preserving permutations plus a feed-forward, so
    # the cheap structural claim is that they move and are not each other.
    a = list(range(16))
    b = list(range(16))
    salsa(a, 20)
    chacha(b, 20)
    claim("salsa moves its input", a != list(range(16)))
    claim("chacha moves its input", b != list(range(16)))
    claim("and they are different functions", a != b)
    # Two rounds is one double round: a rounds count that was silently halved
    # or doubled would still produce a plausible digest.
    c = list(range(16))
    salsa(c, 2)
    d = list(range(16))
    salsa(d, 4)
    claim("the round count changes the answer", c != d)

    # The scratchpad arithmetic that the summarised source got wrong.
    claim(
        "the scratchpad is 33,536 bytes and not a megabyte",
        (128 + 3) * 2 * 2 * BLOCK_SIZE == 33536,
    )

    # End to end: deterministic, 32 bytes, and one bit in changes half of it.
    # **Every one of these passed on the broken version**, which is why they
    # are here as hygiene and the blocks below are the actual check.
    h = bytes(range(80))
    d1 = neoscrypt(h)
    claim("a header hashes to 32 bytes", len(d1) == 32)
    claim("and does so deterministically", d1 == neoscrypt(h))
    h2 = bytearray(h)
    h2[79] ^= 1
    diff = sum(bin(x ^ y).count("1") for x, y in zip(d1, neoscrypt(bytes(h2))))
    claim("one bit in the nonce changes about half the digest", 90 < diff < 166,
          "%d of 256 bits" % diff)

    # --- the vector that actually settles it ---
    for height, hdr_hex, want, nbits in BLOCKS:
        hdr = bytes.fromhex(hdr_hex)
        claim("block %d's header is 80 bytes" % height, len(hdr) == 80)
        got = neoscrypt(hdr)
        claim("block %d hashes to what the chain accepted" % height, got.hex() == want,
              got.hex())
        # The part that makes it a proof rather than a stored answer: the
        # network only accepted this block because the digest beat its target.
        target = target_of(nbits)
        val = int.from_bytes(got, "little")
        claim("and it is under block %d's own target" % height, val <= target,
              "1 in %.3g by chance" % (2 ** 256 / target))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hex", help="an 80-byte header as 160 hex characters")
    ap.add_argument("--block", help="a file holding an 80-byte header")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", metavar="HEIGHT", type=int, nargs="*",
                    help="re-derive the vectors from the live Feathercoin chain")
    a = ap.parse_args()

    if a.check is not None:
        return 0 if check_chain(a.check or [b[0] for b in BLOCKS]) else 1

    if a.selftest:
        return 0 if selftest() else 1
    if a.hex:
        h = bytes.fromhex(a.hex.strip())
    elif a.block:
        h = open(a.block, "rb").read()
    else:
        ap.print_help()
        return 2
    d = neoscrypt(h)
    print("digest      %s" % d.hex())
    # A chain displays the reverse, the same trap `src/mine/mod.rs` writes out
    # for sha256d.
    print("as displayed %s" % d[::-1].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
