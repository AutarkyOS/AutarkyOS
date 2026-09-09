#!/usr/bin/env python3
"""The oracle for yespower, and the reason the kernel's copy can be trusted.

yespower is what BitZeny, Yenten, Koto, WAVI, Veco and PRiVCY hash with, and
`src/mine/yespower.rs` implements it in ring 0. This is the same algorithm
written a second time, in a language with arbitrary-precision integers and no
unsafe blocks, so the two can be required to agree -- the bargain
`tokenizer.py --verify` and `manifest.py --verify` already make. Two
implementations that are supposed to agree do not stay agreeing on their own.

Transliterated from `yespower-ref.c` in <https://github.com/openwall/yespower>,
2-clause BSD, Copyright 2009 Colin Percival, Copyright 2012-2025 Alexander
Peslyak. The *reference* implementation and not `yespower-opt.c`, because
upstream says plainly that the reference exists to be a specification and the
optimised one exists to be used, and a specification is what an oracle needs.

**Not from cpuminer-opt**, which is GPL-2 and is where a search for this lands.
See `design/mining.md` for the rule.

    yespower.py --selftest        against upstream's own published vectors
    yespower.py --vectors         emit what src/mine/yespower.rs must say
    yespower.py --hash HEX ...    hash arbitrary input

The vectors in --selftest are upstream's TESTS-OK, not values this file
computed. A generator of expected values checked against itself is not checked.
"""

import argparse
import sys

import hashlib, hmac, struct

M32 = 0xFFFFFFFF
PWXsimple, PWXgather = 2, 4
PWXbytes = PWXgather * PWXsimple * 8   # 64
PWXwords = PWXbytes // 4               # 16


def rotl(a, b):
    return ((a << b) | (a >> (32 - b))) & M32


def salsa20(B, rounds):
    """B is a list of 16 u32, modified in place."""
    x = [0] * 16
    for i in range(16):
        x[i * 5 % 16] = B[i]
    for _ in range(0, rounds, 2):
        x[4] ^= rotl((x[0] + x[12]) & M32, 7);  x[8] ^= rotl((x[4] + x[0]) & M32, 9)
        x[12] ^= rotl((x[8] + x[4]) & M32, 13); x[0] ^= rotl((x[12] + x[8]) & M32, 18)
        x[9] ^= rotl((x[5] + x[1]) & M32, 7);   x[13] ^= rotl((x[9] + x[5]) & M32, 9)
        x[1] ^= rotl((x[13] + x[9]) & M32, 13); x[5] ^= rotl((x[1] + x[13]) & M32, 18)
        x[14] ^= rotl((x[10] + x[6]) & M32, 7); x[2] ^= rotl((x[14] + x[10]) & M32, 9)
        x[6] ^= rotl((x[2] + x[14]) & M32, 13); x[10] ^= rotl((x[6] + x[2]) & M32, 18)
        x[3] ^= rotl((x[15] + x[11]) & M32, 7); x[7] ^= rotl((x[3] + x[15]) & M32, 9)
        x[11] ^= rotl((x[7] + x[3]) & M32, 13); x[15] ^= rotl((x[11] + x[7]) & M32, 18)

        x[1] ^= rotl((x[0] + x[3]) & M32, 7);   x[2] ^= rotl((x[1] + x[0]) & M32, 9)
        x[3] ^= rotl((x[2] + x[1]) & M32, 13);  x[0] ^= rotl((x[3] + x[2]) & M32, 18)
        x[6] ^= rotl((x[5] + x[4]) & M32, 7);   x[7] ^= rotl((x[6] + x[5]) & M32, 9)
        x[4] ^= rotl((x[7] + x[6]) & M32, 13);  x[5] ^= rotl((x[4] + x[7]) & M32, 18)
        x[11] ^= rotl((x[10] + x[9]) & M32, 7); x[8] ^= rotl((x[11] + x[10]) & M32, 9)
        x[9] ^= rotl((x[8] + x[11]) & M32, 13); x[10] ^= rotl((x[9] + x[8]) & M32, 18)
        x[12] ^= rotl((x[15] + x[14]) & M32, 7); x[13] ^= rotl((x[12] + x[15]) & M32, 9)
        x[14] ^= rotl((x[13] + x[12]) & M32, 13); x[15] ^= rotl((x[14] + x[13]) & M32, 18)
    for i in range(16):
        B[i] = (B[i] + x[i * 5 % 16]) & M32


def blockmix_salsa(B, rounds):
    X = B[16:32]
    for i in range(2):
        for j in range(16):
            X[j] ^= B[i * 16 + j]
        salsa20(X, rounds)
        B[i * 16:i * 16 + 16] = X[:]


class Ctx:
    def __init__(self, version):
        self.version = version
        if version == 5:
            self.rounds, self.PWXrounds, self.Swidth = 8, 6, 8
            self.Sbytes = 2 * ((1 << 8) * PWXsimple * 8)
        else:
            self.rounds, self.PWXrounds, self.Swidth = 2, 3, 11
            self.Sbytes = 3 * ((1 << 11) * PWXsimple * 8)
        self.Smask = ((1 << self.Swidth) - 1) * PWXsimple * 8
        # S as a flat list of u32; S0/S1/S2 are *word* offsets into it.
        self.S = [0] * (self.Sbytes // 4)
        pairs = (1 << self.Swidth) * PWXsimple
        self.S0, self.S1, self.S2 = 0, pairs * 2, pairs * 4
        self.w = 0


def pwxform(X, ctx):
    """X is 16 u32, modified in place. Viewed as X[gather][simple][2]."""
    S, S0, S1 = ctx.S, ctx.S0, ctx.S1
    Smask, w = ctx.Smask, ctx.w
    for i in range(ctx.PWXrounds):
        for j in range(PWXgather):
            xl = X[j * 4 + 0]
            xh = X[j * 4 + 1]
            p0 = S0 + (xl & Smask) // 8 * 2
            p1 = S1 + (xh & Smask) // 8 * 2
            for k in range(PWXsimple):
                s0 = (S[p0 + k * 2 + 1] << 32) + S[p0 + k * 2]
                s1 = (S[p1 + k * 2 + 1] << 32) + S[p1 + k * 2]
                xl = X[j * 4 + k * 2 + 0]
                xh = X[j * 4 + k * 2 + 1]
                x = (xh * xl) & 0xFFFFFFFFFFFFFFFF
                x = (x + s0) & 0xFFFFFFFFFFFFFFFF
                x ^= s1
                X[j * 4 + k * 2 + 0] = x & M32
                X[j * 4 + k * 2 + 1] = (x >> 32) & M32
            if ctx.version != 5 and (i == 0 or j < PWXgather // 2):
                if j & 1:
                    for k in range(PWXsimple):
                        S[S1 + w * 2 + 0] = X[j * 4 + k * 2 + 0]
                        S[S1 + w * 2 + 1] = X[j * 4 + k * 2 + 1]
                        w += 1
                else:
                    for k in range(PWXsimple):
                        S[S0 + (w + k) * 2 + 0] = X[j * 4 + k * 2 + 0]
                        S[S0 + (w + k) * 2 + 1] = X[j * 4 + k * 2 + 1]
    if ctx.version != 5:
        ctx.S0, ctx.S1, ctx.S2 = ctx.S2, ctx.S0, ctx.S1
        ctx.w = w & ((1 << ctx.Swidth) * PWXsimple - 1)


def blockmix_pwxform(B, off, ctx, r):
    """B is a list; operate on B[off .. off + 32r]."""
    r1 = 128 * r // PWXbytes
    X = B[off + (r1 - 1) * PWXwords: off + r1 * PWXwords]
    for i in range(r1):
        if r1 > 1:
            for j in range(PWXwords):
                X[j] ^= B[off + i * PWXwords + j]
        pwxform(X, ctx)
        B[off + i * PWXwords: off + (i + 1) * PWXwords] = X[:]
    i = (r1 - 1) * PWXbytes // 64
    blk = B[off + i * 16: off + i * 16 + 16]
    salsa20(blk, ctx.rounds)
    B[off + i * 16: off + i * 16 + 16] = blk
    for i in range(i + 1, 2 * r):
        blk = B[off + i * 16: off + i * 16 + 16]
        for j in range(16):
            blk[j] ^= B[off + (i - 1) * 16 + j]
        salsa20(blk, ctx.rounds)
        B[off + i * 16: off + i * 16 + 16] = blk


def integerify(X, r):
    return X[(2 * r - 1) * 16]


def p2floor(x):
    y = x & (x - 1)
    while y:
        x = y
        y = x & (x - 1)
    return x


def wrap(x, i):
    n = p2floor(i)
    return (x & (n - 1)) + (i - n)


def smix1(B, r, N, V, Voff, X, ctx, use_salsa):
    s = 32 * r
    for k in range(2 * r):
        for i in range(16):
            X[k * 16 + i] = B[k * 16 + (i * 5 % 16)]
    if ctx.version != 5:
        for k in range(1, r):
            X[k * 32:(k + 1) * 32] = X[(k - 1) * 32:k * 32]
            blockmix_pwxform(X, k * 32, ctx, 1)
    for i in range(N):
        V[Voff + i * s: Voff + (i + 1) * s] = X[:s]
        if i > 1:
            j = wrap(integerify(X, r), i)
            for q in range(s):
                X[q] ^= V[Voff + j * s + q]
        if use_salsa:
            blockmix_salsa(X, ctx.rounds)
        else:
            blockmix_pwxform(X, 0, ctx, r)
    for k in range(2 * r):
        for i in range(16):
            B[k * 16 + (i * 5 % 16)] = X[k * 16 + i]


def smix2(B, r, N, Nloop, V, X, ctx):
    s = 32 * r
    for k in range(2 * r):
        for i in range(16):
            X[k * 16 + i] = B[k * 16 + (i * 5 % 16)]
    for _ in range(Nloop):
        j = integerify(X, r) & (N - 1)
        for q in range(s):
            X[q] ^= V[j * s + q]
        if Nloop != 2:
            V[j * s:(j + 1) * s] = X[:s]
        blockmix_pwxform(X, 0, ctx, r)
    for k in range(2 * r):
        for i in range(16):
            B[k * 16 + (i * 5 % 16)] = X[k * 16 + i]


def smix(B, r, N, V, X, ctx):
    Nloop_all = (N + 2) // 3
    Nloop_rw = Nloop_all
    Nloop_all += 1
    Nloop_all &= ~1
    if ctx.version == 5:
        Nloop_rw &= ~1
    else:
        Nloop_rw += 1
        Nloop_rw &= ~1
    # First smix1 fills the S-boxes, with V aliased to ctx.S and salsa blockmix.
    Xs = [0] * 32
    smix1(B, 1, ctx.Sbytes // 128, ctx.S, 0, Xs, ctx, True)
    smix1(B, r, N, V, 0, X, ctx, False)
    smix2(B, r, N, Nloop_rw, V, X, ctx)
    smix2(B, r, N, Nloop_all - Nloop_rw, V, X, ctx)


def yespower(src, version, N, r, pers=None):
    B_size = 128 * r
    ctx = Ctx(version)
    sha = hashlib.sha256(src).digest()
    if version != 5:
        salt = pers if pers else b""
    else:
        salt = src
    B_bytes = hashlib.pbkdf2_hmac("sha256", sha, salt, 1, B_size)
    B = list(struct.unpack("<%dI" % (B_size // 4), B_bytes))
    sha = struct.pack("<8I", *B[:8])
    V = [0] * (B_size // 4 * N)
    X = [0] * (B_size // 4)
    smix(B, r, N, V, X, ctx)
    Bb = struct.pack("<%dI" % (B_size // 4), *B)
    if version == 5:
        dst = hashlib.pbkdf2_hmac("sha256", sha, Bb, 1, 32)
        if pers:
            h = hmac.new(dst, pers, hashlib.sha256).digest()
            dst = hashlib.sha256(h).digest()
        return dst
    return hmac.new(Bb[B_size - 64:], sha, hashlib.sha256).digest()




# Upstream's own TESTS-OK, verbatim. The input is src[i] = i * 3 over 80 bytes,
# which is what tests.c hashes and is conveniently a block header's length.
# Version 5 is yespower 0.5 and version 10 is yespower 1.0.
UPSTREAM = [
    (5, 2048, 8, b"Client Key", "a59fec4c4fdda16e3b1405adda66d525b68e7cadfcfe6ac066c7ad118cd80590"),
    (5, 4096, 16, b"Client Key", "927e72d0ded3d80475473f40f1743c67289d453d5242d4f55af4e325e06699c5"),
    (5, 4096, 24, b"Jagaricoin", "0e1366973211e7fea8ad9d81989c84a254d968c9d333dd8ff099324f38611e04"),
    (5, 4096, 32, b"WaviBanana", "3ae05abb3c5cf6f75415a92554c98d50e38ec9552cfa78373616f480b24e559f"),
    (5, 2048, 32, b"Client Key", "560a891b5ca2e1c636111a9ff7c894a5d0a2602f43fdcfa5949b95e22fe4461e"),
    (5, 1024, 32, b"Client Key", "2a79e53d1be6669bc556ccc417bce3d22a74a232f56b8e1d39b45792675de108"),
    (5, 2048, 8, None, "5ecbd8e8d7c90baed4bbf8916a1225dcc3c65f5c9165bae81cdde3cffad128e8"),
    (10, 2048, 8, None, "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46"),
    (10, 4096, 16, None, "33fb8f063824a4a020f63dca535f5ca66ab5576468c75d1ccaac7542f76495ac"),
    (10, 4096, 32, None, "771aeefda8fe79a0825bc7f2aee162ab5578574639ffc6ca3723cc18e5e3e285"),
    (10, 2048, 32, None, "d5efb813cd263e9b34540130233cbbc6a921fbff3431e5ec1a1abde2aea6ff4d"),
    (10, 1024, 32, None, "501b792db42e388f6e7d453c95d03a12a36016a5154a688390ddc609a40c6799"),
    (10, 1024, 32, b"personality test",
     "1f0269acf565c49adc0ef9b8f26ab3808cdc38394a254fddeedcc3aacff6ad9d"),
]

# What the kernel asserts. The small parameter sets are here because the
# reference implementation is deliberately unoptimised and a boot selftest that
# takes seconds is one people stop reading -- the large ones live in `diag mine`
# instead. These are computed by this file, so they are only as good as
# --selftest above, which is the point of running that first.
KERNEL = [(10, 1024, 8, None), (5, 1024, 8, None), (10, 1024, 32, None)]


def test_input():
    return bytes((i * 3) & 0xFF for i in range(80))


def selftest():
    """This file against vectors it did not choose."""
    ok = True
    src = test_input()
    for ver, N, r, pers, want in UPSTREAM:
        got = yespower(src, ver, N, r, pers).hex()
        if got != want:
            ok = False
            print("  FAIL yespower(%d, %d, %d, %s)" % (
                ver, N, r, pers.decode() if pers else "NULL"))
            print("       got  %s" % got)
            print("       want %s" % want)
    print("yespower selftest: %s (%d upstream vector(s))"
          % ("ok" if ok else "FAILED", len(UPSTREAM)))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--vectors", action="store_true")
    ap.add_argument("--hash", nargs=4, metavar=("HEX", "VERSION", "N", "R"))
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1
    if a.vectors:
        src = test_input()
        print("// src[i] = i * 3, 80 bytes. Generated by tools/yespower.py --vectors.")
        for ver, N, r, pers in KERNEL:
            h = yespower(src, ver, N, r, pers)
            print("v%-3d N=%-5d r=%-3d %s" % (ver, N, r, h.hex()))
            print("    [%s]," % ", ".join("0x%02x" % b for b in h))
        return 0
    if a.hash:
        hexs, ver, N, r = a.hash
        print(yespower(bytes.fromhex(hexs), int(ver), int(N), int(r)).hex())
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
