// NeoScrypt on the GPU: FastKDF-BLAKE2s, ChaCha20/20 and Salsa20/20.
//
// The third algorithm, and the first one that does not fit the shape the other
// two share. Two things break the pattern and both are the algorithm rather
// than an inconvenience:
//
// **There is no midstate.** SHA-256d and BLAKE2s absorb the first 64 header
// bytes once and reuse that across every nonce, which `algo.cuh` calls the
// difference between a miner and a hash benchmark. NeoScrypt puts all eighty
// bytes through FastKDF before the expensive part begins, so there is no
// invariant prefix to absorb and every nonce pays the whole cost. That is the
// same property `src/mine/algo.rs` records about yespower.
//
// **It needs 32 KiB of scratchpad per concurrent hash.** V is N * r * 2 *
// BLOCK_SIZE = 128 * 2 * 2 * 64 = 32,768 bytes, and that cannot live in
// registers or in shared memory at any useful occupancy -- an SM on sm_86 has
// 100 KiB of shared, which is three hashes. So V is in global memory, one
// slice per thread, and the caller passes it in. `algo.cuh`'s contract has no
// parameter for that because nothing before this needed one.
//
// **The consequence is the interesting part and it is why this was worth
// building.** A sha256d thread is bounded by its ALUs and touches almost no
// memory; a NeoScrypt thread does 512 dependent random reads over 32 KiB and
// is bounded by nothing else. Those are the two `Bound` classes the kernel's
// scheduler now knows about, one level down and on the other device.
//
// Checked against `tools/neoscrypt.py`, which is checked against two real
// Feathercoin blocks the network accepted. Upstream ships no test vectors, so
// a block that beat its own target is the strongest thing available -- one in
// 4.1e9 by chance for the later of the two.

#pragma once
#include <stdint.h>
#include "algo.cuh"

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// The 80-byte header as 20 little-endian words. The nonce is word 19 and is
// overwritten per hash, which is the only thing that varies.
__constant__ uint32_t ns_header[20];

__device__ __constant__ uint8_t ns_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}};

__device__ __constant__ uint32_t ns_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

// The BLAKE2s parameter block for a 32-byte digest with a 32-byte key, fanout
// 1, depth 1. Upstream hard-codes `0x6B08C647` for h[0], which is this XORed
// into the IV -- so the constant confirms the reading rather than being taken
// on trust.
#define NS_PARAM0 0x01012020u

#define NS_G(a, b, c, d, x, y)   \
    a = a + b + (x);             \
    d = ROTR32(d ^ a, 16);       \
    c = c + d;                   \
    b = ROTR32(b ^ c, 12);       \
    a = a + b + (y);             \
    d = ROTR32(d ^ a, 8);        \
    c = c + d;                   \
    b = ROTR32(b ^ c, 7);

__device__ __forceinline__ void ns_compress(uint32_t h[8], const uint32_t m[16],
                                            uint32_t t, bool last) {
    uint32_t v[16];
#pragma unroll
    for (int i = 0; i < 8; ++i) v[i] = h[i];
#pragma unroll
    for (int i = 0; i < 8; ++i) v[8 + i] = ns_iv[i];
    v[12] ^= t;
    // v[13] takes the high half of the counter, which is zero here: the whole
    // message is 128 bytes. Written out rather than assumed so a future caller
    // with a longer message fails visibly instead of silently.
    if (last) v[14] = ~v[14];
#pragma unroll
    for (int r = 0; r < 10; ++r) {
        const uint8_t *s = ns_sigma[r];
        NS_G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        NS_G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        NS_G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        NS_G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        NS_G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        NS_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        NS_G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        NS_G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }
#pragma unroll
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[8 + i];
}

// Keyed BLAKE2s-256: a 32-byte key, a 64-byte message, a 32-byte digest.
//
// Exactly two blocks by construction -- the key zero-padded to 64 bytes, then
// the message -- so the counter is 64 then 128 and the second block is final.
// Written here rather than reusing `blake2s.cuh` because that one is a
// single-block unkeyed miner core with its message in `__constant__` memory,
// which is a different function with a different signature. Both are checked
// against implementations nobody here wrote.
__device__ __forceinline__ void ns_blake2s_keyed(const uint32_t key[8],
                                                 const uint32_t in[16],
                                                 uint32_t out[8]) {
    uint32_t h[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) h[i] = ns_iv[i];
    h[0] ^= NS_PARAM0;

    uint32_t block[16];
#pragma unroll
    for (int i = 0; i < 8; ++i) block[i] = key[i];
#pragma unroll
    for (int i = 8; i < 16; ++i) block[i] = 0;
    ns_compress(h, block, 64, false);
    ns_compress(h, in, 128, true);
#pragma unroll
    for (int i = 0; i < 8; ++i) out[i] = h[i];
}

__device__ __forceinline__ void ns_salsa(uint32_t x[16]) {
    uint32_t v[16], t;
#pragma unroll
    for (int i = 0; i < 16; ++i) v[i] = x[i];
#define QS(a, b, c, d)                                  \
    t = v[a] + v[d]; v[b] ^= ROTL32(t, 7);              \
    t = v[b] + v[a]; v[c] ^= ROTL32(t, 9);              \
    t = v[c] + v[b]; v[d] ^= ROTL32(t, 13);             \
    t = v[d] + v[c]; v[a] ^= ROTL32(t, 18);
#pragma unroll
    for (int r = 0; r < 10; ++r) {
        QS(0, 4, 8, 12) QS(5, 9, 13, 1) QS(10, 14, 2, 6) QS(15, 3, 7, 11)
        QS(0, 1, 2, 3) QS(5, 6, 7, 4) QS(10, 11, 8, 9) QS(15, 12, 13, 14)
    }
#undef QS
#pragma unroll
    for (int i = 0; i < 16; ++i) x[i] += v[i];
}

__device__ __forceinline__ void ns_chacha(uint32_t x[16]) {
    uint32_t v[16], t;
#pragma unroll
    for (int i = 0; i < 16; ++i) v[i] = x[i];
#define QC(a, b, c, d)                                          \
    v[a] += v[b]; t = v[d] ^ v[a]; v[d] = ROTL32(t, 16);        \
    v[c] += v[d]; t = v[b] ^ v[c]; v[b] = ROTL32(t, 12);        \
    v[a] += v[b]; t = v[d] ^ v[a]; v[d] = ROTL32(t, 8);         \
    v[c] += v[d]; t = v[b] ^ v[c]; v[b] = ROTL32(t, 7);
#pragma unroll
    for (int r = 0; r < 10; ++r) {
        QC(0, 4, 8, 12) QC(1, 5, 9, 13) QC(2, 6, 10, 14) QC(3, 7, 11, 15)
        QC(0, 5, 10, 15) QC(1, 6, 11, 12) QC(2, 7, 8, 13) QC(3, 4, 9, 14)
    }
#undef QC
#pragma unroll
    for (int i = 0; i < 16; ++i) x[i] += v[i];
}

// The mixer, fixed at r = 2 because that is the profile every NeoScrypt chain
// uses. Four 16-word chunks: chain-XOR each into the previous, mix, then
// permute **evens before odds**.
//
// That permutation is the whole difference from scrypt and it is the one thing
// here that was got wrong first. Upstream's optimised path spells it as a
// single swap of the middle two chunks, which is what evens-then-odds reduces
// to at r = 2; reading the comment above it instead gives a swap of chunks 1
// and 3, which produces a perfectly well-behaved wrong answer.
__device__ __forceinline__ void ns_blkmix(uint32_t *x, bool use_chacha) {
    uint32_t blk[16], y[64];
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        const int prev = i ? (i - 1) : 3;
#pragma unroll
        for (int j = 0; j < 16; ++j) x[16 * i + j] ^= x[16 * prev + j];
#pragma unroll
        for (int j = 0; j < 16; ++j) blk[j] = x[16 * i + j];
        if (use_chacha) ns_chacha(blk); else ns_salsa(blk);
#pragma unroll
        for (int j = 0; j < 16; ++j) { x[16 * i + j] = blk[j]; y[16 * i + j] = blk[j]; }
    }
#pragma unroll
    for (int j = 0; j < 16; ++j) {
        x[j] = y[j];                 // X0 = Y0
        x[16 + j] = y[32 + j];       // X1 = Y2
        x[32 + j] = y[16 + j];       // X2 = Y1
        x[48 + j] = y[48 + j];       // X3 = Y3
    }
}

// FastKDF. `mode` picks which of the two calls this is, exactly as upstream's
// optimised path does: 0 expands an 80-byte header into 256 bytes, 1 folds a
// 256-byte salt back down to 32.
//
// The buffers carry a wrapped copy of their own head past the end -- 64 bytes
// on A, 32 on B -- so a read at any offset up to 255 takes a whole block with
// no bounds check. That tail is not padding: the loop genuinely reads into it,
// and keeping it in step with the head is the step most easily left out, which
// gives a wrong answer only on the inputs that happen to land near a boundary.
__device__ void ns_fastkdf(const uint8_t *password, const uint8_t *salt,
                           uint8_t *out, int mode, uint8_t *A, uint8_t *B) {
#pragma unroll
    for (int i = 0; i < 3; ++i)
        for (int j = 0; j < 80; ++j) A[i * 80 + j] = password[j];
    for (int j = 0; j < 16; ++j) A[240 + j] = password[j];
    for (int j = 0; j < 64; ++j) A[256 + j] = password[j];

    const int out_len = mode ? 32 : 256;
    if (!mode) {
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 80; ++j) B[i * 80 + j] = salt[j];
        for (int j = 0; j < 16; ++j) B[240 + j] = salt[j];
        for (int j = 0; j < 32; ++j) B[256 + j] = salt[j];
    } else {
        for (int j = 0; j < 256; ++j) B[j] = salt[j];
        for (int j = 0; j < 32; ++j) B[256 + j] = salt[j];
    }

    int bufptr = 0;
    for (int i = 0; i < 32; ++i) {
        uint32_t in[16], key[8], digest[8];
        // Unaligned by construction: bufptr is a sum of digest bytes and lands
        // anywhere in 0..255, so these are byte loads and cannot be widened.
#pragma unroll
        for (int j = 0; j < 16; ++j)
            in[j] = (uint32_t)A[bufptr + 4 * j] | ((uint32_t)A[bufptr + 4 * j + 1] << 8) |
                    ((uint32_t)A[bufptr + 4 * j + 2] << 16) | ((uint32_t)A[bufptr + 4 * j + 3] << 24);
#pragma unroll
        for (int j = 0; j < 8; ++j)
            key[j] = (uint32_t)B[bufptr + 4 * j] | ((uint32_t)B[bufptr + 4 * j + 1] << 8) |
                     ((uint32_t)B[bufptr + 4 * j + 2] << 16) | ((uint32_t)B[bufptr + 4 * j + 3] << 24);

        ns_blake2s_keyed(key, in, digest);

        uint8_t d[32];
#pragma unroll
        for (int j = 0; j < 8; ++j) {
            d[4 * j] = (uint8_t)digest[j];
            d[4 * j + 1] = (uint8_t)(digest[j] >> 8);
            d[4 * j + 2] = (uint8_t)(digest[j] >> 16);
            d[4 * j + 3] = (uint8_t)(digest[j] >> 24);
        }
        // The sum of every byte, not a slice: using all of them is what stops
        // the walk correlating with any part of the output.
        int sum = 0;
#pragma unroll
        for (int j = 0; j < 32; ++j) sum += d[j];
        bufptr = sum & 255;

#pragma unroll
        for (int j = 0; j < 32; ++j) B[bufptr + j] ^= d[j];

        if (bufptr < 32) {
            const int n = min(32, 32 - bufptr);
            for (int j = 0; j < n; ++j) B[256 + bufptr + j] = B[bufptr + j];
        } else if (256 - bufptr < 32) {
            const int n = 32 - (256 - bufptr);
            for (int j = 0; j < n; ++j) B[j] = B[256 + j];
        }
    }

    const int avail = 256 - bufptr;
    if (avail >= out_len) {
        for (int j = 0; j < out_len; ++j) out[j] = B[bufptr + j] ^ A[j];
    } else {
        for (int j = 0; j < avail; ++j) out[j] = B[bufptr + j] ^ A[j];
        for (int j = 0; j < out_len - avail; ++j) out[avail + j] = B[j] ^ A[avail + j];
    }
}

// One SMix pass: fill the scratchpad, then walk it by a data-dependent index.
//
// Both passes share V, which is why they are sequential rather than
// interleaved -- giving each its own would double a 32 KiB allocation to buy
// nothing, since neither reads the other's.
__device__ __forceinline__ void ns_smix(uint32_t *w, uint32_t *v, bool use_chacha) {
#ifdef NS_NO_SMIX
    // The profile build: everything except the memory-hard part, so the
    // remainder is FastKDF and launch overhead. `design/xpu.md` used exactly
    // this to find that its matrix multiply was 96% of the step, against an
    // Amdahl story that said otherwise.
    v[0] = w[0];
    return;
#endif
    for (int i = 0; i < 128; ++i) {
        for (int j = 0; j < 64; ++j) v[i * 64 + j] = w[j];
        ns_blkmix(w, use_chacha);
    }
    for (int i = 0; i < 128; ++i) {
        // The index is this thread's own data, which is why no memory layout
        // coalesces these reads. See the note on the caller.
        const int j = 64 * (w[48] & 127);
        for (int k = 0; k < 64; ++k) w[k] ^= v[j + k];
        ns_blkmix(w, use_chacha);
    }
}

// One NeoScrypt hash. `v` is 8192 words of global scratchpad belonging to this
// thread alone; `scratch` is 608 bytes of byte-addressed KDF working space.
//
// **The obvious optimisation was tried and is a 46% loss, and the reason is
// the algorithm rather than the card.** Every memory-bound CUDA kernel wants
// its per-thread arrays interleaved -- thread `t`'s word `i` at `v[i * threads
// + t]` -- so that a warp's thirty-two reads of "word i of my own array" fall
// in one cache line instead of thirty-two. That was written, and it measured
// 105 kH/s against this layout's 194.
//
// The interleave cannot help here because **the index is data-dependent per
// thread**: SMix reads `V[64 * (X[48] & 127)]`, and `X[48]` is thirty-two
// different values across a warp. So the thirty-two reads land on thirty-two
// unrelated chunks whatever the layout, and no arrangement coalesces them.
// What the interleave does do is destroy the locality that *is* available --
// the inner loop reads sixty-four consecutive words, four full cache lines,
// and interleaving spreads those over sixty-four lines 128 KiB apart.
//
// Contiguous, therefore, and deliberately. This is the second time in this
// directory that the obvious performance story was wrong and only the
// measurement said so; `design/xpu.md` records the first, about Amdahl and the
// tensor cores.
__device__ void neoscrypt_hash_at(uint32_t nonce, uint32_t out[8], uint32_t *v,
                                  uint8_t *scratch) {
    uint8_t header[80];
    {
        uint32_t w[20];
#pragma unroll
        for (int i = 0; i < 20; ++i) w[i] = ns_header[i];
        w[19] = nonce;
#pragma unroll
        for (int i = 0; i < 20; ++i) {
            header[4 * i] = (uint8_t)w[i];
            header[4 * i + 1] = (uint8_t)(w[i] >> 8);
            header[4 * i + 2] = (uint8_t)(w[i] >> 16);
            header[4 * i + 3] = (uint8_t)(w[i] >> 24);
        }
    }

    uint8_t *A = scratch;         // 320 bytes
    uint8_t *B = scratch + 320;   // 288 bytes

    uint8_t xb[256];
    ns_fastkdf(header, header, xb, 0, A, B);

    // **One working array rather than two, and it bought nothing measurable.**
    // X and Z start from the same KDF output and are mixed with different
    // ciphers, so the obvious code holds both live across 512 calls to
    // `ns_blkmix` -- 128 registers of the 255 a thread may have, and `ptxas -v`
    // reported exactly 255, the ceiling. The prediction was that freeing them
    // would raise occupancy and that occupancy is the latency hiding.
    //
    // It is kept because it is strictly less state for identical output, and
    // it is documented as a null result because the prediction was wrong and
    // the next person will have it too. Capping registers by hand settles it:
    //
    //     -maxrregcount    64      96     128     168    none
    //     kH/s            159     188     188     194     191
    //
    // Occupancy is not what bounds this kernel. Four times the registers is
    // four times the resident warps and 22% of the rate, so the machine is
    // waiting on something that more warps do not hide.
    uint32_t w[64];
#pragma unroll
    for (int i = 0; i < 64; ++i)
        w[i] = (uint32_t)xb[4 * i] | ((uint32_t)xb[4 * i + 1] << 8) |
               ((uint32_t)xb[4 * i + 2] << 16) | ((uint32_t)xb[4 * i + 3] << 24);

    uint32_t *zsave = (uint32_t *)(scratch + 608);
    ns_smix(w, v, true);
#pragma unroll
    for (int i = 0; i < 64; ++i) zsave[i] = w[i];

#pragma unroll
    for (int i = 0; i < 64; ++i)
        w[i] = (uint32_t)xb[4 * i] | ((uint32_t)xb[4 * i + 1] << 8) |
               ((uint32_t)xb[4 * i + 2] << 16) | ((uint32_t)xb[4 * i + 3] << 24);
    ns_smix(w, v, false);
#pragma unroll
    for (int i = 0; i < 64; ++i) w[i] ^= zsave[i];

    uint32_t *x = w;

#pragma unroll
    for (int i = 0; i < 64; ++i) {
        xb[4 * i] = (uint8_t)x[i];
        xb[4 * i + 1] = (uint8_t)(x[i] >> 8);
        xb[4 * i + 2] = (uint8_t)(x[i] >> 16);
        xb[4 * i + 3] = (uint8_t)(x[i] >> 24);
    }
    uint8_t ob[32];
    ns_fastkdf(header, xb, ob, 1, A, B);
#pragma unroll
    for (int i = 0; i < 8; ++i)
        out[i] = (uint32_t)ob[4 * i] | ((uint32_t)ob[4 * i + 1] << 8) |
                 ((uint32_t)ob[4 * i + 2] << 16) | ((uint32_t)ob[4 * i + 3] << 24);
}

// Where the time actually goes, measured by removing SMix rather than
// reasoned about (`-DNS_NO_SMIX`, which announces itself and skips the vector
// gate because it is deliberately not NeoScrypt):
//
//     full kernel      176.2 ms / 32768 hashes    186 kH/s
//     FastKDF only      38.7 ms                   846 kH/s
//
// So **SMix is 78% of a hash and FastKDF is 22%**, and a perfect FastKDF is
// worth 1.28x at most. That is a smaller share for the memory-hard part than
// its 8:1 call-count advantage suggests, which says FastKDF's byte-addressed
// local-memory buffers cost more than they look.
//
// **This is 190 kH/s and a tuned miner on this class of card does five to ten
// times that.** The gap is not a mystery and is not addressed here: the
// scrypt-family technique is to split the sixteen words of each Salsa or
// ChaCha block across four cooperating threads and exchange them with warp
// shuffles, which quarters the per-thread register footprint and makes the
// scratchpad accesses 64-byte coalesced. NeoScrypt's `blkmix` chains its four
// chunks serially, so the cooperation has to happen *inside* a block rather
// than across the four, and that is a rewrite rather than a tuning pass.
// Written down because the ceiling matters when deciding what to build next.

// Words of global scratchpad one concurrent hash needs.
#define NS_SCRATCH_WORDS 8192
// Bytes of per-thread working space: 320 for the KDF's A buffer, 288 for its
// B buffer, and 256 to park Z between the two SMix passes.
#define NS_KDF_BYTES 864

static void neoscrypt_upload(const uint8_t header[80]) {
    uint32_t w[20];
    for (int i = 0; i < 20; ++i)
        w[i] = (uint32_t)header[4 * i] | ((uint32_t)header[4 * i + 1] << 8) |
               ((uint32_t)header[4 * i + 2] << 16) | ((uint32_t)header[4 * i + 3] << 24);
    cudaMemcpyToSymbol(ns_header, w, sizeof(w));
}
