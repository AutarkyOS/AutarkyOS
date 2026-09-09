// The GPU as a pool worker: take a job, scan nonces, report what was found.
//
// `miner.cu` beside this is a *benchmark* harness -- it hashes one fixed
// vector as fast as it can and prints a rate. This takes work from somewhere
// else, which is a different program even though the kernel is the same one.
//
// ### It is driven over a pipe, and does not speak the pool's protocol
//
// The obvious thing would be to put a socket and a JSON parser in here. That
// would be the *fourth* implementation of `design/pool.md`'s protocol -- the
// kernel's `src/mine/proto.rs`, the pool which includes that same file, and
// `tools/poolclient.py` are the other three -- and a protocol is exactly where
// a second implementation is most expensive and hardest to see wrong.
//
// So the protocol stays in Rust, in `miner/`, which includes `proto.rs` by
// `#[path]` like the pool does. This process speaks four words on stdin and
// two on stdout. That handshake is internal, has no other implementers, and is
// small enough to read in one screen:
//
//     <- ready
//     -> job <header-160-hex> <target-64-hex>
//     <- ok
//     -> scan <base-8-hex> <count-decimal>
//     <- found <nonce-8-hex>        or  none <hashes-decimal>
//     -> quit
//
// ### sha256d only, and that is a finding rather than a shortcut
//
// `blake2s.cuh` exists and is fast and is **not** a miner. It hashes a single
// 64-byte block with a nonce at word 15, verified against hashlib -- correct
// for what it computes, and not what a blake2s chain computes, which is an
// 80-byte header across two blocks with a length counter. Its verify digest
// matches neither the header hash nor the header's first block, which is how
// this was noticed.
//
// Shipping it as a pool algorithm would have produced shares at half a
// gigahash a second that are wrong, and `algo.cuh`'s own header says why that
// is the worst available outcome: a fast wrong hash is indistinguishable from
// a fast right one from the inside. Extending it to two blocks is real work
// and is not done here.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

#include "algo.cuh"
#include "sha256d.cuh"

// The target, most significant word first. Its own symbol rather than
// `sha256d.cuh`'s, because that header ships a fixed benchmark target and this
// one changes with every job.
__constant__ uint32_t xTarget[8];

__device__ __forceinline__ bool xpu_below(const uint32_t h[8]) {
    return below_target_be(h, xTarget);
}

// Nonces per thread. Two, which is what `design/xpu.md` measured: widening the
// instruction-level parallelism past that bought nothing on this part, and the
// reason is in that file.
#define NPT 2

__global__ void xpu_scan_kernel(uint32_t base, uint32_t *found) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t n0 = base + idx * NPT;
    uint32_t h[NPT][8];
#pragma unroll
    for (int j = 0; j < NPT; ++j) sha256d_hash(n0 + j, h[j]);
#pragma unroll
    for (int j = 0; j < NPT; ++j) {
        if (xpu_below(h[j])) {
            // The *lowest* nonce wins, so a scan is a function of its range
            // rather than of which warp happened to retire first. Two runs
            // over one range then agree, which is what makes a disagreement
            // between this and the pool worth investigating.
            atomicMin(found, n0 + j);
        }
    }
}

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "cuda: %s at line %d\n", cudaGetErrorString(e_), __LINE__); \
    return -1; } } while (0)

static int unhex(const char *s, uint8_t *out, int want) {
    int n = 0;
    for (; n < want; ++n) {
        int hi = -1, lo = -1;
        char a = s[2*n], b = s[2*n+1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        if (hi < 0 || lo < 0) return -1;
        out[n] = (uint8_t)((hi << 4) | lo);
    }
    return s[2*want] == '\0' || s[2*want] == '\n' || s[2*want] == '\r' ? 0 : -1;
}

// Install a job: the midstate over the first 64 header bytes, the three tail
// words the nonce sits beside, and the target.
//
// The midstate is the whole reason a GPU miner is not simply a hash benchmark:
// the first 64 bytes never change across a job's several billion nonces, so
// they are compressed once here on the host and the device does one
// compression per nonce instead of two.
static int set_job(const uint8_t header[80], const uint8_t target_be[32]) {
    uint32_t mid[8];
    memcpy(mid, hIV, sizeof mid);
    sha_host_compress(mid, header);
    uint32_t tail[3] = {
        sha_be32(header + 64), sha_be32(header + 68), sha_be32(header + 72)
    };
    uint32_t tgt[8];
    for (int i = 0; i < 8; ++i) tgt[i] = sha_be32(target_be + 4 * i);

    CK(cudaMemcpyToSymbol(cK, hK, sizeof hK));
    CK(cudaMemcpyToSymbol(cIV, hIV, sizeof hIV));
    CK(cudaMemcpyToSymbol(cMid, mid, sizeof mid));
    CK(cudaMemcpyToSymbol(cTail, tail, sizeof tail));
    CK(cudaMemcpyToSymbol(xTarget, tgt, sizeof tgt));
    return 0;
}

int main(void) {
    // **Unbuffered, and _IOLBF is not good enough here.** Windows' CRT
    // documents line buffering as behaving like *full* buffering, so a reply
    // written to a pipe sits in a buffer while the parent blocks waiting for
    // it. That is a deadlock presenting as a GPU that mines nothing, which is
    // the least informative symptom available.
    //
    // Found by running it rather than by reading it: with _IOLBF this printed
    // nothing at all down a pipe, not even its greeting. _IONBF costs a write
    // per reply, and there are two replies per scan of several million hashes.
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t *d_found = NULL;
    if (cudaMalloc(&d_found, sizeof(uint32_t)) != cudaSuccess) {
        fprintf(stderr, "cuda: no device\n");
        return 1;
    }
    // Touch the device before saying ready, so the parent's first `scan` is not
    // also paying for context creation -- about two hundred milliseconds that
    // would otherwise land inside a measured interval.
    cudaFree(0);
    printf("ready\n");

    char line[512];
    int have_job = 0;
    while (fgets(line, sizeof line, stdin)) {
        if (!strncmp(line, "quit", 4)) break;

        if (!strncmp(line, "job ", 4)) {
            char hh[200], th[80];
            if (sscanf(line + 4, "%199s %79s", hh, th) != 2 ||
                strlen(hh) != 160 || strlen(th) != 64) {
                printf("err malformed job\n");
                continue;
            }
            uint8_t header[80], target[32];
            if (unhex(hh, header, 80) || unhex(th, target, 32)) {
                printf("err job is not hex\n");
                continue;
            }
            if (set_job(header, target)) { printf("err upload failed\n"); continue; }
            have_job = 1;
            printf("ok\n");
            continue;
        }

        if (!strncmp(line, "scan ", 5)) {
            unsigned base = 0, count = 0;
            if (sscanf(line + 5, "%x %u", &base, &count) != 2) {
                printf("err malformed scan\n");
                continue;
            }
            if (!have_job) { printf("err no job\n"); continue; }

            uint32_t none = 0xffffffffu;
            if (cudaMemcpy(d_found, &none, 4, cudaMemcpyHostToDevice) != cudaSuccess) {
                printf("err upload\n"); continue;
            }
            // Round the range down to whole blocks. Scanning a partial block
            // would mean the last threads working nonces outside what was
            // asked for, and a nonce found outside the range is one the parent
            // cannot account for.
            const int threads = 256;
            uint32_t per_block = (uint32_t)threads * NPT;
            uint32_t blocks = count / per_block;
            if (blocks == 0) blocks = 1;
            uint32_t done = blocks * per_block;

            xpu_scan_kernel<<<blocks, threads>>>(base, d_found);
            if (cudaDeviceSynchronize() != cudaSuccess) {
                printf("err launch: %s\n", cudaGetErrorString(cudaGetLastError()));
                continue;
            }
            uint32_t got = none;
            if (cudaMemcpy(&got, d_found, 4, cudaMemcpyDeviceToHost) != cudaSuccess) {
                printf("err readback\n"); continue;
            }
            if (got != none) printf("found %08x\n", got);
            else printf("none %u\n", done);
            continue;
        }

        printf("err unknown\n");
    }
    cudaFree(d_found);
    return 0;
}
