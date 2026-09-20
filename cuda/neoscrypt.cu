// NeoScrypt on the RTX 3050: correctness first, then a rate.
//
//     neoscrypt.exe            verify against two real blocks, then benchmark
//     neoscrypt.exe --verify   verify only
//     neoscrypt.exe --bench N  N threads, after verifying
//
// **It refuses to print a rate it has not earned.** Every algorithm in this
// directory is checked against an implementation nobody here wrote, because a
// fast wrong hash is indistinguishable from a fast right one from the inside.
// For SHA-256d and BLAKE2s that oracle is `hashlib`; NeoScrypt has no library
// anywhere and upstream ships no vectors, so the oracle is
// `tools/neoscrypt.py` and behind it two real Feathercoin blocks.
//
// The blocks are the strongest form of the check available. A block is only on
// that chain because its NeoScrypt digest beat the target its own `nbits`
// declares, so reproducing one is a coincidence at one in 2^256/target -- 1 in
// 6.9e7 for block 432,001 and 1 in 4.1e9 for block 6,346,000.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "neoscrypt.cuh"

struct Vector {
    int height;
    const char *header;
    const char *digest;  // least-significant byte first, as the miner sees it
};

// From `tools/neoscrypt.py`, which derived them from the live chain and can
// re-derive them with `--check`.
static const Vector VECTORS[] = {
    {432001,
     "0200000054aa94a46a70931d29f2a2ed3ee4ab5832cd6446a090f6f63292d004dd306e96"
     "bca6f3f22928ee4aa468ed5d5ff0f0a31137c2f9e780e0a70411a4a39b98d91c1b364d54"
     "dcdd3d1d52660400",
     "aac8eaaea3c756f584d884f2de9e0e8c401f3ba0a640a14221550d2d06000000"},
    {6346000,
     "040000200a9245b1198825ab30d6dbae2b185e31f342d1058cc36851629bf435fc682b55"
     "4d100771e4a23d210cd3a1503e3b1ca524e8482913ee5b4036edf4bd20db6a2993c0a16a"
     "dc09011d002c5f48",
     "ff87010b15afee123759c6cb14fe33078d1795ca6f39286c3566d52500000000"},
};

static void unhex(const char *s, uint8_t *out, int n) {
    for (int i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

__global__ void ns_one(uint32_t nonce, uint32_t *out, uint32_t *v, uint8_t *kdf) {
    neoscrypt_hash_at(nonce, out, v, kdf);
}

__global__ void ns_many(uint32_t base, uint32_t *v, uint8_t *kdf, uint32_t *sink) {
    const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t out[8];
    neoscrypt_hash_at(base + tid, out, v + (size_t)tid * NS_SCRATCH_WORDS,
                      kdf + (size_t)tid * NS_KDF_BYTES);
    // Kept so the whole computation cannot be optimised away, which on a
    // benchmark is the difference between a measurement and a fiction.
    if (out[0] == 0xffffffffu) sink[0] = out[1];
}

static bool verify(void) {
    bool all = true;
    uint32_t *d_out, *d_v;
    uint8_t *d_kdf;
    cudaMalloc(&d_out, 8 * sizeof(uint32_t));
    cudaMalloc(&d_v, NS_SCRATCH_WORDS * sizeof(uint32_t));
    cudaMalloc(&d_kdf, NS_KDF_BYTES);

    for (size_t k = 0; k < sizeof(VECTORS) / sizeof(VECTORS[0]); ++k) {
        uint8_t hdr[80];
        unhex(VECTORS[k].header, hdr, 80);
        // The nonce is the last four bytes and is what the kernel substitutes,
        // so it is read back out of the header rather than passed separately --
        // a vector whose nonce did not round-trip would be checking the wrong
        // thing and looking correct.
        const uint32_t nonce = (uint32_t)hdr[76] | ((uint32_t)hdr[77] << 8) |
                               ((uint32_t)hdr[78] << 16) | ((uint32_t)hdr[79] << 24);
        neoscrypt_upload(hdr);
        ns_one<<<1, 1>>>(nonce, d_out, d_v, d_kdf);
        cudaError_t e = cudaDeviceSynchronize();
        if (e != cudaSuccess) {
            printf("FAIL  block %d: %s\n", VECTORS[k].height, cudaGetErrorString(e));
            all = false;
            continue;
        }
        uint32_t out[8];
        cudaMemcpy(out, d_out, sizeof(out), cudaMemcpyDeviceToHost);
        char got[65];
        for (int i = 0; i < 8; ++i)
            sprintf(got + 8 * i, "%02x%02x%02x%02x", (uint8_t)out[i],
                    (uint8_t)(out[i] >> 8), (uint8_t)(out[i] >> 16), (uint8_t)(out[i] >> 24));
        const bool ok = strcmp(got, VECTORS[k].digest) == 0;
        printf("%-4s  block %d\n", ok ? "ok" : "FAIL", VECTORS[k].height);
        if (!ok) {
            printf("      want %s\n", VECTORS[k].digest);
            printf("      got  %s\n", got);
            all = false;
        }
    }
    cudaFree(d_out);
    cudaFree(d_v);
    cudaFree(d_kdf);
    return all;
}

static void bench(int threads) {
    const int block = 64;
    const int grid = (threads + block - 1) / block;
    threads = grid * block;
    const size_t vbytes = (size_t)threads * NS_SCRATCH_WORDS * sizeof(uint32_t);
    const size_t kbytes = (size_t)threads * NS_KDF_BYTES;
    printf("\n%d thread(s), %.1f MiB of scratchpad + %.1f MiB of KDF buffers\n",
           threads, vbytes / 1048576.0, kbytes / 1048576.0);

    uint32_t *d_v, *d_sink;
    uint8_t *d_kdf;
    if (cudaMalloc(&d_v, vbytes) != cudaSuccess) {
        printf("could not allocate %.1f MiB; try fewer threads\n", vbytes / 1048576.0);
        return;
    }
    cudaMalloc(&d_kdf, kbytes);
    cudaMalloc(&d_sink, sizeof(uint32_t));

    // One warm-up launch, then the measurement. The first launch pays for
    // module load and page-table setup, which on a kernel this long is small
    // but is not nothing.
    ns_many<<<grid, block>>>(0, d_v, d_kdf, d_sink);
    cudaDeviceSynchronize();

    cudaEvent_t t0, t1;
    cudaEventCreate(&t0);
    cudaEventCreate(&t1);
    cudaEventRecord(t0);
    ns_many<<<grid, block>>>(1000, d_v, d_kdf, d_sink);
    cudaEventRecord(t1);
    cudaError_t e = cudaDeviceSynchronize();
    if (e != cudaSuccess) {
        printf("launch failed: %s\n", cudaGetErrorString(e));
        return;
    }
    float ms = 0;
    cudaEventElapsedTime(&ms, t0, t1);
    printf("%d hashes in %.1f ms  =  %.1f H/s\n", threads, ms, threads / (ms / 1000.0));

    cudaFree(d_v);
    cudaFree(d_kdf);
    cudaFree(d_sink);
}

int main(int argc, char **argv) {
    bool verify_only = false;
    int threads = 4096;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--verify")) verify_only = true;
        else if (!strcmp(argv[i], "--bench") && i + 1 < argc) threads = atoi(argv[++i]);
    }

#ifdef NS_NO_SMIX
    // **The one build allowed past the gate, and it announces itself.** With
    // SMix removed this is not NeoScrypt and cannot verify; what it measures is
    // FastKDF plus launch overhead, so the difference against the full kernel
    // says how much of a hash the memory-hard part actually is. The bypass is
    // compiled in rather than reachable by a flag, so no ordinary build has it.
    printf("NS_NO_SMIX: this is not NeoScrypt. FastKDF and launch overhead only.\n");
#else
    if (!verify()) {
        printf("\nrefusing to benchmark a hash that does not match the chain\n");
        return 1;
    }
#endif
    if (verify_only) return 0;
    bench(threads);
    return 0;
}
