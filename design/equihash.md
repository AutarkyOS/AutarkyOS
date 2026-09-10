# Equihash 192,7 on an RTX 3050 Laptop -- decision brief

> **Decision: not built, and the reason is the shape rather than the effort.**
>
> Everything in `src/mine/` answers one question -- given an 80-byte header and
> a nonce, what is the digest -- and the whole tree rests on that: `Hasher::hash`
> returns `[u8; 32]`, `below_target` compares one, `proto::Share` carries a
> nonce, `cuda/algo.cuh`'s contract is `NAME_hash(nonce, out[8])`, and the pool
> credits work as `2^bits` per accepted digest.
>
> **Equihash is not a hash, it is a search.** One nonce yields a variable number
> of 400-byte solutions, or none. Nothing above would survive it unchanged: the
> wire needs a solution field, the miner needs a variable-length share, the pool
> needs a validator that is not a comparison, and the GPU harness needs a
> different contract. That is a second mining system beside the first, not a
> fourth row in a table.
>
> The memory is tight but survivable -- 3.26 GiB at reference quality against
> 3,836 MiB free, or about 2 GiB at the quality shipping miners use. The effort
> is 1,500 to 2,500 lines. Neither is the blocker; the blocker is that the
> abstraction this repository is built on does not describe the problem.
>
> **The research is kept in full because it is worth more than the decision.**
> It found a hazard nobody would have predicted (§0), it built a verifier that
> replays real accepted blocks on two chains, and if the protocol ever grows a
> solution field this is the document that makes the work possible in an
> afternoon rather than a fortnight.
>
> **The refusal has a price now and it is 7x.** Measured after this was written,
> on an axis the decision did not have: zpool pays $0.4742 a worker a day on
> `equihash192` and $0.4721 on `equihash144`, against $0.0499 for the next
> reachable algorithm down and $0.0271 for NeoScrypt, which was built instead.
> Two readings seven minutes apart put the pair's position at the top beyond
> noise. The decision stands -- it was never about the money -- but a decision
> held open should say what it costs, and `design/mining.md` carries the table.
>
> NeoScrypt was built instead: `tools/neoscrypt.py`, `cuda/neoscrypt.cu`,
> `src/mine/neoscrypt.rs`, all checked against two real Feathercoin blocks.


Research only; nothing in the repository was changed. Everything marked
**VERIFIED** was fetched, run, or read during this session. Everything marked
**INFERRED** is arithmetic or judgement over verified inputs. Where something
could not be established it says so rather than guessing.

The headline, before anything else: **there is a working verification oracle
now**, it validates real accepted blocks on two different chains, and building
it turned up a hazard that would otherwise have sunk the implementation
silently — see §0 and §3.

---

## 0. The finding that changes the shape of the job

zpool.ca serves **one** algorithm bucket called `equihash192`, and the four
coins in it **do not share a BLAKE2b personalisation string**. A single solver
is wrong for two of the four.

| Coin | prefix | 16-byte personalisation (hex) | status |
|---|---|---|---|
| ZClassic (ZCL) | `ZcashPoW` | `5a63617368506f57 c0000000 07000000` | **VERIFIED — 5 real blocks replayed** |
| Ycash (YEC) | `ZcashPoW` | `5a63617368506f57 c0000000 07000000` | VERIFIED in source; not block-replayed |
| Zero (ZER) | **`ZERO_PoW`** | `5a45524f5f506f57 c0000000 07000000` | VERIFIED in source; not block-replayed |
| Kerrigan (KRGN) | **`kerrigan`** | `6b6572726967616e c0000000 07000000` | **VERIFIED — 2 real blocks replayed** |

This is exactly the class of bug this repository keeps writing about: the
solver runs at full speed, emits structurally perfect 400-byte solutions, and
every share is rejected with nothing anywhere saying why. It is invisible to
any test that checks the solver against itself.

The layout is `prefix(8) || LE32(n) || LE32(k)` in all four, so only the 8-byte
prefix varies. A solver must take the prefix as a **per-job parameter**, never
a compile-time constant.

Two independent routes agreed: reading the four `src/crypto/equihash.cpp` files,
and replaying real blocks through an oracle written here. The oracle rejects
`ZERO_PoW`, `YcashPoW`, `ZclPoW__` and `zcashPoW` against a ZCL block, and
rejects `ZcashPoW` against a Kerrigan Eq192,7 block.

---

## 1. Which coins use Equihash 192,7

**VERIFIED — zpool.ca, fetched this session.**

`https://zpool.ca/api/status` lists `equihash192` on port 2192: 4 coins,
27,111 KH/s, 571 workers. `https://zpool.ca/api/currencies` resolves those four
by `"algo": "equihash192"`:

| Ticker | Name | Workers | Pool hashrate | Source repo |
|---|---|---:|---:|---|
| **YEC** | Ycash | 281 | 13,472 | `github.com/ycashfoundation/ycash` |
| **ZCL** | ZClassic | 165 | 12,951 | `github.com/ZclassicCommunity/zclassic` |
| **ZER** | Zero | 0 | 0 | `github.com/zerocurrencycoin/Zero` |
| **KRGN** | Kerrigan | 2 | 107 | `github.com/kerrigan-network/kerrigan` |

Ycash and ZClassic are the whole of the economically real activity. Zero had
zero workers at fetch time; Kerrigan is negligible (~$1/day estimate).

### Cross-check 1 — consensus source (VERIFIED)

- **Zero** — `chainparams.cpp`: `const size_t N = 192, K = 7;`, no height
  dependence, no `EquihashN(nHeight)` in `pow.cpp`. 192,7 from genesis.
- **Ycash** — base 200,9; `consensus/upgrades.cpp` overrides to 192/7 at
  `UPGRADE_YCASH`, `nActivationHeight = 570000`.
- **ZClassic** — base 200,9; overridden at `UPGRADE_BUBBLES`,
  `nActivationHeight = 585318`.
- **Kerrigan** — multi-algo (X11, KawPoW, Equihash 200,9, Equihash 192,7)
  selected by `nVersion` bits 8–11; `ALGO_EQUIHASH_192` is
  `nVersion & 0x0F00 == 0x0600`. No `consensus.nEquihashN` exists.

### Cross-check 2 — the live chain, replayed (VERIFIED, and the stronger one)

Binary-searching ZClassic solution sizes over the explorer found the transition
**independently of the source**: last 1344-byte (200,9) solution at height
**585317**, first 400-byte (192,7) solution at height **585318**. That matches
`nActivationHeight = 585318` exactly — two methods, one number.

Sampling the last 8 Kerrigan blocks returned
`{'KawPoW': 4, 'Eq192,7': 2, 'X11': 1, 'Eq200,9': 1}` — the explorer labels the
algorithm per block, confirming the multi-algo reading.

### What this means practically

Mining `equihash192` on zpool means, in practice, **Ycash and ZClassic** — both
`ZcashPoW`, which is convenient. But the pool can serve Zero and Kerrigan jobs
on the same port, and those need different prefixes.

---

## 2. Memory requirement

### The geometry (VERIFIED — the enums are identical in all four repos)

```
IndicesPerHashOutput = 512/N             = 512/192 = 2      (integer division)
BLAKE2b outlen       = (512/N)*N/8       = 2*24    = 48 bytes
CollisionBitLength   = N/(K+1)           = 192/8   = 24
CollisionByteLength  = ceil(24/8)        =            3
HashLength           = (K+1)*CollByteLen = 8*3     = 24 bytes
SolutionWidth        = (1<<K)*(CBL+1)/8  = 128*25/8= 400 bytes
initial list size    = 2^(CBL+1)         = 2^25    = 33,554,432 entries
rounds of collision  = K                 =            7
```

**The structural fact worth internalising:** 192,7 and 144,5 have the *same*
`CollisionBitLength` of 24, therefore the *same* 2^25 initial list. 200,9 has
CBL 20 and a 2^21 list — **16x smaller**. That is why Zcash's algorithm fits in
~1 GB and these do not. 192,7 is not "a bit more than Zcash"; it is a different
scale of problem and a near-twin of Zhash/BTG.

### The arithmetic (INFERRED — arithmetic over the verified geometry)

Per-round table, pair-pointer representation (rows after round 0 store the
unconsumed hash bytes plus two slot references, not a growing index list):

| round | hash bytes kept | pair refs | entry bytes | table |
|---:|---:|---:|---:|---:|
| 0 | 24 | 4 | 28 | 896 MiB |
| 1 | 21 | 7 | 28 | 896 MiB |
| 2 | 18 | 7 | 25 | 800 MiB |
| 3 | 15 | 7 | 22 | 704 MiB |
| 4 | 12 | 7 | 19 | 608 MiB |
| 5 | 9 | 7 | 16 | 512 MiB |
| 6 | 6 | 7 | 13 | 416 MiB |
| 7 | 3 | 7 | 10 | 320 MiB |

- **Exact data floor**, round 0: `2^25 x 28 B` = **896 MiB**.
- **Ping-pong peak**, two live tables: 896 + 896 = **1792 MiB**.
- Full index lists are not an option: round 7 would need
  `2^25 x 128 x 4 B` = **16 GiB**. The tree/pair representation is mandatory,
  not an optimisation.

Hashing work per nonce: `2^25 / 2` = **2^24 = 16,777,216 BLAKE2b calls**,
producing 768 MiB of digest consumed as generated.

### Independent check — the open-source reference solver (VERIFIED)

`tromp/equihash` ships a CUDA solver built for exactly these parameters:

```make
eqcuda1927: nvcc -DWN=192 -DWK=7 -arch sm_35 equi_miner.cu blake/blake2b.cpp
```

Its allocation is readable (`equi_miner.cu` L933-934, constants from `equi.h`).
Recomputing it here:

```
BUCKBITS=20 -> NBUCKETS=1,048,576   NSLOTS=64   slot0=28 B  slot1=24 B
heap0  = 1048576 * 64 * 28 = 1,879,048,192 B = 1792 MiB
heap1  = 1048576 * 64 * 24 = 1,610,612,736 B = 1536 MiB
nslots = 2 * 1048576 * 4   =     8,388,608 B =    8 MiB
TOTAL                      = 3,498,049,536 B = 3336 MiB = 3.26 GiB
```

**This reconciles cleanly with the 896 MiB floor.** Slot capacity is
`2^20 buckets x 64 slots = 2^26`, which is **2x** the 2^25 entries — that factor
is over-provisioning to absorb bucket imbalance, because entries do not
distribute evenly and an overflowing bucket silently drops solutions. So:
896 MiB of data, 1792 MiB with 2x bucket slack, 3336 MiB for the two-heap
ping-pong the algorithm actually needs.

The method was validated by the same subagent on a case with a published
answer: running this arithmetic on tromp's **CPU** solver config for 200,9
yields ~144 MB, which is the figure tromp states in his own README.

### Published miner requirements (VERIFIED, caveats attached)

| Miner | Stated 192,7 VRAM | Note |
|---|---|---|
| **miniZ** | **"almost 2GB"** | `miniz.ch` now 301-redirects to an unrelated domain; verified via Wayback snapshot `web.archive.org/web/20221203090417/https://miniz.ch/features/` |
| lolMiner | supports 192/7, **no figure stated** | verified absence across all 100 releases |
| GMiner | **does not support 192,7** | README lists only 144_5, 125_4, 210_9 |
| tromp `eqcuda1927` | **3336 MiB** (computed from source) | open source, the reference |
| Optiminer | ">6GB" | 2017 AMD-era, ~5x slower than miniZ — **reject this figure** |

miniZ's own benchmark table shows a **2 GB GTX 1050 posting 10.0 Sol/s on
192,7**, while its 125,4 and 150,5 columns (the algorithms miniZ says need 3 GB)
are blank on that card. That internal consistency is what makes ~2 GB credible.

Awesome Miner's page claims GMiner supports this algorithm, which contradicts
GMiner's own README — that entry looks stale.

### Does it fit in 3836 MiB?

**Yes — but the headroom depends entirely on implementation quality.**

| Implementation | Need | Verdict on 3836 MiB free |
|---|---:|---|
| miniZ-class (optimised) | ~2048 MiB | fits, ~1.8 GB spare |
| tromp reference as-is | 3336 MiB | fits, **500 MiB spare — tight** |
| naive full-index | 16+ GiB | impossible |

Three cautions on the tight case (INFERRED):

- **Windows WDDM** reserves VRAM for the desktop, and this is a *laptop* 3050
  driving a display. 3836 MiB is what was free at one moment; it is not a floor.
- **500 MiB of headroom means one solve stream, not two.** No double-buffering a
  second nonce to hide latency, which costs real throughput.
- Dropping `RESTBITS` from 4 to 3 halves NSLOTS and roughly halves the heaps, at
  the cost of more bucket overflow. That is the knob — and its failure mode is
  *lost solutions*, a quiet hashrate loss rather than an error.

---

## 3. A verification vector

Both options in the brief were available, and the second became something
stronger: **a complete working oracle, plus seven replayed blocks across two
chains.**

### The oracle

`eqverify.py` (in this scratchpad) is an independent Equihash 192,7 verifier
written from the algorithm, using `hashlib.blake2b` for the primitive — so the
primitive comes from somebody else's code and only the scaffolding is ours,
the same bargain `tools/neoscrypt.py` documents.

It implements `ExpandArray`, `GetIndicesFromMinimal`, the BLAKE2b generator,
and the full validity check (distinctness, per-round collision, index ordering,
final XOR to zero). Run it with `python eqverify.py`.

### The live API that returned data (VERIFIED)

**ZClassic Insight explorer — works, and exposes everything needed.**

```
https://explorer.zcl.zelcore.io/api/status
https://explorer.zcl.zelcore.io/api/block-index/{height}   -> {"blockHash": "..."}
https://explorer.zcl.zelcore.io/api/block/{hash}           -> parsed fields
https://explorer.zcl.zelcore.io/api/rawblock/{hash}        -> {"rawblock": "<hex>"}
```

Note: the explorer **403s a default `python-urllib` User-Agent**. Send a browser
UA (curl worked throughout).

`/api/block/{hash}` field names, exactly as returned:

```
bits, chainwork, confirmations, difficulty, hash, height, isMainChain,
merkleroot, nextblockhash, nonce, poolInfo, previousblockhash, reward,
size, solution, time, tx, version
```

The equihash solution is the **`solution`** field, 800 hex chars = **400 bytes**,
arithmetically unique to 192,7 (200,9 gives 1344; 144,5 gives 100).

Two traps in that parsed form, both real:

- **There is no `finalsaplingroot` field**, even though the header carries one.
  Use `/api/rawblock/` instead.
- **`nonce` is returned byte-reversed** relative to wire order.

### Header layout, established by parsing rather than assumed (VERIFIED)

Testing `nTime` at two candidate offsets settled it: the value `1788981932`
appears at offset 100, not 68, so the 32-byte `hashFinalSaplingRoot` **is**
present.

```
offset  size  field
     0     4  nVersion             (LE)
     4    32  hashPrevBlock        (wire order = display order reversed)
    36    32  hashMerkleRoot
    68    32  hashFinalSaplingRoot
   100     4  nTime                (LE)
   104     4  nBits                (LE)
   108    32  nNonce
   140     3  CompactSize(400) = fd 90 01
   143   400  packed solution
   ---------
   543     total serialized header
```

The **140 bytes at offset 0** are exactly what BLAKE2b is fed.

### The vector (VERIFIED — this validates)

ZClassic block **3,245,000**, hash
`000012db5636151a4ce9ba093d52fb4d1a49c3746cb4df96fb5f48a2d5e6c068`

header140 (hex, 140 bytes):

```
04000000f32d09454e7cc9a990d735bb28e85f6e4e93dcf359278dfb482e431aad140000
9c434041ba4271b4904bbd6a669824a06d68b2fa445752bc6cadc1918343161f
0929c20bd5fcb1e3df0fe5dbb1f2711b1e5a2d871e4fe55324edd9e0bfa0c526
acb2a16ac091171e
8002754400000000000000000000000000000000000000000000000098ba21d0
```

(concatenate the four lines; split here only for reading — 4+32+32+32, then
time+bits as `acb2a16a`+`c091171e`, then the 32-byte nonce)

solution (hex, 400 bytes):

```
024a655f768607ef9f97f67af43e0ff75ec322e0ff29c7014903f7fd575d4da6654013cfe2e168488c7ed9d7ab48cbe4
14b6048d08c4b88a95860e0e0456a95239ef990ec357c3fbd5c0ff0d9bf6d71be022c6ec5ebc64c499a92f3333aa9d66
d7648279048217b0e4bf9515accc952d31c317a3e9d4a4ac7f3bd9a09711548a6ec9e397585297ac102470325443b3de
f5f48996ca7e180ffbf3f0f2928857bd9c53c3b380d67374628addcbbb8a375695887cb5e5966a0aace84178040def19
783ac42441d84c7e025832ed537d12a438bc6eec45955d36f8706dadd67ef78d50073663b6faeca7ae251c5575b67eac
334d506342b131e6f5380b99625b5e2858a16cd5f6cfd37f6fcaae9bb55ad01521e03a1107908f47060cc56d10c2d1a6
bf939d62b11a14788fa3172107e28f57d5fa83d7e23cc51b66e29cadc1884ddb6693297c40156a89be3570b7871e3d8b
270160b591a4302cafcf927477a2080c2160a9290a0368b78e1ed188c59a8cbf3d0e5f99c70aa1080f2ec0c891eea845
9f9832e2a8f495e4490992744cd6e2ac
```

```
personalisation: "ZcashPoW" || LE32(192) || LE32(7)
               = 5a63617368506f57c000000007000000
expected result: VALID
```

Four more that also validate, same source and method: heights **1000000,
2000000, 3000000, 3240000** — all in `vectors.json` beside this file.

A block is on that chain only because consensus accepted its solution, so
reproducing one is not a coincidence. It is the same argument
`cuda/neoscrypt.cu` makes for using real Feathercoin blocks.

### The negative controls — why this oracle is not vacuous

A verifier that says yes to everything passes every positive test. All of the
following were run, and **all were rejected**:

| tamper | result |
|---|---|
| flip 1 bit in nVersion / prevhash / merkleroot / saplingroot | rejected |
| flip 1 bit in nTime / nBits / nNonce | rejected |
| flip 1 bit in the solution | rejected |
| truncate solution by 1 byte | rejected (length check) |
| verify as n=200,k=9 / 144,5 / 210,9 | rejected (length check) |
| personalisation `ZERO_PoW` / `YcashPoW` / `ZclPoW__` / `zcashPoW` | rejected |

Case sensitivity matters — `zcashPoW` fails. Only `n=192, k=7` with `ZcashPoW`
validates.

### Second chain, second personalisation (VERIFIED)

Kerrigan blocks with `nVersion & 0x0F00 == 0x0600` (heights **143799** and
**143796**, `nVersion = 0x20000600`) verify with prefix **`kerrigan`** at header
length 140, solution offset 143 — and do **not** verify with `ZcashPoW` at any
header length from 60 to 220. That independently confirms both the multi-algo
version-bit encoding and the custom personalisation.

Explorer: `https://explorer.kerrigan.network/api/{status,block-index,block,rawblock}`.
Its `/api/block/{hash}` adds `algo`, `algoDisplay`, `algoId` fields.

### What could not be established

- **Ycash block replay.** `explorer.ycash.xyz` (Inzyght) has a working API —
  `/api/v1/network/blockchain` and `/api/v1/blocks/{height}` returned data — but
  `/api/v1/blocks/verbose/{hash}` and `/api/v1/blocks/raw/{hash}` returned empty
  bodies, and the whole API began returning empty shortly after (rate limiting
  is the likely explanation; it needs `Accept: application/json` and a `Referer`
  to respond at all). `yecblockexplorer.com` returned HTTP 502.
  `explorer.ycash.cl` did not resolve. So Ycash's `ZcashPoW` is
  **source-verified only, not block-replayed** — though it shares its prefix
  with ZClassic, which is replayed, and Ycash's consensus path goes through the
  `equihash` Rust crate whose `initialise_state` writes `"ZcashPoW"`.
- **Zero block replay.** `insight.zerocurrency.io` 404s on every Insight API
  path tried. `ZERO_PoW` is source-verified only.
- **No published static test vectors** for 192,7 were found anywhere. The
  block-replay route is what exists.
- **What zpool's stratum actually sends per coin** is unknown. If zpool runs one
  personalisation across all four, at most two can be correct. Confirm against a
  real job from the port before trusting shares.

---

## 4. Solver structure

### The BLAKE2b generator

Personalisation is `prefix(8) || LE32(n) || LE32(k)` = 16 bytes. BLAKE2b is
initialised with **outlen 48** — and this is a *parameter of the state*, folded
into the BLAKE2b parameter block, which changes the initial chaining value. It
is **not** a truncation of a 64-byte digest. Getting that wrong gives a
plausible digest of the right length that is entirely wrong.

```
base = BLAKE2b(outlen=48, person=personal)
base.update(header[0:140])

for list entry i in [0, 2^25):
    g = base.copy()
    g.update(LE32(i / 2))            # integer division
    d = g.digest()                   # 48 bytes
    entry = d[(i % 2) * 24 : +24]    # 24 bytes = 192 bits
```

Two entries per BLAKE2b call, so 2^24 calls. At 192,7 the 48-byte output is
consumed exactly (2 x 24), with no waste.

The Equihash input is `CEquihashInput` (108 bytes: version, prevhash,
merkleroot, saplingroot/reserved, time, bits) with the 32-byte nonce appended =
**140 bytes**.

**The expansion step is a no-op at 192,7, and it is worth knowing why.** Upstream
runs `ExpandArray(chunk, 24, out, HashLength=24, bit_len=CollisionBitLength=24,
byte_pad=0)`. Because 24 bits is exactly 3 bytes with no padding, the transform
is the identity. At 200,9 (20-bit groups) it is not. A 192,7 solver can skip it,
but only if it knows why it is allowed to.

### The k rounds

Wagner's algorithm on 24-bit digits. At round `r` in 1..7, bucket the current
list on the next 24 bits; for every colliding pair emit the XOR with those 24
bits (now zero) dropped, carrying a reference back to the pair.

- Round `r` consumes bits `[24(r-1), 24r)`.
- After 7 rounds `7 x 24 = 168` bits have been cancelled, and the final 24 bits
  must be zero for a genuine solution — that is the last condition, not a free
  consequence.
- Rows shed 3 bytes of hash per round: 24, 21, 18, 15, 12, 9, 6, 3.
- The list stays near 2^25 entries per round. That is the whole design of
  Equihash: it is why memory does not collapse and why the algorithm is
  memory-hard.

Bucketing on the top `BUCKBITS` of the digit is how collisions are found without
a global sort; `RESTBITS` is the leftover compared within a bucket.

### Final validity conditions

1. **All 2^7 = 128 indices distinct.** Wagner's algorithm genuinely produces
   candidates with repeats, and they are invalid. This must be an explicit check.
2. **Ordered index pairs at every level of the tree.** For each pair combined at
   round `r`, the smallest index in the left subtree must be strictly less than
   the smallest in the right. This is what makes the encoding canonical, so one
   solution has one representation.
3. **XOR to zero** over all 128 hashes, across the full 192 bits.

### Solution encoding

`GetMinimalFromIndices` packs 128 indices at `CollisionBitLength+1 = 25` bits
each, MSB-first, `bytePad = 4 - ceil(25/8) = 0`. `128 x 25 = 3200` bits =
**400 bytes** exactly, no trailing padding. CompactSize(400) = `fd 90 01`.

Worth knowing: for **Ycash and ZClassic, consensus derives (n,k) from the
solution length**, not from the block height — `src/pow.cpp` dispatches on
`nSolSize == 400`. The height-based parameter lookup is used only by the miner.

---

## 5. Honest cost estimate, and the comparison

### Lines of CUDA

Grounded against the reference rather than guessed. `tromp/equihash`, the
open-source solver that builds `-DWN=192 -DWK=7`:

| file | lines |
|---|---:|
| `equi_miner.cu` | 1032 |
| `equi.h` | 133 |
| `blake/blake2b.cpp` | 339 |
| **total** | **~1500** |

That is a mature, terse implementation by the person who designed the solver.
Written in this repository's style — the commentary, the oracle checks, the
`algo.cuh` contract — the realistic figure is **1,500–2,500 lines**:

| part | est. lines | difficulty |
|---|---:|---|
| BLAKE2b-512 device implementation | 200–300 | low — mechanical, but 64-bit |
| list generation kernel | 100–150 | low |
| bucketed collision rounds | 500–900 | **high — this is the job** |
| tree walk-back / solution recovery | 200–350 | **high** |
| distinctness + ordering canonicalisation | 100–150 | medium |
| host job/stratum plumbing | 250–400 | medium |

### The hazards, in the order they will actually bite

1. **The per-coin personalisation string.** A compile-time constant here means
   every share rejected on two of the four coins, with no diagnostic. The oracle
   in §3 is what catches it before hardware does.
2. **Tree walk-back across 7 rounds.** Recovering 128 indices from a chain of
   pair pointers, in the right order, is the hardest correctness problem here.
   An off-by-one produces solutions that look structurally perfect — right
   length, right index count — and fail verification. No partial credit, no
   useful error message.
3. **Bucket overflow.** When a bucket exceeds NSLOTS, entries are dropped. It
   does not crash and does not corrupt: it *lowers the solution rate*, which is
   indistinguishable from bad luck. Needs an explicit counter, or the knob that
   trades memory for solution rate becomes untunable.
4. **Ordering canonicalisation.** Get it wrong and solutions are valid XOR-wise
   and rejected by the pool — the same silent signature as (1).
5. **VRAM at 4 GB.** The reference needs 3336 of 3836 MiB. That works, single
   stream, on a machine where WDDM and the desktop also spend VRAM. Feasible,
   not comfortable.
6. **BLAKE2b is not BLAKE2s.** `cuda/blake2s.cuh` does not help beyond the
   structural shape: 64-bit state, different rotation constants (32/24/16/63 vs
   16/12/8/7), 12 rounds not 10, roughly double the register pressure. Nothing
   is reusable.
7. **Sol/s is not H/s, and `algo.cuh` does not fit.** The current contract is
   `NAME_hash(nonce, out[8])` — one nonce, one digest, compare against a target.
   Equihash produces a *variable number of solutions per nonce*, each then
   hashed and compared. This is a new harness, not a new row in `ALGOS`.

### Against NeoScrypt

`cuda/neoscrypt.cu` (171 lines) and `cuda/neoscrypt.cuh` (401) **already exist**
in this repository, and `tools/neoscrypt.py` (434) is the oracle, already checked
against two real Feathercoin blocks (heights 432001 and 6346000). Single commit
`cd77a1b`.

| | NeoScrypt | Equihash 192,7 |
|---|---|---|
| CUDA already written | **yes, 572 lines** | no |
| Oracle already written | **yes, vs 2 real blocks** | **yes — written this session, vs 7 blocks on 2 chains** |
| New primitive needed | none (BLAKE2s present) | **BLAKE2b — absent** |
| Fits `algo.cuh` contract | **yes** | **no — needs a new harness** |
| VRAM | ~32 KB/thread scratchpad | 2–3.3 GB total |
| Remaining work | tuning, occupancy | 1,500–2,500 lines from scratch |
| Silent-failure surface | word order (documented) | personalisation, walk-back, ordering, bucket overflow |

**NeoScrypt is a tuning problem. Equihash 192,7 is a build.** The honest gap is
not 2x; it is closer to an order of magnitude in effort, and the failure modes
are precisely the kind this repository has spent pages warning about.

The one thing that has moved in Equihash's favour is that the hardest part of
starting — having something to check against that nobody here wrote — is done.
The oracle exists, it discriminates, and it caught a real hazard on its first
day. If Equihash 192,7 is attempted, it should be built against `eqverify.py`
from the first kernel, exactly the way `tools/neoscrypt.py` came before
`cuda/neoscrypt.cu`.

---

## Files produced (scratchpad only — nothing in the repository was changed)

| file | what |
|---|---|
| `eqverify.py` | the verifier; `python eqverify.py` replays the embedded ZCL block |
| `vectors.json` | 5 ZClassic header/solution pairs, all verified |
| `verified-blocks.json` | raw block hex as fetched |
| `zpool-status.json`, `zpool-cur.json` | the zpool API responses, as fetched |
| `equihash-brief.md` | this document |
