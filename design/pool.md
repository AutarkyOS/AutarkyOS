# The pool, and the one protocol it speaks downstream

Status: **the kernel mines three coins on three algorithms against this pool
over one connection, and every share is recomputed and accepted.** What has
not happened is a real chain behind any of it: the pool builds its own headers,
so a share that beat a network target would still be worth nothing.

`design/mining.md` is the other half and should be read first: it covers what
the kernel does with the work this pool hands it.

## The problem this exists to solve

The kernel can now work four coins at once, each on its own algorithm, and
three of the four slots are fed by a *fixture* job because there is nowhere
for a real one to come from. Stratum V1 has no field that says which
proof-of-work a job wants -- a pool serves one coin and the miner is simply
assumed to know. So four coins means four connections, and four socket tasks
do not fit in `MAX_TASKS` beside four mining slices.

One connection carrying jobs for several coins needs a field Stratum does not
have. That field is the whole reason this protocol exists.

| | work |
|---|---|
| Kernel | N hash algorithms, one protocol, a supervisor with real budgets |
| Pool | N stratum dialects, N upstream connections, share accounting, conversion, payout |

## The kernel never learns what a coinbase is

The job the pool sends is an **assembled 80-byte header with a zero nonce**,
an algorithm, and a target. The miner substitutes a nonce at offset 76, hashes,
compares, and sends back the nonce. That is the entire downstream contract.

Monero's stratum has this shape and Bitcoin's does not, and the difference is
the point: Bitcoin's `mining.notify` hands over `coinb1`, `coinb2`, an
extranonce and a merkle branch, and the miner assembles the header itself. Do
that for a dozen coins and the kernel carries a dozen chains' worth of
transaction-format knowledge, in ring 0, to compute a number the pool already
knows.

`work::Template` was already this shape before this document existed. It carries
`header: [u8; 80]` rather than a midstate, and the comment saying why is about
yespower rather than about protocols -- but the consequence is that the kernel
side of this needs no new structure, only a new way to fill one.

**The Stratum V1 client in `src/mine/` is not wasted.** It moves to the pool as
its *upstream* client, where it is ordinary host code with a heap and a test
runner, and it is the same source file rather than a second implementation.
See below.

## What that costs, stated rather than discovered

A miner handed an assembled header **cannot check what it is mining for.** In
Stratum V1 the coinbase arrives in two halves and a suspicious miner can
reconstruct it, read the outputs, and see which address the block would pay.
Here the coinbase is inside a merkle root inside a header, and a merkle root is
a hash: there is nothing to inspect.

That is a real reduction in what a miner can verify and it is not waved away by
the pool being ours. So the job carries **optional** `coinb1`, `coinb2`,
`extranonce` and `branch` fields. When they are present the miner can assemble
the header itself and require it to equal the one it was sent, which is a
complete check: a matching header proves the coinbase it was shown is the
coinbase that was committed to.

The kernel keeps `header::coinbase` and `header::merkle_root` for exactly this,
and `ev::coinbase_value` already reads the outputs. None of it is on the hot
path -- a job is verified once and then hashed several billion times -- so the
verification costs approximately nothing and is the difference between a pool
that asks for trust and one that offers evidence.

Not built yet. The fields are in the protocol from the first version because
adding them later means every deployed miner is one that never checked.

## JSON lines, for one reason

Newline-delimited JSON objects, the way Stratum is. Not because it is a good
wire format -- it is not, and a binary one would be smaller and faster to
parse.

The reason is that `crate::json` is already in the kernel, is already used by
`src/mine/stratum.rs`, and is already checked at boot. A binary protocol needs
a new parser in ring 0, written for this, and the thing this tree has learned
repeatedly is that a second parser is where the disagreement lives. The bytes
saved are a rounding error against a job that arrives every thirty seconds.

## The methods

Three, and a job notification.

```
-> {"id":1,"method":"glados.hello","params":{"v":1,"worker":"...","agent":"glados/1.3.5"}}
<- {"id":1,"result":{"v":1,"slots":4,"session":"..."},"error":null}

<- {"method":"glados.job","params":{
     "slot":1, "coin":"bitzeny", "job":"a3f1",
     "algo":{"name":"yespower","v10":true,"n":2048,"r":8,"pers":"..."},
     "header":"<160 hex chars>",
     "target":"<64 hex chars>",
     "echo":{"extranonce2":"...","ntime":"..."},
     "clean":true
   }}

-> {"id":7,"method":"glados.submit","params":{
     "job":"a3f1", "nonce":"1f8c04b2", "echo":{...}
   }}
<- {"id":7,"result":{"ok":true,"diff":0.001},"error":null}
```

Four decisions in that, each with an alternative that is worse.

**`slot` is the pool's, not the miner's.** The pool says which of its coins a
job belongs to and the miner puts it where it likes; the kernel's own slot
numbering is a local matter. Letting the miner choose would mean the pool
tracking a per-connection mapping to attribute a share, which is state that can
disagree with the miner's.

**`algo` is a structure and never a name.** `"yespower"` alone is not an
algorithm: BitZeny, Yenten and Koto all run yespower and all run it with
different parameters, so a name-only field is a job that hashes a different
function perfectly correctly and has every share rejected. This is the same
refusal `Algo` already makes about a per-coin preset table, moved onto the
wire.

**`echo` is opaque and is returned verbatim.** Whatever the upstream dialect
needs back at submit time -- an extranonce2, an ntime, a Monero job blob id --
travels as a JSON object the miner stores and hands back without reading. The
kernel does not learn what any of it means, and adding an upstream that needs a
fourth field costs no kernel change at all.

**`target` is 32 bytes of hex rather than a difficulty.** `mining.set_difficulty`
sends a decimal, altcoin pools routinely send fractional ones, and the kernel's
own `stratum::decimal` exists because `Json::as_i64` reads `0.001` as `0` and a
target computed from zero either faults or accepts everything. A target on the
wire has no such conversion in it. The pool does the arithmetic once, host-side,
where a float is available and a mistake is visible.

## Why the pool is Rust, and shares the kernel's source

A pool that accounts shares must **validate** them, and validating a share
means computing the same hash the miner computed. If the pool is TypeScript
beside a Deno function, there are now two implementations of yespower that have
to agree, and this tree's whole recorded experience is that two implementations
which are supposed to agree do not stay agreeing on their own -- it is why
`tokenizer.py` has `--verify`, why `v4.py` is not the writer, and why
`differ.rs` exists before the thing it gates.

So the pool includes the kernel's own files. Not a copy and not a port:

```rust
#[path = "../../src/mine/yespower.rs"] pub mod yespower;
```

Nine modules travel that way (`u256`, `hash`, `header`, `blake2s`, `yespower`,
`algo`, `stratum`, `proto`, `ev`) plus three they rest on (`store::sha256`,
`crypto::hkdf`, `json`). They were already almost free of the kernel: `sha256`,
`blake2s`, `u256`, `header` and `ev` name nothing outside themselves at all,
and the rest need three modules and one macro. `kernel_shim` supplies that
macro and nothing else.

**A divergence is a build failure rather than a wrong answer**, which is the
whole of the argument. Change the kernel's yespower and the pool stops
compiling or stops passing its vectors, in the same commit, on the same source.

**And this is the first `cargo test` in the project.** CLAUDE.md opens its
testing section with "There is no `cargo test`", which is true of the kernel and
was true of everything the kernel contains. The hash core is not kernel code in
any meaningful sense -- it touches no hardware and allocates from a heap -- so
on the host it is ordinary Rust with a test runner in front of it, and the
vectors `diag mine` asserts at boot run in about a second instead of a boot.

The boot claims stay. They check the same things on the machine that will
actually run them, which is what `diag paging` exists to say about permissions.

**CLAUDE.md said this could not be done.** `Cargo.toml`'s note records that a
host cdylib fails with "linker `link.exe` not found", and the conclusion drawn
from it -- anything that has to run on the host at build time is out -- was read
as covering host binaries too. Measured, this session: a plain host binary
compiles, links and runs. Whatever was missing has been installed since. The
proc-macro and `-Zbuild-std` findings were not re-tested and are left standing.

## Where this runs, and the one thing GitHub Pages cannot do

The intended home is `pool.aperture.institute`, on a domain this project owns,
and the intended host was GitHub Pages. **Pages cannot run the daemon**, and
the reason is not a setting: it serves static files over 80 and 443 from a CDN,
with no long-lived process and no listener on a port of its own. The pool is a
TCP server that holds connections open for hours and speaks line-delimited JSON
on :3334. Nothing about that is static.

What Pages *is* right for is the half that matters most, which is the published
record. So the two halves get two names, because one hostname resolves to one
place and it can be GitHub's CDN or a server, never both:

| | where | what |
|---|---|---|
| `pool.aperture.institute` | its own repo, GitHub Pages | the published share log, the docs, how to point a miner |
| `stratum.aperture.institute:3334` | a host that runs a binary | the daemon |

**A second repository is genuinely required for the site**, and not as tidiness:
one repository serves one Pages site with one `CNAME`, and this one's is
already `glados.aperture.institute` in `docs/CNAME`.

**The daemon's source stays in this repository**, though, and that is the whole
argument of this file. `pool/` works by including twelve of the kernel's own
files with `#[path]`; move it out and that becomes a submodule or a vendored
copy, and a vendored copy is precisely the drift the arrangement exists to
prevent. The site repository holds published data and HTML and needs none of
the Rust.

### How big a host, measured

`glados-pool --bench` answers it, and the answer is "almost anything", for a
reason worth stating plainly because it is the opposite of the intuition mining
usually carries:

> **A miner grinds several million nonces to find one share. The pool hashes
> exactly once to agree.** So the pool's load scales with the share *rate*,
> which the operator sets by choosing the target, and not with anybody's
> hashrate. A room full of fast miners costs this server no more than the same
> room of slow ones.

Best of nine, on the development machine:

| algorithm | per share | working set | shares/s on one core |
|---|---|---|---|
| sha256d | 0.74 us | 0 | 1,347,708 |
| blake2s | 0.20 us | 0 | 5,025,125 |
| yespower 2 MiB | 1.91 ms | 2,146 KiB | 524 |
| yespower 8 MiB | 7.49 ms | 8,296 KiB | 133 |

And the process itself: **370 KB of binary, 3.49 MB resident** with four coins
configured and five threads.

The transient peak is one working set on top of that, not one per miner, and
that falls out of something accidental rather than designed: `Pool` sits behind
a `Mutex` and validation happens while it is held, so shares are checked one at
a time. Worth knowing before anybody "fixes" that for throughput -- a parallel
validator would make peak memory `threads * 8 MiB`, which is the one way this
program could become large.

**So 32 MB of RAM and one core is comfortable, and the CPU number is the
generous one.** yespower here is the *reference* implementation, deliberately
unoptimised so the vectors have something plain to check; an optimised
validator is roughly eight times faster, and the pool has no reason to want one.

Sized against real miners: a GF63 slice does about 387 H/s of yespower, so at a
12-bit share target (4,096 hashes) it submits one share every ten seconds or so.
That is 0.1 shares a second, and one core absorbs **thirteen hundred** of those
even at the 8 MiB setting.

**The knob that could hurt is the share target, and it is the operator's.** Set
it too low and a single miner submits constantly; one core saturates at 133
yespower-8 MiB validations a second, so anything above about one share per
second per miner means the target is wrong rather than the server small.

Network and disk are noise: a job is a few hundred bytes per coin per thirty
seconds, a share is under two hundred, and the ledger is a few kilobytes.

**Do not build on the small machine.** Cross-compile and copy one file:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

musl rather than gnu so the result is statically linked -- no glibc version to
match against whatever the host is running, no runtime dependencies, and the
whole daemon is a single artefact to copy. A weak box should not be asked to
hold a Rust toolchain.

### The record goes as files, not as an endpoint

`--ledger PATH` writes the share log as canonical JSON. A static site whose
history is a commit chain is **tamper-evident by construction**: a live JSON
endpoint can be quietly rewritten and a commit chain cannot, without it showing.
For a pool whose only asset is being checkable, that beats freshness. It is the
same trade `site.yml` already makes for the download tables, and the same reason
`godel`'s ledger is a file rather than a query.

Three details in the format, each with a worse alternative:

- **The digest covers the rows and not the file.** `generated_at` moves on
  every write, so hashing the whole document would make an unchanged log look
  edited at every republish -- and a record nobody can tell has changed is not
  evidence.
- **The rows are canonicalised to tab-separated text before hashing**, not to
  JSON. Two JSON writers can agree about a document and disagree about its
  bytes, over spacing or escaping, and the digest would then depend on which
  one ran.
- **The write goes through a temporary and a rename.** A publisher may be
  reading at any moment, and half a document is worse than a stale one: it
  parses up to the truncation and then does not.

Checked both ways -- a claim that the digest does not move when only the clock
does, and does move when a share arrives -- and cross-checked against Python's
`hashlib` on a real file: an empty log digests to `e3b0c442...`, which is
sha256 of nothing, computed here by the kernel's own sha256.

**It is not a Merkle root and does not claim to be.** A distributor needs a
tree whose leaves are per-address payouts and whose proofs a contract can
verify. This is a flat digest over a tally: it fixes the published record to a
value now, and gives the tree something to be checked against when it is built.

### What is not secured yet

The protocol is **plaintext**, and over the public internet that is a real
exposure rather than a theoretical one: worker names travel in the clear, and
anything between the miner and the pool can rewrite a job. The kernel has one
TLS session and the updater owns it -- `mine pool` refuses `stratum+tls://` by
name for that reason -- so a TLS miner needs `tls.rs` to stop being welded to
the single-connection API. Until then a miner on an untrusted network is
trusting the network, and that has to be said before anybody points a machine
at this rather than after.

## Non-custodial, which is a structure and not a promise

`design/mining.md` and the plan behind it settle this and it is repeated here
because it constrains the server rather than only the paperwork.

Layer 1, mining, holds nothing. Each miner's *own* address is the payout
address at the upstream pool, so proceeds never pass through anything this
server controls. That is the P2Pool shape and it is what keeps the operation
outside the custody question entirely.

Layer 2, the GLADOS reward, is the operator's fee revenue, which is the
operator's own money, converted and deposited into a Merkle distributor that
miners claim from. The 1,000,000 GLADOS gate is a `require` in the claim
contract rather than a check on this server, for the reason the token page
already gives about kernel-side gating: a check in software the holder can
rebuild is not a check.

**So the share log is the whole product of Layer 1**, and it has to be
published rather than merely kept. Per-worker share counts, each epoch's
Merkle root, every conversion transaction hash. With no treasury and no track
record, that is the only thing standing in for trust.

## What exists now

- `pool/src/lib.rs`, the shared core: twelve of the kernel's own files reached
  by `#[path]`, and the vectors under `cargo test`. Seventeen tests, 0.12 s.
- `src/mine/proto.rs`, the codec, shared by both ends for the same reason.
- `pool/src/pool.rs`, the coin table and share validation, with no socket
  anywhere in it.
- `pool/src/server.rs`, the listener.
- `glados-pool --selftest`, which is the whole path in one process:

```
[pool] listening on 127.0.0.1:63871
[pool] slot 0  selftest-a  sha256d  (local)
[pool] slot 1  selftest-b  blake2s (RFC 7693)  (local)
[pool] 127.0.0.1:63872 hello  worker=selftest.rig agent=glados-pool/selftest
[pool] selftest.rig share job=00000002 nonce=00002a63 -> accepted
[pool] selftest.rig share job=00000001 nonce=000001f7 -> accepted
ok    greeted, mined 2 coins (blake2s + sha256d), and every share was accepted
```

**Two coins is the test and one would not have been.** A pool serving two
coins down one connection while validating both under one algorithm passes a
single-coin check perfectly, and that is precisely the bug this protocol exists
to make impossible.

## And the kernel actually does it

`mine pool <host>:<port> glados` picks the dialect; the word is trailing rather
than a scheme, because a scheme would have to be invented while
`stratum+tcp://` is one people already paste from a pool's own page. Measured,
QEMU against the pool running on the host:

```
glados> mine coins
  slot  label       slices  source   rate            algorithm
  0     btc-ish     1       pool     248884 H/s      sha256d
        5 share(s) found
  1     verge-ish   1       pool     5506646 H/s     blake2s (RFC 7693)
        140 share(s) found
  2     zeny-ish    1       pool     342 H/s         yespower 1.0 N=2048 r=8
        6 share(s) found
```

```
[ledger] gl4d0s.rig1  btc-ish     5 accepted, 0 stale, 0 bad, 0 dup
[ledger] gl4d0s.rig1  verge-ish 166 accepted, 0 stale, 0 bad, 0 dup
[ledger] gl4d0s.rig1  zeny-ish    9 accepted, 0 stale, 0 bad, 0 dup
```

181 shares, every one recomputed at the other end and agreed with, across three
algorithms. **The three coins came from one TCP connection and one socket
task**, which is the thing four Stratum connections could not have done inside
`MAX_TASKS`.

**One bug, and it cost the first end-to-end run.** `stratum::classify` hands
back the whole message rather than the `result` field -- `subscribe_result`
unwraps it too, and the greeting did not. The pool logged the hello and logged
its answer; the kernel reported that nothing had answered. Two logs that both
look correct and disagree about whether a message arrived is the shape to
remember.

**`mine ev` had to learn to say less.** A glados job carries no nbits and no
coinbase, so the block printed `nbits 00000000` and a failed parse of a
zero-byte coinbase: three lines that read as three things being broken. It
names the absence now, which is `src/linux/proc.rs`'s rule -- a field this
machine does not know means the answer does not exist.

## What does not

- **The upstream.** Every coin's `Source` is `Local`, which means the pool
  builds the header itself and there is no chain behind it: a share that beat a
  network target would still be worth nothing. `Source::Upstream` is in the
  enum with no code behind it, so the report says "local" rather than implying
  otherwise. Filling it in is `stratum.rs` -- already shared -- driven by a
  host socket.
- Accounting beyond a per-worker tally: no VarDiff, no PPLNS, no persistence.
  `--ledger` writes the log every minute but nothing reads it back at start, so
  a restart begins from zero.
- TLS, and therefore any safety on an untrusted network. See above.
- The site repository, the DNS record, and the host. None of them exist yet.
- Worker identity, which is `supabase/functions/link` already and needs joining
  up rather than writing.
- Publishing any of it, which is the whole of B4 and the only thing standing in
  for trust.
- Any of it having met a real network.
