# The pool, and the one protocol it speaks downstream

Status: the pool listens, serves two coins on two algorithms down one
connection, and validates the shares that come back by recomputing them. No
coin has been mined against a real chain and nothing has crossed a real
network. What is settled here is the protocol, why it has the shape it has,
and what it costs.

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

## What does not

- **The upstream.** Every coin's `Source` is `Local`, which means the pool
  builds the header itself and there is no chain behind it: a share that beat a
  network target would still be worth nothing. `Source::Upstream` is in the
  enum with no code behind it, so the report says "local" rather than implying
  otherwise. Filling it in is `stratum.rs` -- already shared -- driven by a
  host socket.
- **The kernel speaking this protocol.** `src/mine/client.rs` still speaks
  Stratum V1 to one pool, so `mine coin` fills every slot but the pool's with a
  fixture. The codec is in the kernel and compiles; nothing calls it yet.
- Accounting beyond a per-worker tally: no VarDiff, no PPLNS, no persistence.
  The ledger prints to stdout every minute and is lost on restart.
- Worker identity, which is `supabase/functions/link` already and needs joining
  up rather than writing.
- Publishing any of it, which is the whole of B4 and the only thing standing in
  for trust.
- Any of it having met a real network.
