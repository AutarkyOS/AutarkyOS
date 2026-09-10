// Three implementations of one tree, required to agree.
//
//   tools/distribute.py   builds it, in Python, from the pool's own share log
//   test/merkle.mjs       builds it again, in JavaScript
//   GladosDistributor.sol verifies it, in EVM bytecode, and is the arbiter
//
// The first two agreeing is worth something; the first two agreeing with the
// *third* is the only thing that matters, because the third is what holds the
// tokens. This is `tokenizer.py --verify` applied to a payout.
//
//   node test/cross.mjs <epoch.json from distribute.py>
import fs from "node:fs";
import { ethers } from "ethers";
import { compile } from "./build.mjs";
import { makeVm, deploy, call, fund } from "./evm.mjs";
import { build } from "./merkle.mjs";

const OPERATOR = "0x1111111111111111111111111111111111111111";

let passed = 0;
let failed = 0;
function ok(cond, what) {
  cond ? passed++ : failed++;
  console.log(`${cond ? "ok  " : "FAIL"}  ${what}`);
}

const file = process.argv[2];
if (!file) {
  console.error("usage: node test/cross.mjs <epoch.json>");
  process.exit(2);
}
const doc = JSON.parse(fs.readFileSync(file, "utf8"));
const entries = Object.entries(doc.claims).map(([account, c]) => ({
  account: ethers.getAddress(account),
  amount: BigInt(c.amount),
}));

console.log(`${entries.length} claim(s), python root ${doc.root}`);

// 1. Does JavaScript build the same root from the same pairs?
const tree = build(entries);
ok(tree.root.toLowerCase() === doc.root.toLowerCase(),
   `javascript rebuilds the same root${tree.root.toLowerCase() === doc.root.toLowerCase() ? "" : `  (${tree.root})`}`);

// 2. Do the two produce the same proofs, element for element? Two builders can
//    agree on a root and disagree on a proof when one of them mishandles an odd
//    node, and only the proof is what a claimant actually sends.
let sameProofs = true;
for (const e of entries) {
  const mine = tree.proof(e.account).map((x) => x.toLowerCase());
  const theirs = doc.claims[e.account.toLowerCase()].proof.map((x) => x.toLowerCase());
  if (mine.length !== theirs.length || mine.some((x, i) => x !== theirs[i])) sameProofs = false;
}
ok(sameProofs, "and the same proof for every claim, element for element");

// 3. The arbiter. Every Python proof, against the compiled contract.
const art = compile(["GladosDistributor.sol", "TestToken.sol"]);
const dist = {
  abi: art["GladosDistributor.sol"].GladosDistributor.abi,
  bytecode: art["GladosDistributor.sol"].GladosDistributor.evm.bytecode.object,
};
const tok = {
  abi: art["TestToken.sol"].TestToken.abi,
  bytecode: art["TestToken.sol"].TestToken.evm.bytecode.object,
};
const vm = await makeVm();
await fund(vm, OPERATOR);
const token = await deploy(vm, OPERATOR, tok, [10n ** 27n]);
const at = await deploy(vm, OPERATOR, dist, [token, OPERATOR]);

let allVerify = true;
let sum = 0n;
for (const e of entries) {
  const c = doc.claims[e.account.toLowerCase()];
  sum += BigInt(c.amount);
  const r = await call(vm, OPERATOR, at, dist, "verifyProof",
    [c.proof, doc.root, e.account, BigInt(c.amount)]);
  if (!r.ok || r.result !== true) {
    allVerify = false;
    console.log(`      ${e.account} did not verify`);
  }
}
ok(allVerify, "every python proof verifies against the contract's own bytecode");
ok(sum === BigInt(doc.total), `the amounts sum to the declared total (${sum} vs ${doc.total})`);

// 4. And the negative, or the check above is satisfied by a verifier that says
//    yes to everything.
{
  const e = entries[0];
  const c = doc.claims[e.account.toLowerCase()];
  const r = await call(vm, OPERATOR, at, dist, "verifyProof",
    [c.proof, doc.root, e.account, BigInt(c.amount) + 1n]);
  ok(r.result === false, "and one wei more than the leaf does not");
}

// 5. The whole pipeline, end to end: fund an epoch with this exact root and
//    total, give every claimant the gate, and let them all claim. Anything the
//    builder got wrong about amounts or ordering shows up here as a claim that
//    reverts, or as an epoch that runs short on the last one.
{
  const GATE = 1_000_000n * 10n ** 18n;
  const total = BigInt(doc.total);
  await call(vm, OPERATOR, token, tok, "mint", [OPERATOR, total]);
  await call(vm, OPERATOR, token, tok, "approve", [at, total]);
  const stamp = (t, n) => ({ header: { timestamp: t, number: n, cliqueSigner: () => ({ toString: () => "0x0" }) } });
  const open = await call(vm, OPERATOR, at, dist, "openEpoch",
    [doc.root, total, GATE, 87_400n], { block: stamp(1000n, 1n) });
  ok(open.ok, "an epoch opens with the published root" + (open.ok ? "" : "  (" + open.reason + ")"));

  let allClaimed = true;
  let paid = 0n;
  for (const e of entries) {
    const c = doc.claims[e.account.toLowerCase()];
    await fund(vm, e.account);
    await call(vm, OPERATOR, token, tok, "mint", [e.account, GATE]);
    const before = await call(vm, OPERATOR, token, tok, "balanceOf", [e.account]);
    const r = await call(vm, e.account, at, dist, "claim",
      [0, BigInt(c.amount), c.proof], { block: stamp(1010n, 2n) });
    if (!r.ok) {
      allClaimed = false;
      console.log("      " + e.account + " could not claim: " + r.reason);
      continue;
    }
    const after = await call(vm, OPERATOR, token, tok, "balanceOf", [e.account]);
    if (after.result - before.result !== BigInt(c.amount)) allClaimed = false;
    paid += BigInt(c.amount);
  }
  ok(allClaimed, "every miner in the share log claims exactly their allocation");
  ok(paid === total, "and the epoch pays out to the wei with nothing left over (" + paid + ")");

  const e0 = await call(vm, OPERATOR, at, dist, "epochs", [0]);
  ok(e0.result[1] === e0.result[2], "the epoch's funded and claimed totals match");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
