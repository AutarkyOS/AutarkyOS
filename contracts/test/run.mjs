// What the distributor must do, and the much longer list of what it must refuse.
//
// A distributor that pays a valid claim is half checked, and it is the wrong
// half: the interesting behaviour of a contract holding somebody's tokens is
// every path where it says no. So most of what follows is refusals, and each
// one asserts *which* refusal -- getting the wrong one is a real failure and
// "it reverted" hides it.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { compile } from "./build.mjs";
import { makeVm, deploy, call, fund } from "./evm.mjs";
import { build, leaf } from "./merkle.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

let passed = 0;
let failed = 0;
function ok(cond, what) {
  if (cond) {
    passed++;
    console.log(`ok    ${what}`);
  } else {
    failed++;
    console.log(`FAIL  ${what}`);
  }
}
function eq(a, b, what) {
  ok(String(a) === String(b), `${what}${String(a) === String(b) ? "" : `  (got ${a}, wanted ${b})`}`);
}

const OPERATOR = "0x1111111111111111111111111111111111111111";
const STRANGER = "0x2222222222222222222222222222222222222222";
const A = "0x00000000000000000000000000000000000000aa";
const B = "0x00000000000000000000000000000000000000bb";
const C = "0x00000000000000000000000000000000000000cc";
const D = "0x00000000000000000000000000000000000000dd";

const ONE = 10n ** 18n;
const GATE = 1_000_000n * ONE;
const DAY = 86_400n;

function artifacts() {
  const c = compile(["GladosDistributor.sol", "TestToken.sol"]);
  return {
    dist: {
      abi: c["GladosDistributor.sol"].GladosDistributor.abi,
      bytecode: c["GladosDistributor.sol"].GladosDistributor.evm.bytecode.object,
    },
    token: {
      abi: c["TestToken.sol"].TestToken.abi,
      bytecode: c["TestToken.sol"].TestToken.evm.bytecode.object,
    },
  };
}

/// A block whose timestamp we control, because half of what this contract does
/// is about a deadline and a test that cannot move the clock cannot check it.
function at(ts) {
  return { header: { timestamp: ts, number: 1n, cliqueSigner: () => ({ toString: () => "0x0" }) } };
}

async function main() {
  const art = artifacts();
  const vm = await makeVm();
  for (const a of [OPERATOR, STRANGER, A, B, C, D]) await fund(vm, a);

  const token = await deploy(vm, OPERATOR, art.token, [10n ** 27n]);
  const dist = await deploy(vm, OPERATOR, art.dist, [token, OPERATOR]);

  // Everybody who will claim holds exactly the gate, except D, who holds one
  // short -- the boundary is where a `>=` becomes a `>` by accident.
  for (const [who, bal] of [[A, GATE], [B, GATE * 5n], [C, GATE], [D, GATE - 1n]]) {
    await call(vm, OPERATOR, token, art.token, "mint", [who, bal]);
  }

  const entries = [
    { account: A, amount: 100n * ONE },
    { account: B, amount: 250n * ONE },
    { account: C, amount: 650n * ONE },
  ];
  const tree = build(entries);
  const total = entries.reduce((s, e) => s + e.amount, 0n);

  // ---------------------------------------------------- the leaf format
  {
    const r = await call(vm, OPERATOR, dist, art.dist, "leafOf", [A, 100n * ONE]);
    eq(r.result, leaf(A, 100n * ONE), "the JS leaf matches the contract's leaf");
  }

  // ---------------------------------------------------- opening an epoch
  {
    const r = await call(vm, STRANGER, dist, art.dist, "openEpoch", [tree.root, total, GATE, 1_000_000n]);
    eq(r.reason, "NotOperator", "a stranger cannot open an epoch");
  }
  {
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [ethers.ZeroHash, total, GATE, 1_000_000n], { block: at(1000n) });
    eq(r.reason, "NoRoot", "an empty root is refused");
  }
  {
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [tree.root, total, GATE, 500n], { block: at(1000n) });
    eq(r.reason, "DeadlineInPast", "a deadline already past is refused");
  }
  {
    // No approval yet, so the pull must fail rather than create an epoch that
    // exists and cannot pay.
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [tree.root, total, GATE, 1_000_000n], { block: at(1000n) });
    eq(r.reason, "TransferFailed", "an unfunded epoch is not created");
    const n = await call(vm, OPERATOR, dist, art.dist, "epochCount");
    eq(n.result, 0n, "and no epoch was recorded");
  }

  await call(vm, OPERATOR, token, art.token, "approve", [dist, 10n ** 27n]);
  const DEADLINE = 1000n + 30n * DAY;
  {
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [tree.root, total, GATE, DEADLINE], { block: at(1000n) });
    ok(r.ok, "the operator opens epoch 0");
    const e = await call(vm, OPERATOR, dist, art.dist, "epochs", [0]);
    eq(e.result[1], total, "the epoch records what actually arrived");
  }

  // ---------------------------------------------------------- claiming
  {
    const r = await call(vm, A, dist, art.dist, "claim",
      [0, 100n * ONE, tree.proof(A)], { block: at(2000n) });
    ok(r.ok, "a holder with a valid proof claims");
    const bal = await call(vm, A, token, art.token, "balanceOf", [A]);
    eq(bal.result, GATE + 100n * ONE, "and receives exactly the leaf amount");
  }
  {
    const r = await call(vm, A, dist, art.dist, "claim",
      [0, 100n * ONE, tree.proof(A)], { block: at(2000n) });
    eq(r.reason, "AlreadyClaimed", "the same claim a second time is refused");
  }
  {
    // B's proof, but A's amount. The leaf is a pair and a proof is only valid
    // for the pair it was built from.
    const r = await call(vm, B, dist, art.dist, "claim",
      [0, 100n * ONE, tree.proof(B)], { block: at(2000n) });
    eq(r.reason, "BadProof", "claiming somebody else's amount is refused");
  }
  {
    const r = await call(vm, B, dist, art.dist, "claim",
      [0, 250n * ONE, tree.proof(A)], { block: at(2000n) });
    eq(r.reason, "BadProof", "claiming with somebody else's proof is refused");
  }
  {
    const r = await call(vm, STRANGER, dist, art.dist, "claim",
      [0, 100n * ONE, tree.proof(A)], { block: at(2000n) });
    // A stranger holds no tokens, so the gate stops them before the proof does.
    ok(r.reason.startsWith("BelowGate"), `an address not in the tree is refused (${r.reason})`);
  }

  // ----------------------------------------------------------- the gate
  {
    // D is in no tree at all but is one wei short of the gate, which is the
    // boundary this check exists for.
    const r = await call(vm, D, dist, art.dist, "claim",
      [0, 1n, []], { block: at(2000n) });
    ok(r.reason.startsWith("BelowGate"), `one wei below the gate is refused (${r.reason})`);
  }
  {
    // C sells down below the gate after mining, and forfeits. Intended: the
    // gate is a holding requirement rather than an entry fee.
    await call(vm, C, token, art.token, "transfer", [STRANGER, 1n]);
    const r = await call(vm, C, dist, art.dist, "claim",
      [0, 650n * ONE, tree.proof(C)], { block: at(2000n) });
    ok(r.reason.startsWith("BelowGate"), "selling below the gate before claiming forfeits");
    // And buying back restores it, so the check is on the balance now rather
    // than on a flag set once.
    await call(vm, STRANGER, token, art.token, "transfer", [C, 1n]);
    const back = await call(vm, C, dist, art.dist, "checkClaim", [0, C, 650n * ONE, tree.proof(C)],
      { block: at(2000n) });
    eq(back.result[0], true, "and buying back restores it");
  }

  // ------------------------------------------------------ checkClaim view
  {
    const r = await call(vm, A, dist, art.dist, "checkClaim", [0, A, 100n * ONE, tree.proof(A)],
      { block: at(2000n) });
    eq(r.result[1], "already claimed", "checkClaim explains an already-claimed claim");
    const s = await call(vm, A, dist, art.dist, "checkClaim", [0, STRANGER, 1n, []], { block: at(2000n) });
    eq(s.result[1], "below the gate", "checkClaim explains a gate failure");
    const bad = await call(vm, A, dist, art.dist, "checkClaim", [0, B, 999n * ONE, tree.proof(B)],
      { block: at(2000n) });
    eq(bad.result[1], "proof does not match the root", "checkClaim explains a bad proof");
  }

  // --------------------------------------------------------- the deadline
  {
    const r = await call(vm, B, dist, art.dist, "claim",
      [0, 250n * ONE, tree.proof(B)], { block: at(DEADLINE + 1n) });
    eq(r.reason, "EpochClosed", "a claim after the deadline is refused");
  }
  {
    const r = await call(vm, OPERATOR, dist, art.dist, "reclaim", [0], { block: at(2000n) });
    eq(r.reason, "EpochOpen", "the operator cannot reclaim before the deadline");
  }
  {
    const r = await call(vm, STRANGER, dist, art.dist, "reclaim", [0], { block: at(DEADLINE + 1n) });
    eq(r.reason, "NotOperator", "a stranger cannot reclaim");
  }
  {
    const before = await call(vm, OPERATOR, token, art.token, "balanceOf", [OPERATOR]);
    const r = await call(vm, OPERATOR, dist, art.dist, "reclaim", [0], { block: at(DEADLINE + 1n) });
    ok(r.ok, "the operator reclaims the remainder after the deadline");
    const after = await call(vm, OPERATOR, token, art.token, "balanceOf", [OPERATOR]);
    // A claimed 100; B and C never did. So 900 goes back.
    eq(after.result - before.result, 900n * ONE, "and gets back exactly what nobody claimed");
    const again = await call(vm, OPERATOR, dist, art.dist, "reclaim", [0], { block: at(DEADLINE + 2n) });
    eq(again.reason, "AlreadyReclaimed", "and cannot reclaim twice");
  }

  // -------------------------------------------- a token that takes a cut
  //
  // The real token does not tax wallet-to-wallet transfers -- read off the
  // chain rather than assumed. This is the test for being wrong about that:
  // the epoch must record what arrived, not what was asked for, so the
  // contract can never promise more than it holds.
  {
    await call(vm, OPERATOR, token, art.token, "setTax", [500, STRANGER]); // 5%
    const t2 = build([{ account: A, amount: 100n * ONE }]);
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [t2.root, 100n * ONE, 0n, DEADLINE * 2n], { block: at(1000n) });
    ok(r.ok, "an epoch opens even when the token takes a cut");
    const e = await call(vm, OPERATOR, dist, art.dist, "epochs", [1]);
    eq(e.result[1], 95n * ONE, "and records the 95 that arrived, not the 100 requested");
    // The claim for 100 is now more than the epoch holds, and it is refused
    // here rather than as a failed transfer for whoever claims last.
    const c = await call(vm, A, dist, art.dist, "claim", [1, 100n * ONE, t2.proof(A)],
      { block: at(2000n) });
    ok(c.reason.startsWith("Insolvent"), `an over-promised claim is refused as insolvent (${c.reason})`);
    await call(vm, OPERATOR, token, art.token, "setTax", [0, STRANGER]);
  }

  // ------------------------------------------------------- reentrancy
  //
  // The token calls back into the distributor during the transfer, trying the
  // same claim again. Effects land before the interaction, so the reentrant
  // call must find `hasClaimed` already true.
  {
    const t3 = build([{ account: A, amount: 10n * ONE }, { account: B, amount: 10n * ONE }]);
    await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [t3.root, 20n * ONE, 0n, DEADLINE * 3n], { block: at(1000n) });
    const iface = new ethers.Interface(art.dist.abi);
    const reenter = iface.encodeFunctionData("claim", [2, 10n * ONE, t3.proof(A)]);
    await call(vm, OPERATOR, token, art.token, "setHook", [dist, reenter]);
    const before = await call(vm, A, token, art.token, "balanceOf", [A]);
    const r = await call(vm, A, dist, art.dist, "claim", [2, 10n * ONE, t3.proof(A)],
      { block: at(2000n) });
    ok(r.ok, "a claim succeeds while the token reenters");
    const after = await call(vm, A, token, art.token, "balanceOf", [A]);
    eq(after.result - before.result, 10n * ONE, "and the reentrant claim paid nothing extra");
    const e = await call(vm, OPERATOR, dist, art.dist, "epochs", [2]);
    eq(e.result[2], 10n * ONE, "the epoch counted one claim, not two");
    await call(vm, OPERATOR, token, art.token, "setHook", [ethers.ZeroAddress, "0x"]);
  }

  // ------------------------------------------- a token that returns nothing
  {
    await call(vm, OPERATOR, token, art.token, "setSilent", [true]);
    const t4 = build([{ account: A, amount: 7n * ONE }]);
    const r = await call(vm, OPERATOR, dist, art.dist, "openEpoch",
      [t4.root, 7n * ONE, 0n, DEADLINE * 4n], { block: at(1000n) });
    ok(r.ok, "a token that returns no data still works");
    const c = await call(vm, A, dist, art.dist, "claim", [3, 7n * ONE, t4.proof(A)], { block: at(2000n) });
    ok(c.ok, "and the claim against it succeeds");
    await call(vm, OPERATOR, token, art.token, "setSilent", [false]);
  }

  // ------------------------------------------------- the tree itself
  {
    // A single-leaf tree has an empty proof, and it is the shape most easily
    // got wrong -- the loop never runs and the root is the leaf.
    const one = build([{ account: A, amount: 1n }]);
    eq(one.root, leaf(A, 1n), "a one-leaf tree's root is its leaf");
    eq(one.proof(A).length, 0, "and its proof is empty");
    // Odd counts, which is where carry-versus-duplicate would show.
    for (const n of [2, 3, 5, 7, 8, 9, 33]) {
      const es = [];
      for (let i = 0; i < n; i++) {
        es.push({ account: ethers.getAddress("0x" + (i + 1).toString(16).padStart(40, "0")), amount: BigInt(i + 1) });
      }
      const t = build(es);
      // **Verified by the contract, not by the builder that made them.** A
      // proof folded with the same code that built the tree agrees with itself
      // whatever the rules are -- reversed handedness, a singly-hashed leaf, a
      // duplicated odd node all pass. The arbiter has to be the bytecode.
      let allOk = true;
      for (const e of es) {
        const v = await call(vm, OPERATOR, dist, art.dist, "verifyProof",
          [t.proof(e.account), t.root, e.account, e.amount]);
        if (!v.ok || v.result !== true) allOk = false;
      }
      // And a proof from the wrong tree must not verify, or the check above is
      // satisfied by a verifier that says yes to everything.
      const other = build(es.map((e) => ({ account: e.account, amount: e.amount + 1n })));
      const wrong = await call(vm, OPERATOR, dist, art.dist, "verifyProof",
        [other.proof(es[0].account), t.root, es[0].account, es[0].amount]);
      if (wrong.result === true) allOk = false;
      ok(allOk, `every proof verifies against the contract in a tree of ${n}, and a foreign one does not`);
    }
    let threw = false;
    try {
      build([{ account: A, amount: 1n }, { account: A, amount: 2n }]);
    } catch {
      threw = true;
    }
    ok(threw, "a duplicate account in one tree is refused at build time");
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  fs.writeFileSync(path.join(here, "..", "out", "root.txt"), tree.root + "\n");
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
