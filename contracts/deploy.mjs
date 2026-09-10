// Put the distributor on a real chain, and drive it.
//
//   node deploy.mjs status
//   node deploy.mjs deploy                       --send
//   node deploy.mjs open   epoch.json --amount 0.005 --send
//   node deploy.mjs claim  epoch.json --epoch 0      --send
//
// ### Simulation is the default and `--send` is the whole safety model
//
// Every command runs as `eth_call` against the live chain first and prints what
// would happen. Nothing is broadcast without `--send`. That is not politeness:
// the difference between a correct epoch and one funded with the wrong number
// is a transaction that succeeds either way, and the only moment anybody can
// catch it is before it is signed.
//
// ### The key is yours and this file never sees it twice
//
// Read from `GLADOS_KEY` in the environment, used to sign, and never printed,
// never written to a file, never included in an error message. If you are
// reading this to check that claim: search the file for `GLADOS_KEY` -- there
// are two uses, one to read it and one to refuse when it is absent.
//
// Use a wallet that holds what this event needs and nothing else. The operator
// address is immutable in the deployed contract, so it is also the one address
// that cannot be rotated afterwards.
import fs from "node:fs";
import { ethers } from "ethers";
import { compile } from "./test/build.mjs";

const RPC = process.env.GLADOS_RPC || "https://rpc.mainnet.chain.robinhood.com";
const TOKEN = process.env.GLADOS_TOKEN || "0x3d609ecafc6aa7dba67dd7ad1d10b49c52d57777";
const PAIR = process.env.GLADOS_PAIR || "0x93f777932d98d15b351d1bce8c76b34381eede5b";
const QUOTE = process.env.GLADOS_QUOTE || "0x0bd7d308f8e1639fab988df18a8011f41eacad73";

const argv = process.argv.slice(2);
const cmd = argv[0];
const SEND = argv.includes("--send");
const flag = (name, dflt) => {
  const i = argv.indexOf("--" + name);
  return i >= 0 ? argv[i + 1] : dflt;
};

const ERC20 = [
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address,address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function deposit() payable",
  "function decimals() view returns (uint8)",
];

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const net = await provider.getNetwork();

  const key = process.env.GLADOS_KEY;
  if (!key && cmd !== "status") {
    console.error("set GLADOS_KEY to the operator's private key, in the environment.");
    console.error("It is used to sign and is never printed or stored by this script.");
    console.error("  PowerShell:  $env:GLADOS_KEY = '0x...'");
    console.error("  bash:        export GLADOS_KEY=0x...");
    process.exit(2);
  }
  const wallet = key ? new ethers.Wallet(key, provider) : null;

  const art = compile(["GladosDistributor.sol"]);
  const D = art["GladosDistributor.sol"].GladosDistributor;
  const iface = new ethers.Interface(D.abi);

  const addrOf = flag("at", process.env.GLADOS_DISTRIBUTOR);

  // ------------------------------------------------------------- status
  if (cmd === "status") {
    console.log(`chain      ${net.chainId}`);
    console.log(`rpc        ${RPC}`);
    console.log(`token      ${TOKEN}`);
    console.log(`pair       ${PAIR}`);
    console.log(`quote      ${QUOTE}`);
    const pairC = new ethers.Contract(PAIR, [
      "function getReserves() view returns (uint112,uint112,uint32)",
    ], provider);
    const [r0, r1] = await pairC.getReserves();
    const qIs0 = BigInt(QUOTE) < BigInt(TOKEN);
    const [rq, rt] = qIs0 ? [r0, r1] : [r1, r0];
    console.log(`pool       ${ethers.formatEther(rq)} quote against ${ethers.formatEther(rt)} token`);
    if (wallet) {
      console.log(`operator   ${wallet.address}`);
      console.log(`  gas      ${ethers.formatEther(await provider.getBalance(wallet.address))} ETH`);
      const q = new ethers.Contract(QUOTE, ERC20, provider);
      console.log(`  quote    ${ethers.formatEther(await q.balanceOf(wallet.address))}`);
    }
    if (addrOf) {
      const d = new ethers.Contract(addrOf, D.abi, provider);
      const n = await d.epochCount();
      console.log(`distributor ${addrOf}, ${n} epoch(s)`);
      for (let i = 0n; i < n; i++) {
        const e = await d.epochs(i);
        console.log(`  #${i}  mode=${e.mode === 0n ? "Direct" : "Market"}  funded=${ethers.formatEther(e.funded)}` +
                    `  claimed=${ethers.formatEther(e.claimed)}  gate=${ethers.formatEther(e.gate)}`);
      }
    }
    return;
  }

  // ------------------------------------------------------------- deploy
  if (cmd === "deploy") {
    const factory = new ethers.ContractFactory(D.abi, D.bytecode, wallet);
    const tx = await factory.getDeployTransaction(TOKEN, wallet.address, PAIR, QUOTE);
    const gas = await provider.estimateGas({ ...tx, from: wallet.address });
    const price = (await provider.getFeeData()).gasPrice ?? 0n;
    console.log(`deploying with operator ${wallet.address}`);
    console.log(`  token ${TOKEN}\n  pair  ${PAIR}\n  quote ${QUOTE}`);
    console.log(`  gas   ${gas} at ${ethers.formatUnits(price, "gwei")} gwei = ${ethers.formatEther(gas * price)} ETH`);
    if (!SEND) return console.log("\nsimulated only. Add --send to broadcast.");
    const c = await factory.deploy(TOKEN, wallet.address, PAIR, QUOTE);
    console.log(`  tx    ${c.deploymentTransaction().hash}`);
    await c.waitForDeployment();
    const at = await c.getAddress();
    console.log(`\ndistributor at ${at}`);
    console.log(`export GLADOS_DISTRIBUTOR=${at}`);
    return;
  }

  if (!addrOf) {
    console.error("set GLADOS_DISTRIBUTOR or pass --at 0x...");
    process.exit(2);
  }
  const dist = new ethers.Contract(addrOf, D.abi, wallet);

  // --------------------------------------------------------------- open
  if (cmd === "open") {
    const doc = JSON.parse(fs.readFileSync(argv[1], "utf8"));
    const amount = ethers.parseEther(flag("amount", "0"));
    const gate = ethers.parseEther(flag("gate", "0"));
    const days = Number(flag("days", "30"));
    const deadline = BigInt(Math.floor(Date.now() / 1000) + days * 86400);
    if (amount === 0n) {
      console.error("--amount is required, in whole quote tokens (e.g. --amount 0.005)");
      process.exit(2);
    }

    const q = new ethers.Contract(QUOTE, ERC20, wallet);
    const have = await q.balanceOf(wallet.address);
    console.log(`epoch root  ${doc.root}`);
    console.log(`claims      ${Object.keys(doc.claims).length}`);
    console.log(`funding     ${ethers.formatEther(amount)} quote (you hold ${ethers.formatEther(have)})`);
    console.log(`gate        ${ethers.formatEther(gate)}`);
    console.log(`deadline    in ${days} day(s)`);
    if (have < amount) {
      console.error("\nnot enough quote token. Wrap some first:");
      console.error(`  node deploy.mjs wrap --amount ${ethers.formatEther(amount)} --send`);
      process.exit(1);
    }
    // **The leaves are denominated in the quote token**, so their sum has to be
    // what is funded. A mismatch is an epoch that either runs short on the last
    // claim or strands the difference until the deadline.
    const sum = Object.values(doc.claims).reduce((a, c) => a + BigInt(c.amount), 0n);
    if (sum !== amount) {
      console.error(`\nthe tree sums to ${ethers.formatEther(sum)} but --amount is ${ethers.formatEther(amount)}.`);
      console.error("Rebuild the epoch with --total equal to what you are funding.");
      process.exit(1);
    }
    if (!SEND) return console.log("\nsimulated only. Add --send to broadcast.");

    const allow = await q.allowance(wallet.address, addrOf);
    if (allow < amount) {
      const a = await q.approve(addrOf, amount);
      console.log(`  approve ${a.hash}`);
      await a.wait();
    }
    const tx = await dist.openEpochOnMarket(doc.root, amount, gate, deadline);
    console.log(`  open    ${tx.hash}`);
    const rc = await tx.wait();
    const ev = rc.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
      .find((x) => x && x.name === "EpochOpened");
    console.log(`\nepoch ${ev ? ev.args.epoch : "?"} open, funded ${ev ? ethers.formatEther(ev.args.funded) : "?"}`);
    return;
  }

  // -------------------------------------------------------------- claim
  if (cmd === "claim") {
    const doc = JSON.parse(fs.readFileSync(argv[1], "utf8"));
    const id = BigInt(flag("epoch", "0"));
    const me = wallet.address.toLowerCase();
    const c = doc.claims[me];
    if (!c) {
      console.error(`${wallet.address} is not in this epoch`);
      process.exit(1);
    }
    const check = await dist.checkClaim(id, wallet.address, BigInt(c.amount), c.proof);
    console.log(`claimable   ${check[0]}${check[0] ? "" : "  (" + check[1] + ")"}`);
    if (!check[0]) process.exit(1);

    // A slippage bound the claimant chooses, defaulting to 2% off what the pool
    // owes right now. Zero is refused by the contract, deliberately.
    const pairC = new ethers.Contract(PAIR, ["function getReserves() view returns (uint112,uint112,uint32)"], provider);
    const [r0, r1] = await pairC.getReserves();
    const qIs0 = BigInt(QUOTE) < BigInt(TOKEN);
    const [rq, rt] = qIs0 ? [r0, r1] : [r1, r0];
    const wf = BigInt(c.amount) * 997n;
    const out = (wf * rt) / (rq * 1000n + wf);
    const slip = BigInt(Math.round(Number(flag("slippage", "2")) * 100));
    const minOut = (out * (10000n - slip)) / 10000n;
    console.log(`spending    ${ethers.formatEther(BigInt(c.amount))} quote`);
    console.log(`pool owes   ${ethers.formatEther(out)} token before tax`);
    console.log(`minimum     ${ethers.formatEther(minOut)} (${flag("slippage", "2")}% tolerance)`);
    if (!SEND) return console.log("\nsimulated only. Add --send to broadcast.");

    const tx = await dist.claimOnMarket(id, BigInt(c.amount), c.proof, minOut);
    console.log(`  claim   ${tx.hash}`);
    const rc = await tx.wait();
    const ev = rc.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } })
      .find((x) => x && x.name === "Claimed");
    console.log(`\nreceived ${ev ? ethers.formatEther(ev.args.received) : "?"} GLADOS`);
    return;
  }

  // --------------------------------------------------------------- wrap
  if (cmd === "wrap") {
    const amount = ethers.parseEther(flag("amount", "0"));
    console.log(`wrapping ${ethers.formatEther(amount)} ETH into ${QUOTE}`);
    if (!SEND) return console.log("simulated only. Add --send to broadcast.");
    const q = new ethers.Contract(QUOTE, ERC20, wallet);
    const tx = await q.deposit({ value: amount });
    console.log(`  ${tx.hash}`);
    await tx.wait();
    console.log(`now holding ${ethers.formatEther(await q.balanceOf(wallet.address))}`);
    return;
  }

  console.error("commands: status, deploy, wrap, open, claim");
  process.exit(2);
}

main().catch((e) => {
  // Deliberately not `console.error(e)`: an ethers error can carry the
  // transaction it was signing, and a signed transaction is not a secret but
  // the habit of dumping whole objects near a wallet is a bad one to build.
  console.error(e.shortMessage || e.message || String(e));
  process.exit(1);
});
