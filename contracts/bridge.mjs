// The conversion leg: get mining proceeds onto 4663, ready to fund an epoch.
//
//   node bridge.mjs status
//   node bridge.mjs routes
//   node bridge.mjs quote --amount 100 --chain 137
//   node bridge.mjs send  --amount 100 --chain 137 --send
//
// ### What this does and where it starts
//
// The whole conversion is five legs and only one of them is a transaction
// anybody has to build:
//
//   mine -> pool credits a balance      the venue does this
//        -> pays out to your address    the venue does this, at a threshold
//        -> [swap to a bridgeable token] avoidable, see below
//        -> bridge to 4663              THIS FILE
//        -> fund an epoch               deploy.mjs open
//
// **The swap is avoidable and that is worth more than automating it.**
// unMineable pays POL on Polygon, which has to be sold for USDC before it can
// cross. Kryptex pays USDC on Polygon directly, and Across carries USDC from
// Polygon to USDG on 4663 in one hop. Choosing the venue that pays the token
// the bridge already takes removes a DEX integration, a slippage bound and a
// second approval from a path that moves real money. `design/payout.md` has
// the fee comparison; this is the operational argument for the same choice.
//
// ### Simulation is the default, exactly as in deploy.mjs
//
// Nothing is broadcast without `--send`. The difference between a correct
// bridge deposit and one that goes nowhere is a transaction that succeeds
// either way -- the failure is not a revert, it is money sitting in a
// SpokePool with an output amount no relayer will fill. The only moment to
// catch that is before signing.
//
// ### Three numbers that must come from the quote and never from here
//
// `outputAmount`, `quoteTimestamp` and `exclusiveRelayer` are Across's, read
// from its own suggested-fees response and passed through untouched.
// Recomputing any of them locally is how a deposit becomes unfillable: the
// relayer prices the fill against the quote it issued, and a deposit naming a
// different output is one nobody is obliged to take. It would not revert. It
// would simply never arrive.
import { ethers } from "ethers";

const API = process.env.ACROSS_API || "https://app.across.to/api";
const DEST = 4663;
const DEST_RPC = process.env.GLADOS_RPC || "https://rpc.mainnet.chain.robinhood.com";

// The destination side. USDG is what a Market or MarketV3 epoch is funded in.
const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
const WETH_4663 = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73";

// Origin chains worth naming, with an RPC each. Only the ones a mining venue
// actually pays out on: Across carries sixteen and listing all of them here
// would be a table nobody maintains.
const ORIGINS = {
  137: {
    name: "Polygon",
    rpc: process.env.POLYGON_RPC || "https://polygon-bor-rpc.publicnode.com",
    tokens: { USDC: { at: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6 } },
  },
  8453: {
    name: "Base",
    rpc: process.env.BASE_RPC || "https://base-rpc.publicnode.com",
    tokens: { USDC: { at: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6 } },
  },
  42161: {
    name: "Arbitrum",
    rpc: process.env.ARBITRUM_RPC || "https://arbitrum-one-rpc.publicnode.com",
    tokens: { USDC: { at: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 } },
  },
};

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
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
];

// Confirmed present on the live Polygon SpokePool's *implementation* -- the
// address Across's API returns is a 680-byte ERC-1967 proxy, and probing it
// directly says every function is absent. Same trap the tokenized stocks set.
const SPOKE = [
  "function depositV3(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message) payable",
];

async function api(path) {
  const r = await fetch(API + path);
  const text = await r.text();
  if (!r.ok) {
    // **The too-low case arrives as a 400, not as `isAmountTooLow`.** The flag
    // exists in the success body and is documented, so the first version of
    // this checked only that and let the real refusal surface as a raw API
    // error with an id in it -- which reads like the bridge is broken rather
    // than like the amount is small. Measured against the live API: 0.01 USDC
    // from Polygon returns 400 AMOUNT_TOO_LOW.
    let code = "";
    try {
      code = JSON.parse(text).code || "";
    } catch { /* not JSON; fall through to the raw message */ }
    if (code === "AMOUNT_TOO_LOW") {
      const e = new Error("amount too low");
      e.tooLow = true;
      throw e;
    }
    throw new Error(`Across ${r.status}: ${text.slice(0, 300)}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Across answered something that is not JSON: ${text.slice(0, 200)}`);
  }
}

function originOf(id) {
  const o = ORIGINS[id];
  if (!o) {
    console.error(`chain ${id} is not one this script carries an RPC for.`);
    console.error(`known: ${Object.keys(ORIGINS).join(", ")}`);
    console.error("Across reaches 4663 from sixteen chains; `routes` lists them.");
    process.exit(2);
  }
  return o;
}

async function main() {
  // ------------------------------------------------------------- routes
  //
  // Read from Across rather than written down, because a table of routes in a
  // source file is a table that is wrong the first time one is added.
  if (cmd === "routes") {
    const rs = await api(`/available-routes?destinationChainId=${DEST}`);
    const by = new Map();
    for (const r of rs) {
      const k = r.originChainId;
      if (!by.has(k)) by.set(k, new Set());
      by.get(k).add(`${r.originTokenSymbol}->${r.destinationTokenSymbol}`);
    }
    console.log(`${rs.length} route(s) into ${DEST}\n`);
    for (const k of [...by.keys()].sort((a, b) => a - b)) {
      const mine = ORIGINS[k] ? "  <- this script can send from here" : "";
      console.log(`  ${String(k).padEnd(7)} ${[...by.get(k)].sort().join("  ")}${mine}`);
    }
    return;
  }

  const key = process.env.GLADOS_KEY;
  if (!key && cmd === "send") {
    console.error("set GLADOS_KEY to the operator's private key, in the environment.");
    console.error("It is used to sign and is never printed or stored by this script.");
    process.exit(2);
  }

  // ------------------------------------------------------------- status
  //
  // Where the money is, on both sides, in one place. The question an operator
  // actually has mid-conversion is "did it arrive yet", and the honest answer
  // is two balance reads rather than a bridge explorer.
  if (cmd === "status") {
    const who = flag("address", key ? new ethers.Wallet(key).address : null);
    if (!who) {
      console.error("pass --address, or set GLADOS_KEY so this can derive it.");
      process.exit(2);
    }
    console.log(`operator   ${who}\n`);

    const dp = new ethers.JsonRpcProvider(DEST_RPC);
    for (const [sym, at] of [["USDG", USDG], ["WETH", WETH_4663]]) {
      const c = new ethers.Contract(at, ERC20, dp);
      const [bal, dec] = await Promise.all([c.balanceOf(who), c.decimals()]);
      console.log(`  ${DEST}  ${sym.padEnd(5)} ${ethers.formatUnits(bal, dec)}`);
    }
    for (const [id, o] of Object.entries(ORIGINS)) {
      for (const [sym, t] of Object.entries(o.tokens)) {
        try {
          const p = new ethers.JsonRpcProvider(o.rpc);
          const c = new ethers.Contract(t.at, ERC20, p);
          const bal = await c.balanceOf(who);
          console.log(`  ${String(id).padEnd(5)} ${sym.padEnd(5)} ${ethers.formatUnits(bal, t.decimals)}  (${o.name})`);
        } catch (e) {
          // A dead public RPC is not an empty balance, and printing zero here
          // would be a number somebody plans against.
          console.log(`  ${String(id).padEnd(5)} ${sym.padEnd(5)} unknown, ${o.name} RPC did not answer`);
        }
      }
    }
    console.log("\nUSDG on 4663 is what `deploy.mjs open --amount` spends.");
    return;
  }

  // -------------------------------------------------------- quote / send
  if (cmd !== "quote" && cmd !== "send") {
    console.error("usage: node bridge.mjs status|routes|quote|send");
    process.exit(2);
  }

  const chainId = Number(flag("chain", "137"));
  const symbol = flag("token", "USDC");
  const origin = originOf(chainId);
  const tok = origin.tokens[symbol];
  if (!tok) {
    console.error(`${origin.name} entry here carries ${Object.keys(origin.tokens).join(", ")}`);
    process.exit(2);
  }
  const amountStr = flag("amount", "");
  if (!amountStr) {
    console.error("--amount is required, in whole tokens (e.g. --amount 100)");
    process.exit(2);
  }
  const amount = ethers.parseUnits(amountStr, tok.decimals);
  const outputToken = flag("out", USDG);

  // Too low is a refusal and not a warning, whichever way it arrives. Under
  // the minimum a deposit can still be made and no relayer will fill it, which
  // looks exactly like a bridge that lost the money.
  let q;
  try {
    q = await api(
      `/suggested-fees?inputToken=${tok.at}&outputToken=${outputToken}` +
      `&originChainId=${chainId}&destinationChainId=${DEST}&amount=${amount}`
    );
  } catch (e) {
    if (!e.tooLow) throw e;
    console.error(`${amountStr} ${symbol} is below what Across will route on this path.`);
    console.error("The fee is nearly all flat relayer gas, so small trips are");
    console.error("dominated by it. Send more, or the deposit sits unfilled.");
    process.exit(1);
  }
  if (q.isAmountTooLow) {
    console.error(`${amountStr} ${symbol} is below what Across will route on this path.`);
    process.exit(1);
  }

  const fee = BigInt(q.totalRelayFee.total);
  const out = amount - fee;
  const pct = Number((fee * 1000000n) / amount) / 10000;

  console.log(`from       ${origin.name} (${chainId})  ${symbol}`);
  console.log(`to         ${DEST}  ${outputToken === USDG ? "USDG" : outputToken}`);
  console.log(`send       ${ethers.formatUnits(amount, tok.decimals)}`);
  console.log(`fee        ${ethers.formatUnits(fee, tok.decimals)}  (${pct.toFixed(4)}%)`);
  console.log(`  capital  ${ethers.formatUnits(q.capitalFeeTotal, tok.decimals)}`);
  console.log(`  relay gas ${ethers.formatUnits(q.relayGasFeeTotal, tok.decimals)}`);
  console.log(`  lp       ${ethers.formatUnits(q.lpFeePct === "0" ? 0n : (amount * BigInt(q.lpFeePct)) / 10n ** 18n, tok.decimals)}`);
  console.log(`receive    ${ethers.formatUnits(out, tok.decimals)}`);
  console.log(`fill       ~${q.estimatedFillTimeSec}s`);
  console.log(`spoke      ${q.spokePoolAddress}`);

  if (cmd === "quote") {
    console.log("\nA quote is not a fill. `send` broadcasts; `send --send` really does.");
    return;
  }

  // ---------------------------------------------------------------- send
  const provider = new ethers.JsonRpcProvider(origin.rpc);
  const wallet = new ethers.Wallet(key, provider);
  const erc = new ethers.Contract(tok.at, ERC20, wallet);
  const have = await erc.balanceOf(wallet.address);
  console.log(`\nyou hold   ${ethers.formatUnits(have, tok.decimals)} ${symbol} on ${origin.name}`);
  if (have < amount) {
    console.error("not enough to send that.");
    process.exit(1);
  }

  // **The recipient is always the sender.** There is no flag for it and there
  // should not be: this script exists to move the operator's own float onto
  // 4663, and a recipient argument is one typo away from bridging the event's
  // funding to a stranger, irreversibly, with the transaction succeeding.
  const recipient = wallet.address;
  // Across recommends a deadline a few hours out. Short enough that an
  // unfilled deposit becomes refundable rather than pending forever; long
  // enough that a busy relayer set still takes it.
  const fillDeadline = Math.floor(Date.now() / 1000) + 3 * 3600;

  console.log(`recipient  ${recipient}  (always you)`);
  console.log(`deadline   ${new Date(fillDeadline * 1000).toISOString()}`);

  if (!SEND) {
    console.log("\nsimulated only. Add --send to broadcast.");
    return;
  }

  const allow = await erc.allowance(wallet.address, q.spokePoolAddress);
  if (allow < amount) {
    const a = await erc.approve(q.spokePoolAddress, amount);
    console.log(`  approve  ${a.hash}`);
    await a.wait();
  }

  const spoke = new ethers.Contract(q.spokePoolAddress, SPOKE, wallet);
  const tx = await spoke.depositV3(
    wallet.address,
    recipient,
    tok.at,
    outputToken,
    amount,
    out,                                  // Across's number, not ours
    DEST,
    q.exclusiveRelayer,
    Number(q.timestamp),                  // Across's quote timestamp
    fillDeadline,
    Number(q.exclusivityDeadline),
    "0x"
  );
  console.log(`  deposit  ${tx.hash}`);
  await tx.wait();
  console.log(`\ndeposited. Watch it land with:\n  node bridge.mjs status`);
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
