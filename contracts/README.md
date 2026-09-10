# The claim contract

`GladosDistributor.sol` is Layer 2 of the pool: Layer 1 never holds a miner's
coins, and this distributes the operator's *own* fee revenue, converted to
GLADOS, against a Merkle root published from the share log.

```bash
npm install          # solc, an EVM, and an ABI coder. No framework.
npm run build        # compile
npm test             # 60 claims, mostly about what it refuses
```

The end-to-end check, which is the one that matters:

```bash
python ../tools/distribute.py ledger.json --total 1e24 --coin btc \
    --map workers.json --out epoch.json
node test/cross.mjs epoch.json
```

Three implementations of one tree, required to agree: `tools/distribute.py`
builds it in Python from the pool's own ledger, `test/merkle.mjs` builds it
again in JavaScript, and the compiled contract verifies it. The first two
agreeing is worth something; the first two agreeing with the **third** is the
only thing that matters, because the third is what holds the tokens.

`cross.mjs` then funds a real epoch with that root in a real EVM and has every
address in the ledger claim, so a builder that got amounts or ordering wrong
shows up as a claim that reverts rather than as a root that looks fine.

## Two ways an epoch can pay, and the arithmetic picks

`Direct` holds the reward token and a claim transfers it: one market buy, made
by the operator when they convert, and every claimant gets the same rate.

`Market` holds the quote token and **each claim is the claimant's own buy on
the pool**. Every claim moves the price, pays the token's buy tax into whatever
the token does with it, and appears on-chain as a trade rather than as an
operator handing out tokens converted somewhere nobody watched. The operator
never converts anything, so there is no conversion rate to have to trust.

It is not a better mode, it is a different trade, and the numbers decide:

| | pot | per claim | gas as a share of it |
|---|---:|---:|---:|
| 36h event, 256 miners | $0.54 | $0.0021 | 2,286% |
| 36h event, 800 miners | $1.68 | $0.0021 | 2,286% |
| a year, 1000 miners, quarterly | $127.75 | $0.1278 | 38% |
| a year, 1000 miners, yearly | $511.00 | $0.5110 | 9% |

A swap is about $0.048 of gas on this chain and a transfer $0.029, so a claim
has to be worth more than that before either mode pays for itself. `Market` is
right for a large annual epoch and absurd for a weekend.

The cost `Market` carries beyond gas is stated in the contract and asserted in
the tests: **the leaf is denominated in the quote token, so the first claimant
gets a better price than the last.** That is a race, it is inherent to paying
through a market rather than around one, and it is why `Direct` still exists.

## No hardhat, no foundry

What is needed is a compiler and an EVM, and each is one package. A framework
would bring a config file, a plugin system and a directory layout, none of which
this repository would then be able to explain the way it explains everything
else. `test/evm.mjs` is ninety lines and is the whole harness.

## What is not done

- **Not deployed.** No address, no verified source on any explorer.
- **Not reviewed by anybody.** Written and tested in one sitting. A contract
  that holds tokens should be read by somebody who did not write it.
- **The gate size is not decided.** `design/live800.md` shows 1,000,000 is
  unreachable for 800 entrants -- the pool holds 130 gates -- and that 50,000
  is the number that lets an event happen. The contract takes it per epoch and
  does not care.
- **No worker-to-address mapping service.** `distribute.py` takes a worker name
  that *is* an address, which is the convention every no-account pool uses, and
  a `--map` file otherwise. `supabase/functions/link` already does signature
  recovery and would replace the file.
