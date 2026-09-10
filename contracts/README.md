# The claim contract

`GladosDistributor.sol` is Layer 2 of the pool: Layer 1 never holds a miner's
coins, and this distributes the operator's *own* fee revenue, converted to
GLADOS, against a Merkle root published from the share log.

```bash
npm install          # solc, an EVM, and an ABI coder. No framework.
npm run build        # compile
npm test             # 44 claims, mostly about what it refuses
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
