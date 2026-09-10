// The Merkle tree, in JavaScript, matching `GladosDistributor._leaf` and
// `_verify` exactly.
//
// There is a second implementation of this in `tools/distribute.py`, and the
// two are required to agree on the root for the same input. That is the same
// bargain `tokenizer.py --verify` makes with the kernel's tokenizer, and it
// exists for the same reason: a tree builder and a tree verifier that were
// written from one person's idea of the format agree with each other and with
// nothing else.
import { ethers } from "ethers";

const coder = ethers.AbiCoder.defaultAbiCoder();

/// **Double-hashed**, matching the contract. A singly-hashed leaf over
/// `abi.encode(address, uint256)` is 64 bytes, which is exactly the shape of an
/// internal node under sorted-pair hashing -- so it could be offered as one and
/// a proof forged around it. Hashing twice makes the leaf preimage 32 bytes.
export function leaf(account, amount) {
  const inner = ethers.keccak256(coder.encode(["address", "uint256"], [account, amount]));
  return ethers.keccak256(inner);
}

function parent(a, b) {
  const [x, y] = a.toLowerCase() <= b.toLowerCase() ? [a, b] : [b, a];
  return ethers.keccak256(coder.encode(["bytes32", "bytes32"], [x, y]));
}

/// Build the tree. `entries` is `[{account, amount}]`.
///
/// **An odd node is carried up rather than duplicated.** Duplicating the last
/// leaf is the other common convention and it is the one with a known flaw: a
/// tree of an odd number of leaves becomes indistinguishable from one where the
/// last leaf genuinely appears twice, which lets a proof for it be reused.
/// Carrying is what OpenZeppelin's builder does and what `_verify` above
/// implies, since a carried node simply contributes no proof element.
export function build(entries) {
  if (entries.length === 0) throw new Error("an empty tree has no root");
  // Sorted by account, so the same input always produces the same tree
  // whatever order the caller assembled it in -- the root is published and a
  // root that depends on map iteration order is not reproducible.
  const sorted = [...entries].sort((a, b) => (a.account.toLowerCase() < b.account.toLowerCase() ? -1 : 1));
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].account.toLowerCase() === sorted[i - 1].account.toLowerCase()) {
      throw new Error(`duplicate account in the tree: ${sorted[i].account}`);
    }
  }
  const leaves = sorted.map((e) => leaf(e.account, e.amount));
  const layers = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(i + 1 < prev.length ? parent(prev[i], prev[i + 1]) : prev[i]);
    }
    layers.push(next);
  }
  const index = new Map(sorted.map((e, i) => [e.account.toLowerCase(), i]));
  return {
    root: layers[layers.length - 1][0],
    entries: sorted,
    proof(account) {
      let i = index.get(account.toLowerCase());
      if (i === undefined) throw new Error(`${account} is not in this tree`);
      const out = [];
      for (let l = 0; l < layers.length - 1; l++) {
        const layer = layers[l];
        const sib = i ^ 1;
        if (sib < layer.length) out.push(layer[sib]);
        i = Math.floor(i / 2);
      }
      return out;
    },
  };
}
