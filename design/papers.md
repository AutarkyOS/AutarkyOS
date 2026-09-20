# Four mining papers, against the `pool/` and `miner/` this repo actually has

A research note, kept for the reason the SGD head and the Product-of-Experts
council are kept: three of the four papers turned out to be about a different
problem, and knowing *which* different problem is worth more than a summary
that made them fit. Nothing here is a citation this project earned by wanting
one.

Read `design/pool.md` and `pool/src/pool.rs`'s `Window` first if you have not;
this brief argues against them by name.

**What was checked against the code rather than taken on trust**, since the
brief was compiled by an agent and its value is in the specifics: `make_job`
does build the wire target from `target_with_leading_zeros(bits)` and
`up_target` appears only inside `Issued.up`, so the oblivious-share reading
holds; `Contribution.work` is `2^bits` and carries nothing about the network;
and `choose` is least-virtual-time with every weight 1. The parts drawn from
Rosenfeld have since been written into `Window`'s own doc comment and into
`market.rs`'s header, which is where somebody changing those decisions will
actually be standing.

**What was not checked**: the provenance table below is the agent's own, and
paper 4 is flagged there as abstract-only. That flag is the most useful line in
the document and is left exactly as it was written.

## Verdict, up front

**Three of the four papers are about a different problem, and the fourth is
about a third problem again. None of them is about a small Stratum proxy, a
PPLNS window, or splitting one GPU across coins.**

| | setting | applicable here |
|---|---|---|
| 1. Wang, Liew, Zhang (2021) | selfish mining / block withholding by an adversary with fraction α of one chain's hashpower | **no** |
| 2. Soria, Moya, Mohazab (2023) | industry-equilibrium economics: how much hash a rational miner buys, as a function of reward, cost, N | **partly, and only as one FOC** |
| 3. Li et al. (2025) survey | a survey of exactly paper 1's problem, across protocols | **no**, but it is a good map of what paper 1 belongs to |
| 4. Pankovska, Sai, Vranken (2023) | designing a *protocol-level* incentive that rewards renewable-energy miners with higher block-selection probability | **no** -- it is not about pool payout schemes at all |

Papers 1 and 3 are the selfish-mining literature. That is a miner with
meaningful hashpower deciding whether to publish a block it found. This pool
relays work upstream and credits miners; it never decides whether to publish
anything, and this project's whole machine earns $0.07/day. The α at which any
result in those papers becomes interesting is 0.12 at the very lowest (paper 3,
Table 2). There is no reading under which this system is that miner.

Paper 4 is the one the brief was expected to land on and it does not. It is
about green-energy incentive design at the consensus layer. It contains nothing
about PPLNS, PPS, proportional payment, pool-hopping, or block withholding.

**The one thing in this brief that is directly implementable did not come from
any of the four papers.** It came from chasing the question they failed to
answer -- see [What actually answers your three questions](#what-actually-answers-your-three-questions).
Rosenfeld (2011) gives a closed-form variance/maturity tradeoff for the PPLNS
window, and a named attack the current `Window` is exposed to.

## Provenance -- what I actually read

Stated because a confidently wrong summary is worse than a gap.

| | obtained | route |
|---|---|---|
| 1 | **full text** | ar5iv HTML of arXiv:1911.12942 |
| 2 | **full text**, CC-BY | Helda (U. Helsinki) bitstream of the published FRL PDF, plus the author's own essay summary in Mohazab's Aalto dissertation |
| 3 | **full text** | arXiv HTML of arXiv:2502.17307v1 |
| 4 | **abstract and metadata only -- NOT the full text** | Semantic Scholar (verbatim abstract), OU research portal landing page, Crossref |

For paper 4 the PDF is behind Cloudflare at research.ou.nl, behind IEEE
Xplore, and behind an authentication wall at the Radboud repository. Three
independent routes refused it. Everything below about paper 4 is at
abstract-level confidence and is flagged where it matters. In particular I did
**not** verify which RL algorithm it uses, its simulation parameters, or its
limitations section.

Keyword counts, run over the extracted text rather than recalled:

```
paper 1:  "pool" 3   "PPLNS" 0   "hopping" 0   "multi-coin" 0
paper 3:  "pool" 0   "PPLNS" 0   "hopping" 0   "multi-coin" 0
```

Paper 1's three occurrences of "pool" all mean *a coalition holding α of the
network*, never a payout arrangement:

> "we assume the network is split into two mining pools: one is an adversary
> that controls a fraction α of the whole network's computing power"

Paper 3 does not contain the word at all.

---

## 1. Wang, Liew, Zhang -- "When Blockchain Meets AI"

arXiv:1911.12942, *Int. J. Intelligent Systems* 36(9), 2021.

### (a) Setting

Selfish mining, squarely. An adversary controlling fraction α of a
Bitcoin-like chain chooses among four actions -- **Adopt**, **Override**,
**Match**, **Wait** -- over states `(l(a), l(h), fork)`: length of the private
chain, length of the honest chain, and whether a fork is irrelevant / relevant
/ active. This is Sapirshtein-Sompolinsky-Zohar's MDP with an RL solver
bolted on.

The contribution is *not* a better attack. It is that solving the mining MDP
needs parameters (α, and γ, the fraction of honest miners that would build on
the attacker's branch in a tie) that a real miner cannot observe and that drift.
So they replace the MDP solve with multi-dimensional Q-learning that keeps
paired Q-functions `(Q(a), Q(h))` and optimises the *ratio*
`f(s,a) = q(a)/(q(a)+q(h))` -- "relative mining gain" -- because the objective is
non-linear in a way standard Q-learning cannot express.

Headline result: with the environment starting at (α=0.35, γ=1) and then
changing, a policy solved offline for (0.35, 1) "is not optimal anymore" while
the RL learner tracks it. Evaluated over Tw = 10^5 steps in a Monte Carlo
simulator of 1000 miners.

### (b) Applicability here

**None.** Not to the window, not to the payout scheme, not to `choose`.

Every element of the model is absent from this system. There is no private
chain -- the pool forwards a share the instant it beats upstream's target
(`pool.rs:654`). There is no fork to match. There is no α worth naming. The
four actions have no counterpart in a proxy that relays `mining.notify` and
credits work.

The one *methodological* echo, and I flag it as an echo rather than a finding:
their reason for reaching for RL is that the model parameters are unobservable
and non-stationary. That is structurally the same complaint `market.rs` makes
about expected value -- the pool "holds two of those three" and the third is not
on the wire. But the conclusion drawn there (get the number from a pool that
already sold the coin, via `payrate.py`) is *better* than learning it, because
it is a measurement rather than an estimate. The paper's own future-work
section concedes the cost of slow convergence in a setting where you pay
electricity while learning. At $0.36/day of electricity against $0.07/day of
revenue, a learner that spends days converging is a strictly worse answer than
reading `estimate_current` off an API.

### (c) Warning

Nothing directed at a small pool. The paper is written from the attacker's
side and its threat model has no pool operator in it.

---

## 2. Soria, Moya, Mohazab -- "Optimal mining in proof-of-work blockchain protocols"

*Finance Research Letters* 53:103610, May 2023. CC-BY, full text read.

### (a) Setting

**Not selfish mining.** This is industrial-organisation economics: a Tullock
contest for the demand curve for hashpower. Miner *i* picks hashes `h_i`; the
probability of winning is `h_i / Σh_j`, a linear contest success function; the
payoff is that probability times block reward `R` minus `h_i · c` in
electricity. They add exogenous **passive hash** `H_p` (miners who run flat out
regardless of price), pool fee `f`, and heterogeneous costs.

The symmetric-equilibrium result, their Eq. 12:

```
h*_i ≈ -H_p/N + R_{t-1}(1-f)(N-1) / (N² c_t)
```

and the electricity-price elasticity, Eq. 16:

```
ε_{h,c} = - R(1-f)(N-1) / [ R(1-f)(N-1) - c·N·H_p ]
```

with the reading: at `H_p = 0` demand for hash has **unit elasticity**, and as
passive hash rises the demand becomes arbitrarily elastic -- which is their
policy point, that Pigouvian taxes on mining electricity are efficient.

The RL is *confirmatory, not a method*. They solve the game analytically and
then run tabular Q-learning (α=0.05, γ=0.01-0.03, 400k-600k iterations, N=5 and
N=10 symmetric miners at R=100, c=1) and a neural-network variant to show
naive profit-maximising agents converge to the same equilibrium. Q-learning
landed at mean hash 14.19 against an equilibrium of 16; the network got 16.06.
The RL is a robustness check on the algebra. Do not read this paper as an RL
paper.

Pools appear, but only as a fee `f` assumed exogenous and uniform: "We assume
that the fee is determined exogenously by the market... its implication is
simply that there is no arbitrage." They explicitly defer pool-size and
fee-formation to Cong, He and Li (2021).

### (b) Applicability here

**This is the only one of the four with anything for you, and it is one first-order
condition, not a design.**

The FOC behind Eq. 12 says: buy hash until marginal revenue equals marginal
cost. Applied across several coins on one device, where the scarce thing is
device-seconds rather than hashes, the same condition says **allocate the next
second of device time to whichever coin has the highest marginal
revenue-per-second, and at an interior optimum equalise marginal revenue across
the coins you run.**

`miner/src/main.rs::choose` is currently:

```rust
.min_by_key(|(i, s)| (s.spent.as_nanos() / s.weight as u128, *i))
```

least-virtual-time with all weights 1. Weights proportional to measured
$/device-second -- which is exactly what `tools/payrate.py`'s
`estimate_current` gives you -- is the right shape under this paper's model.
`design/pool.md` already says so in "What does not": "every weight is 1, which
is honest and is not a policy."

So the paper is a *citation* for a decision this repo has already reasoned its
way to, not a source of new information. It does not tell you the weights; the
API does. Its own model would also warn you that the interior optimum is
*not* the right answer when a coin's marginal revenue never exceeds marginal
cost -- their KKT condition (6)-(7) says mining happens **iff** individual
rationality holds, and at profit ≤ 0 the constraint binds at `h = 0`. In their
three-miner asymmetric simulation the `c = 5` miner "chooses the hash value of
zero at the end of the simulation."

At $0.07/day against $0.36/day, this model's answer for the whole machine is
`h* = 0`. That is not a joke at the project's expense; it is the paper's
literal prediction, and it is worth writing next to `choose` that the
profitability-weighted allocator is optimising a subproblem whose outer problem
has a corner solution.

Two things it does **not** touch: the PPLNS window (rounds, variance and
maturity do not appear in the model at all -- payoffs are per-period expected
values) and pool-hopping (the fee is a constant, miners never choose a pool).

### (c) Warning

Mild and structural rather than an attack. Their Eq. 12's `-H_p/N` term is the
passive-hash burden. On a small, obscure, ASIC-free algorithm -- which is what
`payrate.py`'s classifier is selecting for -- `H_p` is a *large* fraction of the
network. Their elasticity result then says the return to any hash you add is
unusually sensitive to your electricity cost, and their bound `c·H_p < R` is
the condition for mining to be worth anything at all. That is the algebraic
form of the $0.36-against-$0.07 measurement.

---

## 3. Li, Xie, Huang, Zhou, Song, Zeng, Deng, Zhang -- "Survey on Strategic Mining in Blockchain: A RL Approach"

arXiv:2502.17307, IJCAI 2025. Ten pages. Full text read.

### (a) Setting

A survey of exactly paper 1's problem. Sections: MDP analysis of strategic
mining, RL frameworks for it, a consensus-protocol classification, open
problems. Its subject is *security thresholds* -- the minimum attacker
hashpower at which deviating beats honest mining.

Reported thresholds, MDP side (their Table 1): Eyal & Sirer 2014 at 0.25,
Sapirshtein et al. 2016 at 0.232, Marmolejo-Cossío et al. 2019 at 0.26297,
Feng & Niu 2019 at 0.26, Zur et al. 2020 at 0.2468. RL side (Table 2): Hou et
al. 2019 at 0.25 via DQN, Bar-Zur et al. 2022 at 0.20/0.17/0.12 via MCTS+DQN
under varying fee conditions, Bar-Zur et al. 2023 at 0.21/0.19 with compliant
miners, Sarenche et al. 2024 at 0.24198 for longest-chain PoS.

Protocol taxonomy: chain-based (longest chain, heaviest chain, FruitChain),
vote-based (PBFT, Tendermint, Algorand, HotStuff, Eth2), parallel-confirmation
(Avalanche, Conflux, Sui).

Three open problems: extend beyond longest-chain protocols; build MDP models
that account for network latency and adaptive strategies; and analyse
multi-agent settings, where "agents may compete, complicating the analysis of
selfish mining attacks" and POMG formulations "face scalability challenges as
the number of miners increases."

### (b) Applicability here

**None, and this is the strongest "no" of the four**, because it is a survey
and its coverage is checkable. The word "pool" does not occur in the paper.
Neither does PPLNS, proportional, pool-hopping, or multi-coin. Its entire
subject is a single miner's deviation on a single chain.

Its value to this project is as a *map*: if the strategic-mining literature is
ever worth revisiting -- it becomes relevant the day this pool has enough of
some small coin's network hashrate to matter, which is a real threshold at
0.12-0.26 and not an abstract one -- this is the right ten pages to read to
find out who to read. That is a genuine but purely bibliographic use.

### (c) Warning

One, and it is about the *coins you select*, not about the pool.

The thresholds above are fractions of a network. `payrate.py` deliberately
selects for algorithms an ASIC does not dominate, which is to say algorithms
with small networks. A small network is one where 12-26% of hashrate is cheap
to assemble. That is a property of the coins this project is being pointed at,
and it is worth knowing that the selection criterion and the attackability
criterion point the same way. It is not an exposure the pool has; it is an
exposure the pool's *upstream chains* have, and a chain that gets reorganised
takes your credited-but-unpaid work with it.

---

## 4. Pankovska, Sai, Vranken -- "Determining Optimal Incentive Policy for Decentralized Distributed Systems Using RL"

IEEE ICBC 2023, pp. 1-5. DOI 10.1109/ICBC56567.2023.10174946.
**Abstract and metadata only. I could not obtain the full text.**

### (a) Setting

From the verified abstract:

> "This paper aims to address the problem by investigating the use of a
> two-level deep reinforcement learning (RL) model to design incentive policies
> for green mining in cryptocurrencies... we develop and test incentive
> policies, according to which cryptocurrency participants who primarily use
> renewable energy for their mining operations are more likely to add new blocks
> to the blockchain. Our results show that even when the green score of each
> crypto miner (determined by their use of green energy sources) has relatively
> small importance (up to 0.3) in their selection probability, miners still
> shift towards green mining."

So: the incentive being designed is a **consensus-layer block-selection rule**
that weights a miner's chance of adding a block by an energy-provenance score.
The designer is a protocol architect or a social planner. The "two-level" RL is
a planner learning a policy while agents learn to respond to it -- the AI
Economist shape. *That structural reading is my inference from the phrase and
from the citation neighbourhood; I did not read the method section and cannot
confirm which algorithms are used or what the environment looks like.*

### (b) Applicability here

**No -- and specifically, the guess that this is the closest paper to pool payout
design is wrong.** Nothing in it is about splitting a found block's reward among
contributors. It is about who gets to find the block, decided by a criterion
that is not work.

Two further reasons it does not transfer, both of which I can state from the
abstract alone:

- **This pool cannot change who wins a block.** It is a proxy. The
  block-selection rule belongs to the upstream chain. A policy lever the system
  does not hold is not a lever.
- **A green score needs an oracle.** The paper's mechanism requires the system
  to know each miner's energy provenance. Nothing in `pool/src/` can learn that
  and nothing on the Stratum wire carries it. `design/pool.md`'s own standard --
  a field this machine does not know means the answer does not exist -- refuses
  this before the economics does.

There is a thin analogy -- *any* reward that is not proportional to work is a
policy lever, and PPLNS is already one -- but it is thin enough that invoking
this paper for it would be exactly the over-claim to avoid.

### (c) Warning

None obtainable. If a warning exists it would be in the limitations section,
which I did not read. **Do not cite this paper for anything about pool payouts
on the strength of this brief.** If it matters, get the PDF through an
institutional IEEE subscription; nothing I tried reached it.

---

## What actually answers your three questions

Since three of four papers do not, here is what does -- from sources I fetched
and read for this brief rather than from the four.

### PPLNS window size: Rosenfeld (2011) gives you the formula

*Analysis of Bitcoin Pooled Mining Reward Systems*, arXiv:1112.4980, §3.3.
Full text read.

With `p` the probability a share is a block, `B` the block reward, `f` the fee,
`N` the window:

- expected payout per share is `(1-f)pB` -- fair, independent of N
- reward **variance** is `≈ pB²/N`
- **maturity time** (mean delay to being paid for a share) is `pN/2`
- and the invariant: **variance × maturity = ½(pB)², always.**

That last line is the whole of the window-size decision, and it says the choice
is not an optimisation. There is no best N. There is a dial between "miners
get paid smoothly" and "miners wait", and the product is fixed. `--window`
being an operator constant is *correct*; what is missing is that the operator
has nothing telling them what they are trading. Printing the implied maturity
(`pN/2` in expected blocks) next to the window at startup would make the dial
legible, and it needs the same network target `market.rs` is already waiting
for.

Rosenfeld's worked case, N = D: the number of payouts per share is Poisson with
λ=1, so **36.79% of shares are never paid at all** and the mean is 1. A miner
who does not know that reads a run of unpaid shares as the pool cheating.

### PPLNS against hopping: the current `Window` is the *simple* variant, and simple PPLNS is not hopping-proof

`pool/src/pool.rs`'s doc comment on `Window` is right about the mechanism --
"the window keeps moving whether or not you are in it, so leaving costs you the
window and there is nothing to game" -- and Rosenfeld agrees, **under the
assumption that D and B are constant.** He then removes it:

> "If we drop the assumption that D and B are fixed, this simple variant is not
> hopping-proof. A participant's contribution is determined by the current
> difficulty, while his reward is influenced by the future difficulty.
> Pool-hoppers can use knowledge of imminent difficulty adjustments to their
> advantage -- joining when the difficulty is set to decrease, and leaving when
> the difficulty is set to increase."

This is a live exposure for this pool specifically, for a reason the repo has
already half-written down. `Contribution.work` is `2^bits` -- the *miner's*
VarDiff target, not the miner's share of the *network*. Rosenfeld's
hopping-proof variant, **unit-PPLNS**, stores two things per share:

- `units` = the value of `p` at submission, i.e. share difficulty ÷ network
  difficulty
- `amplifier` = the value of `B` at submission

and sizes the window `X` in multiples of the average time to find a block
rather than in raw work. Both stored fields are quantities `market.rs` says the
pool does not have: the network target, and the coinbase value in coin units.
**So the missing network difficulty is not only blocking expected value -- it is
the difference between simple PPLNS and hopping-proof PPLNS.** That is a
sharper reason to want it than the one currently written down, and it is worth
adding to `market.rs`'s header.

One operational trap, also from §3.3, that applies the moment `--window` is
changed between restarts: because PPLNS has no round boundaries there is no
safe moment to change parameters, and changing X without rescaling stored share
values silently changes every outstanding miner's pending reward. Rosenfeld's
fix is to scale stored units by `X₂/X₁` and amplifiers by `X₁/X₂`. Today
`--window` is read at startup and applied to a persisted window, so a restart
with a different value does exactly the thing he warns about.

### Payout scheme against block withholding: PPLNS is the right choice, and you get a bonus property

Rosenfeld §6.2 splits withholding into **sabotage** (never submit a found
block; hurts the pool, gains the attacker nothing) and **lie in wait** (delay
submitting, and meanwhile pile hashrate into the pool where the block is
waiting -- a genuinely profitable attack).

The decision already made here is the right one, for a reason worth being
explicit about: under PPLNS a saboteur's damage is shared across participants --
each loses `h/H` of their reward -- whereas under **PPS the entire loss falls on
the operator**, who earns `(f - h/H)pB` per share and can be driven bankrupt
since `f` is a couple of percent. For a pool this size, run by one person, with
no float, PPS is not a scheme to consider.

Schrijvers, Bonneau, Boneh & Roughgarden (FC 2016) is the formal treatment:
they model a pool as an unordered history of reported shares with miners
choosing to report or delay, and show **proportional payment is not incentive
compatible**, then construct a scheme that is. (I read the paper's abstract and
several independent descriptions, not the proofs -- treat the construction as
unverified here.)

**And there is a property this design has by accident that is worth knowing
about.** Rosenfeld's §6.2.3 proposes "oblivious shares" -- shares a miner cannot
recognise as full blocks without submitting them -- as the true fix for
withholding, and notes it would need a Bitcoin protocol change. This pool
approximates it for free. `pool.rs:445` sends the miner
`target_with_leading_zeros(bits)`, the VarDiff **share** target; `up_target`
lives only in the pool's `Issued` record and never crosses the wire. Combined
with `design/pool.md`'s central decision -- the miner receives an assembled
80-byte header and cannot reconstruct the coinbase -- **a miner running this
protocol cannot tell a block from a share.** Both halves of sabotage and
lie-in-wait need that recognition.

Do not oversell it. It is obfuscation, not a guarantee: a miner who knows which
coin it is on can read the network target from a block explorer and reproduce
the comparison itself. But it raises the cost from free to deliberate, it costs
nothing, and the design note in `pool.md` currently records only the *cost* of
the opaque header (a miner cannot audit what it mines for) without the
compensating benefit. Both belong there.

### Multi-coin allocation weights: none of the four is about this, and the right frame is not selfish mining

You are right that this is a portfolio/bandit problem, and none of the four
papers is in that literature. Paper 2 is the closest and it gives you a
static first-order condition, not an allocation rule under uncertainty.

The honest position: `payrate.py` already supplies measured $/day per
algorithm, so the exploration half of a bandit is *already solved by
measurement* -- you are not learning an unknown reward, you are reading a quoted
one. What remains is a weighting, and equalising marginal revenue per
device-second (paper 2's FOC) is the correct static answer. Reaching for RL
here would be building a learner for a quantity you can look up, which is the
error paper 1 spent a paper avoiding in the opposite direction.

---

## Concrete, implementable

Ordered by ratio of value to work. Only the first two came from reading; the
rest are consequences.

1. **Print the maturity implied by `--window`.** `pN/2` in expected blocks,
   next to the window at startup. It makes the variance/maturity dial legible
   and it costs nothing once the network target exists.
2. **Add the hopping reason to `market.rs`'s header.** The absent network
   difficulty is not only an EV blocker; it is what separates the simple PPLNS
   in `Window` from Rosenfeld's hopping-proof unit-PPLNS. That is a stronger
   argument for wanting it and it is currently unwritten.
3. **Refuse, or loudly warn on, a `--window` that differs from the persisted
   one.** Changing X mid-flight without rescaling stored shares silently moves
   every miner's pending reward.
4. **Record the oblivious-share property in `design/pool.md`.** One paragraph,
   with the caveat that a miner who knows the coin can still infer the network
   target out of band.
5. **Weight `choose` by measured payrate**, with a comment that paper 2's own
   IR constraint says the outer problem has a corner solution at zero given the
   measured economics.

Nothing here needs an RL agent, and three of the four papers argue for one.

## Sources

- [arXiv:1911.12942 -- When Blockchain Meets AI](https://arxiv.org/abs/1911.12942) ([full text](https://ar5iv.labs.arxiv.org/html/1911.12942))
- [Soria, Moya & Mohazab, *Finance Research Letters* 53:103610](https://doi.org/10.1016/j.frl.2022.103610) (open access via [Helda](https://helda.helsinki.fi/handle/10138/357731); author's summary in [Mohazab's Aalto dissertation](https://aaltodoc.aalto.fi/items/15d43232-6954-48c3-b2c7-e74f38c8cf3a))
- [arXiv:2502.17307 -- Survey on Strategic Mining in Blockchain](https://arxiv.org/abs/2502.17307)
- [Pankovska, Sai & Vranken, IEEE ICBC 2023](https://research.ou.nl/en/publications/determining-optimal-incentive-policy-for-decentralized-distribute/) -- **full text not obtained**
- [Rosenfeld, *Analysis of Bitcoin Pooled Mining Reward Systems*, arXiv:1112.4980](https://arxiv.org/pdf/1112.4980)
- [Schrijvers, Bonneau, Boneh & Roughgarden, *Incentive Compatibility of Bitcoin Mining Pool Reward Functions*, FC 2016](https://timroughgarden.org/papers/bitcoin.pdf) -- abstract only
