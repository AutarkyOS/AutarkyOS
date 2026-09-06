# A connectome in the kernel

Status: **built and verified live (full + runnable).** `tools/connectome.py`
produces the `GLADOSXN` file, `src/ai/connectome.rs` loads and runs it, the
`connectome` shell verb drives it, and a boot selftest plus `diag connectome`
(suite 36) check the machinery. The steer was "full + runnable", and both
halves are done: the whole 448-node graph loads, and a toy dynamical system
steps over it. It is wired to nothing that decides -- exactly as far from the
router as the Oracle is.

## The ask, and the honest form of it

The request was to find a brain-scan dataset and "maybe integrate a healthy
human brain into the system." The first half is doable and the second, taken
literally, is not -- so this is the version that is.

There is no downloadable human brain a kernel could run. A human structural MRI
is millimetre voxels and statistically-inferred fibre tracts, not cells and not
synapses; no human's synaptic wiring has ever been traced, and the largest
mapped human fragment as of 2024 is a single cubic millimetre. "Integrate a
human brain" is a category error rather than a hard task, and pretending
otherwise would be exactly the kind of figure this project refuses to publish.

What is real, complete, and small is *Caenorhabditis elegans*: 302 neurons, ~7,000
synapses, the only whole-animal nervous system ever mapped connection by
connection (White et al. 1986; reconstructed since). It is public, and at ~84 KB
in the format below it lives in the kernel heap as an ordinary graph. So the
honest form of the ask is not a metaphor -- it is an actual entire brain, at the
one scale where "the complete wiring diagram" is a fact.

## What the tool produces

`tools/connectome.py` fetches OpenWorm's Cook/White hermaphrodite edge list and
writes `GLADOSXN` (format defined in the tool's docstring, verified by a
walk-and-assert reader that is deliberately not the writer):

```
  448 neurons, 7379 connections (4681 chemical, 2698 electrical)
  most-connected: AVAR 199, AVAL 195, hyp 137, AVBR 129, AVBL 125, ...
```

Two honesty notes that belong next to those numbers:

- **448, not 302.** The *full* edge list includes the muscles and other end
  organs the neurons drive, not neurons alone. A neurons-only graph is 302; the
  richer one is what makes locomotion runnable, since a motor circuit with no
  muscle to move is only half a loop. Whichever we load, the count is stated,
  not rounded to the famous number.
- **AVAL/AVAR on top is the biology, not luck.** Those are the command
  interneurons for backward locomotion, and their dominating the degree list is
  the standard sanity check that a connectome parse is faithful. It passed.

## Why this fits AUTARK's grain rather than being bolted on

The machine already runs a fitted dynamical system and shows it: the Oracle
(`src/ai/futures.rs`) fits `v_next = a + b*v + c*u` per telemetry variable with
the router's own Cholesky and rolls it forward under interventions. A connectome
is the same kind of object one step up -- a graph you evolve in time -- built
from what is already here:

- **State** is one activation per node, a `Vec<f32>` of length 448, in a
  `Racy<Vec<f32>>` beside the loaded graph.
- **A step** is `x_next[i] = tanh(gain * (W x)[i] / in_scale[i])`, where `W` is
  the weighted adjacency (chemical edges directed and taken excitatory,
  electrical edges symmetric).
- **Observation** today is `connectome show` and the active-count a step
  reports; the forked Oracle-style window over time is the obvious next step and
  is not built.

**Two deliberate departures from the first sketch, both recorded because they
are real trades.** The draft said "one `Mat::matvec`, split across cores." It is
not, and should not be: `Mat` is the model's *quantised* weight kernel over a
dense matrix, and this graph is sparse -- 7,379 edges over 448 nodes is 1.6%
density, so a dense 448x448 matvec would be sixty times the arithmetic and would
first have to materialise a dense adjacency the file does not carry. The step is
a direct walk of the edge list instead, which is both cheaper and closer to what
the data is. And the draft's `tanh(W x + b)` gained a per-node divisor: a hub
like AVAL has an incoming weight sum in the hundreds, so without normalising by
`in_scale` the very first step saturates every downstream node to +-1 and the
dynamics carry no information. `in_scale[i]` is that sum, computed once at load.

The chemical-edges-are-excitatory simplification is stated in the module and
here rather than hidden: the dataset records synapse *weight* but not sign, so
there is no honest way to make some inhibitory, and the toy is labelled a toy.
It is a small, real dynamical system with a provenance -- the same register the
Oracle is in, and the opposite of the word-prophecy draft Oracle replaced.

## What it is and is not

It is: a loadable graph you can query ("what does AVAL connect to"), and a toy
simulator the machine runs and watches, in the register the Oracle established
-- a real system, honestly labelled.

It is not: a human brain, a consciousness, a second mind competing with the
model, or a source of routing decisions. It is a dataset with dynamics, kept at
arm's length from anything that decides, for the same reason the Oracle is never
prophecy. `LOADED` and `STATE` are read by the shell verb and the selftest and
by nothing in `voter`, `council`, `godel` or the router.

## How the steer was resolved

1. **Full (448), not neurons-only.** The steer was "full + runnable", and full
   is what makes locomotion visible in the dynamics -- a motor circuit with no
   muscle to drive is half a loop.
2. **Runnable, and honestly a demo.** The simulator has no ground truth to check
   against the way `identify` and `hosts_in` do, so what the selftest asserts is
   the *machinery* -- the parser walks and lands on the last byte, a step is
   deterministic, an excitatory edge drives its target -- and never a claim
   about worm behaviour. The dynamics are watched, not verified.
3. **Loaded on demand, not compiled in.** The `GLADOSXN` file is read from the
   namespace (`connectome load <path>`), so the 84 KB graph costs nothing until
   asked for and the kernel image does not carry it. Under QEMU it arrives via
   `fat get`; on the GF63 it would come off the ESP.

## What was seen live

Driven under QEMU (WHPX), against the real `out/connectome.bin`:

```
  connectome load /tmp/conn   -> loaded 448 neurons, 7379 connections
  connectome info             -> 448 neurons, 7379 connections (4681 chemical, 2698 electrical)
  connectome neigh AVAL       -> AVAL connects to 132: RIAL, PVCL w21, AVBL, DA01..DA09, VA01..VA10, AS02..AS11 ...
  connectome stim AVAL 100
  connectome step 1 4         -> 58 active; top VA06 VA05 VA09 VA08 VA10 DA07 AS09 DA04
  connectome step 4 4         -> 419 active; top dBWML17/18, dBWMR17/18, vBWMR18, DD04 ...
```

The propagation is the biology, not luck, which is the same sanity check the
degree list is. AVAL is the backward-locomotion command interneuron; one
synaptic hop from it lands on exactly the A-class and VA motor neurons it is
known to drive, and four hops reach the body-wall muscles (dBWM/vBWM) and the
D-class motor neurons -- the backward-locomotion motor pathway, traced through
the loaded graph. A wrong parse or a wrong step would not produce that; it would
produce noise that happened to be finite.
