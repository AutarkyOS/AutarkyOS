# A connectome in the kernel

Status: **proposal, host tooling only.** `tools/connectome.py` exists and is
verified; nothing kernel-side is built, and this note is here to be argued with
before any of it is.

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
is the same kind of object one step up -- a graph you evolve in time -- and it
reuses machinery that is already here:

- **State** is one activation per node, a `Vec<f32>` of length 448.
- **A step** is `x_next = tanh(W x + b)`, where `W` is the weighted adjacency
  (chemical edges directed, electrical edges symmetric) -- one `Mat::matvec`,
  the kernel's most exercised kernel, split across cores for free by the same
  `parallel_split` prefill uses.
- **Observation** is the same window the Oracle already draws: activations over
  time, forked under a stimulus applied to a named sensory neuron.

That is the whole of it. No new numeric substrate, no floats-for-one-feature
bargain, nothing the selftests cannot reach. It is a small, real dynamical
system with a provenance, which is the same thing the Oracle is and the opposite
of the word-prophecy draft that Oracle replaced.

## What it would and would not be

It would be: a loadable graph the model can query ("what does AVAL connect
to"), and a toy simulator the machine can run and watch, in the register the
Oracle established -- a real system, honestly labelled, never dressed up as more
than a 302-cell worm.

It would not be: a human brain, a consciousness, a second mind competing with
the model, or a source of routing decisions. It is a dataset with dynamics,
kept at arm's length from anything that decides, for the same reason the Oracle
is never prophecy.

## Open questions for steer, before any kernel code

1. **Neurons-only (302) or full (448)?** Full is required for locomotion;
   neurons-only is cleaner if the goal is just the wiring.
2. **Static graph, or runnable?** A read-only indexed graph (the model can ask
   about connectivity) is a day; a runnable simulator with the window is more,
   and its dynamics have no ground truth to check against the way `identify` and
   `hosts_in` do -- it would be a demo, not a verified claim, and this tree is
   careful about which of those a thing is.
3. **Where it sits.** A new `GLADOSXN` on-disk format is a commitment; loading
   it as an Aiksi-queryable object under `/ai/connectome` reuses the namespace
   and commits to nothing. The latter first, probably.

The strong recommendation is (1) load it as data the model can query, (2) leave
the simulator as a clearly-labelled demo if wanted at all, and (3) never wire it
to a decision -- keeping it exactly as far from the router as the Oracle is.
