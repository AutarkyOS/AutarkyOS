# Two doctrines, recorded before they are built

These are direction, not code. They are written down now so that when the work
starts it starts from a decision rather than a mood, and so a later session can
tell what was intended from what merely happened.

## The network stack diverges from upstream, on purpose

Upstream GLaDOS grows an ordinary stack -- correct, RFC-shaped, built to
interoperate. AUTARK's later stack does not inherit that goal. It is built
around aggressive security as the first principle rather than a hardening pass
over a compatibility-first design, and the two produce different code at every
layer:

- **Every inbound artifact is untrusted input to a parser, and the parser is
  the attack surface.** The stack is written to be read by an adversary looking
  for exactly the memory-safety and state-machine faults a from-scratch stack is
  most likely to contain. So the discipline is the one `smp.rs` and `differ`
  already use -- bit-exact checks, asserted state machines, pure decision
  functions split from I/O -- applied to every framing and reassembly path,
  because a lenient parser is how a stack gets turned against its host.
- **Deception is a layer, not an application.** The Mirror (decoys, canaries,
  honeypots, tarpits) is part of the stack's normal operation rather than a
  service bolted on top. A connection's default posture is suspicion.
- **Cost is imposed inbound, never outbound.** The stack may waste an
  attacker's time and resources against itself without limit -- this is where
  "over the top" is licensed -- but it does not reach off the machine to do it.
  That line is argued in full in `mirror.md` and is not re-litigated per
  feature.
- **Legibility over features.** A stack nobody can audit is a stack that
  defends nothing, so surface stays small and every extension carries its
  "why" and its adversary in the comment, the register the rest of this tree
  keeps.

Not started. The current `src/net/` is upstream's stack with the Mirror grafted
on; the divergence above describes where a rewrite would go, when there is a
reason to pay for one.

## Foreign code is dissected, not supported

The conventional job of an OS is to *run other people's programs*: a syscall
ABI, a loader, compatibility shims, a promise to keep old binaries working.
AUTARK inverts the goal. It has no user/kernel split and one address space; it
was never going to be a good host for foreign binaries, and it does not try.
What it does instead is **understand** them.

The competency is surgical reverse-engineering: take an unknown binary, an
unknown protocol, an unknown process, and reduce it to a model the machine
fully understands -- structure, entry points, control flow, the format it
speaks -- rather than a black box it agrees to execute. The same epistemic move
the network side already makes is the template: `fingerprint` turns an opaque
banner into a named service by its content, `recon` turns an unknown host into a
structured record, `fmt` turns unknown bytes into a typed structure. Extended to
code and processes, that is: parse the container (ELF, PE, Mach-O, raw), map the
sections and imports, recover the control-flow graph, name what can be named,
and hand the model a structure it can reason over -- the outline `fmt::outline`
already builds for source, built instead for machine code.

The register is deliberate and matches the fork's persona: the system does not
invent from nothing and does not accommodate on another system's terms. It
captures what exists, takes it apart, and keeps only what it can bend to its own
representations -- the ledger, the invariant, the Merkle namespace. Foreign
structure is raw material, understood completely before it is used, never
trusted enough to simply run. The aesthetic touchstones the operator named
(occult-industrial appropriation; a maximalist far-future engineering
ambition) are exactly that: methods of *taking and transcending* rather than
originating, held at the distance any dark touchstone is held -- a mood for the
work, not a value in it.

Not started, and larger than one module. The honest first step is a static
analyser that treats a binary the way `fmt` treats a file: identify the
container, then produce a structured, model-readable outline. Everything
dynamic -- tracing a live process, instrumenting execution -- rests on that and
comes after it. The point to hold from the outset: the deliverable is
*understanding* a foreign artifact, measured against ground truth the way every
other claim in this tree is, not compatibility with it.
