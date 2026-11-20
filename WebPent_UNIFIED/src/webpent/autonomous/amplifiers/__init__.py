"""Advisory amplifier layers (v82).

Four layers of capability amplifiers, every one of them advisory:

* recon amplifiers widen what the hunter *sees* (takeover, cloud storage,
  wayback, deep JS, CT mining),
* quality amplifiers harden what it *claims* (self-adversarial validation,
  triager simulation, FP autopsy),
* operational amplifiers change how it *works* (swarm roles, temporal
  intelligence, rate-limit cartography, session topology),
* intuition amplifiers (statistical anomaly detection, cross-target
  patterns, hypothesis quality scoring).

Hard invariants for every module in this package: no new execution
authority, no network of its own (every external fetch goes through an
injected fetcher callable), advisory output only (re-rank, annotate,
never promote, never suppress evidence), redact() on anything persisted,
bounded sizes, and a corrupt or missing input degrades to "no signal",
never an exception that breaks a hunt.
"""
