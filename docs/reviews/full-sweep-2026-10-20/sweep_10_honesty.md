# Axis 10/12 — HONESTY (does anything claim more than it does?)

Depths: (a) docstring claims, (b) report/grading honesty, (c)
verification-document claims.

## Shallow (docstring claims)

One overclaim found and PoC'd: forge/schemas.py calls forge Family
"a superset of the campaign layer's families" — it is not (4 campaign
members have no forge counterpart). → part of **F-01**. All other
docstring claims spot-checked against mechanics (the no-LLM claims in
storyteller, the zero-network claims in forge/deep, the advisory-only
claims in integration layers) — they hold.

## Medium (report honesty)

- The report generator never grades (no score/grade attribute,
  source-locked); the truth validator compares every report claim
  against recorded results and flags inflation, deflation and
  fabrication; the retrospective cites recorded numbers only. The
  reporting chain's honesty is test-enforced, not aspirational.
- The forge query engine's per-hit breakdown publishes its own
  arithmetic (0.4/0.3/0.2/0.1) with a neutral 0.5 context dimension
  for payloads that declare no requirement — the corpus never
  overstates fit.

## Deep (verification-document claims)

docs/verification_forge_deep.md claims: red-first (75 tests red on
ModuleNotFoundError), zero getattr/hasattr in the new packages, seal
unmoved, suite 3,943 → 4,018. Two claims fail this sweep's audit:
- "no `getattr`/`hasattr` dynamic indirection anywhere in the new
  packages" — forge/integration.py:93 carries a live `hasattr`
  (**F-03**: the claim was written from a getattr-only grep).
- The suite numbers have since grown by later rounds (monotonic);
  ground truth is re-established in sweep_04.

## Verdict for this axis

F-01 (false superset claim) and F-03 (false zero-hasattr claim) are
honesty findings; both fixed in Phase 5 with red tests.
