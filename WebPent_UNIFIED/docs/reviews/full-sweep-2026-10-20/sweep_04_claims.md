# Axis 4/12 — CLAIMS VS REALITY (does the suite and do the docs say what happened?)

Depths: (a) suite ground truth, (b) verify_all and gates, (c)
documented claims re-checked.

## Shallow (suite ground truth) — executed this sweep

Full suite re-run from this tree: **4,322 passed, 0 failed in 187s**
with tests/lab excluded from the batch command, plus tests/lab run
separately: **7 passed** → total **4,329 passed, 0 failed**, exactly
the monotonic count after Waves 3-5 (+63 over 4,266). No broken,
skipped-into-passing, or silently-deselected tests. 10 warnings
(pre-existing capture warnings).

## Medium (gates)

`verify_all.py` and the construction-authority gate are re-run in
Phase 5 after the fixes (they gate the final verdict). The Wave-3
documented numbers (145/145 verify_all, gate exit 0, 26 allowlisted
files) are the baseline the Phase-5 run is compared against.

## Deep (documented claims re-checked)

Claims that SURVIVED the audit:
- Suite count 4,329 monotonic — TRUE (re-run above).
- Seals d10783ec… / 30fd86c6… — TRUE (sha256 this sweep).
- Zero getattr in campaign/forge/deep — TRUE (grep: 0).
- Red-first history in verification_forge_deep.md — consistent with
  the red-round records it cites.

Claims that FAILED the audit:
- "no `getattr`/`hasattr` dynamic indirection anywhere in the new
  packages" (verification_forge_deep.md) — FALSE: one live `hasattr`
  at forge/integration.py:93; the claim came from a getattr-only
  grep. → **F-03**.
- forge/schemas.py "a superset of the campaign layer's families" —
  FALSE by PoC. → **F-01**.

## Verdict for this axis

Suite ground truth is solid. Two document/claim findings (F-01,
F-03), both fixed in Phase 5.
