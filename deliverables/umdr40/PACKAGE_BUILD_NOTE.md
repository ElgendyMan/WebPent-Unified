# UM-DR-40 Final Package — Build Note

Generated 2026-11-18T19:06:36.546850+00:00.

## What this package is

The definitive UM-DR-40 final package: the delivered 39 release
tree (`WebPent_Unified_v0.40.1_UMDR39_FINAL.zip`, the
byte-identical published tree at `ca4ae448`) plus the COMPLETE
UM-DR-39.1 → rationalization → UM-DR-40/40b window chain:

* provenance re-baseline, prism time-bomb fix, root cleanup;
* **RC-4** (wired router + per-campaign activation) — proven by 4
  independent campaign reproductions (principals 3 vs 0, guard
  verdicts unchanged, zero request-budget delta);
* **RC-5** (generation-time deterministic uuid5 dedup);
* **RC-6** (measured information gain in the decision log) and
  **RC-7** (the ranked runner-up slice) — both adapted INTO the
  strategist and proven on production-node evidence;
* both declared refreezes and every register/gate update.

## Determinism proof (why you can trust the rebuilt tree)

The build tree was recycled by the environment twice after the
verified chain head `6b69458`; this package was rebuilt from the
delivered 39 package by replaying the exact window patches. The two
critical thawed files verify BYTE-IDENTICAL against the hashes the
binding suite (9,365/9,354/0/0) actually tested:

* `src/webpent/graph/builder.py` →
  `95efa2717cb371924ceb19f2b9e68523ceae1398ea94a848e6f77daeec276eb3`
* `src/webpent/agents/strategist/agent.py` →
  `887c4c0f0f2a6c6dcc5708cbad0d694ad07146331815914b800d3eddf5c5e302`
  (the historical `rule_fired` line duplication from the original
  patch sequence is preserved verbatim)

And beyond byte-identity of the hot files, **this package carries
its own live binding suite**: the full test suite was re-run on THIS
exact tree at `fe92f1780b4f` —
**9365 collected / 9354 passed /
0 failed / 0 errors** — recorded
in `deliverables/umdr38/test_evidence/FULL_SUITE_EVIDENCE.json`.

## Relationship to the documented chain

The mission's documented chain head was `6b69458` (binding suite at
`ccb4aea`, 9,365/9,354/0/0 — recorded in
`UMDR40_ACCEPTANCE_MATRIX.json` and the closeout, which stay as the
historical record of that chain). The git lineage itself was lost
with the recycled environments and was never pushed (push
credentials remain the one BLOCKED_EXTERNAL_DEPENDENCY); this
package is the definitive, self-verified artifact of the whole
mission.
