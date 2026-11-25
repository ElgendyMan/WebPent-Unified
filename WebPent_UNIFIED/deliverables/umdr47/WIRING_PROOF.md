# UM-DR-47 — WIRING PROOF (Phase W gate: brain OFF vs brain ON)

> Law 47-1: "العقل الذي لا يغيّر سلوك الحملة ليس عقلًا — والفرق صفر يعني W لم تُغلق."
> Produced by code: `tests/test_umdr47_w_gate.py::TestWiringGate::test_off_on_difference_is_real`
> (the full official entrypoint `run_unified_hunt` on the authorized counting IDOR lab — the UM-DR-37 fixture with a request counter).

## The OFF/ON campaign (one lab, run twice, same scope)

| Metric | brain OFF (46 behavior) | brain ON (47 wiring) | Difference |
|---|---|---|---|
| W4 coverage-gap research tasks in the pool | 0 | > 0 (asserted by the gate) | **real** |
| W5 chain-step hypotheses in the pool | 0 | 0 (recorded honestly — see note) | n/a in this lab |
| Request sets (paths hit) | baseline set | **different set** (asserted: `sorted(off) != sorted(on)`) | **real** |
| Research memory saved at campaign end (W6) | no | yes — file written, privacy-scrubbed | **real** |
| Safe-stop / watchdog construction (W7) | not constructed | constructed on the live stream (engagement-scoped) | **real** |

Note (honest): this lab's clean crawl produces no marker disagreement for
chains to compose, so W5 = 0 here. The sequential chain-step machinery
(gate: step N rankable only after step N-1 closes; per-step guarded proof)
is proven on the chain-bearing fixture in
`tests/test_umdr47_w_engine.py::TestW5ChainSteps` (3 tests).

## The root cause found and fixed (the 46 lesson, precisely)

The 46 brain was advisory **in the deepest sense**: its SKG input channels
(`skg_evidence`, `object_identity_observations`) had **NO production
writer** — they existed only in test fixtures. The SKG therefore always
built without resources/relations in real campaigns, so the brain had
nothing to reason over. Diagnosed live (traced node runs: `auth_obs=2 →
unverified=0 → chains=0`).

The wiring data fix (`_derived_wiring_channels` in
`src/webpent/production/brain_engine.py`) derives those channels from REAL
campaign data, deterministic and evidence-ref'd:

1. **crawl object variance** — crawled route paths with a varying object
   segment (e.g. `/api/invoices/INV-A-101`, `/api/invoices/INV-B-777`, …)
   → object-identity observations + endpoint READ relations;
2. **bac_observations** (the access_control node's real records) →
   per-tested-identity authorization-coverage ledger rows.

Plus the timing fix: the brain node now re-runs on every
**strategist-bound route** (the composed `_research_route_redirects`
chain, the umdr31/32 precedent) — AFTER the testing lanes produced
authorization observations — instead of only in the pre-testing advisory
chain where they cannot exist yet.

## The literal priority formula (W3, restored from the owner's §6 vision)

```
Priority = (ExpectedInformationGain × Impact × Confidence) / (Cost + Risk)
```

Pure function (`priority_formula`), declared estimators (all SKG/brain-derived, no LLM):
EIG ← hypothesis `info_gain` or unverified-cell density (W4) ·
Impact ← vuln-class severity × SKG sensitive reachability (W1) ·
Confidence ← the hypothesis's own confidence ·
Cost ← the experiment planner's differential-triple estimate ·
Risk ← the brain's endpoint profile risk (state-changing surface without an authz marker).

**Sensitivity tests (law 47-3): one per variable** — flipping EIG, Impact,
Confidence, Cost or Risk each flips the ranking
(`tests/test_umdr47_w3_priority.py::TestSensitivityEachVariable`, 5 tests).
Applied in BOTH selection lanes: `rank_open_hypotheses` (strategist) and
`AutonomousExperimentSelector._score` (AVI) — flag-gated, fail-closed,
flag-off keeps the 46 scoring byte-comparable.

## Test evidence (49/49 green, locally)

| File | Tests | Covers |
|---|---|---|
| tests/test_umdr47_w3_priority.py | 13 | the literal formula + 5 sensitivity tests + both-lane ranking |
| tests/test_umdr47_w_engine.py | 13 | W1 context, W4 tasks, W5 sequential gate, the node, flag gating |
| tests/test_umdr47_w6_memory.py | 11 | save/load roundtrip, append-only, cross-target isolation, **privacy negatives on real cookie-shaped input**, learned-context seam (flag on/off) |
| tests/test_umdr47_w7_watchdog.py | 9 | repetition/scope/budget thresholds, snapshot + scrub, determinism |
| tests/test_umdr47_w_gate.py | 3 | **the OFF/ON gate itself** + watchdog construction site |

Commands:
```
uv run python -m pytest tests/test_umdr47_w3_priority.py tests/test_umdr47_w_engine.py \
  tests/test_umdr47_w6_memory.py tests/test_umdr47_w7_watchdog.py tests/test_umdr47_w_gate.py -q
# => 49 passed
```

## Hard limits preserved (unchanged)

No network I/O from the engine, no authorization, no scope expansion, never
a finding, never a confirmation — CausalGuard/ProofBundle/Replay remain the
sole confirmation authorities; memory is demotion-only; the watchdog
observes and stops, never executes.
