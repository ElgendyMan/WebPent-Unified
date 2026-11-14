# ABHIE v4 — Completion Report

## Executive result

ABHIE v4 has been implemented as a bounded, deterministic, target-neutral expert research-reasoning layer inside WebPent. The implementation covers Research Brain State, unknown discovery, security-boundary mapping, competing hypotheses with a benign alternative, safe strategy selection, scoped reflection memory, evidence-dependent attack-chain intelligence, senior advisory review, and a truthful six-class offline benchmark.

The implementation is an engineering milestone, **not a qualification milestone**. No target was contacted by the ABHIE runner, no credentials were used, no mutation was performed, no finding was created, and no governance authority was granted.

## Delivered surface

| Area | Delivered result | Verification |
|---|---|---|
| Research Brain State | Versioned snapshot/restore, enum and tuple round-trip, deterministic digest, target/engagement scoping, dictionary normalization | `tests/test_abhie_v4.py` |
| Unknown discovery | Five bounded weakness directions with causal-oracle validation language | `tests/test_abhie_v4.py` |
| Boundary graph | Deterministic nodes/crossings and dangerous-crossing advisory marker | `tests/test_abhie_v4.py` |
| Hypothesis competition | Multiple candidates, explicit benign alternative, deterministic prioritization | `tests/test_abhie_v4.py` |
| Strategy selection | Deterministic read-only/local proposal and hard blocks for unsafe capabilities | `tests/test_abhie_v4.py` |
| Reflection | Versioned redacted lessons with target/engagement isolation | `tests/test_abhie_v4.py` |
| Attack chains | Evidence dependencies and explicit negative-control/proof/replay requirements; advisory only | `tests/test_abhie_v4.py` |
| Senior review | Fail-closed review with `no_finding_created` and `no_governance_override` invariants | `tests/test_abhie_v4.py` |
| Core integration | Fixed keyword-only boundary bridge; zero-request, no-mutation composition | `tests/test_abhie_v4.py` |
| Benchmark | Six required classes; one historical IDOR case scorable; five classes blocked | `tests/test_abhie_benchmark.py`, generated JSON artifact |

## Benchmark truth

The benchmark reads `reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json` as a read-only recorded artifact. It does not run a target or manufacture evidence. The only scorable class is IDOR, represented by the recorded case `controlled.idor.owner_resource.v1`. Privilege escalation, business-logic authorization failure, tenant isolation, workflow abuse, and sensitive-information exposure remain `BLOCKED` because the source artifact does not provide complete candidate/control/oracle/proof/replay evidence for them.

| Metric | Value | Interpretation |
|---|---:|---|
| Registered classes | 6 | The full ABHIE v4 class contract is registered |
| Scorable classes | 1 | Historical evidence supports IDOR only |
| Blocked classes | 5 | Missing evidence is excluded, not treated as FN or clean |
| Scorable recorded cases | 1 | One complete historical case joined |
| Evidence completeness | 1.0 | Completeness of the one joined recorded case’s required fields |
| Requests sent by benchmark runner | 0 | Offline replay/report generation only |
| Precision / recall / F1 | `null` | No approved multi-run denominator or live detection measurement |
| Real-world detection rate | `null` | Not measured and not claimed |

## Verification results

The ABHIE-focused regression suite passed **11 tests**. The full repository suite after regenerating the current direct-I/O inventory produced **2,152 passed and 7 failed**. The seven failures are pre-existing/non-ABHIE blockers: one missing Juice Shop source evidence file at `/tmp/juice-shop-source/data/static/challenges.yml`, three Local Causal Lab approval/provenance cases, and three Option B runtime/readiness cases. No ABHIE-focused test failed in the full run.

| Gate | Result |
|---|---|
| Focused ABHIE + benchmark tests | PASS — 11 passed |
| Full pytest | NOT GREEN — 2,152 passed, 7 known blockers |
| Scoped Ruff | PASS |
| Compileall | PASS |
| Import smoke | PASS |
| Generic target neutrality | PASS |
| Tracked secret scan | PASS |
| Direct-I/O inventory regeneration | PASS — 377 records |
| G-02 check | PASS |
| `git diff --check` | PASS |

The current inventory files were regenerated from the source and are intentionally part of the pending source changes. No historical ground truth, thresholds, approval state, or failing validator was weakened to improve the result.

## Governance and release boundary

The following values remain frozen and unchanged: `official_isolated_p10_runs_authorized=false`; `P10=NOT_QUALIFIED`; `P9=NOT_QUALIFIED`; `VIP=NOT_QUALIFIED`; `Bug Bounty=BLOCKED`; `human_signoff=false`; and `qualification_effect=false`. ABHIE does not create findings, sign human approval, promote hypotheses, override the central quality controller, or open an execution gate.

The source changes are ready for the release workflow only after the pending source/docs/artifact commit is created. The release manifest and provenance sidecar must be generated in separate subsequent commits, followed by non-force push/parity verification and only then the final ZIP.
