# UM-DR-32 Final Evaluation Report

**Window:** UM-DR-32 — §9 (Phase Seven), the controlled end-to-end capability lab
**Report date:** 2026-11-09
**Machine record:** `reports/qualification/umdr32_benchmark.json` (release-grade
provenance: clean tree, ground-truth manifest hash recorded)
**Population honesty:** team-authored, author-known fixture — a development
and mechanism-validation population. NOT an independent holdout. No
real-world recall/precision claim. No cross-tool comparison.

---

## 1. What improved, and by how much

### 1.1 Object/alias RESOLUTION (the understanding metrics — kept separate from detection)

| Arm | Alias pairs confirmed (of 4) | False merges | Missed | Precision | Abstention respected |
|---|---|---|---|---|---|
| baseline | 0 | 0 | 4 | — | yes |
| object_identity | 0 | 0 | 4 | — | yes |
| **alias_resolution** (and every later arm) | **4** | **0** | **0** | **1.0** | yes |

The never-merge pairs (tenant-namespace, resource-type, query-value) and
the abstain pair (slug without evidence) were NEVER confirmed in ANY
arm. Namespace separation held everywhere.

### 1.2 Vulnerability DETECTION (the campaign metrics)

Four ground-truth scenarios on the controlled fixture (V-IDOR-601,
V-ALIAS-701, V-XTENANT-501, V-APPROVAL), identical recon, equivalent
budgets (ceiling 120 requests/arm):

| Arm | Scenarios found | TP | FP | FN | Precision | Recall | F1 | Requests |
|---|---|---|---|---|---|---|---|---|
| baseline | 0 | 0 | 0 | 4 | — | 0.0 | — | 28/120 |
| object_identity | 0 | 0 | 0 | 4 | — | 0.0 | — | 28/120 |
| alias_resolution | 0 | 0 | 0 | 4 | — | 0.0 | — | 28/120 |
| multi_identity | 3 | 3 | 0 | 1 | **1.0** | 0.75 | 0.857 | 65/120 |
| composite_workflow | 4 | 4 | 0 | 0 | **1.0** | **1.0** | **1.0** | 82/120 |
| **unified** | **4** | **4** | **0** | **0** | **1.0** | **1.0** | **1.0** | 82/120 |

**Precision was preserved at every step: zero false positives in every
arm.** The unified arm reaches every ground-truth scenario for 54
additional requests over baseline (well inside the equivalent ceiling),
with scenario-level deduplication (one vulnerability counted once
however many representations or questions surfaced it).

## 2. Which scenarios were discovered, how

- **V-IDOR-601** (foreign same-tenant user reads the owner object): the
  multi-identity matrix generated the differential question (owner
  allowed + foreign principal with a denied control); the
  privilege-differential route CONFIRMED on the real triple.
- **V-ALIAS-701** (the alias representation loses authorization): the
  alias layer confirmed orders/701 ↔ o/701 as the same object; the
  cross-representation differential found foreign DENIED on the
  canonical but GRANTED on the alias — the contrast that defines an
  alias bypass.
- **V-XTENANT-501** (a t1 principal reads a t2 object): the identity
  layer kept t1/orders/501 and t2/orders/501 distinct (namespace rule);
  the tenant-boundary differential rule generated the question; the
  route CONFIRMED with the own-tenant object as the positive baseline.
- **V-APPROVAL** (a viewer completes the manager-only approval): the
  composite engine built the full observed path
  (create→submit→approve) with the role-scoped boundary; the manager
  control run completed legitimately; the viewer run completed the
  planted flaw; the vault negative control was denied → the
  privilege-differential route returned the policy-violation candidate.

## 3. Which scenarios were missed, where, and why (the honest arm reading)

- baseline → 0/4: the pre-UM-DR-32 engine has NO cross-principal
  execution and NO sequence reasoning — the exact capability gap this
  window set out to close. This is the measured baseline, not a defect.
- object_identity / alias_resolution → 0/4 detections: understanding
  alone does not detect. These arms improve RESOLUTION (0/4 → 4/4
  aliases) — the separation §9.3 E demands, and the reason the
  capability matrix reports both metric families independently.
- multi_identity → 3/4: V-APPROVAL requires sequence reasoning (the
  approval is a legitimate single request for a logged-in user; only
  the ROLE boundary makes it a violation) — delivered by the workflow
  capability in the next arm.

## 4. Which features produced measurable value

| Feature | Measured value |
|---|---|
| Alias resolution | resolution 0/4 → 4/4 at zero false merges (the prerequisite for the alias-bypass detection) |
| Multi-identity differentials | +3 scenarios (IDOR, alias-bypass, cross-tenant) at precision 1.0 — the first cross-principal detections in the engine's measured history |
| The validator-route closure | the enabler: without the registry entry every differential would be missing-validator (the UM-DR-31.1 wall) |
| Composite workflows | +1 scenario class (sequence/role-boundary) no single-request method can express |
| Unified chain | 4/4 at P=1.0 with the identical budget contract |

## 5. Which features remain partial

See the qualification matrix limitations: schema-less alias
corroboration, cross-campaign identity memory, execution-as-graph-node
(deliberately deferred), attribute-signature automation.

## 6. Which assumptions were disproved

- "identity knowledge alone would find more": measured FALSE —
  resolution is not detection; the detection gains arrive only when the
  differential/sequence layers consume the identity layer's output.
  The dependency chain is real and now documented by arm.
- "the alias layer might merge look-alikes": measured FALSE across six
  arms and 4 never-merge pairs + 1 abstain pair — zero false merges.
- "differentials would burn the budget": measured FALSE — the deduped
  differential phase costs 24 requests for 8 targets; the unified arm
  finishes at 82/120.

## 7. What cannot yet be claimed

1. No generalization beyond this fixture's population (team-authored,
   author-known, single fixture).
2. No independent validation (M10 stays BLOCKED_EXTERNAL_DEPENDENCY).
3. No real-world precision/recall numbers.
4. No superiority over any other tool (explicitly out of scope, §1.5).
5. The full 45-node LLM campaign traversal was not executed (no
   operator credentials in this window); the wiring is proven at the
   LangGraph level with real compiled graphs.

## 8. Determinism

Repeat runs of the complete six-arm evaluation produce identical
confirmed-scenario sets per arm (test-enforced:
`test_determinism_repeat_run`). All reasoning modules are pure
functions of the observation set (ingest-order independence is
test-enforced for the registry).
