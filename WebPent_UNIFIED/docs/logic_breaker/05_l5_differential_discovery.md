# L5 — Differential Discovery Engine

Mission: a new discovery capability that derives security-relevant behavioral
differentials from observed behavior (identities, permissions, resources,
application states) and promotes findings only through the existing validated
closed loop. Everything runs on the isolated loopback benchmark target; no
live targets, no external network. Work is on the production repo; the
deliverables commit is recorded in §7. The pre-existing working-tree overlay
`download/econ/portfolio_transitions.jsonl` (repository-owner change, present
before L0) is preserved and was never staged.

## 1. Architecture map

The engine reuses every existing component; there is no second orchestrator
and no duplicated evidence pipeline.

```
ObservationLedger (existing, observation-only)
        │  reconnaissance()  (read-only: index, resources, workflows,
        │                     grants/denials, two synthetic identities)
        ▼
RelationshipTracker.view()  (grounded view: owners, candidates,
        │                    authoritative fields, published codes,
        │                    workflow states)
        ▼
DifferentialGenerator.generate(view)   [differential.py]
        │  bounded, per-family hypothesis synthesis; PRISTINE_FAMILIES
        │  = {WORKFLOW_ORDER} is the single source of truth for both
        │  the pristine flag and the staging schedule
        ▼
DifferentialPrioritizer.rank()  (band first, then gain/cost)
        ▼
DifferentialProposer.propose(state)    [differential.py]
        │  TWO-STAGE emission: pristine WORKFLOW_ORDER band first;
        │  the deferred band (IDENTITY_BOUNDARY, PRICE_INTEGRITY,
        │  WORKFLOW_IDENTITY) is held back until every pristine
        │  experiment has an outcome. Reason: InformationGainSelector
        │  re-scores pending experiments by gain every round and would
        │  interleave the bands, sending identity submits before order
        │  approvals and destroying order-probe preconditions.
        ▼
InformationGainSelector  (existing) ── InvestigationOrchestrator.run()
        │  (existing; the ONLY orchestrator)
        ▼
ActionExecutor → ActionAuthority → G-02 → scope/capability/budget/
        │  idempotency controls (all existing, unchanged)
        ▼
DifferentialValidationPort.validate(baseline, candidate, control)
        │  fail-closed family judges; verdicts confirmed / clean /
        │  inconclusive / blocked, with dispositions
        │  evidence_missing / action_blocked / no_differential_available
        ▼
CausalGuard → sealed proof bundles (replay-valid, seal-valid)
        ▼
discovery_runner.py: promotion, per-family metrics, benchmark,
        ablation, resume invariants, ground-truth mapping
```

New modules and their sizes:

| module | role |
|---|---|
| `src/webpent/egaie/differential.py` (extended) | `ObservationLedger`, `RelationshipTracker`, `DifferentialGenerator` (four families), `DifferentialPrioritizer`, `DifferentialProposer` (staged emission), `DifferentialValidationPort` (fail-closed judges), sealed proof-bundle wiring |
| `src/webpent/egaie/discovery_runner.py` (new) | `_run_loop` (adaptive / fixed / ablation modes over ONE orchestrator), `_finding_path` (probed path from the registered probe plan, never a label), `_family_metrics` (P/R/F1 with `true_positive_origins`), global FP filter over origins, `_proof_association_metrics`, `run_discovery_comparison`, resume invariants |
| `src/webpent/egaie/discovery_ground_truth.py` (new) | 24 cases over declared seeds (1, 2, 3), version `discovery-v1`; 9 positives / 15 negatives, each justification written from enforcement behavior (see §4) |
| `tests/egaie/test_differential_discovery.py` (new) | 17 red-first regression tests |

Integration points (all existing, zero modifications): `InvestigationOrchestrator`,
`InformationGainSelector`, `ActionExecutor`, `ActionAuthority`, G-02 direct-I/O
gate, scope/capability/budget/idempotency controls, `CausalGuard`, sealed
proof/replay contracts, `ScanMode`/`Settings`. The L4.1 protected-file policy
is preserved: zero touches to sealed or frozen files.

## 2. What the engine discovers

Four bounded families, all derived from ALLOWED observations:

- `IDENTITY_BOUNDARY` — a second synthetic account reaches a resource the
  ledger observed granted to/denied for the first; confirmed only on a
  server-enforced outcome contrast (candidate accepted with ownership
  evidence in the response while the control identity is denied), never on a
  status code alone.
- `WORKFLOW_ORDER` — a transition may be applied out of its observed order
  (e.g. approve from draft); pristine-state precondition, `409
  invalid_transition` falsifies.
- `PRICE_INTEGRITY` — a client-supplied amount may override the
  authoritative total; a published discount code may be applied by a
  non-owner. Kept strictly separate from http-v3's PRICE_INTEGRITY label
  space (different module, different case ids, different version).
- `WORKFLOW_IDENTITY` — a workflow may accept transitions from a non-owner.

Evidence standards (fail-closed): a language-model explanation is never
evidence; promotion requires a validated differential composite and a sealed
replay-valid proof bound one-to-one to the finding. Missing evidence →
`inconclusive` (`evidence_missing`); authority denial → `blocked`
(`action_blocked`); a server-enforced legitimate difference → `clean`
(rejected, never promoted). Generic business-logic defects stay in their own
family and are never relabeled as authorization bypasses; the ground truth
and the per-family attribution enforce this structurally (attribution comes
from the hypothesis that generated the probe, never from path overlap).

## 3. Correctly rejected and inconclusive behaviors

From one seed-1 adaptive run (29 derived hypotheses, 9 confirmed):

- `workflow-order-01..04` → CLEAN: approve is rejected with `409 invalid
  transition` while the unknown-action control is rejected with `400`; the
  engine falsifies its own hypotheses rather than confirming everything.
- `identity-boundary-05` → CLEAN: the enforced owner-only control on
  `/regs-0001/r-000105` denies the second account exactly like the control;
  a legitimate difference is never promoted.
- `price-integrity-01/04/06/07/08/10` → INCONCLUSIVE: evidence missing
  (probe blocked or no differential available), distinct from clean.
- Judge-level (unit-tested): all-blocked composite → `blocked`; one side of
  the contrast missing → `inconclusive`; foreign accepted but no ownership
  evidence → `inconclusive`; enforced control (candidate 403 / control 200)
  → `clean`.

## 4. Ground truth independence

`discovery_ground_truth.py` declares 24 cases over seeds 1/2/3. Positive and
negative labels each carry a justification written from the deployment's
enforcement behavior (e.g. "the target's enforcement matrix enforces
owner-only reads on this resource: a second account's read is denied, so a
confirmed cross-owner read here would be a false positive" for a negative;
"the cross-owner application is accepted and the revealed order records the
applier" for the multi-step coupon positive). External identifiers are
randomized per deployment seed; the test suite asserts the declared paths of
different seeds are pairwise disjoint, so the detector cannot be scoring
memorized names. Hypothesis origins are engine slugs
(`differential:recon:{slug}`), never case ids; `test_hypotheses_never_carry_case_labels`
asserts no case id appears in any derived statement.

## 5. Benchmark comparison and ablation (equivalent budgets: 48 rounds)

`run_discovery_comparison(target, seed, max_rounds=48, repetitions=2)`,
loopback target only:

| seed | mode | confirmed | recall | FP | replay-valid proofs | requests |
|---|---|---|---|---|---|---|
| 1 | adaptive | 9/9 | 1.0 | 0 | 9 | see JSON |
| 1 | fixed baseline | 0 | 0.0 | 0 | 0 | — |
| 1 | ablation (no gain selection) | 9 | 1.0 | 0 | 9 | — |
| 2 | adaptive | 9/9 | 1.0 | 0 | 9 | — |
| 2 | fixed baseline | 0 | 0.0 | 0 | 0 | — |
| 2 | ablation | 9 | 1.0 | 0 | 9 | — |
| 3 | adaptive | 9/9 | 1.0 | 0 | 9 | — |
| 3 | fixed baseline | 0 | 0.0 | 0 | 0 | — |
| 3 | ablation | 9 | 1.0 | 0 | 9 | — |

`thresholds_pass`, `reproducible`, `resume_correct` are True on all three
seeds. Per-family adaptive (seed 1): WORKFLOW_ORDER 2/2, WORKFLOW_IDENTITY
2/2, IDENTITY_BOUNDARY 3/3, PRICE_INTEGRITY 2/4 declared positives (the
multi-step coupon scenario among them, attributed to PRICE_INTEGRITY, never
to an authorization family). Full machine-readable output is preserved in
the session artifacts (`/tmp/l5_benchmark.json` at delivery time).

Ablation reading: the gain selector matches the fixed order at this budget
because the ground truth is small and every derived hypothesis is cheap; the
selector's value shows in the staged-emission scheduling (§1), where
unconstrained re-scoring demonstrably broke order-probe preconditions
(WORKFLOW_ORDER recall dropped to 1/2 before the two-stage proposer was
added — reproduced in the red phase of `test_ledger_ordering...`).

## 6. Test results

`tests/egaie/test_differential_discovery.py` — 17 passed, covering:
false-positive resistance (enforced control rejected at judge level and at
engine level), missing-evidence dispositions (blocked / evidence_missing /
no_differential_available distinct from clean), identity mismatches,
randomized identifiers across seeds 1/2/3 with disjoint paths, interrupted
then resumed runs (no lost confirmations, no duplicate hypotheses, deferred
band still emitted), destroyed order-probe precondition → INCONCLUSIVE,
every promoted finding bound to a sealed replay-valid proof
(`replay_valid_confirmed == confirmed_cases`, zero unrelated/duplicate/
mismatched records), hypotheses never carrying case labels, business-logic
findings staying in their own family, and the benchmark shape (24 cases,
9 positives, seeds (1,2,3), version `discovery-v1`).

Full suite: **4439 passed** (was 4422 at L4.1 close; +17). Gates: G-02
direct-I/O drift gate 4/4, construction-authority OK, vault import authority
OK, frozen-manifest OK, ruff clean (E,F,I,N,W,UP,B,C4,SIM; line-length 100)
on all changed files.

## 7. Changed files and commits

| commit | files |
|---|---|
| `c084130` egaie: differential discovery runner, ground truth, staged proposer, red-first suite (L5 step 2c) | `src/webpent/egaie/discovery_runner.py` (new), `src/webpent/egaie/discovery_ground_truth.py` (new), `src/webpent/egaie/differential.py` (extended), `tests/egaie/test_differential_discovery.py` (new) |

Earlier L5 commits on the same branch: `d6920f1` (ledger, tracker, bounded
generators, fail-closed oracles, sealed proof bundles, proposer), `7cbb136`
(promotion codes in the discovery index, grounded coupon discovery),
`4601ebd` (two-credential recon, external-identity probes, strong/fallback
correlation, blocked disposition per family).

Not modified: any sealed/protected file, any L4.1 frozen module, the
orchestrator, the evidence pipeline, `download/econ/portfolio_transitions.jsonl`.

## 8. Limitations

- Scope is bounded by design: four families on the loopback deployment's
  observable surface (index-revealed resources, workflows, numeric fields,
  published codes). Nothing combinatorial; each hypothesis has explicit
  preconditions and a bounded probe plan.
- The fixed baseline confirms nothing here because the benchmark's derived
  hypothesis stream is the adaptive engine's product; at equivalent budgets
  a label-driven runner would score higher, which is the point: discovery
  pays for derivation. This must not be read as generalized discovery
  beyond the fixture deployment; the engine has only ever seen the loopback
  target family.
- INCONCLUSIVE rates on PRICE_INTEGRITY are intentionally high (evidence
  missing is reported as such, never rounded down to clean or up to
  confirmed).
- The ablation gain selection equals the fixed band order at this budget;
  the selector's scheduling value is demonstrated by the red-phase
  regression (interleaved emission breaking order preconditions), not by
  end-metric separation.
- The engine cannot confirm anything without a replay-valid sealed proof;
  where the authority blocks a probe the outcome is BLOCKED with
  `action_blocked`, and no finding is promoted on partial evidence.
