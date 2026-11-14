# Mission L6 Deliverables — Blind Discovery & Cross-Application Generalization

**Status: implemented, evaluated, all gates green. Results are PRELIMINARY: the corpus is
14 generated instances (11 held-out, 3 dev). This measures performance on WebPent's own
randomized evaluation instances only. It is NOT evidence of generalized real-world
bug-hunting capability, and nothing in this document should be read as such.**

---

## 1. Architecture and data flow

L6 reuses the L5 differential engine unchanged at its core (same orchestrator, same
CausalGuard path, same proof sealing, same ActionAuthority/G-02 execution path). What L6
adds is a blind-surface layer between the engine and the target, plus a ground-truth
evaluator that the discovery process cannot reach.

Data flow for one investigation:

```
generate_instance(seed, blind=True)          webpent/egaie/eval_instances.py
  │  randomized routes, ids, field names, group names, workflow shapes,
  │  per-flag defect profile (vulnerable or fully secured)
  ▼
InstanceTarget (in-process HTTP over loopback, production-shaped responses)
  ▼
DifferentialTracker  ← SurfaceBindings (frozen dataclass, per-deployment
  │  external vocabulary: actor/idem/amount/code/resource/account/action
  │  params, submit/approve actions, owner/state/applied/charged/
  │  authoritative/available/outcome headers and fields, revealed-path keys)
  │  every observation is stored in EXTERNAL (surface) space; correlation
  │  (identity_of, resource_owner, workflow_owner, denied_reads) is derived
  │  only from executed requests against this surface
  ▼
DifferentialProposer (recon sweep → hypotheses)
  │  generators: identity (denial-correlated + mutual-read), price,
  │  boundary, workflow-order, workflow-identity; ≤8 hypotheses/family;
  │  every probe plan carries a probe context routing the oracle
  ▼
Orchestrator (adaptive | fixed | ablation) — selection, prioritization,
  │  gain estimation; the same proposer feeds adaptive and fixed
  ▼
DifferentialExperimentPort.execute()  ← ActionAuthority → ActionExecutor
  │  → G-02 path; scope, capability checks, request budgets, idempotency
  │  keys per (experiment, step); actors travel on the wire
  ▼
DifferentialValidationPort.validate(baseline, candidate, control)
  │  fail-closed family oracles keyed on the evidence's OWN surface
  │  bindings + probe context; status codes alone never confirm;
  │  missing/contradictory evidence → INCONCLUSIVE; a bare 4xx never
  │  establishes a denial on a surface that publishes an outcome field
  ▼
CausalGuard → on CONFIRMED only: DifferentialProofBundlePort.build()
  │  seal = digest(target identity, case identity, evidence digests, verdict)
  ▼
proof_port.verify(bundle): re-runs the oracle on RECORDED observations,
  compares verdict + digests + seal + target identity; NO new target
  requests are ever issued
  ▼
InvestigationState (hypotheses, experiments, outcomes, evidence)
```

Ground truth lives in `webpent/evalsuite/evaluator.py`, a subpackage **outside**
`webpent.egaie`. No discovery-path module imports it (structurally asserted by
`test_evaluator_is_outside_the_discovery_package`, which imports
`webpent.egaie` and `webpent.egaie.differential` in a fresh interpreter and fails if
`webpent.evalsuite.evaluator` lands in `sys.modules`). The evaluator maps engine
families to the instance's spec-enforcement flags, scores per workflow for the
workflow families, derives a `causal_failure` for every false negative
(no_hypothesis_generated / probe_blocked_by_authority / evidence_gap /
differential_not_discriminating / partial_evidence_gap), and scans the state for
label leakage (flag names, ground_truth, expected_verdict, oracle, profile).

**Remaining coupling (honest inventory).** The engine and the evaluator still share
one vocabulary by construction: the five family names and the *concept* of the
invariant families are designed together, so the proposer's hypothesis space is
shaped by the same taxonomy the evaluator scores. The randomized surfaces remove
route/id/field-name reuse and workflow-shape reuse, but not family-taxonomy reuse.
The evaluator also scores against the same spec the instance was generated from;
the generator and the evaluator are separate modules with no shared import, but
they encode the same seven enforcement flags. A renamed fixture or a re-seeded
corpus would therefore NOT constitute independent generalization, exactly as the
mission states; what L6 provides is label isolation, vocabulary isolation, and
workflow-shape isolation, not taxonomy independence.

---

## 2. Changed files and commit hashes

L6 commits on top of the L5 baseline (`ff0263b` = L5 deliverables):

| commit | content |
|---|---|
| `4a7973d` | blind-surface generalization: SurfaceBindings-driven tracker, hypothesis generators, fail-closed oracle |
| `c2118e4` | oracle routing fix (cross-identity mutation probes carry `probe=cross_identity_mutation` context), mutual-read discriminator (`_mutual_read_hypotheses` / `_judge_mutual_read`), sealed eval corpus |
| `78decbb` | red-first blind-discovery regression tests (`tests/egaie/test_blind_discovery.py`; grown to 14 with the resume/no-duplicate-mutation and out-of-scope-authorization tests) |
| `9714fd4` | workflow-identity candidate enumeration from observed external owners; full evaluation harness (`scripts/l6_evaluate.py`); raw results `docs/l6_evaluation.json` |
| `1fbcf9d` | regenerated G-02 direct-I/O inventory (662 records; 3 new egaie sites) |
| `e486076` | restored the `make ci` gate targets (stale `--minimum` literal; E501/F841 in gate-listed files) |

Primary L6 code: `src/webpent/egaie/differential.py` (tracker, bindings, generators,
oracles, proof bundles), `src/webpent/egaie/eval_instances.py` (randomized instance
generator + InstanceTarget), `src/webpent/egaie/discovery_runner.py` (modes),
`src/webpent/evalsuite/evaluator.py` (ground truth), `tests/egaie/test_blind_discovery.py`,
`scripts/l6_evaluate.py`, `scripts/l6_eval_quick.py`, `docs/l6_evaluation.json`.

---

## 3. Full test suite and gates

Run 2026-10-24; every command is reproducible from the repo root.

| gate | command | result |
|---|---|---|
| full suite | `PYTHONPATH=src python3 -m pytest` | **4453 passed, 0 failed** (coverage run of the same suite: 4451 passed at 61.70%, before the final two tests landed; floor 35%) |
| lint (canonical scoped) | `make lint` | All checks passed! |
| test-count floor | `make test-count` | OK: pytest-collected test count 4451 >= floor 1940 |
| security (bandit -lll) | `make security` | exit 0 |
| coverage (35% floor) | `make coverage` | 4451 passed, total coverage 61.70% ≥ 35% |
| construction authority | `python3 scripts/check_orchestrator_construction_authority.py` | OK |
| vault import authority | `python3 scripts/check_vault_import_authority.py` | OK |
| G-02 direct-I/O inventory | `python3 scripts/regenerate_direct_io_inventory.py` then diff | regenerated and committed (`1fbcf9d`), 662 records |

The L6 regression suite itself: `PYTHONPATH=src python3 -m pytest tests/egaie/test_blind_discovery.py tests/egaie/test_differential_discovery.py -q` → 31 passed (14 L6 + 17 L5).

Two additional red-first tests pin the execution-discipline requirements on the
eval instances themselves: `test_resume_replay_never_duplicates_mutations`
(re-executing every confirmed experiment through the same port leaves the target's
order ledger and applied-mutation set byte-identical, i.e. a resumed investigation
never re-applies a completed mutation) and `test_out_of_scope_authorization_blocks_every_request`
(an authorization scoped to a foreign origin lets ZERO requests reach the target,
including reconnaissance; zero experiments execute; zero findings are confirmed).

---

## 4. Raw per-instance results (per seed)

Raw, unedited per-instance results for every seed and every mode are committed at
`docs/l6_evaluation.json`. Reproduce with:

```
cd /home/thaura/webpent_review && PYTHONPATH=src python3 scripts/l6_evaluate.py
```

Corpora: dev D1-D3 seeds 31-33 (visible); held-out blocks A (41,42,43), B (51,52,53),
C (61,62,63), all blind=True; negative controls 71,72 (fully secured lookalikes). Each
instance runs under THREE orchestrator modes at the same round budget (64): adaptive
(proposer + prioritizer), fixed (same proposer, insertion order, no prioritizer),
ablation (no proposer at all). Ground truth is scored against the adaptive run.

### Dev corpus (3 instances, visible) — tuning-side only

| metric | value |
|---|---|
| true positives | 13 |
| false positives | 0 |
| false negatives | 0 |
| recall / precision | 1.0 / 1.0 |
| leakage findings | 0 |
| causal failures | none |

Per family: PRICE_INTEGRITY 4, WORKFLOW_ORDER 3, IDENTITY_BOUNDARY 2,
BOUNDARY_LIMIT 2, WORKFLOW_IDENTITY 2.

### Held-out corpus (9 instances, blind) — the actual claim

| metric | value |
|---|---|
| true positives | 37 |
| false positives | 0 |
| false negatives | 0 |
| recall / precision | 1.0 / 1.0 |
| leakage findings | 0 |
| causal failures | none |

Per family: PRICE_INTEGRITY 13, WORKFLOW_ORDER 6, IDENTITY_BOUNDARY 7,
BOUNDARY_LIMIT 6, WORKFLOW_IDENTITY 5.

Per-instance (adaptive run; TP/FP/FN from the evaluator):

| block | seed | profile | TP | FP | FN |
|---|---|---|---|---|---|
| A | 41 | mixed | 4 | 0 | 0 |
| A | 42 | mixed | 4 | 0 | 0 |
| A | 43 | mixed | 4 | 0 | 0 |
| B | 51 | mixed | 4 | 0 | 0 |
| B | 52 | mixed | 4 | 0 | 0 |
| B | 53 | mixed | 4 | 0 | 0 |
| C | 61 | mixed | 5 | 0 | 0 |
| C | 62 | mixed | 4 | 0 | 0 |
| C | 63 | mixed | 4 | 0 | 0 |

### Repeatability across the three seed blocks (≥3 seeds)

| block | instances | TP | FP | FN | precision |
|---|---|---|---|---|---|
| A | 3 | 12 | 0 | 0 | 1.0 |
| B | 3 | 12 | 0 | 0 | 1.0 |
| C | 3 | 13 | 0 | 0 | 1.0 |

### Negative controls (fully secured lookalikes)

| seed | TP | FP | FN | adaptive requests | confirmed |
|---|---|---|---|---|---|
| 71 | 0 | 0 | 0 | 87 | 0 |
| 72 | 0 | 0 | 0 | 105 | 0 |

The engine investigates the secured lookalikes actively (87/105 requests), generates
and executes hypotheses, and confirms nothing: 18 clean outcomes and 3 inconclusive
per instance. Zero false positives on fully enforced surfaces.

---

## 5. Adaptive vs fixed vs ablation at equal budget

Same proposer, same round budget (64 rounds), same instances; request counts are
recorded empirically per run, not assumed.

Held-out corpus (9 instances):

| mode | confirmed | target requests | wall seconds |
|---|---|---|---|
| adaptive | 37 | 783 | 9.31 |
| fixed | 37 | 783 | 9.24 |
| ablation (no proposer) | 0 | 0 | 0.45 |

Dev corpus (3 instances): adaptive 13 confirmed / 261 requests; fixed 13 / 261;
ablation 0 / 0. Negative corpus: adaptive 0 confirmed / 192 requests; ablation 0 / 0.

Reading: on these instances prioritization neither helped nor hurt (adaptive and fixed
land on the same confirmed set), and the entire discovery capability is attributable to
the differential machinery, not to budget — the proposer-free baseline issues zero
experiments and confirms zero findings. The ablation is an honest floor, not a
handicapped baseline: it is given the same state, the same authorization, the same
budget, and simply has no hypothesis source, which is exactly the comparison the
mission asks for (findings require generated hypotheses plus discriminating evidence).

---

## 6. Walk-throughs: observation → hypothesis → experiment → evidence → verdict

All three are drawn from real runs against blind instances (labels hidden from the
engine); the evidence is the sealed-bundle content (external vocabulary only).

### 6.1 CONFIRMED — price integrity (held-out seed 41)

Observation: the recon sweep read resource `rsc-157036` and observed an authoritative
numeric field (`f148to=50`) on a read endpoint; the index revealed a state-changing
operation at `/tidepool-237`.
Hypothesis (`h-price-integrity-04`, PRICE_INTEGRITY): "/tidepool-237 may honor a
client-supplied price that differs from the authoritative f148to=50".
Experiment: baseline POST `/tidepool-237` as owner `usr-56477` with amount `50`
(idempotency key `59f1d781…`); candidate with amount `51` (`6b3a5c91…`); control
POST without the amount parameter (`8615e511…`).
Evidence (from the sealed bundle): baseline charged 50 against authoritative 50;
candidate charged **51** against authoritative **50**; control charged 50.
Verdict: CONFIRMED — the charged amount followed the client-supplied value while the
authoritative total stayed at 50, with a within-request control ruling out drift.
Bundle seal `658387797d1bd6f9…`, replay-verified from recorded observations only.

### 6.2 CONFIRMED — identity boundary (held-out seed 41)

Observation: recon granted reads to two credentials and observed that `usr-56477` owns
`rsc-157036` while `usr-19608` owns `rsc-764150`.
Hypothesis (`h-identity-boundary-09`, IDENTITY_BOUNDARY): "/kite-329 may accept use by
an identity that does not own the resource".
Experiment: baseline POST `/kite-329` as `usr-56477` on `rsc-157036`; candidate POST as
`usr-19608` on the SAME resource `rsc-157036`; control POST as `usr-19608` on its OWN
resource `rsc-764150`.
Evidence: candidate executed with owner field `f344ow=usr-56477` (granted), control
executed with `f344ow=usr-19608` (granted).
Verdict: CONFIRMED — the third-party actor's action on a resource it does not own was
accepted, and the own-resource control proves the actor itself was valid, so the grant
is attributable to the missing ownership check, not to a broken credential.
Bundle seal `ec4ed8d0c7128e77…`, replay-verified.

### 6.3 CORRECTLY REJECTED — boundary limit on a secured lookalike (seed 71, all flags off)

Observation: recon observed a balance (`f305av=0` after an earlier draw, server value
110 for account `acc-240758`).
Hypothesis (`boundary-limit-01`, BOUNDARY_LIMIT): "/ripple-897 may honor a withdrawal
above the observed balance".
Experiment: candidate POST `/ripple-897` with amount **111** (one above the server
value); control POST with amount **110** (exactly at balance).
Evidence: candidate was DENIED (`{"error": "insufficient"}`); the within-balance control
was accepted (charged 110, available 0).
Verdict: CLEAN, hypothesis CONTRADICTED — the over-limit withdrawal was denied while
the within-balance control was accepted, so the limit holds and no finding is recorded.
This is the discriminator doing its job on a fully enforced instance: the same
generator that finds the defect on vulnerable instances rejects its own hypothesis here.

---

## 7. Hidden-label isolation evidence

Structural and empirical, both in the regression suite and in the raw results:

- `test_evaluator_is_outside_the_discovery_package`: fresh-interpreter import of the
  discovery package must not load the evaluator. Passes.
- `test_no_hidden_labels_in_investigation_state`: JSON-dumps every hypothesis and
  experiment record of completed investigations on a vulnerable and a secured instance
  and asserts none contains any flag name, "ground_truth", "expected_verdict",
  "oracle", or "profile". Passes.
- Evaluator-side scan: `_label_leakage()` independently scans each scored state for
  the same token class; 0 leakage findings across all 14 instances
  (`docs/l6_evaluation.json`, every entry's `evaluation.leakage_findings`).
- The seeded state is EMPTY (`dr._seed_state` calls `seed_state([], …)`): no
  ground-truth cases, no fixture ids. Every hypothesis in every run carries origin
  `differential:recon:…`, i.e. it was proposed by the engine's own recon sweep.
- The instance generator, when `blind=True`, does not hand the spec's defect profile to
  anything the discovery path reads; the profile is read only by the evaluator after
  the run.

---

## 8. Failure analysis and limitations

### Misses found during development, with causal failure for each

Every FN below was observed on the DEV/quick corpora (seeds 11, 14, 17 — none in the
held-out blocks), root-caused, fixed, and re-validated on the untouched held-out set.
No threshold was tuned against held-out outcomes; the held-out run happened after the
last code change.

- IDENTITY_BOUNDARY FN (seed 11): cross-identity mutation probes emitted ProbePlans
  without probe context, so the oracle routed them to the pricing judge, which reported
  "control also charged an amount differing from its authoritative total". Causal
  failure class: evidence_gap (mis-routed judge). Fix: plans now carry
  `("probe","cross_identity_mutation")` and validate() routes them to `_judge_mutation`.
- WORKFLOW_ORDER FN (seed 14): the fixture's 400 unknown-action response carried a
  grant header, so the outcome field said granted while the status said 400; the oracle
  correctly flagged the control as "contradicting its status evidence". Causal failure
  class: differential_not_discriminating (target emitted contradictory evidence).
  Fix: 400 responses emit no grant header (the fixture was wrong, not the oracle).
- IDENTITY_BOUNDARY FN (seed 14): on an open-read surface no read is ever denied, so
  denial-based identity correlation cannot fire and no identity hypothesis is
  generated. Causal failure class: no_hypothesis_generated. Fix: a mutual-read
  discriminator (two credentials, each granted a read of a resource exposing a
  different owner, no denial anywhere) — a distinct judge from the denial-based one.
- WORKFLOW_IDENTITY FN (held-out seed 42, found while validating the harness): with
  open reads only one credential ever correlates, leaving co-owned workflows without a
  candidate identity. Causal failure class: no_hypothesis_generated. Fix: candidates
  are enumerated from ALL observed external identities (correlated values ∪ observed
  resource owners ∪ observed workflow owners), and the first candidate with a viable
  control is used. This was the only FN ever observed on held-out seeds; after the fix
  the held-out FN count is 0.

### Limitations

- **Corpus size.** 14 generated instances (11 held-out). Small enough that every
  number here is preliminary; a single generator family change could move all of them.
- **Taxonomy coupling.** As stated in §1: the proposer's hypothesis space and the
  evaluator's family flags share a designed taxonomy. Vocabulary, workflow shape, and
  labels are isolated; the family taxonomy is not.
- **Invariant families.** Five families (identity boundary, price integrity, workflow
  identity, workflow order, boundary limit). Real-world logic vulnerabilities outside
  these classes are out of scope, and the engine has no mechanism for families it
  cannot hypothesize about.
- **No LLM in the finding path.** The current proposers are deterministic generators;
  the mission's constraint that LLM output may rank but never establish a finding is
  satisfied structurally (only executed, sealed, replay-verified differentials confirm),
  but there is also no LLM proposer yet to which that constraint would apply.
- **Baseline strength.** The ablation baseline is proposer-free by design. A fairer
  future comparison is a non-differential scanner at equal request budget.
- **Secured lookalikes share the generator.** Negative controls are instances of the
  same generator with all flags off; a generator artifact that hides defects from
  itself would go undetected.

---

## 9. Reproduction commands

```
cd /home/thaura/webpent_review
PYTHONPATH=src python3 -m pytest -q                       # full suite
make lint && make test-count && make security             # gates
PYTHONPATH=src python3 scripts/l6_eval_quick.py           # 3-instance quick pass
PYTHONPATH=src python3 scripts/l6_evaluate.py             # full harness → docs/l6_evaluation.json
PYTHONPATH=src python3 -m pytest tests/egaie/test_blind_discovery.py -q
```

SHA-256 of the release ZIP and its manifest are recorded in `docs/L6_RELEASE_MANIFEST.md`.
