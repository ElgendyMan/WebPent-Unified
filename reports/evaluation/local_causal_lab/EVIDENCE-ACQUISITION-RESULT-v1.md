# Evidence Acquisition & Target-Backed Validation Layer — Result v1

## Executive decision

The Evidence Acquisition layer is **implemented and fail-closed**, but the milestone does **not** produce a target-backed confirmed vulnerability. The first WebGoat target-backed case was evaluated at the readiness gate only. Because the required owner/requester identity separation, disposable ownership fixture, bounded semantic authorization signal, and replayable target state were not attested, execution stopped before any network request.

> The offline `CONFIRMED` result validates the causal engine and ProofBundle mechanics only. It is not target-backed evidence, does not increase the P10/VIP case count, and does not establish discovery quality.

## Before / after

| Capability | Before this milestone | After this milestone |
|---|---|---|
| Evidence provenance | Offline and target-shaped observations could be confused by callers | Typed `evidence_origin` distinguishes `offline_fixture` and `target_runtime`; vNext target-backed paths require the latter explicitly |
| Target readiness | No central target-evidence readiness decision | Option B contract checks identity, ownership, reset, oracle signal, observable invariant, and replayable transition before requests |
| Offline promotion boundary | Offline fixture success existed | Offline evidence is isolated from target-backed promotion and scoring |
| Replay integrity | Context and evidence digests were checked | Replay additionally checks oracle decision, invariant analysis, evidence references, evidence origin, and sealed digest |
| WebGoat IDOR | Historical flow was inconclusive and prohibited from reuse | A distinct redesign was assessed; capability gap remains formally `BLOCKED` without rerunning the old flow |

## Implemented controls

The existing causal and proof contracts were extended without adding another generic architecture layer. `CausalObservation` carries a typed evidence-origin value. `ProofBundle` vNext seals that origin and includes the target context, campaign/run identifiers, structured evidence references, oracle decision, invariant analysis, validator result, and replay metadata. The central verifier rejects a causal vNext target-backed path when any observation lacks explicit `target_runtime` provenance.

The target-evidence readiness contract lives inside the existing local causal lab Option B contract. It returns `BLOCKED` before any request when a required capability is missing. This preserves the approved GET-only, local-only boundary and does not create credentials, login sessions, tokens, external callbacks, or destructive state changes.

## WebGoat result

The source-backed WebGoat redesign remains blocked under `WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE`. The source-backed lesson is session-bound and the currently approved adapter does not provide two independently controllable synthetic identities, a disposable owner-owned resource, a bounded semantic GET observation, and an independent denied control. Reusing the prior B2/B2.1 request flow was explicitly excluded, so no such flow was run.

The new target-backed first-case attempt therefore executed only readiness preflight. The resulting artifact is `TARGET-BACKED-FIRST-CASE-RESULT-v1.json`; it records zero network requests, zero observations, zero sealed ProofBundles, and a fail-closed `BLOCKED` result. The exact reopen requirement is recorded in `WEBGOAT-TARGET-EVIDENCE-CAPABILITY-GAP-v1.json`.

## Validation

The focused causal, verifier, security-invariant, readiness, and replay-mismatch suite passed **23 tests**. Ruff and compileall passed. Full pytest completed with **2,002 passed and 4 historical failures**. The four failures remain the known `approval_source_hash_mismatch` in the historical Option B approval import and were not altered, suppressed, or re-pinned.

The G-02 inventory was regenerated from current source and the G-02 runtime/precommit checks passed with **343 records**. Generic target neutrality, tracked-secret scanning, local causal packet validation, and target-adapter review validation passed. The approval validator continues to fail closed solely on the historical approval-source hash mismatch.

## Governance and qualification boundary

| Gate | State |
|---|---|
| Target-backed causal confirmations | **0** |
| Offline fixture confirmations | **1**, engine-only |
| Scoring ProofBundles | **0** |
| Target-backed replay successes | **0** |
| Official isolated P10 authorization | `false` |
| P10 / P9 / VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |

The next legitimate reopening condition is an owner-approved local WebGoat fixture/session capability, or an equivalent approved target fixture, that supplies the missing independent identities, ownership relation, deterministic reset, bounded semantic authorization observation, and negative control. No policy, frozen ground truth, threshold, credential, permission, or external scope was changed in this milestone.

## Provenance files

- `src/webpent/shared/proof_oracles.py`
- `src/webpent/models/proof_bundle.py`
- `src/webpent/shared/verifier.py`
- `src/webpent/adapters/local_causal_lab/option_b_contract.py`
- `src/webpent/adapters/webgoat/causal_experiment.py`
- `reports/evaluation/local_causal_lab/WEBGOAT-TARGET-EVIDENCE-CAPABILITY-GAP-v1.json`
- `reports/evaluation/local_causal_lab/TARGET-BACKED-FIRST-CASE-RESULT-v1.json`
- `reports/evaluation/local_causal_lab/CAUSAL-ENGINEERING-METRICS-vNEXT-v1.json`
