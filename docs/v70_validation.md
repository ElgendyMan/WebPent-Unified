# WebPent v70 Validation Report

> **Historical validation report:** This document records the v62–v70 validation run and its original dependency findings. It is retained for audit history and is not the current v72 source of truth. See [`v72_plan_compliance_audit.md`](v72_plan_compliance_audit.md) and [`v72_release_notes.md`](v72_release_notes.md) for the v72 result.

## Scope

This report records the validation status of the additive v62–v70 implementation in the WebPent repository. The changes preserve the existing execution path and add fail-closed projections, lifecycle contracts, proof validators, coverage metrics, bounded Copilot suggestions, benchmark metrics, and a read-only coverage CLI command.

No WAPTLab or Juice Shop source, container, database, or runtime state was modified by this implementation or by the release checks. The WAPTLab artifact safety check explicitly records `target_contacted=false` and `waptlab_modified=false`.

## Implemented layers

| Version layer | Implemented contract | Safety property |
|---|---|---|
| v62 | `TargetKnowledgeModel`, deterministic `KnowledgeBuilder`, and target-understanding projection | Engagement-scoped, typed, additive, and fail-closed |
| v62 | Target Knowledge projection into the Attack Graph | Evidence-backed graph projection; it does not create findings |
| v63 | Hypothesis lifecycle and bounded experiment ledger | Deterministic transitions; incomplete validation cannot promote a finding |
| v64 | Multi-agent role registry and ProofBundle validators | Structural, causal, negative-control, and replay checks are explicit |
| v65 | Coverage Intelligence and Copilot boundary | Metrics use observed outcomes; LLM suggestions have no finding, proof, or execution authority |
| v66 | Evaluation metrics and `webpent coverage` CLI command | Offline, deterministic, redaction-safe read-only reporting |
| v70 | Release contracts, VIP gate integration, and documentation | New files are included in the official Ruff and release allowlist |

## Gate results

The final local gate was run from the project virtual environment with `PYTHONPATH=src`.

| Check | Result |
|---|---:|
| Python `compileall` over source and scripts | Passed |
| Ruff over source, tests, and scripts | Passed with zero errors |
| Full pytest suite | **904 passed**, 0 failed |
| Static preserved test-function guard | 855 functions, threshold 818, passed |
| WAPTLab artifact safety | Passed; 20 catalog entries, no target contact, no lab modification |
| VIP quality gate code/qualification checks | Passed |
| Bandit high-severity check | Passed |
| pip-audit strict/SBOM | Blocked by 17 known vulnerabilities in 9 packages |

The static function guard and pytest count measure different properties. The release gate checks the preserved function baseline separately, while the authoritative behavior regression result is the full pytest result of 904 passed tests.

## Evidence and confirmation policy

The new code does not turn target observations, LLM text, graph nodes, or hypotheses into findings by itself. A reportable result still requires actual behavior and the applicable evidence, causal signal, negative control, replay, and sealing requirements. The Copilot boundary accepts only bounded research-action suggestions and rejects authority-bearing keys such as finding, proof, or execution requests.

> Passing local contracts does not prove that a live WAPTLab run discovers 15–18 confirmed vulnerabilities in one campaign. That claim requires an authorized live run with preserved artifacts and reproducible evidence.

## Known blockers and limitations

The VIP artifact preserves the following limitations instead of hiding them:

1. The worker critical-path coverage remains below the project’s aspirational target.
2. The existing LangChain/LangGraph advisory set remains documented in the pip-audit production artifact; this is an environment/dependency blocker rather than a silent code fix.
3. The WAPTLab regression artifact is a local contract artifact and does not claim live confirmations.
4. The repository still emits dependency deprecation and development-secret warnings in tests; production deployment must provide strong independent secrets and review dependency upgrades separately.

## Reproduction commands

```bash
project=/tmp/webpent_v60_smart_implementation
venv=/tmp/webpent_v60_review_stage/webpent_v60_smart_stage/.venv
export PYTHONPATH="$project/src"

"$venv/bin/python" -m compileall "$project/src" "$project/scripts" -q
"$venv/bin/ruff" check "$project/src" "$project/tests" "$project/scripts" \
  --line-length 100 --output-format concise
"$venv/bin/pytest" "$project/tests" -q --tb=short
cd "$project"
PYTHONPATH=src "$venv/bin/python" scripts/run_vip_quality_gate.py
```

## Conclusion

The v62–v70 implementation was internally validated for code behavior and release-contract wiring at the time of this report. Its dependency findings were subsequently addressed by the v72 LangGraph/LangChain upgrade and strict pip-audit verification. This report is **not** evidence that the Autonomous Bug Hunter has achieved a fixed live target count; that remains a separate authorized benchmark and must not be inferred from offline or mock artifacts.
