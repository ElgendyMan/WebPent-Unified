# VABH-FIL v8 Design

**Author:** Manus AI
**Status:** Implemented as an advisory, fail-closed research-intelligence layer.

## Purpose

VABH-FIL v8 extends the existing WebPent research stack with an expert-oriented reasoning layer. It consumes recorded engagement state, target-neutral world-model data, coverage gaps, prior failures, and scoped memory. Its output is a ranked research direction, investigation questions, hypotheses, adaptive strategy, attack-graph updates, skepticism checks, and readiness analysis.

The implementation is intentionally bounded. It does not send requests, mutate target state, use credentials, create findings, override a causal oracle, alter policy, or grant P10/VIP qualification. A result may describe what evidence would be needed, but it cannot claim that the evidence exists.

## Composition

| Layer | v8 responsibility | Authority boundary |
|---|---|---|
| Executive brain | Select an information-seeking direction and explain priority, cost, uncertainty, and stop conditions. | Cannot execute or confirm. |
| Expert reasoning | Convert recorded assumptions into security questions, potential weaknesses, required evidence, and validation approaches. | Cannot infer a vulnerability from reachability or intended behavior. |
| Adaptive strategy and graph | Rank recorded paths by information gain and represent unresolved trust or workflow relationships. | Graph updates remain unconfirmed. |
| Hypothesis evolution | Retain, reject, merge, or block theories based on recorded evidence references. | Confidence cannot become confirmation without a causal oracle. |
| False-positive defense | Challenge intended behavior, attacker capability, impact, alternatives, and reproducibility. | Cannot override central verification. |
| Scoped memory | Store redacted, target/engagement-scoped lessons in-process. | No cross-engagement leakage or sensitive storage. |
| Benchmark and review | Produce strict offline benchmark, scorecard, and readiness report. | Metrics remain null when evidence is incomplete; review cannot qualify VIP. |

## Safety Invariants

Every public contract has fail-closed fields for execution, mutation, finding creation, confirmation, oracle override, and qualification. The controlled benchmark enforces `requests_sent == 0`. The composition root returns a result with zero requests, no mutations, no findings, and no qualification approval.

Target-specific semantics remain outside the generic v8 core. The core accepts recorded values and opaque identifiers rather than hard-coded routes, products, credentials, or target workflows. Any future authorized live adapter must be separately scoped and must not silently expand the authority of this package.

## Evaluation Boundary

The benchmark registers six scenario classes, but a case is scorable only when realistic target modeling, hidden assumptions, autonomous investigation, multiple paths, a causal oracle, a sealed proof bundle, and replay verification coexist. The current recorded artifact does not establish all of those conditions together. Therefore the evaluation reports blocked cases, zero requests, and null production-quality metrics rather than fabricated detection results.

## Governance

The v8 layer is advisory and subordinate to the existing central quality, policy, oracle, and qualification authorities. The implementation preserves `official_isolated_p10_runs_authorized=false`, P10/P9/VIP as `NOT_QUALIFIED`, Bug Bounty as `BLOCKED`, and human signoff as false. Opening a controlled lab, using credentials, changing frozen ground truth or thresholds, enabling state mutation, or opening an official run gate remains outside this implementation and requires an owner decision.

## Reproducibility

`python3 scripts/run_vabhfil_v8_evaluation.py` regenerates the v8 benchmark, score, and readiness artifacts from recorded state. `PYTHONPATH=src:. pytest -q tests/test_vabhfil_v8.py` runs the focused regression suite. The release package contains the source, tests, scripts, reports, artifacts, documentation, raw governing specification, content manifest, and hash manifest.

## References

No external sources were used. This document is an implementation record for the governing specification supplied as the task attachment and the existing WebPent source tree.
