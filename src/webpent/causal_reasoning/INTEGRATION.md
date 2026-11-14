# src/webpent/causal_reasoning/INTEGRATION.md
# Proposal #1 — Causal Reasoning Engine: Integration Guide

Additive, non-breaking layer. No existing file is modified. All outputs are
read-only inferences; downstream agents decide whether to act.

## Where to wire it in the existing graph

The existing LangGraph pipeline (`src/webpent/graph/builder.py`) already
emits `Finding` objects into `state["findings"]` via the `merge_findings`
reducer, and the planner builds a hypothesis queue. Three hook points:

### Hook 1 — Engagement start (after recon / target understanding)

```python
from webpent.causal_reasoning import CausalReasoningEngine, ContextFingerprint

fp = ContextFingerprint(
    fingerprint_id=f"fp:{engagement_id}",
    engagement_id=engagement_id,
    target_type=target.target_type,
    frameworks=tuple(recon_signals.get("frameworks", [])),       # e.g. ("django","drf")
    auth_scheme=recon_signals.get("auth_scheme", "unknown"),     # jwt|session|oauth|api_key|none
    auth_policy_pattern=recon_signals.get("auth_policy", "unknown"),  # middleware|decorator|inline
    validation_pattern=recon_signals.get("validation", "unknown"),    # shared_layer|per_route|none
    error_behavior_signature=recon_signals.get("error_sig", "unknown"),
    orm_in_use=recon_signals.get("orm", "unknown"),
    api_style=recon_signals.get("api_style", "unknown"),
    observed_route_count=len(state.get("crawled_data", {}).get("routes", [])),
)
engine = CausalReasoningEngine(fingerprint=fp)
transferred_lessons = engine.start()   # from analogous past targets
# -> feed transferred_lessons into the planner's priority queue. Each
#    TransferredLesson carries typical_route_globs + weakness_category +
#    confidence; the planner can boost those globs in the search order.
```

### Hook 2 — After each confirmed finding (in the validator/reducer)

```python
# state["findings"] just gained a new confirmed Finding:
knowledge_v2 = state.get("target_knowledge_v2")  # TargetKnowledgeV2, if built
entities = {eid: e.model_dump() for eid, e in knowledge_v2.entities.items()} if knowledge_v2 else None
result = engine.ingest_finding(new_finding.model_dump(), knowledge_entities=entities)
# result.hypotheses      -> CausalHypothesis list: why this finding exists
# result.at_risk_regions -> AtRiskRegion list: sibling regions sharing the
#                          same architectural weakness, uncovered-first
#                          (priority_score already weights coverage gap).
# -> append top_regions(10) to the planner's hypothesis queue as
#    Hypothesis(kind="causal_sibling_probe", ...). The engine never marks
#    these as findings — they are search priorities, not detections.
```

### Hook 3 — Engagement end (before reporter)

```python
end = engine.end_engagement(finding_families={f.vuln_class for f in state["findings"]})
# end["root_cause_clusters"] -> RootCauseCluster list: group findings by
#     architectural root cause, each carrying sibling_paths_predicted
#     (probe these in the next engagement) and remediation_hint ("fix once,
#     fix everywhere"). Append these clusters to the report's "root cause
#     analysis" section.
# end["persisted_record"] -> stored in ~/.webpent/causal_memory/ so the NEXT
#     engagement on a similar target starts with transferred lessons.
```

## Design guarantees (matching the project's trust spine)

- **No execution authority.** The engine never issues a request, never
  promotes a hypothesis to a finding, never mutates `state`. It only emits
  bounded, confidence-scored inferences.
- **Deterministic / replay-safe.** Same inputs -> same outputs. No LLM, no
  randomness, no network. Identifiers are content-hashed (`stable_id`).
- **Redaction-safe.** `ContextFingerprint` and all metadata pass through
  `_safe_mapping`, which strips secret-like keys (authorization, cookie,
  token, jwt, ...) and bounds every value. No URLs with userinfo, no
  credentials are ever persisted.
- **Bounded.** Every collection has a max length; every string a max
  length. A pathological finding cannot grow the store unboundedly.
- **Additive.** New `CausalRule`s can be appended to `CAUSAL_RULES` without
  changing existing inferences. New `WeaknessCategory` members are
  backward-compatible (unknown values fall through to `UNKNOWN`).

## Files

| File | Purpose |
|---|---|
| `contracts.py` | Pydantic models + enums + helpers (route globbing, stable IDs, fingerprint similarity) |
| `architecture_inferrer.py` | Finding -> causal hypothesis + sibling at-risk regions (12 causal rules) |
| `contextual_memory.py` | Cross-engagement persistent JSONL store + knowledge transfer + pattern distillation |
| `root_cause_analyzer.py` | Cluster findings by architectural root cause + enumerate sibling paths + remediation hints |
| `engine.py` | Engagement-scoped facade (start / ingest_finding / end_engagement) |
| `__init__.py` | Public API re-exports |
| `tests/test_causal_reasoning.py` | 24 deterministic offline tests |

## Mapping to the proposal's three components

1. **نموذج بنية النظام الاستدلالي** → `ArchitectureInferrer` + `CausalRule`
   table. One finding infers the architectural weakness; propagation over
   `TargetKnowledgeV2.entities` enumerates sibling regions; `AtRiskRegion`
   carries `priority_score` with a coverage-gap bonus so uncovered siblings
   are probed first.
2. **ذاكرة سياقية دائمة** → `ContextualMemory`. Persists `ContextFingerprint`
   per engagement (framework, auth policy, validation pattern, error
   signature, ORM, API style). On a new target, fingerprint similarity
   retrieves analogous past engagements and emits `TransferredLesson`
   ("framework X typically suffers weakness Y in paths Z"). Pattern
   distillation accumulates cross-engagement rules.
3. **مُحلّل جذور الخلل** → `RootCauseAnalyzer`. Clusters findings by
   inferred root cause (not by vuln class), enumerates every sibling path
   sharing that cause, and attaches a `remediation_hint` so one fix
   addresses many findings.
