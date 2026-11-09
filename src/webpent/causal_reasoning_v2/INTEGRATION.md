# Causal reasoning v2 integration contract

The causal reasoning packages are additive. Their three lifecycle hooks are
available through `CausalIntegrationLayer`, but the supplied WebPent mainline
graph does **not** automatically register or invoke them. This package-level
merge intentionally leaves the frozen mainline graph and its 695-entry
`frozen_modules.sha256` manifest unchanged.

## Compatible state and model shapes

`build_graph_from_state()` reads the current WebPent
`state["target_knowledge"]` projection (`nodes` + `edges`) and also accepts the
older `target_knowledge_v2` (`entities` + `relations`) shape.
`on_finding_confirmed()` emits advisory hypothesis dictionaries compatible
with `webpent.models.hypothesis.Hypothesis`; causal provenance is kept in
`origin_detail` and `hint_provenance`, while `origin` uses the project's
existing `HypothesisOrigin` enum.

## Lifecycle usage

Keep one layer instance per engagement so its in-memory graph, conclusions,
and known defective objects are not shared between concurrent engagements:

```python
from webpent.causal_reasoning_v2 import CausalIntegrationLayer
from webpent.models.hypothesis import Hypothesis

causal = CausalIntegrationLayer(
    engagement_id=engagement_id,
    memory_dir=memory_dir,
)

# Engagement start: optional transferred hypotheses.
start_hypotheses = [
    Hypothesis.model_validate(item)
    for item in causal.on_engagement_start(state)
]

# After a finding is confirmed by WebPent's existing validation pipeline:
sibling_hypotheses = [
    Hypothesis.model_validate(item)
    for item in causal.on_finding_confirmed(finding_dict, state)
]

# Before report serialization:
root_cause_clusters = causal.on_report_finalize(confirmed_findings)
```

These outputs are suggestions and report annotations only. They do not confirm
findings, authorize requests, change scope, or bypass the existing
human-approval and evidence-validation paths. Hooks are fail-safe and return
neutral results when disabled with `WEBPENT_CAUSAL_V2_DISABLED=1`.

## Enabling graph-level wiring

Automatic invocation from the shipped LangGraph requires a separate,
reviewable graph change, an explicit feature flag, state/checkpoint handling
for per-engagement lifecycle data, and a refreshed frozen-module manifest.
That graph change is deliberately not implied by this additive package merge.
