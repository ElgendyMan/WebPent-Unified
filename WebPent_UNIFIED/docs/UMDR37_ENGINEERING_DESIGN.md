# UM-DR-37 Engineering Design

Generated 2026-11-16T05:24:44.894368+00:00.

Principle: extend the measured components, never duplicate them (the
inventory of existing intelligence-layer code is embedded in the
mission's execution; every extension below names its host module).

| Mission part | Host module | What was added |
|---|---|---|
| 5.2 evidence vocabulary | appmodel/models.py | UNKNOWN + CONTRADICTED provenance with deterministic weakest confidences |
| 5.5 reconciliation | appmodel/models.py | mark_contradicted(): original evidence kept, conflict logged both sides |
| 5.6 versioning | appmodel/models.py | revision counter + delta_since() explainable deltas |
| 5.2 staleness | appmodel/models.py | observed_at stamps (first observation wins) |
| 7.1 lifecycle | research/lifecycle_view.py | unified deterministic VIEW over the 3 status vocabularies, fail-closed |
| 10.2 learning | egaie (no change needed) | AblatedFeedbackSelector + ShadowSelector instrumentation; causal property pinned on the REAL selector |
| 3.4 evidence | scripts/pytest_accounting_plugin.py | hook-phase accounting, schema v3 |
| 14 funnel | production/discovery_funnel.py (existing) | wired into the campaign runner from the tee'd raw state |

Design rule kept throughout: LLM/LLM-free determinism (all campaign
runs are `no_llm=True`), no new agents, confirmation authority
untouched (CausalGuard remains the sole authority).
