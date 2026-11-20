# UM-DR-37 Application Model Spec

Generated 2026-11-16T05:24:44.894368+00:00.

The typed application model (`src/webpent/appmodel/`) realizes the
mission's layering as follows:

- **Structural**: org/tenant/application/endpoint entities from real
  channels (crawled_data: openapi_routes, surface_records, endpoints).
- **Identity**: identity entities from identity_profiles;
  authenticates_as relations.
- **Resource/ownership**: OWNS relations materialized ONLY from crawled
  records carrying owner_identity (never from hypothesis text).
- **Workflow**: workflow entities + exposes/performs relations;
  workflow invariants live in the research loop.
- **Security model**: the advisory contract — the model has NO
  confirmation/authorization authority (pinned by
  test_umdr36_appmodel_influence).

Every entity/relation carries provenance (DECLARED/OBSERVED/INFERRED/
UNKNOWN/CONTRADICTED), deterministic confidence, evidence_refs (<=50),
and (UM-DR-37) observed_at. Contradictions keep both sides and are
logged. Revisions are countable via delta_since().

Influence is PROVEN, not assumed: research hints change hypothesis
priority (bounded +0.10 boost) and AVI experiment selection order
(with/without withhold tests). Downstream consumers: hypothesis node,
AVI selector, discovery funnel semantic stages.
