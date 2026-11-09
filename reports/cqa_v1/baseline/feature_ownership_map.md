=== feature ownership map ===

| Area | Canonical paths | Protection rule |
|---|---|---|
| Legacy validators and governance | `src/webpent/`, `scripts/`, existing `tests/` | Do not modify for CQA activation |
| IRTA v3 local validation | `src/webpent/irta/v3/`, `tests/irta/test_v3_*.py` | Additive CQA integration only |
| Historical evidence | `reports/`, `docs/`, prior manifests | Preserve byte-for-byte |
| CQA v1 artifacts | `src/webpent/cqa/`, `tests/cqa/`, `reports/cqa_v1/`, `metrics/cqa_v1/` | New scope only |
