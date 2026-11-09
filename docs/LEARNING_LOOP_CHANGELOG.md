# Learning Loop Sprint — Implementation Changelog

## New contracts and components

- `src/webpent/memory/lesson_models.py` — typed structured lesson, provenance, confidence, priority-adjustment, and metric contracts.
- `src/webpent/memory/lesson_extractor.py` — deterministic proof-gated extraction of negative/positive/priority/coverage lessons.
- `src/webpent/memory/lesson_consultant.py` — client-isolated advisory retrieval and bounded priority adjustments.
- `src/webpent/memory/writeup_parser.py` — structural writeup/CVE parsing with no raw-content trust.
- `src/webpent/memory/improvement_tracker.py` — actual-data campaign metrics and trend tracking.
- `src/webpent/memory/learning_lifecycle.py` — idempotent extraction/persistence/metrics/audit lifecycle glue.
- `tests/test_learning_loop.py` — focused tests for schemas, isolation, masking, ranking, parser, metrics, and dashboard output.
- `scripts/run_learning_loop_demo.py` — reproducible two-campaign live Juice Shop demonstration using real LLM advisory calls.

## Modified components

- `src/webpent/memory/lessons.py` — additive structured schema and client-scoped persistence/search/summary APIs.
- `src/webpent/memory/vectorstore.py` — mixed-source `source_id` deduplication for idempotent batch ingestion.
- `src/webpent/recon/hypothesis_generator.py` — optional advisory ranking metadata while preserving candidate completeness and authority boundaries.
- `src/webpent/production/autonomous_recon.py` — optional consultation/extraction/metrics/audit wiring; legacy unscoped behavior preserved.
- `src/webpent/service/facade.py` — read-only learning metrics/dashboard integration and optional completion lifecycle hook.
- `src/webpent/production/product_layer.py` — escaped read-only Learning dashboard section.
- `src/webpent/cli/ingest.py` — repeatable writeup/CVE ingestion and explicit deterministic `--no-llm` mode.
- `config/isolation_denylist.yaml` — updated reviewed line for the bounded static loader map.
- `src/webpent/shared/direct_io_inventory.py` — aligned dynamic-import approval range.
- `docs/direct_io_inventory.json` and `docs/direct_io_inventory.md` — regenerated from the canonical current-source scanner.
- `docs/FULL_SUITE_EVIDENCE.txt` — final machine-generated full-suite evidence.

## Safety decisions

- The frozen trust spine and promotion authority were not modified.
- Lesson and RAG content is advisory only; it cannot create ProofBundles, authorize tools, expand scope, or promote findings.
- Campaign/client isolation is explicit in both storage and retrieval.
- LLM prompts use structural/masked projections; raw target content and credentials are excluded.
- No bounty report is generated when no promoted sealed finding exists.

## Validation

- Full suite: 2079 passed, 0 failed.
- Exact acceptance: 20-test input passed in all 3 rounds.
- Five security gates: all exit 0.
- Frozen manifest: 13 files matched.
- Focused learning/RAG/recon regression set: 18 passed.
