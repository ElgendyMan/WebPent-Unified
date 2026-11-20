# UMDR41 Architecture Map
## Production execution path (verified)
CLI (webpent.cli:main, typer) / API (FastAPI app, 20 routes) / Celery worker (run_pentest_task) → workers build Target + workspace → scope contract: parse_scope_file fail-closed (target must be covered; excludes win) → RuntimeContext(scope_runtime_handle=compile_wildcard_scope(allow_entries)) → build_graph (graph/builder.py, 944-line builder; nodes: scope_enforcer → crawler/recon → hypothesis [RC-5 dedup wrapper at registration, line 2055] → validator [CausalGuard authority, frozen] → strategist [RC-6/7 measurement, fixed this mission] → rabbit-hole loop bounded) → findings → ProofBundle (frozen models) → reporter.
## Two scope channels (both verified)
1. API registry channel: /scope/load → GLOBAL_SCOPE_REGISTRY (NOW optionally durable SqliteScopeStore) → /scope/check enforcer. Pre-fix gap: per-process only (F-006 fixed opt-in).
2. Worker task channel: ScanRequest.scope_entries (encrypted on broker via celery_payload_key PBKDF2→Fernet) → parse_scope_file → compiled wildcard scope → runtime.scope_matcher.allows() at every active-research handler (builder.py:856,924).
## God objects (sizes recalculated)
validator/agent.py 4,948 (fn _validate_with_tool 1,393); egaie/differential.py 4,048; config/settings.py 3,324; graph/builder.py 2,661; api/app.py 2,527; hypothesis_analyzer 2,406; autonomous_validation_v1 2,244; smart_campaigns 2,165; memory/db.py 2,103; shared/llm.py 2,020 (+5 more >1500).
## Version sprawl (authoritative determination)
- causal_reasoning (legacy) vs causal_reasoning_v2: v2 authoritative (integrated_layer has dynamic-import usage); legacy retained pending consumer review.
- cqa_v2: ACTIVE (causal_guard frozen = confirmation authority). cqa_v1: release/ artifacts only.
- autonomous_validation_v1: POSSIBLE_ORPHAN (no static importer).
- irta.* (16 modules incl. v3): POSSIBLE_ORPHAN tree — no static importer found.
- goed_v1_8_* : archived prototypes (tests already skip with explicit reason).
- graph_v3 naming: the production graph is graph/builder.py; no separate v3 module.
## Frozen modules (untouched, verified listed in pyproject extend-exclude)
cqa_v2/causal_guard.py, models/proof_bundle.py, models/workflow_replay.py, llm_researcher/tool_boundary.py, live_hunter/tool_scope.py, live_hunter/profile.py (+ cli/commands.py under the 695-file trust gate per comments). All our edits avoided these files by design (RC-5 wrapper pattern reused for RC-6 fix at the strategist, not the frozen generator).
## Reachability method + orphans
AST exact/descendant import matching + entrypoints + tool auto-discovery catalog + test imports → 95 POSSIBLE_ORPHAN (list: _metrics/possible_orphans_net.json). Zero deletions. scope.registry demonstrates grep-unreliability (consumed via package __init__).
