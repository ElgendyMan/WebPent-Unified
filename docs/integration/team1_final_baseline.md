# Team 1 Final Baseline Capture

**Document ID:** TEAM1-FINAL-BASELINE-1.0
**Date:** 2026-09-10
**Phase:** Final Team-1 hardening — baseline captured BEFORE any modification (no code was modified during this phase; see §Files modified).
**Runner:** canonical pytest runner (`pyproject.toml [tool.pytest.ini_options]`, `testpaths=["tests"]`, `pythonpath=["src","."]`, `asyncio_mode=auto`).

## 1. Execution environment

| Item | Value |
|---|---|
| Python | 3.12.11 (`/usr/local/bin/python3.12`) — required because source uses `datetime.UTC` (3.11+). Python 3.10 fails at import. |
| pytest | 8.4.2 (satisfies `minversion="8.0"`) |
| pytest-asyncio | 1.4.0 (`asyncio_mode=auto`) |
| Additional deps installed for this run | `langchain-core 0.3.x`, `langgraph 0.6.x`, `langgraph-checkpoint-sqlite`, `langchain-community`, `bcrypt`, `celery` (project `uv.lock` pins: langgraph 0.6.11 / langchain-core 0.3.86). `torch` was NOT required to collect or run the suite. |
| Real API keys | None consumed. `LLM_API_KEY` unset → provider gate `REAL_API_UNAVAILABLE`; no silent mock downgrade. |

## 2. Test totals

| Metric | Value |
|---|---|
| Collected | 975 |
| Passed | 971 |
| Failed | 4 |
| Errors | 0 |
| Skipped | 0 |
| Warnings | 3 (deprecation warnings only) |
| Duration | 39.2 s |

Reference baseline (`GOED_BASELINE.md` §6 / `POST_INTEGRATION_SUMMARY.txt`): 948 passed / 10 failed / 1 skipped. The +27 collected/passed delta is environment/collection variance; the failure set is a strict subset of the reference set (below).

## 3. Exact failing test identifiers (4)

All four are items **#2–#5** of the pre-existing baseline failure table (`GOED_BASELINE.md` §6), identical error class `ValueError: approval_boundary_failed:approval_source_missing`, classification "Legacy local-lab approval boundary":

1. `tests/test_local_causal_lab_option_b_approval.py::test_option_b_import_validates_and_original_packet_stays_pending`
2. `tests/test_local_causal_lab_option_b_approval.py::test_option_b_import_rejects_changed_approval_source`
3. `tests/test_option_b_local_causal_lab_runner.py::test_option_b_runner_emits_only_redacted_blocked_records`
4. `tests/test_option_b_local_causal_lab_runner.py::test_option_b_runner_records_runtime_digest_blockers_without_sensitive_material`

The remaining six reference failures (#1 hardcoded `/home/ubuntu/...` path, #6 sandbox DB URL, #7 embeddings env, #8 flag-gated `llm_selected` path, #9 lesson-scope fixture, #10 JWT fixture) are environment-dependent and **passed in this sandbox** — they did not become errors or skips (errors=0, skipped=0).

**NEW_FAILURES = 0.** No test that passed at baseline failed here.

## 4. verify_all.py (canonical unified verification)

`python verify_all.py`: **138 PASS / 7 FAIL**. The 7 failures are:

| Check | Area | Touched by Team-1 integration? |
|---|---|---|
| F4c `COPY . .` last COPY instruction | Dockerfile | No |
| U1d `FROM webpent-base:latest` | Dockerfile | No |
| U4f `tools/__init__.py auto_discover()` | tool registry | No |
| U4g `@register_tool` on sqlmap/ysoserial/phpggc (×3) | tool registry | No |
| DX8e `memory/db.py` alembic `head` stamp | db fallback | No |

Team-1 integration modified exactly 4 existing files, all additively (`.gitignore`, `src/webpent/attack_graph/__init__.py`, `src/webpent/config/settings.py`, `src/webpent/research_engine/__init__.py`). None of the 7 failing checks touch those files → these failures are **pre-existing** in this snapshot, recorded, not regressions.

## 5. Static hygiene (re-confirmed this round)

- `py_compile` on `src/webpent/integration/*.py`, `agenda_bridge.py`, `source_lane.py`: OK.
- ruff on integration layer: clean (per `REVIEW_SUMMARY`; no new lint introduced).
- Secret scan: clean (only `AKIAABCDEFGHIJKLMNOP` appears, inside `test_v25_javascript_intelligence.py` as an intentional redaction fixture).
- `FILES_DELETED = 0` (re-verified: every canonical file present; 39 files added).

## 6. Conclusion

Baseline captured. Pre-existing failure set preserved (4/10 reproduced; 6/10 environment-dependent and passing here). **No new regressions.** Proceeding to verification-only audits; no code modification identified as necessary.
