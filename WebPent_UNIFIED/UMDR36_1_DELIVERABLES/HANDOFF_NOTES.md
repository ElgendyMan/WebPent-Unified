# UM-DR-36.1 — Handoff notes for continuation

Everything is saved. The repository work lives in `/home/z/my-project/work/repo`
(branch `recovery/umdr36-closure`, 8 commits on top of baseline 1968f63) and a
pushable bundle `WebPent_Unified_recovery-umdr36-closure.bundle` is in this
folder (`git clone <bundle> && cd WebPent-Unified && git checkout recovery/umdr36-closure`).

## Open items (exact next steps)

1. **Production E2E zero-findings diagnosis (mission §5.1)** — the campaign
   (`scripts/umdr36_1_production_e2e_campaign.py`) ran the REAL entrypoint
   end-to-end (graph invoked, report generated, artifact written) but
   `findings_total: 0`. Diagnostic leads, in order:
   - Verify `identity_profiles` actually reached `auth_node`: check the run's
     `state["identity_profiles"]` / `identity_records` (the hunt summary now
     exposes `findings_detail`/`hypotheses_dump`; add a debug print in
     `agents/authentication/agent.py:831-839` unseal/bootstrap path).
   - Check `access_control_node` candidate extraction: `agents/access_control/agent.py:175`
     `_extract_candidate_records` needs `/api/invoices/<id>` URLs in
     `crawled_data` (the lab links them from `/`; confirm the httpx crawler
     followed them — `shared/http_discovery.py`).
   - Check `assess_access_control` verdict (bac_identity_tester.py:325) — with
     owner+foreign profiles it must see owner 200 + foreign 200 + denied control.
     If `coverage_gap`, the second profile wasn't authenticated.
   - Quick instrumented rerun: `timeout 600 uv run python scripts/umdr36_1_production_e2e_campaign.py`
     with `WEBPENT_LOG_LEVEL=DEBUG`.
2. **Full-suite evidence + BUILD_INFO re-baseline** — the suite run was
   launched (`scripts/run_tests_with_evidence.py`, log:
   `/home/z/my-project/work/full_suite.log`) but had not completed at handoff.
   After a green run: create the dedicated re-baseline commit (subject
   `BUILD_INFO re-baseline: ...`, touching ONLY BUILD_INFO.json) with the
   provenance schema the redesigned gate expects (`umdr36-1-provenance-v1`,
   source/tested/evidence revisions, manifest digest = sha256 of the re-pinned
   frozen_modules.sha256, test_accounting from the run).
3. **Two-decision learning proof** — `run_adaptive(3)` records 3 REAL
   experiment outcomes (e-pos-authbypass-1: confirmed) but the returned state
   carried no `decisions` list; find where the orchestrator stores
   DecisionRecords (egaie/orchestrator.py:140 `record_decision`) and read the
   actual container to complete the before/after selection trace.
4. **Remote CI / PR** — blocked: no GitHub credentials in this environment
   (`git push` fails: could not read Username; no `gh`; API rate-limited).
   Push the provided bundle and open the PR from it.

## Verified-green in this environment
- uv lock --check / uv sync --locked --extra dev / pip check / import / CLI.
- New adversarial suites: 23/23 provenance + 17/17 evidence (+ parse checks).
- DR-009 manifest re-pin (frozen gate integrity restored for the declared drift).
- Portable recovery toolchain + §1.4 verification command (honest NOT_VERIFIED
  until items 1-2 land).
