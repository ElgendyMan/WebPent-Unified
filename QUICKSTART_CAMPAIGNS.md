# Quick-Start Guide — Running WebPent Campaigns
**Applies after Unfreeze 2026-10-05 (Hunting Intelligence live wiring).**
All new intelligence features are **default-off**. A standard campaign runs exactly as before unless you opt in.

> **Verified environment (2026-10-05 fix sprint):** Python 3.12, `langgraph==1.2.10` +
> `langgraph-checkpoint-sqlite==3.1.1` (exact pins — do not widen without re-running the
> full suite), full suite 3043/3043, frozen gate 695/695. See `EVIDENCE_REPORT_20261005.md`.

---

## 0. Prerequisites
- Python 3.11+ (project pinned to 3.12 in CI).
- Install dependencies: `pip install -e .` (or `pip install -r requirements.txt`).
- LLM access is **required** for live campaigns (`WEBPENT_LLM_*` env vars or `settings.yaml`). Synthetic tests run offline.
- Only run against targets you own or are explicitly authorized to test. Scope is enforced by `ScopeLaw` + `ToolBoundary`; out-of-scope requests are blocked before execution.

## 1. Minimal campaign (default-off, no new features)
```python
from webpent.agents.hunter_runner import run_hunter_campaign

result = run_hunter_campaign(
    target_url="https://your-approved-target.example",
    engagement_id="eng_20261005_demo",
    principal_credentials={
        "owner": {"username": "owner@example.com", "password": "...", "role": "owner"},
        "foreign": {"username": "user@example.com", "password": "...", "role": "foreign_user"},
    },
    max_hypotheses=12,
    max_decisions=12,
    families=("IDOR", "BOLA"),  # optional: restrict families
)
print("findings:", result.get("confirmed_findings", []))
```
Artifacts land under `./hunt_artifacts/<engagement_id>/` (notes, audit ledger, evidence).

## 2. Opting in to the new Hunting Intelligence features
### 2.1 Session recovery (`recovery_enabled=True`)
Wraps every exploit call with `RecoveringExploiter`. After 3 consecutive dead-session
responses (401/403/302-to-login) it re-logins, re-provisions principals, re-binds M4,
and resumes the same hypothesis. After 3 failed recoveries the campaign is **halted
fail-closed** (`CampaignHalted`) — never silently loops.
```python
result = run_hunter_campaign(
    ...,
    recovery_enabled=True,  # default False
)
```
Requires `principal_credentials` so recovery can re-login. Recovery is bounded:
max 3 attempts, audit events emitted on every transition (`session.expired`,
`session.recovered`, `session.exhausted`, `campaign.halted`).

### 2.2 Planner enrichment (`enrichment_enabled=True`)
Feeds an advisory `EnrichedContext` (tech stack, auth type, payload suggestions) into
`HypothesisGenerator.generate(...)`. Advisory only — it never overrides scope, family
selection, or frozen prompt text. With it enabled you typically get the same findings
with fewer hypotheses (A/B verdict: `learning_proven`).
```python
result = run_hunter_campaign(
    ...,
    enrichment_enabled=True,  # default False
)
```

### 2.3 API-key principals (5th auth type)
The auth detector now emits an advisory `api_key` signal (5th type) when it sees an
`X-API-Key`/`Apikey` header, a non-Bearer/non-Basic `Authorization` value, or an
`?api_key=`/`?key=` query param on a protected route. Confidence is conservative
(0.4–0.6); signals are **never auto-provisioned** — an operator must supply the key.

Provision an API-key principal directly:
```python
from webpent.recon.login_executor import LoginExecutor

le = LoginExecutor(target_url="https://api.example")
login_result = le.login_with_api_key(
    alias="owner",
    name="X-API-Key",  # header name preserved in M4 seal: api-key:name=value
    value="sk-live-...",
    validation_url="https://api.example/v1/me",  # REQUIRED (fail-closed: no URL -> reject)
)
assert login_result.success
# Seal via M4 in the normal provisioning flow (principal_provisioning accepts auth_type="api_key").
```
In a campaign profile, pass `{"auth_type": "api_key", "api_key": "sk-live-..."}`.

## 3. Verify your install
```bash
# Frozen trust spine (must be 690 OK + exactly 5 FAILED = the unfrozen wiring files)
sha256sum -c frozen_modules.sha256 | grep -c ": OK"      # expect 690
sha256sum -c frozen_modules.sha256 | grep ": FAILED"     # expect exactly 5 wiring files

# Sprint regression (synthetic, no network)
PYTHONPATH=src pytest tests/team1_acceptance/test_hunting_sprint_*.py --noconftest -q
```

## 4. Rollback (if anything misbehaves)
All five changes are isolated to five files and default-off. To revert fully:
```bash
git checkout src/webpent/agents/hunter_runner.py \
             src/webpent/recon/hypothesis_generator.py \
             src/webpent/recon/login_executor.py \
             src/webpent/recon/auth_detector.py \
             src/webpent/recon/principal_provisioning.py
sha256sum -c frozen_modules.sha256   # expect 695/695 OK
```
No data migration; no persistent state change.

---

## 5. Video POC + campaign scripts (FINAL PREP SPRINT 2026-10-05)

One-command campaign on any authorized target: `scripts/run_campaign.sh`
(pre-flight checks + optional POC watcher + bounded hunt), kill switch:
`scripts/stop_campaign.sh`, verification sweep: `scripts/verify_campaign.sh`,
submission export: `scripts/export_findings.sh`. Full runbook:
`docs/CAMPAIGN_GUIDE.md`. Templates: `scope_template.yaml` (real scope-file
grammar with HackerOne/Bugcrowd mapping notes) + `credentials_template.yaml`
(owner/foreign principal profiles).

Video POC (optional enhancement — failure NEVER blocks promotion):
```bash
WEBPENT_POC_ENABLED=1 ./scripts/run_campaign.sh          # auto-record per promotion
webpent-poc record --finding <uuid> --engagement <id>    # manual single POC
webpent-poc export --engagement <id>                     # bug-bounty submissions (md+json)
webpent-poc embed --report <html> --poc-dir hunt_artifacts/poc
```
Artifacts: `hunt_artifacts/poc/poc_<id>.webm` (≤5 MB, ≤30 s) + `poc_<id>.json`
(steps/timings/digests; tokens redacted). Audit events: `poc.recorded` /
`poc.failed`. Note: the frozen `webpent` typer app cannot gain a `poc`
subcommand without editing sealed trust-chain code, so the POC surface ships
as the dedicated `webpent-poc` console script.
