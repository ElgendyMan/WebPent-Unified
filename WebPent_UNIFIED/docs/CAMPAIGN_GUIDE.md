# Campaign Starter Guide — Live Engagement Runbook

**FINAL PREPARATION SPRINT (2026-10-05).** Everything here runs on the v2/v3
verified environment: full suite green, frozen gate 695/695, `pip check` exit 0.
Goal: from zero to a running, verifiable, exportable campaign on ANY authorized
target in minutes.

> **Authorization gate:** only run against targets you own or are explicitly
> authorized to test. Scope is enforced fail-closed by `ScopeLaw` +
> `ToolBoundary`; the hunter refuses to start without a scope file.

---

## 0. Five-minute setup

```bash
# 1) environment (verified pins — see EVIDENCE_REPORT_20261005.md)
python3.12 -m venv .venv && source .venv/bin/activate
# torch FIRST from the CPU index (v4: installing the package first pulls the
# CUDA-enabled torch from PyPI, contradicting the clean CPU-only freeze)
pip install torch==2.14.1+cpu --index-url https://download.pytorch.org/whl/cpu
pip install -e .

# 2) secrets (fail-closed: empty keys block stricter profiles)
export JWT_SECRET_KEY="$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")"
export AUDIT_SECRET_KEY="$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")"
export CELERY_PAYLOAD_KEY="$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")"

# 3) engagement inputs from the templates
cp scope_template.yaml my_engagement.scope        # edit to the program policy
cp credentials_template.json creds.json           # owner + foreign principals
export TARGET_URL="https://your-authorized-target.example"
export ENGAGEMENT_ID="eng_$(date +%Y%m%d)_demo"
export SCOPE_FILE=my_engagement.scope
export CREDENTIALS_FILE=creds.json
```

## 1. Pre-flight verification

```bash
./scripts/verify_campaign.sh        # trust gate + keys + scope + ledger + audit
```
All `[FAIL]` lines must be resolved before starting. `[WARN]` lines are
optional artifacts (safe on a first run).

## 2. Start the campaign (one command)

```bash
./scripts/run_campaign.sh
```
What it does: validates inputs → runs the **real-browser POC smoke** when the
POC stack is requested (see below) → starts the video-POC watcher when
`WEBPENT_POC_ENABLED=1` (otherwise records nothing; promotions unaffected) →
runs the bounded hunter (`webpent hunt --target ... --scope ...`) with
budgets. Artifacts land in `hunt_artifacts/$ENGAGEMENT_ID/`.

### Real-browser POC smoke (pre-flight gate, v5)

Every shipped POC *unit* test uses a fake browser factory; the smoke is the
only check that proves the REAL Playwright chromium stack works before the
first live recording. It runs 4 strictly local phases (zero external
network) against real chromium: data: URL render + webm finalization, a full
owner-vs-foreign replay over loopback HTTP with SERVER-SIDE proof of
same-origin token injection and cross-origin non-injection, the
identical-body BOLA signature, and fail-soft degradation on a real browser
failure. It runs automatically when `WEBPENT_POC_ENABLED=1` (hard gate — a
broken browser stack aborts the start) or on demand with
`WEBPENT_POC_SMOKE=1`; standalone: `python3 scripts/poc_smoke_real_browser.py`
(evidence webm lands in `hunt_artifacts/poc_smoke/`).

Useful passthrough options (after the script name):
`--max-hypotheses 12 --max-decisions 12 --max-cost-usd 5 --time-budget 900`

## 3. Watch / stop

```bash
webpent campaign status "$ENGAGEMENT_ID"    # redacted state + budgets
webpent campaign cost   "$ENGAGEMENT_ID"    # spend + LLM usage
./scripts/stop_campaign.sh                  # KILL SWITCH: operator halt, evidence preserved
```
`stop_campaign.sh` appends the halt event to the immutable audit ledger and
stops the POC watcher; it never deletes artifacts.

## 4. Verify after the run

```bash
./scripts/verify_campaign.sh
```

## 5. Record video POCs (optional enhancement)

Automatic: `WEBPENT_POC_ENABLED=1 ./scripts/run_campaign.sh` (watcher records
each promoted finding). Manual for one finding:

```bash
export WEBPENT_POC_OWNER_TOKEN="<owner session token>"
export WEBPENT_POC_FOREIGN_TOKEN="<foreign session token>"
webpent-poc record --finding <finding-uuid> --engagement "$ENGAGEMENT_ID"
```
Artifacts: `hunt_artifacts/poc/poc_<id>.webm` (≤5 MB AND ≤30 s — over-cap
artifacts are renamed `.oversize`/`.overtime` and refused as evidence) +
`poc_<id>.json` (steps, timings, body HASHES — never raw response content;
tokens redacted). Failures degrade to `status=failed` — a POC problem never
blocks a promotion. POC events are appended to the engagement's existing
audit chain (pass `--artifact-root` / watcher `--artifact-root`, both wired
by the shipped scripts).

## 6. Export bug-bounty submissions

```bash
./scripts/export_findings.sh
# -> hunt_artifacts/$ENGAGEMENT_ID/submissions/<finding_id>_bugbounty.md (+ .json)
```
Each submission contains: severity, CVSS score (+ vector when the finding
carries one), affected URL, numbered
repro steps, cURL pairs with `$OWNER_TOKEN`/`$FOREIGN_TOKEN` placeholders
(literal tokens are never exported; all fragments are shell-quoted), impact,
remediation, ProofBundle
reference, and POC attachment links. Videos are copied next to each rendered
HTML report and embedded idempotently (`webpent-poc embed`), so the video
references resolve.

## 7. CLI surface (POC)

| command | purpose |
|---|---|
| `webpent-poc record --finding <id> --engagement <id> [--output DIR]` | record one video POC (fail-soft) |
| `webpent-poc export --engagement <id> [--finding <id>] [--output DIR]` | export promoted finding(s) |
| `webpent-poc embed --report <html> --poc-dir DIR` | embed videos into a report |
| `python scripts/poc_watcher.py --engagement <id> [--once]` | watcher sweep |

Note: the frozen `webpent` typer app cannot gain a `poc` subcommand without
editing sealed trust-chain code, so the POC surface ships as the dedicated
`webpent-poc` console script.

## 8. Rollback / abort

Findings, ledger, and audit chain survive any abort. To stop mid-campaign use
`stop_campaign.sh` (operator halt, fail-closed). Nothing in this sprint
modified the frozen trust spine: `sha256sum -c frozen_modules.sha256` → 695/695
must hold at all times (`verify_campaign.sh` checks it first).

## 9. Interim authority boundaries (Sprint R2 — read before Phase 1 engagements)

The M1 call-graph re-anchor (deliverables/r2_dossiers/D1_ANCHOR_REPORT_R2.md) confirmed the
factory-routed spine, and documented two interim boundaries that are live until the frozen-file
unfreeze requests (E-1..E-4) are ruled on. Both are fail-safe for a default Phase 1 run; the
operator obligations are:

**9.1 OOB confirmation route stays DISABLED (default).** The OOB callback receiver
(`/api/oob/...`) is gated by `WEBPENT_OOB_CONFIRM_ROUTE_ENABLED` and is **default-off**. Until
the BYP-02 advisory-only demotion lands (D2/R2-02), the armed route would flip findings to
Tool-Confirmed outside the PromotionPipeline — the sole promotion authority. Do not set
`WEBPENT_OOB_CONFIRM_ROUTE_ENABLED=true` on Phase 1 engagements. The routes are also inert
without `WEBPENT_OOB_CALLBACK_SECRET`; keeping it unset double-gates the feature.

**9.2 Phase 1 engagements run the default legacy scan profile.** The smart execution lane is a
second, parallel authorization model (BYP-04) whose enforcement point is frozen; the interim
control is procedural. Leave `scan_mode` at its default `LEGACY` — do NOT set
`WEBPENT_SCAN_MODE` / `SCAN_MODE` / `SCAN_PROFILE` to a smart profile for Phase 1 engagements.

**9.3 Do not deploy `WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY`.** The mode name is the
contract: on the graph path it currently degrades to a legacy-only recon run (BYP-05; the
builder-level rejection is pending unfreeze E-2, tracked by the xfailed contract
`test_t06_builder_rejects_unsupported_legacy_only`). There is no supported operational reason to
set it; the SDD §8 flag-based rollback is the only supported rollback.

**9.4 Verification commands for this section (single-command reproducibility):**

```bash
python3 -m pytest tests/test_r2_spine_authority_contracts.py -v   # 3 passed + 4 xfailed (dossier tripwires)
sha256sum -c frozen_modules.sha256                                # 695/695 — unchanged by R2
```

---

## M2-impl (2026-10-06): Research-Campaign Transport Restored — Operator Notes

**What changed.** The research-campaign lane is now live through the real
graph. Previously every state key the lane relied on was silently dropped
by the graph runtime (undeclared in the state schema — finding NF-M2-01),
so the campaign node always skipped and the intake records never left the
recon frame. This window restores transport via **declared state keys**,
**factory re-derivation** at the campaign node, and **durable
rehydration** through CampaignState. The orchestrator object itself is
never transported in state (prohibited — checkpoint serialization fails
loudly by design).

**Operator-visible skip (honesty contract).** When the research-campaign
lane skips, it is LOUD: the graph log carries a named warning —
`RESEARCH CAMPAIGN SKIPPED (operator-visible, R7): <reason>` — and the
final state carries `research_campaign_skipped` (reason string) plus
`research_campaign_executed=False`. Reasons seen in practice:
`no_hypotheses` (empty hypothesis channel), `no_canonical_hypotheses`
(every channel entry failed canonical normalization), `no_orchestrator:
<factory error>` (target/entrypoint derivation failed closed). A silent,
normal-looking completion with a skipped campaign is no longer possible.
**If you see this warning: the autonomous research loop did not run for
this engagement** — check the target binding and the hypothesis channel.

**Spine flag semantics (SDD §8 — now enforced).** The five feature flags
are resolved once per engagement inside the production-spine factory
(strict-bool env fallback; default OFF) and consumed fail-closed:
`WEBPENT_EXPLORATION_INGRESS_ENABLED` and
`WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED` gate fixture scheduling at the
intake boundary (disabled = nothing schedulable from the fixture path);
`WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED` gates multi-principal
experiment dispatch; `WEBPENT_LIVE_PROXY_SOURCE_ENABLED` is hardwired off
in Phase 1 (any enable attempt is rejected at the factory, and its
consumer refuses unconditionally); `WEBPENT_FOREIGN_REPORT_WRITER_ACCESS`
gates report-writer authority (M3 boundary). Flags are bound to the
engagement + target fingerprint: placeholder bindings (`target_unknown`)
never schedule, and fixture/artifact data can never set a flag — the
snapshot derives from the factory-resolved config only. Set the env vars
to the literal `true` on a documented launch surface to authorize fixture
scheduling for an engagement.

**Transport design note (audit chain + durable state).** Every seam run
produces a REAL append-only, hash-chained `EngagementAuditChain` for the
engagement — intake/publish audit events land under the artifact root
(default `artifacts/hunter-<engagement_id>/audit/`, override with
`WEBPENT_AUDIT_ROOT`); the graph state carries a serializable DESCRIPTOR
of the chain (paths), not the live object. Candidate registration writes
a durable, versioned CampaignState record per engagement instance
(`.../campaign_state/<instance>.campaign_state.json`) used for dedupe
memory (duplicates are rejected across invocations) and for rehydration
(the campaign node's factory re-derivation re-registers the persisted
candidates — a fresh empty research loop is never accepted). Corrupted
durable state refuses the run loudly rather than silently resetting
dedupe memory.
