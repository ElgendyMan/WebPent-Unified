# UM-DR-29 Production Readiness Report

Window: UM-DR-29 (2026-11-07) · Version: 0.35.0 ·
Companion artifacts: `UMDR29_BASELINE_REPORT.md`,
`UMDR29_ARCHITECTURE_AND_GAP_ANALYSIS.md`,
`UMDR29_FEATURE_QUALIFICATION_MATRIX.json`, `RELEASE_NOTES_v0.35.0.md`.

## Final qualification classification (directive §18)

**LAB_QUALIFIED** — single-tenant, controlled environments.

Rationale: every wired capability is campaign-integrated and internally
validated (evidence per the matrix); the two release-critical external
gates are honestly blocked:

- **Gate G (independent discovery qualification): BLOCKED_EXTERNAL_DEPENDENCY**
  — no independent custodian or unseen holdout corpus exists. M10 stays
  closed. Internal replica results (recall 1.0 / precision 1.0, 73/73)
  are recorded as replica-population progress, NOT as independent
  validation. The real blind measurement remains 0.137 recall / 0.6667
  precision (120 samples, 2026-11-06) — honestly below the Charter §4.1
  bar, which continues to refuse budget expansion by construction.
- **Gate H (competitive qualification): BLOCKED_EXTERNAL_DEPENDENCY** — no
  authorized XBOW access. No numerical competitive claim is made anywhere
  in this release; the differentiation strategy (stateful depth,
  business-invariant reasoning, causal replayable proof, research
  efficiency, evidence-backed graph, extensible families, deployment
  flexibility) is a stated objective, not a measured result.

## Gate-by-gate (A–H) summary

| Gate | Verdict | Key evidence |
|---|---|---|
| A — repository & release integrity | **PASS** | version sources agree (pyproject/Dockerfile/`__version__` — enforced by `test_release_packaging.py`); frozen manifest 639/639 with the ≥630 documented floor; BUILD_INFO.git_head corrected to a real commit; zip + SHA-256 produced at delivery |
| B — functional | **PASS for wired capabilities** | stateful discovery, representation oracle, CausalGuard authority, ProofBundle+replay, campaign persistence — all campaign-integrated with tests. Knowledge-graph planning feedback, adaptive-planner wiring, coverage-gap map: honestly UNIT_TESTED/PROPOSED (matrix) |
| C — safety | **PASS** | scope chain (parser→enforcer→final-boundary) green; no safety assertion touched this window; fail-closed flags unchanged |
| D — security | **PASS-WITH-NOTES** | no new unresolved issue; dependency posture unchanged from 0.34.x (langgraph-adjacent CVE adjudication carried forward — re-scan remains release-env-bound); 2 pinned unapproved raw-transport identities physically removed with the archived dead code (pin 36→34 records, adjudicated) |
| E — evidence | **PASS** | frozen gate + evidence-integrity suites green; ordered evidence traces (UM-DR-28) intact |
| F — operational | **PASS-WITH-NOTES** | runbooks (`docs/workers_ops_runbook.md`, RELEASE_PROCESS.md rollback), verified backup/restore harness (M12), worker/lease recovery tests; notification transports remain operator-side configuration |
| G — independent discovery | **BLOCKED** | see above; M10 closed |
| H — competitive | **BLOCKED** | see above; no comparative numbers published |

## Deployment boundaries (explicit)

- Safe for: **single-tenant controlled deployments** against **authorized
  targets only** (authorization manifest + scope enforcement are
  fail-closed and tested).
- NOT claimed: multi-tenant hosting, Kubernetes/air-gapped/cloud deployment,
  enterprise compliance certifications (SOC 2 / ISO 27001 / PCI DSS — none
  assessed), general-purpose production pentesting-as-a-service.

## What would move the classification up

1. **Independent holdout corpus + custodian** (operator side): unlocks
   Gate G; with recall ≥ 0.5 ∧ precision ≥ 0.7 on the blind population,
   M10 reopens and the discovery engine can be re-labeled.
2. **Recall program engineering** (repo side, ranked in the gap analysis):
   wire the 18 unwired agent modules (dom_xss, oauth_hunter,
   multi_step_auth, tenant_isolation, …), wire business-logic invariant
   reasoning, connect the stateful prober to learned transition grammars.
3. **Authorized competitor access** (operator side): unlocks Gate H.
4. 0.34.2 cleanup backlog (run_campaign.sh rewrite, langgraph CVE
   accumulation re-scan) — unchanged, owned.
