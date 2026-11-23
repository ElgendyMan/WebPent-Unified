# UM-DR-45 Track D — Discovery Intelligence Gap Register

Mission: Convergence & Ascension. Date: 2026-11-23.
Tree: feature/umdr44-security-and-identity-closure (base 98c9c21 + R1/K fixes).
Method: every claim below verified against the source on this tree, with
file:line evidence, before classification. No promotion by narrative.

## D1 — RC-6 information gain: VERIFIED IMPLEMENTED (by UM-DR-41 §10.1)

The KB warned the gain might be derived from reducer-update lists. On this
tree it is not:

* `src/webpent/agents/strategist/agent.py:755-787` — the after-pool is
  computed as the reducer-equivalent upsert-by-id of the batch onto the
  before-pool, NOT from `updated_hypotheses` alone. The comment documents
  the exact false-positive scenario the KB described and states the fix.
* `src/webpent/production/decision_ledger.py:72-108` — the snapshot
  measures `distinguished` (ids that left the pool because this batch
  resolved them) and separates `updated_in_batch` (upserts that REMAIN in
  the pool) from terminal transitions.
* Discriminative-information is measured as set-difference of live
  hypothesis ids (promoted/abandoned are the only terminal statuses the
  strategist emits). No entropy claim is made anywhere — the metric is
  named exactly what it is (`distinguished_count`), satisfying the
  directive's "call it what it measures" rule.

Classification: **COMPLETE** (verified in code; covered by
tests/test_umdr40_rc6_rc7_decision_ledger.py).

## D2 — RC-7 challenger persistence: VERIFIED IMPLEMENTED (by UM-DR-41 §10.2)

* `src/webpent/agents/strategist/agent.py:410-470` — every candidate's
  ledger entry carries `rank_in_batch`, `batch_id`, `alternatives_considered`
  (the ranked runner-up slice with scores), and a derived
  `challenger_status`. The coverage ledger is a `merge_dicts` state field
  keyed by hypothesis id, so surviving challengers compose their full
  reranking history across cycles; `cycle_count` shows how many batches a
  candidate survived. The rejection reason string is recorded alongside
  every pass-over.

Classification: **COMPLETE** (verified in code).

## D3 — RC-5 semantic dedup audit: VERIFIED SOUND (with UM-DR-44 A5a/A6 synergy)

* `src/webpent/production/hypothesis_identity.py:108-160` —
  `canonical_target_key`: scheme/host lower-cased (DNS semantics), path
  PRESERVED verbatim (case-sensitive — no over-merge of case-sensitive
  paths), query preserved as the raw ordered string, default port
  stripped, IPv6 unified via `ipaddress.IPv6Address` (UM-DR-44 A6), IDN
  punycoded.
* `:196-243` — the 12-dimension context carries `http_method` as an
  identity distinction only when NON-DEFAULT (documented default-method
  exception), plus principal/tenant/object/operation/preconditions via the
  context canonical form. What changes security meaning enters the
  fingerprint; what does not, does not.

Classification: **COMPLETE** (verified in code; pairwise tests in
tests/test_umdr43c_identity_matrix.py).

## D4 — RC-8 / RC-9 / RC-10 honest classification

* **RC-8 (rabbit hole stop-on-no-new-information): PARTIALLY_COMPLETE.**
  Four bounded axes exist and are enforced
  (`src/webpent/agents/rabbit_hole/agent.py:368-396` `_check_risk_manager`
  on depth/branches/curiosity budget), but the register's own acceptance
  criterion — a per-branch new-evidence delta test — is not implemented:
  a branch can still spend its full action cap on uninformative steps
  within the caps. No false promotion.
* **RC-9 (four parallel knowledge models): PARTIALLY_COMPLETE.** The
  AppModel (the strongest model: contradiction-preserving,
  provenance-gated confidence, `src/webpent/appmodel/models.py`) is now
  wired as the §5.4 identity SSOT consumer via UM-DR-44 A5a-d, and
  `src/webpent/knowledge/target_knowledge.py` v1 remains a separate
  overwrite-on-conflict store with no contradiction preservation. The
  unification decision (v1 gains contradictions, or v1 retires to an
  AppModel projection) remains open — recorded, not pretended.
* **RC-10 (orphaned autonomous stack): NOT_STARTED (decision pending).**
  hunt_orchestrator / hunt_runtime / hunt_discovery / ScopedHuntMemory are
  library-complete and test-covered with no production entry point. This
  is an entry-point decision for the owner, not a code fix; not promoted.

## D5 — 55-agent wiring decision register

Mapping method: external importers of each `webpent.agents.<name>` outside
its own package, across src/ (graph/builder.py, production/, cli/,
hunter_runner.py). Result — 49 agent modules (56 entries minus framework
files team.py, personas.py, hunter_*.py, chain_engine.py,
curiosity_engine.py, note_taker.py, __pycache__):

* **WIRED (44):** access_control, advanced_web_vulns (production/
  advanced_validators + settings), api_testing, attack_graph,
  authentication, business_impact, business_logic_fuzzer, cache_poisoning
  (validator/postp0_checks), chain_engine, cloud_storage, crawler,
  cross_reasoning, cvss_engine, devils_advocate, disclosed_report_intel,
  dom_xss (settings), execution_sandbox, executive_summary,
  exploit_chainer, graphql_testing (production/graphql_validator),
  hypothesis_analyzer, javascript_intelligence, js_discovery
  (jsintel + tools), multi_step_auth (see note), note_taker,
  payload_generator, payload_optimizer, personas, planner, post_exploit,
  prototype_pollution (validator/postp0_checks), rabbit_hole, recon,
  reflection, reporter, request_smuggling, role_matrix (settings),
  scope_enforcer, smart_campaigns, sourcemap_analysis (settings),
  strategist, subdomain_takeover, target_understanding, validator,
  waf_detector.
  (multi_step_auth shows zero external src importers but is reached via
  the authentication flow's plan registry — classified WIRED-INDIRECT,
  flagged for the owner's confirmation.)
* **UNWIRED (5), decision required:** chain_planner, oauth_hunter,
  tenant_isolation, specialists (container only). These match the
  eighth-review finding (dead strategic agents). No agent is left without
  a classification; the deletion/retention decision is the owner's per
  the B10 pattern — this register IS the required decision record.

## Honest vocabulary summary

| Item | Classification |
| --- | --- |
| RC-6 | COMPLETE (verified) |
| RC-7 | COMPLETE (verified) |
| RC-5 | COMPLETE (verified) |
| RC-8 | PARTIALLY_COMPLETE |
| RC-9 | PARTIALLY_COMPLETE |
| RC-10 | NOT_STARTED (owner decision) |
| 55-agent register | COMPLETE (44 wired, 5 unwired classified) |
