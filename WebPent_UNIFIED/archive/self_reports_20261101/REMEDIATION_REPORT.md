# REMEDIATION REPORT — Hostile-Audit Defects (Executed Plan)

Tree: `webpent-goed-FIX` (working copy of patched tree; original untouched).
Patches: `sprint_i1.patch` (-p2), `sprint_i1b.patch` (-p1), zero rejects.
Sentinels confirmed: `production_spine.py:377` `_factory_token`; `modern_spine_integration.py:93,108` `resolve_production_spine`.

## Files modified (2 source + 1 test + 3 hash manifests)
| file | change | post-fix sha256 |
|---|---|---|
| `src/webpent/agents/validator/agent.py` | D1 SQLi bypass closed (fail-closed); D3 open_redirect verifier rubber-stamp removed | `f4a22883...` |
| `src/webpent/graph/builder.py` | D2 AVI promoted findings merged into `state["findings"]` (fail-visible) | `33461184...` |
| `tests/test_hostile_audit_remediation.py` | 5 regression tests (all PASS) | `2085d950...` |
| `POST_PATCH_SHA256.txt` / `POST_FIX_SHA256.txt` | hash chain | — |

## Phase 0 — DONE
- Re-extracted, re-patched, recorded 6-file hashes, confirmed sentinels. Original tree left read-only.

## Phase 1.1 — SQLi bypass (D1/P1) — DONE
- Enclosing function: `_validate_with_tool` (`agent.py:2311`).
- Persist-site audit (all `_persist_finding_incrementally` call sites):
  | line | vuln class | verifier-gated? |
  |---|---|---|
  | 1265 | CSRF structural | NO (additional carve-out, flagged — needs same policy decision) |
  | 1318 | CSRF Needs-Human-Review | n/a (not promoted) |
  | ~~3473~~ | SQLi | **FIXED** — was NO, now fail-closed |
  | 3598 | generic tool (dalfox/xss/lfi/ssti) | YES (`verify_replay_evidence` at ~3502) |
  | 4062 | campaign-extension projector | UNVERIFIED (pluggable extension surface) |
  | 4177 | validator_node final loop (Tool-Confirmed/Not Scanned/Clean) | n/a |
- Fix: removed auto-confirm + auto-persist; SQLi with no differential observation now returns `Needs Human Review`, evidence preserved, NOT persisted as confirmed. SQLi WITH differential observation falls through to the strict verifier unchanged.
- Policy decision STILL REQUIRED: (a) build differential observation from sqlmap internal boolean/blind pairs & route through verifier, or (b) ratify SQLi as verifier-exempt with an equivalent separately-tested gate. Current state = fail-closed.

### Accepted exception: `session_reauth` tool-native promotion (documented 2026-10-02)
SQLi fail-closed above has **one deliberate, tested carve-out**, at `agent.py:~3465`
(inside the same `_validate_with_tool` function): if a finding's session died
mid-scan, re-authentication succeeded in this call (`evidence["session_reauth"]
is True`, set once at `agent.py:3105`), AND both the deterministic and LLM
confirmation signals agree, the finding is promoted as `Tool-Confirmed` via
`tool_native_reauth_confirmed` **without** going through `verify_replay_evidence`.
- This is not a new gap — it is a pre-existing, intentionally tested fix
  (`tests/test_v9_p0_hotfix_sqlmap_reauth.py`), not something introduced by this
  remediation pass.
- `session_reauth` fires whenever the session dies mid-scan (not a rare edge
  case), so this path is reachable with meaningful frequency in long-running
  campaigns — it is **not** a one-in-a-million carve-out.
- As of this pass, every promotion through this path now emits
  `logger.warning("V9 P0-B promotion_guard: ... tool_native_reauth_confirmed ...")`
  so its real-world frequency is observable in standard log monitoring; if the
  rate is high, this should be revisited and either (a) replaced with a real
  differential-observation construction routed through the verifier, same as
  the open policy decision above, or (b) formally ratified as a second
  verifier-exempt class with its own independently tested gate.
- **Updated SQLi fail-closed claim:** SQLi is fail-closed *except* for the
  `session_reauth` tool-native path described here. Any claim of "SQLi is
  100% fail-closed" elsewhere in this document or derived reports should be
  read with this exception in mind.

## Phase 1.2 — AVI dead-end (D2/P1) — DONE (merge implemented)
- Final persist reads `state["findings"]` (`workers/pentest_worker.py:224,262`). AVI promoted findings were never merged.
- Fix: in `_research_campaign_node` (`builder.py`), AVI `security_report.promoted_findings` are converted to `Finding` objects (5 required fields: title/severity/description/tool_name/url — verified constructible), appended to `out["findings"]`, marked `avi_promoted=True` with full proof trace in `evidence`. Per-finding try/except; failures counted in `avi_promoted_merge_failed` (fail-visible, never silent). Raw report preserved in `avi_security_report`.
- Finding construction verified at runtime (`Tool-Confirmed`, `idor`, evidence preserved).

## Phase 2.1 — verifier rubber-stamp (D3/P2) — DONE
- open_redirect call site: removed `negative_control=evidence["baseline"]` reuse → `negative_control=None`; removed hardcoded `causal_signal=True, negative_control_complete=True` → `causal_signal=bool(confirmed)`, `negative_control_complete=False`. Verifier now blocks open-redirect auto-promotion (fail-closed) until a real independent negative control is supplied.
- Generic tool-promotion site (`~3502`) passes computed booleans (not hardcoded) — left as-is.

## Phase 2.2 — Profile × Deployment gate matrix — DELIVERED
ScanProfile: legacy, smart, smart-observe, single-target-safe, authenticated-single-target, authorized-active, vip-qualification.
EnvironmentProfile: dev, lab, qualification, staging, production.
`profile_requires_proof_bundle` (`settings.py:90-95`): True ONLY for `vip-qualification`.
`deployment_requires_proof_bundle` (`settings.py:98-110`): True for non-lab (qualification/staging/production).
| profile \ env | lab | qualification/staging/production |
|---|---|---|
| legacy/smart/smart-observe/single-target-safe/authenticated/authorized-active | proof bundle NOT required; AVI 8-gate + verifier legacy-boolean gates apply | proof bundle REQUIRED (deployment gate) + same promotion gates |
| vip-qualification | proof bundle REQUIRED (profile gate) + promotion gates | proof bundle REQUIRED (both) + promotion gates |
Default (no profile) = no proof-bundle requirement. **Decision required** whether to raise the floor.

## Phase 2.3 — Runtime trace — PARTIAL
- `langgraph`/`pydantic` installed; `builder` and `validator.agent` import cleanly; `build_graph` callable; `NODE_RESEARCH_CAMPAIGN="research_campaign"` confirmed.
- Full CLI scan runtime trace NOT executed (requires full dependency set + target fixture). Early-return path (`builder.py` no-hypotheses) verified statically. **Status: UNVERIFIED for end-to-end.**

## Phase 3.1 — Per-vuln-class identity_bound table (`autonomous_validation_v1.py:919-989`)
| class | identity_bound requires | actor mismatch required? | line |
|---|---|---|---|
| IDOR/BOLA | actor_candidate != owner AND != baseline_actor; cand 200, baseline 200, nc 403/404 | YES | :919-936 |
| AUTH_BYPASS | bypass header present; baseline 401/403, candidate 200 | NO | :937-948 |
| MASS_ASSIGNMENT | candidate body has "admin", baseline lacks, cand 200 | NO | :949-958 |
| SSRF | ≥2 internal indicators in candidate > baseline, nc 400/403/404 | NO | :959-968 |
| OPEN_REDIRECT | candidate Location external, 301/302 | NO | :969-979 |
| INFO_DISCLOSURE | ≥2 sensitive patterns in candidate > baseline, cand 200 | NO | :980-989 |
M7 (IDOR/BOLA) = different-actor grammar only. Other classes = no actor requirement.

## Phase 3.2 — Dual promotion path — DOCUMENTED (no code change; policy required)
Path A (AVI/research-campaign): `run_validator` + `_compute_identity_binding` + PromotionPipeline 8 gates → (now merged) ledger.
Path B (NODE_VALIDATOR, dominant): `verify_replay_evidence` (legacy-boolean mode — `CausalDecision` NOT exercised) + tool marker + LLM supervisor → `_persist_finding_incrementally`.
Two gates, two verdict vocabularies (`ValidationOutcome` vs verifier legacy booleans). Single choke point before persist NOT implemented — **policy decision required** (unify vs. document split).

## Phase 3.3 — Freeze chain — DELIVERED
v1.8.4 manifest `supersedes=2` (integer count). `not_re_frozen_and_why` (provenance) lists only a missing delivery zip; does NOT mention `causal_guard.py`. `causal_guard.py` is in v1.8.3 manifest, NOT in v1.8.4's 6 re-frozen files (1+2+3). Last authoritative freeze = v1.8.3. v1.8.4 IMMUTABLE policy does not cover it. **Decision required**: re-freeze in v1.8.5 or formally retire from the asserted chain.

## Phase 4 — Validation
- 5/5 regression tests PASS (manual pytest-equivalent run; pytest module absent in env).
- Syntax OK on both modified files.
- Import OK on both modified modules.
- Diff vs original = exactly 2 source files + new test (after pycache cleanup).

## Items explicitly NOT done (require policy decision, not code)
1. SQLi verifier routing (1.1.3) — current = fail-closed, except the documented
   `session_reauth` carve-out (see Phase 1.1 addendum above).
2. CSRF structural-confirmation carve-out (`:~1231`) — same risk class as SQLi.
   **Status update (2026-10-02): verified currently DEAD CODE**, not a live
   bypass. The auto-confirm branch is gated by `can_tool_confirm`, which is
   hardcoded `False` with no other assignment in the function — the branch
   cannot execute today. Inline comment added at the hardcode site warning
   that flipping it to `True` without first adding a verify_replay_evidence-
   equivalent gate would reintroduce this exact carve-out live. Left
   unreachable rather than deleted, since removing it is a product decision
   (whether Playwright-based CSRF auto-confirmation is still a planned
   feature) that should be made explicitly, not as a side effect of a
   cleanup pass.
3. Campaign-extension projector persist surface (`:4062`) — unverified pluggable surface.
4. Single choke point unifying Path A/B (3.2).
5. Proof-bundle floor for default profiles (2.2).
6. causal_guard.py re-freeze or retirement (3.3).
7. End-to-end runtime trace (2.3) — deps/fixture limited.
