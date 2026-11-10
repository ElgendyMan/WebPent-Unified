# UM-DR-33 Security & Dependency Reports (Consolidated)

Covers deliverables #3 (SAST source-to-sink), #4 (agentic security),
#5 (dependency risk) and #6 (remediation matrix) in one authoritative
document — one measurement, one source, cross-linked.

Window: UM-DR-33 Phase 2 | Date: 2026-11-10 | Tree: clean at measurement

---

## 1. SAST source-to-sink report (§4, Workstream B)

### 1.1 Toolchain and fresh measurements

| Tool | Version | Scope | Findings |
|---|---|---|---|
| bandit | 1.9.4 | `src/` | 234 (0 HIGH, 28 MEDIUM, 206 LOW) |
| ruff | 0.17.4 (project config) | `src/` | 3,376 |
| ruff | 0.17.4 | `src/` + `tests/` + `scripts/` | 8,063 |
| mypy | 2.4.1 | security-critical paths (cqa_v2, scope, safety) | 28 errors / 23 files |
| pip-audit | 2.10.1 | environment ∩ project pins | 1 (resolved, below) |

**Ruff count reconciliation (§4.1):** the previously reported
discrepancy (~3,750 vs ~8,056) is a **scope artifact, not a
disagreement**: src-only ≈ 3.4–3.8k depending on ruff version; the
whole tree ≈ 8.0–8.1k. These are lint/maintainability findings — **not
vulnerabilities** — and are not represented as such.

### 1.2 The 28 MEDIUM bandit findings — every one traced source-to-sink

Full per-finding classification (method: re-run bandit, then read each
call site and trace provenance):

| Group | Sites | Verdict |
|---|---|---|
| B608 SQL construction | 12 | **0 confirmed defects.** 2 are false positives on LLM prompt prose (the word "select"); 10 interpolate only hardcoded table/column literals, `?`-placeholder expansions of module constants, or whitelist-filtered keys — every row value is parameter-bound |
| B310 urlopen | 1 | **Defensible:** loopback-only URL (adapter rejects non-`http`/non-`127.0.0.1`), `ScopeValidator` scheme+host allowlist gates the request; `file://` unreachable |
| B314 XML parse | 1 | **Defensible (empirically tested):** ET never resolves external entities (ParseError); expat ≥2.4 blocks amplification (billion-laughs raises `ParseError`); caught and converted to structured error |
| B104 bind-all | 1 | **False positive:** string membership test on `"0.0.0.0"`; no socket in module |
| B108 temp paths | 13 | **10 defensible** (env-overridable service root, input-dir defaults, marker-string FPs; container-isolated), **2 test/lab-only** (egaie harness paths, no production wiring) |

**Confirmed defects found by the typing audit instead (mypy-driven) —
both FIXED this window:**
1. `cqa_v2/proof_bundle_builder.py` — every production ProofBundle carried
   `bundle_id=None` (explicit `None` overriding the `default_factory`);
   empirically verified, fixed via documented frozen-window thaw
   (DR-009, old pin `5fdb526f…` recorded), 7 regression tests.
2. `safety/kill_switch.py` — `redis.Redis.from_url(None)` on every
   publish when subscriber-started-but-no-URL; hardened to clean no-op
   (2 regression tests).

Deferred with justification (no demonstrated defect; frozen files):
`/tmp/webpent-service` default root (5 frozen files) is container-isolated
and env-overridable — hardening queued behind the frozen protocol;
`memory/ab_lab.py` column whitelist (frozen; all call sites pass literal
kwargs today).

## 2. Dependency risk report (§4.2)

Audited the **project-declared pinned set** (35 pins), not sandbox noise
(tornado/vtk/weasyprint advisories are jupyter/mne tooling — not project
dependencies).

| Dependency | Advisory | Reachability | Resolution |
|---|---|---|---|
| pydantic-settings | CVE-2026-58203 (path traversal via nested-secrets symlink) | Project never uses `secrets_dir` (grep-verified) — path unreachable | Environment upgraded 2.13.1 → **2.15.0 (the project pin, ≥ fixed 2.14.2)** |
| chromadb==1.5.9 | **CVE-2026-45829 / PYSEC-2026-311, CVSS 9.3** — pre-auth code injection via the chroma **server** REST API (`trust_remote_code` model repository), affects 1.0.0–1.5.9 | WebPent uses **embedded mode only** (`memory/vectorstore.py:216`: `langchain_chroma.Chroma(collection_name, embedding_function, persist_directory)` — no host/port, no HTTP client, no server process spawned; embedding function is WebPent's own local model, not a remote repository) | **1.5.9 is the latest PyPI release — no fixed version exists yet.** Constraint posture: (a) embedded-only construction verified and pinned by review; (b) `DISABLE_RAG=true` skips the chain entirely; (c) **upgrade trigger documented**: when chromadb > 1.5.9 ships the fix, bump the pin and run the full suite. Not treated as a permanent exemption |
| all other 33 pins | — | — | advisory-free in the audited environment |

No dependency silently drifted; the environment was normalized TO the
pins (7 packages aligned; pydantic 2.12.5→2.13.5→per-pin).

## 3. Agentic security report (§5, Workstream C)

Gap analysis against the mission checklist (C1–C6), then fixes:

| Control | Status at baseline | UM-DR-33 action |
|---|---|---|
| Prompt/goal injection boundary | **Strong**: `UntrustedContent` wrapper (instruction-regex marking, credential fail-closed), trusted/untrusted prompt hard-separation, OpenAPI/redirect/header adversarial fixtures | RAG-passage wrapping as `UntrustedContent` documented as the remaining hardening (advisory corpus + per-run char budget + advisory-only consumption mitigate) |
| Tool gateway | **Strong**: vector-only subprocess (`_validate_cmd` type-rejects strings; `shell=False`), executable allowlist, closed tool enum, SSRF-pinned host check, poison-argv hard-deny, sandbox facade scope-checks EVERY command with fail-closed empty default | Apex executor's optional `scope` documented as defense-in-depth (the Sandbox facade is the authoritative check) |
| External hard budgets | Layered: BudgetGuard (REQUESTS law), step governor, global rate governor, spend governor; research-loop corruption fails closed (UM-DR-31) | **FIXED:** corrupted `node_step_trace` (present-but-not-list — no legit write path) now fails CLOSED with budget fully consumed instead of deactivating the governor; legacy absent-key behavior preserved and pinned |
| Research-memory integrity | Lesson isolation (client/engagement scoping, write sanitization, fail-closed unscoped reads), A/B promotion gating | `MemoryPromotionPolicy` wiring + lesson expiry documented as the next hardening step (the contract exists unused in `governed_artifacts.py`) |
| Example config safety | Settings-level placeholder rejection (CHANGE-ME family, auth-on fail), Compose required-variable syntax, preflight SystemExit | **FIXED:** credential-loader placeholder rejection (fail-closed, secret mappings only — form-field names exempt; the shipped template is rejected with a named field); template contracts evolved with tests |
| Kill switch / OAST | Operator-only engagement, HMAC-nonce correlation, candidate-only verdicts, digest dedupe | **FIXED:** fanout `from_url(None)` hardening; multi-process heartbeat floor documented as future work |

## 4. Remediation matrix (deliverable #6)

| # | Defect / gap | Evidence | Fix | Regression coverage | Frozen procedure |
|---|---|---|---|---|---|
| R1 | bundle_id=None on every production ProofBundle | empirical repro pre-fix | `proof_bundle_builder.py` conditional kwargs | 7 tests (`test_umdr33_evidence_chain_fixes`) | DR-009 window #1, old pin recorded |
| R2 | Corrupted trace resets step budget (deactivates governor) | code trace: channel append-only, no legit non-list | `budget_governor.py` fail-closed corrupted-present branch | 6 tests (`test_umdr33_hard_budget_and_creds`) | DR-009 window #2 |
| R3 | Placeholder credentials load silently | template round-trip analysis | `cli/loaders.py` secret-mapping rejection | 14 tests + 2 evolved contract tests | DR-009 window #2 |
| R4 | Suite dirties working tree (econ CLI journal) | bisected to `test_cli_transition_persists…` | `cli/econ.py` state-dir journals | 2 tests (`test_umdr33_tree_hygiene`) | not frozen |
| R5 | Ground-truth identity dual hash | two serializers for one manifest | `webpent.shared.canonical_json` (single contract) | 18 tests incl. mutations | new module |
| R6 | kill_switch from_url(None) TypeError per publish | code trace | guard before from_url | 2 tests | not frozen |
| R7 | info_gain decorative (never read by score) | UM-DR-31 review + code confirmation | W_INFO_GAIN in weighted sum | 19 tests (`test_umdr33_info_gain_operational`) | DR-009 window #3 |
| R8 | Discovery funnel absent | mission §12 | `production/discovery_funnel.py` (16 stages, honest markers, drop explanations) | 20 tests | frozen from birth |
| R9 | 152-vs-154/159 accounting error | node-ID recount | erratum in UM-DR-32 reports (preserved, corrected) | accounting JSON | docs |
| R10 | README Python floor/tested conflation | README:201 vs pyproject | explicit floor/tested/recommended | — | docs |
