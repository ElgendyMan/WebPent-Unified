# ADVERSARIAL REVIEW — v89 PRISM (Red Team Level)

═══════════════════════════════════════════════════════════
Target reviewed: webpent_v89_prism.zip (PRISM wave, 15 units U-PRISM-1..15)
Review period: 2026-10-18
Reviewer: Adversarial Reviewer (Red Team Level)
Method: inventory → 9-axis sweep → executed PoCs (no claims taken from the plan doc)
Environment: clean container, deps installed from the ZIP's own pyproject (torch, langgraph stack, celery, fastapi, pytest-asyncio installed manually — see F-002, F-003)
═══════════════════════════════════════════════════════════

## Phase 1 — Inventory (executed)

- Extracted the ZIP to a fresh directory. 3,867 files.
- Claim map built from docs/plans/2026-10-18-v89-prism.md → module → test.
- prism scope: 15 modules (src/webpent/prism/), 229 tests (tests/prism/), config/prism/ (taxonomy, scorer_weights, learning_params, classifier_patterns, archetypes, curiosity_params), CLI (src/webpent/cli/prism.py, 9 commands).
- Zip mtimes: 2026-10-18 files are only src/webpent/prism/, tests/prism/, config/prism/, docs/plans/2026-10-18-v89-prism.md, CLI, plus packaging junk (.ruff_cache, .pytest_cache, webpent.db, download/ — see F-009). No spine file (modern_spine.py, profile.py, hunt_contracts.py) is dated in this wave — spine untouched by the ZIP's own timestamps.

## Phase 2 — Gate (executed, not trusted)

- `pytest tests/prism/` on clean env: **229 passed** in ~4.6 s, three consecutive runs, identical result. Claim "≥200 new tests" VERIFIED.
- `pytest tests/` full suite on clean env: **3836 passed, 2 FAILED** (F-001, F-002). Claim "zero failures" (PRISM-L-12) **BROKEN on any machine other than the build box**.
- `ruff check src/webpent/prism tests/prism`: **clean**. Claim VERIFIED.
- Prism source grep: zero randomness in decision paths (only wall-clock recorded_at metadata), zero network (no socket/urllib/requests/httpx), zero subprocess/eval/exec/pickle/yaml.load, zero hardcoded credentials. PRISM-L-3 (no network) VERIFIED structurally.

═══════════════════════════════════════════════════════════
## Phase 3 — Findings
═══════════════════════════════════════════════════════════

### FINDING-001: The release gate does not reproduce from the delivered ZIP

Category: Evidence / Doc-Lie
Severity: HIGH
Claim being challenged: "PRISM-L-12: ≥200 new tests … zero failures, PRISM-L-13 review" and the standing claim that the delivered ZIP is the gate's evidence.

Location:
- File: tests/oracle/test_oracle_integration.py:367–380
- Test: tests/oracle/test_oracle_integration.py::test_law_checklist[ORACLE-L-12]

What was claimed: "all 16 gates: zero failures, PRISM-L-13 red team".

What actually exists: the test hardcodes the original build machine into the subprocess it spawns:
- `venv_python = "/home/thaura/venv/bin/python"` (literal)
- `env["PLAYWRIGHT_BROWSERS_PATH"] = "/home/thaura/pw-browsers"` (literal)
- `env["HOME"] = "/home/thaura"` (literal)

The gap: on any machine other than the build box the subprocess is spawned from a nonexistent interpreter and the checklist fails. Executed: full suite from the extracted ZIP on a clean container → `2 failed, 3836 passed`. The gate evidence is machine-bound, therefore the "zero failures" claim in the wave doc is unverifiable from the artifact the wave shipped.

Proof of Concept (executed):
```
$ python3 -m pytest tests/ -q
...
FAILED tests/oracle/test_oracle_integration.py::test_law_checklist[ORACLE-L-12]
2 failed, 3836 passed
```

Impact: every future "zero failures" claim rests on an environment that only exists on one machine. The evidence chain the project treats as its spine (honesty is the product) silently degrades: the ZIP cannot prove its own gate.

Suggested fix: `venv_python = sys.executable`, `cwd = Path(__file__).resolve().parents[1]`, drop HOME/PLAYWRIGHT overrides (or resolve them from env with a skip when absent). Re-run on a clean container.

Status: CONFIRMED (executed)

### FINDING-002: JWT issuance depends on an undeclared dependency; API auth path breaks on clean install

Category: Doc-Lie / Real-Target
Severity: HIGH
Claim being challenged: pyproject is the complete dependency manifest ("packaging only src/tests/docs/pyproject/README" with a passing gate).

Location:
- File: src/webpent/api/auth.py:322–338
- Test: tests/test_v63_vip_security_regression.py::test_jwt_contains_required_claims_and_revocation_is_effective (FAILED on clean env)

What actually exists: `_create_access_token` tries `from jose import jwt` then `from jwt import ...`; **neither `python-jose` nor `pyjwt` appears in pyproject dependencies**. On a clean `pip install -e .` both imports raise ModuleNotFoundError, the second one uncaught (`raise` at line 338).

The gap: a declared feature path (API auth token issuance, covered by a security regression test) cannot be imported from the package's own manifest.

Proof of Concept (executed):
```
$ python3 -m pytest "tests/test_v63_vip_security_regression.py::test_jwt_..." -q
FAILED ... ModuleNotFoundError: No module named 'jose'
```

Impact: anyone reproducing the gate from the ZIP gets a red suite and concludes the project lies; in deployment, the token-mint path of the API is dead code until an operator guesses the missing package.

Suggested fix: declare `pyjwt` (or `python-jose`) in pyproject [project.dependencies]; keep the try-chain but raise a named error listing both options.

Status: CONFIRMED (executed)

### FINDING-003: apply_priors is order-sensitive — PRISM-L-9 ("ties broken by stable keys") is not enforced inside the API

Category: Determinism
Severity: MEDIUM
Claim being challenged: "no randomness, no dict-order behavior; ties broken by stable keys."

Location:
- File: src/webpent/prism/integration.py:141–164 (`apply_priors`)
- Test: NO TEST EXISTS for input-order invariance

What actually exists: patterns are applied in caller-given order; each `adjust()` recomputes the delta against the already-adjusted prior (float compounding). No `sorted()` inside the module.

Proof of Concept (executed):
```python
pA = Pattern(... key="xss_probing", success_rate=0.95, samples=40 ...)
pB = Pattern(... key="xss_probing", success_rate=0.10, samples=8 ...)
integ.apply_priors(BrainState(priors={"xss_probing": 0.5}), [pA, pB]).priors
  -> 0.49999999999999994
integ.apply_priors(BrainState(priors={"xss_probing": 0.5}), [pB, pA]).priors
  -> 0.5
```

The gap: same inputs, different output, purely from list order. Today PatternExtractor returns sorted patterns so the built-in path is deterministic; the moment the Brain (or the LLM advisory layer) supplies a sequence built from a set or dict, the PRISM-L-9 claim breaks at the API boundary, silently, in the 16th decimal of a number that gates hypotheses.

Impact: a determinism claim that holds only for one caller is not a determinism claim. Audit replay between runs/versions becomes inexact.

Suggested fix: canonical sort inside `apply_priors` by `(pattern.pattern_id, pattern.updated_at, pattern.success_rate)` before iterating; add an order-invariance regression test.

Status: CONFIRMED (executed)

### FINDING-004: Campaign name bypasses PII redaction — docstring says every text blob is redacted

Category: Security / Doc-Lie
Severity: MEDIUM
Claim being challenged: ledger docstring: "every text blob passes PII redaction before insert (PRISM-L-6/L-7)".

Location:
- File: src/webpent/prism/ledger.py:4–7 (docstring), 120–131 (`open_campaign` stores `name` raw), CLI `webpent prism campaigns` prints it
- Test: NO TEST EXISTS asserting `name` is redacted

Proof of Concept (executed):
```python
led = CampaignLedger(tmp)
cid = led.open_campaign("target.example", "victim corp — john.doe@corp.com 01001234567")
# SELECT name FROM campaigns -> 'victim corp — john.doe@corp.com 01001234567'  (raw)
```
Same text passed in `notes` or `decision.reason` IS redacted; `name` is not.

The gap: the operator-authored name is the least constrained string in the system and the only one that skips `redact_pii`. It lands in the DB, in `campaign_id` (sha256 of name — no leak there), and in CLI output.

Impact: an operator who names a campaign after the target URL with credentials or a contact identity in it persists PII indefinitely, in the exact store whose docstring promises redaction. The export path carries it out of the machine.

Suggested fix: `name = redact_pii(name)` in `open_campaign` (and in any rename path); regression test with an email+phone name asserting the stored row is redacted.

Status: CONFIRMED (executed)

### FINDING-005: "Audit log utf-8 capped" — the cap does not exist

Category: Doc-Lie / Real-Target (resource exhaustion)
Severity: MEDIUM
Claim being challenged: docs/plans/2026-10-18-v89-prism.md:64 "U-PRISM-13 dashboard+CLI (9 commands, audit log utf-8 capped)".

Location:
- File: src/webpent/prism/compliance.py:152–165 (`enforce` appends a line per violation, unbounded)
- grep across src/webpent/prism + src/webpent/cli/prism.py: zero occurrences of MAX_LINES/cap/rotation
- Test: NO TEST EXISTS for log capping

What actually exists: utf-8 append ✓, cap ✗. No rotation, no size guard, nothing in the CLI bounds it.

Impact: in a long CEM engagement with a noisy integration the audit log grows without bound — the same class of disk-growth bug the Dojo wave fixed with MAX_HISTORY_LINES=5000. The plan documents a property the code does not have.

Suggested fix: either implement the cap (last N lines, matching the Dojo's MAX_HISTORY_LINES pattern) or correct the plan doc; a regression test asserting the cap.

Status: CONFIRMED (code-level; growth-by-design not simulated at scale)

### FINDING-006: Conflict penalty punishes agreeing evidence

Category: Doc-Lie / logic defect
Severity: MEDIUM
Claim being challenged: tiering docstring: conflicts are "an anomaly arguing against a direct or side-effect signal".

Location:
- File: src/webpent/prism/tiering.py:144–147 (`_conflicts` returns a pair whenever any anomaly-type and any active-type evidence coexist), 161–183 (penalty applied unconditionally on a pair)
- Test: NO TEST EXISTS for a corroborating anomaly

Proof of Concept (executed):
```python
direct  = profile(kind="direct_response", strength="decisive", corroboration="independent_multiple")
anomaly = profile(kind="header_anomaly",  strength="decisive", corroboration="independent_multiple")  # AGREES
integrate([direct])                 -> integrated 0.3733, penalty 0.0
integrate([direct, anomaly])        -> integrated 0.2589, penalty 0.1, verdict likely→possible
```

The gap: an anomaly that confirms the direct hit takes the same penalty as one that contradicts it. Two agreeing signals score LOWER than one signal alone. The docstring's stated semantics (argues against) are not what the code computes (coexists).

Impact: the integrator systematically under-scores corroborated findings — exactly the evidence the Brain should trust most — and over-penalizes well-covered hypotheses. Flips at the likely/possible boundary change what the operator sees.

Suggested fix: compute agreement inside `_conflicts` (same signal_kind, or anomaly direction consistent with the direct signal) and penalize only genuine disagreement; add a corroborating-anomaly regression test.

Status: CONFIRMED (executed)

### FINDING-007: prune() crashes on mixed naive/aware datetimes

Category: Missing-Test / robustness
Severity: LOW
Location: src/webpent/prism/patterns.py:171–176; ledger.py:72–73 (`_utc_now` returns timezone-aware).

What was claimed: stale decay at 90 days.
What actually exists: `datetime.fromisoformat(updated_at) < cutoff` — a pattern whose `updated_at` is naive (any caller passing `now` without tz, the common case in this codebase's tests) compared against an aware `now` raises `TypeError: can't compare offset-naive and offset-aware datetimes`. Executed PoC: CONFIRMED. Fail-closed (crash, not silent decay), but it puts an exception on the learning path the first time a ledger-aware caller and an extract-naive caller meet.

Suggested fix: normalize both sides (`cutoff.replace(tzinfo=None)` after asserting naive, or always attach tz). Test: prune with aware now and naive updated_at.

### FINDING-008: Refusal-by-exception on the Brain's call path

Category: Authority / robustness
Severity: LOW
Location: src/webpent/prism/integration.py (`validate_finding`, `record_outcome` — raise `PrismLawError` on unscored findings / no profiles).

What was claimed: PRISM-L-2 "an unscored finding gets no Prism score" — compliant at intake, and `blocked=False` is structurally honest.
What actually exists: the refusal is a raised exception into the caller. The standing invariant "amplifier failure never breaks a round" (v82) is not preserved if the Brain calls Prism inline: one malformed finding kills the enrichment path of the round.
Suggested fix: return a passthrough result (`ValidatedFinding(..., refused=True, profiles=[])`) and let the caller log it; keep `raise` only behind an explicit strict flag.
Status: SUSPECTED (no executed round-crash repro — Prism is not yet wired into the autonomous loop; by design this wave)

### FINDING-009: ZIP ships caches, a SQLite DB and download artifacts

Category: Evidence / hygiene
Severity: LOW
Location: webpent_v89_prism.zip: `.ruff_cache/`, `.pytest_cache/`, `webpent.db` (auth_token_versions with 90 synthetic test users), `download/` artifacts.

What was claimed (v78 standard, standing): "packaging only src/, tests/, docs/, pyproject and README".
Impact: the package's own claims about what it contains are false; the DB embeds test state that can confuse a fresh extraction (a `webpent.db` in CWD will be picked up by default paths). Determinism of a fresh extraction is polluted.
Suggested fix: restore the v78 packlist; add a packaging test asserting no cache/DB files in the artifact.

### FINDING-010: Dead config key and unvalidated threshold ordering

Category: Doc-Lie (minor)
Severity: LOW
Location: src/webpent/prism/tiering.py (`COHERENCE_KEYS` includes "none"; unreachable — largest group is always ≥1), `verdict_thresholds` ordering (confirmed≥likely≥possible≥weak) never validated while the scorer validates its own tiers.

Impact: an inverted threshold set produces nonsense verdicts with no error at load.
Suggested fix: validate ordering in `__init__`; drop "none" or make it reachable for the empty-signals case.

### FINDING-011: time_saved_hours described as configured; it is hardcoded

Category: Doc-Lie
Severity: LOW
Location: src/webpent/prism/metrics.py:26–27 ("the configured max_time_hours default") vs :175 (`avoided * 0.5` — no config exists in the module).
Suggested fix: read `max_time_hours` from config (default 0.5) or reword the docstring.

═══════════════════════════════════════════════════════════
## Claims table
═══════════════════════════════════════════════════════════

| Claim | Status | Finding ref |
|---|---|---|
| ≥200 new tests | VERIFIED | 229 counted and passed |
| zero failures (PRISM-L-12) | **BROKEN** on clean env | F-001, F-002 |
| ruff clean | VERIFIED | run on prism scope |
| PRISM-L-3 no network | VERIFIED (structural grep: none) | — |
| PRISM-L-2 advisory-only | VERIFIED (no execution authority; blocked=False; not wired into the loop) | F-008 note |
| PRISM-L-9 deterministic / ties by stable keys | **PARTIAL** | F-003 (order), F-007 (naive/aware) |
| PRISM-L-6/L-7 PII redaction on insert | **PARTIAL** | F-004 (name) |
| PRISM-L-4 no silent failures | VERIFIED for the detector | F-005 (cap claim false) |
| 9 CLI commands | VERIFIED | — |
| config: min_samples 5 / floor 0.6 / cap ±0.20 / stale 90d | VERIFIED | matches config/prism/learning_params.yaml |
| classifier ≥20 patterns, ≥5 archetypes | VERIFIED | 24 patterns, 5 archetypes |
| spine untouched this wave | VERIFIED by zip timestamps (no spine file dated 2026-10-18); no git history in the ZIP — could not diff hashes |

═══════════════════════════════════════════════════════════
## ADVERSARIAL REVIEW VERDICT
═══════════════════════════════════════════════════════════

Severity counts:

| Severity | Count | Confirmed | Suspected |
|---|---|---|---|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 2 | 2 | 0 |
| MEDIUM | 4 | 4 | 0 |
| LOW | 5 | 4 | 1 (F-008) |
| Total | 11 | 10 | 1 |

CRITICAL findings: none.

HIGH findings:
1. FINDING-001: gate "zero failures" does not reproduce from the ZIP (machine-bound test paths). Must-fix-before: any future "zero failures" claim.
2. FINDING-002: JWT issuance path dead on clean install (undeclared dependency). Must-fix-before: next package.

MEDIUM findings: F-003 (order-sensitive priors, PRISM-L-9 partial), F-004 (campaign name unredacted), F-005 (audit-log cap claimed, absent), F-006 (agreeing anomaly penalized, score 0.373→0.259).

Coverage assessment:
- Axes fully covered: 1 (Claims vs Reality — every wave claim traced to artifact and executed), 2 (Security — no injection/SSRF/deserialization/network surface in prism; redaction gap found), 3 (Determinism — 3 suite runs + PoC), 4 (Advisory-only — structural verification, not wired into the loop), 5 (Evidence — full-suite rerun on clean env), 6 (Real-Target — PII/export, resource-growth, CLI output), 8 (Missing tests), 9 (Doc vs Code).
- Axes partially covered: 7 (Spine — verified by zip timestamps only; the ZIP carries no git history, so hash-level "spine untouched" cannot be proven from the artifact alone).
- Axes not covered: none.

Limitations of this review: (a) no git history inside the ZIP, so spine non-modification is inferred from timestamps, not proven; (b) the suite was run with CPU-side deps only where the code lazily imports them (torch installed without NVIDIA libs — irrelevant to CPU tests; celery/fastapi/pytest-asyncio installed manually, which is itself F-002/F-003 territory for the manifest); (c) F-008 judged at design level since Prism is not yet wired into the loop.

🎯 Final Verdict:

**VERDICT: FAIL** (for the release claim as shipped; the prism logic itself is one fix-pass away)

- 🔴 The work is not ready to ship **as a claimed gate**: the artifact cannot reproduce its own "zero failures" on a clean machine (F-001, F-002). Honesty-is-the-product fails at the evidence layer, not the logic layer.
- 🔴 No CRITICAL findings; no exploit against the advisory-only boundary was found. What was attempted and did not break the module: prompt-level manipulation of enrichment (input is typed and validated), authority escalation through scoring (no execution path exists), network fingerprinting claims (no network code), SQL injection in the ledger (parameterized throughout), ReDoS in the classifier (no regex on external input).
- The structural issues are concentrated in: evidence packaging (F-001, F-002, F-009) and two semantic defects in scoring/redaction (F-003, F-004, F-006).

Required before re-review (Round 2): fix F-001..F-006 with failing tests first; then the same clean-container gate must pass from the new ZIP alone.

═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════
ROUND 2 APPENDIX — Fix Verification + Second-Pass Review (2026-10-18)
═══════════════════════════════════════════════════════════

Method: every fix verified by executing the original PoC or its
regression test on the patched tree, not by reading the diff.

## Fix disposition (F-001..F-011)

| ID | Fix applied | Verified by |
|----|-------------|-------------|
| F-001 | test_oracle_integration.py: portable `sys.executable` + cwd + PYTHONPATH, no machine paths, no HOME/PLAYWRIGHT overrides | pytest collects oracle tests via subprocess on this machine |
| F-002 | pyproject.toml adds `pyjwt>=2.8.0`; api/auth.py `_create_access_token` tries jose then pyjwt, named RuntimeError if both missing | import + token mint succeeds with pyjwt only |
| F-003 | integration.apply_priors canonical-sorts patterns by (pattern_type, key, pattern_id) before sequential capped deltas | regression: forward/backward orders produce identical priors + history |
| F-004 | ledger.open_campaign runs `redact_pii(name)` before hashing/insert | regression: stored name contains neither the email nor the phone; `[pii-redacted:` marker present |
| F-005 | compliance.enforce rewrites the on-disk log with `MAX_LOG_LINES = 5000` truncation (newest kept) | regression: 5250 enforced violations → exactly 5000 lines on disk; in-memory log keeps all 5250 (L-4) |
| F-006 | tiering._conflicts penalizes only genuine disagreement (anomaly score strictly below the paired active score); corroborating anomaly → 0.0 penalty, no conflict records | regression: agreeing pair → penalty 0.0, conflicts empty; disagreeing pair → penalty > 0 |
| F-007 | patterns.prune normalizes both `now` and `updated_at` to UTC-aware (naive interpreted as UTC) | regression: aware-now/naive-stamp and naive-now/aware-stamp both prune correctly |
| F-008 | integration.validate_finding returns `verdict="refused"` ValidatedFinding instead of raising; record_outcome returns `[]` for unscored findings (no-ledger still raises) | regression + updated edge-case test to the new advisory contract (PRISM-L-2) |
| F-009 | delivery rebuilt without caches/DBs: 0 `__pycache__`, 0 `.pytest_cache/.ruff_cache`, 0 `*.db`, 0 `download/` in webpent_v89_prism_fixed.zip (3223 files) | `unzip -l | grep` count = 0 |
| F-010 | tiering validates `verdict_thresholds` ordering (confirmed ≥ likely ≥ possible ≥ weak); COHERENCE_KEYS = 3; scorer_weights.yaml `none` key removed | regression: unordered thresholds rejected; 3-key config loads; missing coherence key rejected |
| F-011 | metrics.MetricsEngine takes optional config path, reads `rabbit_hole.max_time_hours` (validated positive), falls back to documented 0.5 default; CLI wires `curiosity_params.yaml` | regression: max_time_hours=1.5 × 2 avoided = 3.0 h saved; bad/missing config raises PrismLawError |

## Round 2: new findings

No new HIGH or MEDIUM defects. Two improvements applied during the
second pass:

1. compliance.enforce_all was O(n²) on disk (rewrote the whole log per
   violation). Batched to read → append-all → truncate → write-once;
   regression test proves byte-identical output vs the per-violation
   loop. LOW, fixed.
2. direct_io_inventory.json drift: the F-003 fix added 5 `getattr`
   dynamic-resolution records in prism/integration.py. Regenerated the
   artifact through `scan_direct_io` (reviewable diff: +5 records,
   transport counts unchanged 92 approved / 22 unapproved); the pinned
   transport tests still pass. LOW, fixed.

Second-pass checks that found nothing: stale `"none"` coherence
references (none outside tiering's removed key), hardcoded 0.5 metrics
references (methodology string updated to cite the config key),
`MetricsEngine()` bare constructions outside tests (only the CLI, now
wired), prism→platform wiring (CLI typer registered; enrich → validate
→ apply_priors → record_outcome → audit → metrics executed end-to-end
in one smoke run: all six links pass).

## Post-fix verification battery

- tests/prism: 246 passed — run twice, identical results (determinism).
- Full suite (`tests -q`, UI excluded): 3855 passed, 0 failed. The
  lab.example.com proxy denials in the log are the suite's own
  deliberate network-denial checks, not failures.
- ruff: changed files (prism/, tests/prism/, cli/prism.py, api/auth.py,
  test_oracle_integration.py) clean. The whole tree carries ~2.7k
  pre-existing style findings (mostly E501) from earlier waves; out of
  scope for this pass and untouched.
- Packaging: webpent_v89_prism_fixed.zip, 3223 files, no caches/DBs.

## Updated verdict

**VERDICT: PASS-WITH-CONDITIONS.** All 11 findings from Round 1 are
fixed and pinned by 17 new regression tests
(tests/prism/test_redteam_fixes_regression.py). The two Round-1 gate
breakers (reproducibility from clean checkout, dependency declaration)
are cleared. Remaining conditions, none blocking the prism logic:

1. The full-tree ruff baseline (~2.7k pre-existing style findings)
   should be triaged in a dedicated hygiene wave before the next
   release claim.
2. The delivery ZIP carries no git history (inherited from Round 1);
   spine non-modification remains inferred from timestamps until the
   project ships git provenance.
3. F-008's refusal-passthrough contract is now enforced by test; any
   future call site that re-raises on refusal must update both the
   contract test and the edge-case test together.
