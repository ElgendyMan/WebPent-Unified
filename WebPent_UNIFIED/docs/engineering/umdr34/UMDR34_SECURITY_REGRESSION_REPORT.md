# UM-DR-34 Security Regression Report

**Phases 8/9/11 deliverables — the adversarial regression matrix, gate
quality, and end-to-end security verification.**

---

## 1. New regression suites (170 tests)

| Suite | Tests | Coverage |
|---|---|---|
| `test_umdr34_canonical_scope_authority.py` | 38 | wildcard/origin/path/method adversarial matrix; determinism; deny precedence; decision record; parser unification; target-only mode |
| `test_umdr34_engagement_lifecycle.py` | 16 | fail-closed admission; atomic nested restore; exception-path cleanup; thread/async isolation; control-plane separation; bare-host port binding |
| `test_umdr34_boundary_enforcement.py` | 18 | sync/async/redirect denials with **zero-network-attempt assertions**; rate parity; fail-closed governor; metadata-target denial |
| `test_umdr34_llm_redaction.py` | 25 | key checks; cookie families; guarded runnable invoke/ainvoke/batch/stream with a recording fake provider; messages; content blocks; UntrustedContent projection; redact_value |
| `test_umdr34_checkpoint_safety.py` | 7 | degraded marker; logged; secret-free logs; no blank-runtime resume; valid restore unchanged |
| conftest hygiene fixtures | 2 | documented test isolation for the new global state (governor window, engagement context) |

**Zero-network-attempt discipline (§8):** every negative
transport-level test asserts the counting mock's attempt count is `0`
(pre-network denial) or exactly the in-scope hop count (redirect
chains) — testing that a helper returns False is never accepted alone.

## 2. Adversarial matrix highlights (§8)

* **Wildcards**: `*.example.com` matches complete subdomain labels and
  nested subdomains; apex NOT included; `?`/`[seq]`/misplaced `*`
  rejected at compile; no suffix-of-other-domain match; trailing dots;
  IDNA (unicode ⇔ punycode); IPv4/IPv6 exact; CIDR boundaries.
* **Origins**: http vs https distinguished; ws/wss TLS-posture rule;
  explicit vs default port; **port 0 rejected**; out-of-range/negative
  rejected; userinfo denied; malformed URLs denied (never raise);
  bare-host rules bind default ports only.
* **Paths**: `/api` vs `/api2`; include/exclude precedence
  (`matched_deny_rule` asserted); encoded separators/dots/backslash/
  double-encoding ⇒ `scope_path_ambiguous`; dot-segment normalization;
  query/fragment neutrality.
* **Methods**: allowed sets; destructive defaults; redirect method
  re-check (original method AND GET-downgrade both evaluated);
  severity ceilings; blacklisted payloads.

## 3. End-to-end security verification (§11)

Executed at the **real production boundary** (the same
`make_safe_httpx_client`/`make_safe_httpx_async_client` chokepoints,
redirect hook chain, and engagement context the compiled graph's nodes
use), with counting mocks proving pre-network denial:

| # | Scenario (§11) | Result |
|---|---|---|
| 1 | Valid in-scope request proceeds | ✅ 1 attempt, 200 |
| 2 | Out-of-scope hostname denied pre-network | ✅ 0 attempts |
| 3 | Same-host excluded path denied | ✅ 0 attempts |
| 4 | Out-of-scope redirect denied | ✅ 1st hop only; redirect blocked pre-2nd-request |
| 5 | In-scope origin, unauthorized port | ✅ 0 attempts |
| 6 | HTTP/HTTPS scheme mismatch | ✅ 0 attempts |
| 7 | Wildcard cannot widen via glob metacharacters | ✅ compile-time rejection |
| 8 | Empty campaign scope denies | ✅ `scope_policy_empty` |
| 9 | Malformed policy denies | ✅ `request_url_rejected` / parse fail-closed |
| 10 | Nested context restores outer policy | ✅ lifecycle test |
| 11 | Private-target exception limited to explicit authorization | ✅ bare-host binds default ports; other port denied (0 attempts) |
| 12 | Link-local / metadata targets denied | ✅ 169.254.169.254 blocked under any engagement (0 attempts) |
| 13 | Sync and async transports enforce identical decisions | ✅ same denials + same ceiling on both |
| 14 | Playwright paths enforce the policy | ✅ route handler unchanged in behavior (already enforced) + guard installation pinned by pre-existing suites |
| 15 | External-tool invocation rejected pre-spawn when out of scope | ✅ pre-existing per-tool preflights (sqlmap/dalfox/nuclei/katana/ffuf/httpx) re-verified green |
| 16 | Rate limits active with `stealth_mode=False` | ✅ `rate_limit_enabled=False` asserted AND ceiling enforced in engagement |
| 17 | Async requests cannot exceed the budget | ✅ async window denial |
| 18 | Redis/backend failure cannot disable governance | ✅ coordination-required denial path (unit-level; see LIMITATIONS) |
| 19 | Sensitive cookie values cannot reach a fake LLM provider | ✅ invoke/ainvoke/batch/stream, `provider.received` inspected |
| 20 | Checkpoint context failures visible, no false-success resume | ✅ degraded marker + dropped channel + ERROR log |

Each denied request records: decision fields (status, fingerprint,
reason/violation_code, matched rules), the execution path (which
transport), and the network-attempt count (0 for pre-network denials).

## 4. Security-gate quality (§9)

* **Orchestrator construction gate**: now detects alias bindings
  (`MO = ModernOrchestrator`), `getattr(..., "ModernOrchestrator")`,
  importlib string references, and eval/exec indirection — outside the
  factory/allowlist. Docstring states plainly: the text matcher is
  static defense-in-depth; the RUNTIME authority is the factory token.
  Runs green; its regression test green.
* **State-contract gate**: new AST pass covers in-place mutations —
  `state.update({...})` and `state["literal"] = ...` inside `*_node`
  functions face the same declaration check as returned keys.
  Deliberately conservative (no flow analysis — no false assurance).
  Runs green.
* **Vault import gate**: reviewed; runs green; allowlist NOT widened;
  the honestly-documented un-enforced comparative-flow bar (OQ-3) is
  unchanged.
* **Frozen-module gate**: 14 files re-pinned via the DR-009 protocol
  (`scripts/refreeze_manifest_umdr34.py`, old pins recorded in the
  script); the gate's documented-thaw ledger extended with the
  UM-DR-34 entry. 647/647 gate tests green.

## 5. Test-contract updates (all one-way strengthenings)

| Test | Change | Why |
|---|---|---|
| `test_global_rate_governor.py::test_memory_snapshot_shape` | + `coordination_scope` required field | §5.3 visibility (process-local must be reportable as such) |
| `test_byte_level.py::TestEvidenceBundle` | Cookie header now fully redacted | §6.4 key-aware redaction is strictly stronger |
| `test_g02_direct_io_inventory.py` pins | 34→29 records / 28→25 identities | the §4.8 fix REMOVED the raw httpx client identities (adjudicated security removal) |
| `test_frozen_module_gate.py` | + UM-DR-34 documented thaw set | DR-009 ledger entry for this window's 14 files |

No security assertion was weakened to make a count green. No test was
silently removed. The full-suite accounting reconciles exactly
(`UMDR34_TEST_ACCOUNTING.json`).

## 6. Honest limitations (PARTIAL items)

1. **Scenario 18 multi-process demonstration** is unit-level (a real
   multi-Celery-worker Redis outage drill was not executable in this
   sandbox); the coordination-required denial path is tested, the
   production drill is not.
2. **Scenario 14 Playwright** relies on the pre-existing route-handler
   suites; no new live-browser run was added in this window (browser
   binaries unavailable in the sandbox).
3. **Forms channel state-filtering** (business-logic fuzzer input) —
   the transport boundary is now fail-closed; the state-layer filter
   for `crawled_data["forms"]` remains a documented residual.
4. **APEX subsystem** (optional scope + LocalSandbox) — out of the live
   campaign path; unchanged, documented in the architecture map.
