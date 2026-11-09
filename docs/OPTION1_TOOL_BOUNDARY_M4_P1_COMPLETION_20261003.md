# Option 1 — ToolBoundary Adapter, M4 Legacy Gate, and P1 Fixes

**Date:** 2026-10-03  
**Workspace:** `/tmp/webpent_vuln_arsenal`

## Verdict

**PASS for the requested Option 1 scope.** The frozen ToolBoundary authority was not modified. Target/tool output is masked at the LLM consumption boundary through a non-frozen adapter, legacy authentication can fail closed when governed mode requires M4, and the three P1 fixes are implemented.

## Implemented changes

1. **ToolBoundary prompt adapter**
   - Added `src/webpent/llm_researcher/tool_boundary_adapter.py`.
   - Wraps ToolBoundary-shaped output with `UntrustedContent`.
   - Exposes masked content, summary, structural metadata, and a bounded query interface.
   - Keeps raw output available only through the deterministic-validator handle.
   - `interface.py` uses the adapter for prompt-facing projections; prompt paths do not import the frozen ToolBoundary authority directly.

2. **Static boundary gate**
   - Added `scripts/check_tool_boundary_prompt_boundary.py`.
   - Added the gate to the service health gate registry and the `Makefile` CI target.
   - The gate checks adapter existence, prompt integration, direct frozen-boundary imports, and the untrusted projection implementation.

3. **Dalfox masking**
   - Dalfox now returns a `MaskedToolOutput` after bounded deterministic processing.
   - The object is string-compatible for existing deterministic/legacy equality and containment checks, while its normal string/prompt representation is the masked summary.
   - The raw output remains accessible only through `raw_for_deterministic_validation()`.

4. **Legacy credential path**
   - Added `src/webpent/agents/authentication/m4_boundary.py`.
   - `auth_node` now fails closed when `m4_enforced=True` and an authorized/attached M4 projection is absent.
   - The failure is redacted and returns no session headers, cookies, or identity profiles.
   - Existing non-governed compatibility callers retain their established contract.

5. **P1 fixes**
   - `SQLI`, `SQL-INJECTION`, and `SQL INJECTION` normalize to `SQL_INJECTION` in payload lookup APIs.
   - `persona=all` is handled as a bounded deterministic advisory profile combination.
   - Dashboard completion alerts use supplied `time_total`, with a timestamp fallback when it is not supplied.

## Verification

- Full suite: **2188 passed, 0 failed, 10 warnings**.
- Acceptance suite: **20 passed × 3 rounds**.
- Focused Option 1/P1 tests: **12 passed** in the final validation command.
- Dalfox URL-flag, scope, hardening, adapter tests: **19 passed**.
- Frozen manifest: **OK (13 files)**.
- `tool_boundary.py` SHA-256:
  `c46608c3add66d66898ede7b9e89345c3ddaa7cc14bf624ae1ccac57cf2a0cd0`
- State contract: **exit 0**.
- Orchestrator construction authority: **exit 0**.
- Isolation denylist: **exit 0**.
- Vault import authority: **exit 0**.
- Test-count gate: **2188 collected >= 1940 floor, exit 0**.
- ToolBoundary prompt boundary gate: **exit 0**.
- Direct-I/O inventory contract: **4 passed**.
- Source compilation: **OK**.

## Scope note

The legacy authentication guard is intentionally opt-in through `m4_enforced`; this preserves the existing compatibility behavior for callers that are not using the governed campaign path. Governed callers must provide the redacted M4 authorization/attachment projection, and the legacy node cannot mint or infer that authority.

## Sanitization

The release archive excludes caches, bytecode, virtual environments, runtime databases, raw campaign artifacts, logs, and operator credential files.
