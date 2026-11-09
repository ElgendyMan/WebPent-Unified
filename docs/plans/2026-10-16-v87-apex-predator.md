# Implementation Plan — v87 The Apex Predator (docs/plans/2026-10-16-v87-apex-predator.md)

Date: 2026-10-16. Baseline: **0.10.1 (v86.1), 3164 passed**. Target version: **0.11.0**.
Source of truth: the user's proposal "The Apex Predator (المفترس الأعلى)" — 12 units
(U-APEX-1..12) across 4 waves, 10 laws (APEX-L-1..L-10), ≥30 external tools,
Docker sandbox, parallel execution, result fusion, MCP server, dashboard, learn loop.

## Charter — the ten laws, in project voice

- **APEX-L-1 TOOLS NOT CODE**: never re-implement what a vetted external tool does;
  the apex layer orchestrates, it does not reimplement.
- **APEX-L-2 VETTED ONLY**: every registered tool is documented, audited, actively
  maintained (`vetted: true` in the registry); nothing unvetted ever executes.
- **APEX-L-3 SCOPE BEFORE TOOL**: every tool call passes the ScopeGuard before
  execution; an argument naming a host outside the authorized scope fails closed.
- **APEX-L-4 SANDBOX ALWAYS**: every tool executes inside the sandbox abstraction
  (Docker backend when available, resource-limited local backend otherwise);
  zero host filesystem access outside declared volumes.
- **APEX-L-5 PARALLEL BY DEFAULT**: independent chain steps run concurrently,
  dependencies respected, deterministic result ordering regardless of wall clock.
- **APEX-L-6 FUSE RESULTS**: multiple tool outputs fuse into one fused picture with
  consensus scoring; a single tool's opinion never becomes the record.
- **APEX-L-7 LEARN FROM EVERYTHING**: every chain outcome is recorded, every tool
  accuracy measured, every failure analyzed — in a bounded, redacted ledger.
- **APEX-L-8 SPEED IS THE EDGE**: selection, scheduling, caching, and timeouts all
  weigh speed; measured speedup is proven, not claimed.
- **APEX-L-9 ADVISORY-ONLY**: apex plans, proposes, and measures. The operator
  approves; nothing is sent, executed against a real target, or decided autonomously.
- **APEX-L-10 PREAMBLE BEFORE**: every CLI command and every artifact opens with the
  advisory preamble line before any output.

## Standing constraints (inherited from the Dojo charter and the v82+ barriers)

Zero network from `src/webpent/apex/*` in tests (socket-patched, like the Dojo L-1
proof); all backends injected — the Docker backend is argv-constructed and never
executed here (Docker daemon is denied in this environment, and that is recorded as
`blocked` in traceability, exactly like the worker row); deterministic outputs with
injected clocks; bounded state (capped ledgers); broken files load as empty; redaction
on every persisted path; advisory-only by construction — apex produces plans and
measurements, never Findings (a FusedFinding is an advisory hypothesis ranking, and
the code says so on every surface).

## File map (all new, plus packaging/docs edits)

| File | Responsibility |
|---|---|
| `src/webpent/apex/__init__.py` | package exports + PREAMBLE_LINE |
| `src/webpent/apex/tool_registry.py` | U-APEX-1: ToolSpec, ToolRegistry, vetting |
| `src/webpent/apex/sandbox.py` | U-APEX-2: SandboxConfig, Sandbox, ScopeGuard, backends |
| `src/webpent/apex/executor.py` | U-APEX-3: ExecResult, ToolExecutor, parsers |
| `src/webpent/apex/tool_chain_builder.py` | U-APEX-4: ToolStep, ToolChain, builder + optimizer |
| `src/webpent/apex/parallel_runner.py` | U-APEX-5: parallel dependency-aware runner + speedup |
| `src/webpent/apex/orchestrator.py` | U-APEX-6: AdaptiveOrchestrator brain↔tools loop |
| `src/webpent/apex/tool_selector.py` | U-APEX-7: capability/speed/stealth/history selection |
| `src/webpent/apex/result_fusion.py` | U-APEX-8: FusedFinding, consensus, conflict resolution |
| `src/webpent/apex/speed_optimizer.py` | U-APEX-9: cache, prefetch, adaptive timeout, batching |
| `src/webpent/apex/mcp_server.py` | U-APEX-10: 5 MCP tools, token auth, local-only manifest |
| `src/webpent/apex/dashboard.py` | U-APEX-11: snapshot builder + text renderer |
| `src/webpent/apex/learning.py` | U-APEX-12: bounded outcome ledger, accuracy, improvements |
| `src/webpent/cli/apex.py` | `webpent apex` typer sub-app (preamble + capped audit) |
| `config/apex/tools.yaml` | ≥31 vetted tool entries (9 categories) |
| `config/apex/chains.yaml` | hypothesis-type → chain templates |
| `config/apex/selection.yaml` | selector weights + thresholds |
| `config/apex/ui.yaml` | dashboard sections/limits |
| `tests/apex/test_u_apex_1.py` … `test_u_apex_12.py` | one file per unit, failing-first |
| `tests/apex/test_apex_integration.py` | zero-network socket patch, isolation, advisory-only proof |

Version sync: `pyproject.toml`, `src/webpent/__init__.py`, `tests/test_release_packaging.py`
pin, `CHANGELOG.md`, `README.md`, `docs/vip_autonomous_bug_hunter_traceability.md` → 0.11.0.

## Tasks

### Task 1 (Wave 1) — U-APEX-1 Tool Registry
Files: `tests/apex/test_u_apex_1.py`, `src/webpent/apex/__init__.py`,
`src/webpent/apex/tool_registry.py`, `config/apex/tools.yaml`.
1. Failing tests: load the shipped yaml; ≥31 tools; schema-complete (id/name/category/
   binary/install_command/input_type/output_format/capabilities/speed/stealth/vetted
   on every entry); `find_by_capability` and `find_by_speed` filter correctly; `get`
   raises a named error for unknown ids; `verify_installed` detects a missing binary
   (a never-installed name) without executing anything; categories limited to the 9
   declared ones; every entry `vetted: true` (APEX-L-2).
2. Implement ToolSpec/ToolRegistry per the spec API.
3. Done when: all 6 spec tests + schema/vetting tests green.

### Task 2 — U-APEX-2 Execution Sandbox + ScopeGuard
Files: `tests/apex/test_u_apex_2.py`, `src/webpent/apex/sandbox.py`.
1. Failing tests: DockerSandbox builds a `docker run` argv with `--network`,
   `--memory`, `--cpus`, `--rm`, read-only rootfs and declared volumes — without
   executing docker; LocalSandbox executes an injected backend (no real subprocess in
   tests) with a timeout and captures stdout/stderr/exit code; ScopeGuard rejects a
   command argument naming an out-of-scope host with a named exception, accepts
   in-scope ones, and fails closed on an empty scope; cleanup resets state.
2. Implement per spec API + ScopeGuard (L-3).
3. Done when: 5+ spec tests green; zero subprocess/docker calls in tests.

### Task 3 — U-APEX-3 Tool Executor
Files: `tests/apex/test_u_apex_3.py`, `src/webpent/apex/executor.py`.
1. Failing tests: execute returns a full ExecResult through a fake sandbox; timeout
   path produces exit_code 124 with a `timed_out` flag; parse_output handles jsonl,
   json, xml, and text formats deterministically; exit code captured; unknown tool
   rejected before any execution.
2. Implement per spec API; duration via injected clock.
3. Done when: 5 spec tests green.

### Task 4 (Wave 2) — U-APEX-4 Tool Chain Builder
Files: `tests/apex/test_u_apex_4.py`, `src/webpent/apex/tool_chain_builder.py`,
`config/apex/chains.yaml`.
1. Failing tests: build from hypothesis type maps to the shipped template with
   dependency-linked steps; optimize removes duplicate tool steps and orphans;
   estimated_duration/requests computed from registry speeds; same inputs →
   byte-identical chain (determinism); unknown hypothesis type → an explicit
   fallback recon chain with a stated reason.
2. Implement per spec API.
3. Done when: 5 spec tests green.

### Task 5 — U-APEX-5 Parallel Runner
Files: `tests/apex/test_u_apex_5.py`, `src/webpent/apex/parallel_runner.py`.
1. Failing tests: independent steps run concurrently and the measured wall time of a
   3×(injected 0.1s sleep) chain is under 0.25s (speedup >3x proven, not claimed);
   dependencies are respected (a dependent step never starts before its parent's
   result); max_parallel caps concurrency (observed via a concurrency probe);
   results are ordered by step id regardless of completion order (deterministic);
   estimate_speedup = sum(durations)/critical-path.
2. Implement with ThreadPoolExecutor + topological scheduling, injected runner fn.
3. Done when: 5 spec tests green.

### Task 6 — U-APEX-6 Adaptive Orchestrator
Files: `tests/apex/test_u_apex_6.py`, `src/webpent/apex/orchestrator.py`.
1. Failing tests: orchestrate(decision) → chain built → steps executed via injected
   runner → results collected → learning recorded (full cycle); on_tool_result feeds
   the feedback queue and is visible in get_status; status reflects running/idle and
   chain count; same decision twice → identical result (deterministic).
2. Implement per spec API; fuses results at chain completion (L-6).
3. Done when: 4 spec tests green.

### Task 7 (Wave 3) — U-APEX-7 Tool Selector
Files: `tests/apex/test_u_apex_7.py`, `src/webpent/apex/tool_selector.py`,
`config/apex/selection.yaml`.
1. Failing tests: fastest capable tool wins at neutral context; high
   stealth_requirement flips the ranking toward stealthier tools; every selection
   carries a reason string and ≥1 alternative; selection is deterministic; historical
   accuracy (from the learning ledger) reorders equal-speed tools.
2. Implement scoring = capability(1.0 gate) + weights(speed, stealth, accuracy,
   resource) from selection.yaml.
3. Done when: 5 spec tests green.

### Task 8 — U-APEX-8 Result Fusion
Files: `tests/apex/test_u_apex_8.py`, `src/webpent/apex/result_fusion.py`.
1. Failing tests: fuse groups findings by (vuln_class, endpoint) across tools;
   consensus = agreeing tools / total tools and is <1 when only one tool reports;
   conflict resolution picks the higher-confidence fused finding and records the
   disagreement; confidence weighted by tool accuracy; deterministic output order.
2. Implement per spec API; every FusedFinding marked advisory.
3. Done when: 5 spec tests green.

### Task 9 — U-APEX-9 Speed Optimizer
Files: `tests/apex/test_u_apex_9.py`, `src/webpent/apex/speed_optimizer.py`.
1. Failing tests: cache hit returns the stored result without re-execution (counted
   via probe); TTL expiry with an injected clock; prefetch warms the cache for likely
   chains; adaptive_timeout shrinks for a fast target and grows for a slow one within
   clamps; optimize orders chains by estimated duration.
2. Implement per spec API.
3. Done when: 4+ spec tests green.

### Task 10 (Wave 4) — U-APEX-10 MCP Server
Files: `tests/apex/test_u_apex_10.py`, `src/webpent/apex/mcp_server.py`.
1. Failing tests: manifest lists exactly the 5 spec tools with schemas; dispatch of
   each tool returns a dict carrying the preamble; wrong/missing token is rejected
   (auth enforced, constant-time compare); server declares local-only binding; a
   dispatched apex_tools(category) filters by category.
2. Implement without external deps: registration + dispatch + manifest; the
   networked MCP transport is the operator's deployment concern and stays out of
   this codebase (advisory surfaces only).
3. Done when: 4 spec tests green.

### Task 11 — U-APEX-11 Operator Dashboard + CLI
Files: `tests/apex/test_u_apex_11.py`, `src/webpent/apex/dashboard.py`,
`src/webpent/cli/apex.py`, `config/apex/ui.yaml`.
1. Failing tests: every CLI command (`status`, `tools list`, `tools install`,
   `chain build`, `chain run`, `findings fused`, `dashboard`, `mcp serve`, `learn`)
   prints the PREAMBLE_LINE first and appends a capped audit line; dashboard renders
   all sections from a snapshot; findings fused lists fused results with consensus;
   `tools install` is advisory (prints the vetted install command, executes nothing).
2. Implement mirroring `cli/dojo.py` (typer sub-app, `_emit`, capped audit 1000).
3. Done when: 4+ spec tests green; runner-based smoke of each command.

### Task 12 — U-APEX-12 Continuous Learn Loop
Files: `tests/apex/test_u_apex_12.py`, `src/webpent/apex/learning.py`.
1. Failing tests: chain outcome recorded with redacted paths; tool accuracy needs
   MIN_SAMPLES before a number is returned (no claim before evidence — L-6/L-7);
   best chain for a hypothesis type comes from recorded outcomes; improvements
   suggested from failures; ledger capped; broken/corrupt file loads as empty.
2. Implement per spec API; deterministic.
3. Done when: 4+ spec tests green.

### Task 13 — Integration + zero-network proof
Files: `tests/apex/test_apex_integration.py`.
1. Socket-patched (like the Dojo L-1 proof) full-cycle test: decision → chain →
   parallel run → fusion → learning → dashboard, proving zero network and zero
   subprocess from apex code paths in tests; L-9 advisory proof: no apex module
   imports network/send primitives; state isolation via `WEBPENT_APEX_DIR`.
2. Done when: integration green.

### Task 14 — Version, docs, packaging, final gates
Files: version pins (5 files), CHANGELOG 0.11.0 entry, README status paragraph,
traceability rows (Apex implemented rows + Docker backend blocked row), direct-IO
inventory regeneration if lines shifted, ZIP build + extraction-verify
(target ≥3364 passed = 3164 + ≥200 new), ruff clean on the apex scope.
Done when: fresh full-suite run from the extracted ZIP passes and the count is
monotonic; delivery closed with the standing phrase.
