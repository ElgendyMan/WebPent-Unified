# M7_PHASE_REPORT.md — M7 (Executable Knowledge Base / EKG-CG)

**Phase:** M7 of the CANONICAL_PHASE_REGISTRY (Part 4 §9 — P1).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-20.
**Baseline entering:** post-M6 tree (UM-DR-19); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** NONE REQUIRED — the entire phase is a NEW package (`src/webpent/ekg/`) outside the frozen gate. Zero frozen-file changes.

---

## 1. What was delivered

### 1.1 — The typed knowledge item schema (`ekg/schema.py`)

Every registry-named field: category, preconditions, **authorization capability**, tool name + **version pin**, typed **argument schema** (`ArgumentSpec`: string/integer/boolean/enum, required, regex pattern, max_length), **safe execution template**, **expected evidence**, **negative-control procedure**, **validator ref**, **budget** (max_runs + timeout), **cleanup**, **provenance** (author/reviewer/status/action_type).

The structural rule: the safe execution template IS an argv — `list[str]`, literal tokens carry no shell metacharacters (schema-level rejection), and placeholders match the declared arguments BOTH WAYS (undeclared placeholder ⇒ invalid; declared-but-unused argument ⇒ invalid).

### 1.2 — Deterministic validation + argv-typed execution (`ekg/executor.py`)

- `validate_fill` — required/type/enum/pattern/length/undeclared enforcement; coerced output only when the error list is empty. This is the deterministic gate an LLM's (or anyone's) fill must pass.
- `render_argv` — one argv token per placeholder value: a fill like `"; rm -rf /"` stays ONE token (test-pinned).
- `execute_knowledge_item` — the gate chain: validate → **authorization capability** (caller's authorize callback; authorizer errors are fail-closed refusals) → **budget** (per engagement+item+version, max_runs) → the frozen argv-typed `run_command` (list[str]-only, explicit `shell=False`) → best-effort cleanup. Refusal statuses, never exceptions: `invalid_fill` / `authorization_refused` / `budget_exhausted`.

### 1.3 — The lifecycle (`ekg/lifecycle.py`)

- `KnowledgeRegistry` — **version pinning** (`id@version` key; same version + different content refused), latest-wins deterministic lookup.
- Review-gated **release**: human reviewer required, distinct from the author; a NEW action type requires human review; a **regression per template** is mandatory — the deterministic sample fill by default, hand-written `RegressionSpec` for pattern-bearing items (the sample cannot know their patterns — the release refuses honestly without one).
- `assert_registry_regressions` — re-runs every recorded regression (argv equality against the recorded expectation): an in-place template edit that bypasses version discipline is CAUGHT (test-pinned).

### 1.4 — Zero arbitrary LLM shell execution (the acceptance)

Structural, three ways: (a) the schema has no string-command field anywhere; (b) the executor's only runner interface is `list[str]` (the frozen wrapper type-rejects everything else); (c) a package-wide source test pins the absence of `os.system` / `shell=True` / `subprocess.run(` / `Popen(` / `os.popen`. An LLM that "selects action + fills typed schema" can produce nothing outside a validated argv.

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §9) | Status |
|---|---|
| typed knowledge item schema (all 12 named fields) | **delivered** (§1.1) |
| no LLM arbitrary shell; LLM selects + fills, deterministic code validates | **delivered + structurally tested** (§1.2, §1.4) |
| knowledge lifecycle (versioning, review, regression per template, human review for new action types) | **delivered** (§1.3) |
| zero arbitrary LLM shell execution (structural enforcement + test) | **delivered** (§1.4) |
| every executable template regression-tested | **delivered** (release refuses without a regression; assert runs them all) |

Deferred with owners: migrating the existing descriptive RAG knowledge packs into typed items → a content-migration window (the schema/registry are the engine); the LLM selection loop itself → behind the Charter §4.1-style qualification discipline (same posture as M3's gate).

## 3. Gate evidence at closure

- **Tests:** `tests/test_m7_executable_knowledge.py` — 17 passed.
- **Frozen-module gate:** 661 passed (no frozen changes).
- **Test-count gate:** 8,469 ≥ floor 8,115.
- **Authority manifest:** untouched (13 files).

— End of M7_PHASE_REPORT.md —
