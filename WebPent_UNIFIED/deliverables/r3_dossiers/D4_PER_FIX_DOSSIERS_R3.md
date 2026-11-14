# R3 PER-FIX DOSSIERS (D4) — Ruling R3-002, Dispatch #005

One dossier per ruling item. Each maps: ruling clause → diff → tests.
Commits are independently revertable (C3). All claims re-runnable per D1.

---

## DOSSIER E-1 — OOB advisory demotion (commit a42d005; completions in a3420bc, 58c-window)

Ruling clauses (§3.2) → implementation:

| Clause | Requirement | Landed as |
|---|---|---|
| 3.2(i) | valid token → ADVISORY record; never seal ProofBundle; never touch confidence | `_oob_db_lookup_and_record_advisory` (api/app.py) — ProofBundle construction + `_OOB_CONFIRMED_MARKER` + `mark_oob_confirmed` call REMOVED; calls `db.append_oob_advisory_evidence` |
| 3.2(ii) | RF-03 MANDATORY HUNK: parity check validates advisory state | api/app.py handler tail: 204 ⇔ correlated advisory record exists; loud 500 if advisory missing; loud 500 if Tool-Confirmed observed (unauthorized-mutation alarm) |
| 3.2(iii) | RF-04: replay-idempotent, dedupe by correlation token | `append_oob_advisory_evidence`: token-keyed dedupe inside `BEGIN IMMEDIATE`; repeat → `("duplicate")`, no second record, idempotent 204 |
| 3.2(iv) | Finding model additive/optional/default-empty/authority-neutral; extra=forbid stays | `Finding.advisory_evidence: list[dict[str, Any]] = Field(default_factory=list)` (models/findings.py) |
| 3.2(v) | db.py advisory sibling; no confidence mutation; transactional; malformed → no partial writes | `DatabaseManager.append_oob_advisory_evidence` — single-statement write surface (`UPDATE findings SET advisory_evidence = ?` only), `_write_lock` + `BEGIN IMMEDIATE` + rollback on error; contract validated BEFORE any write opens (TypeError/ValueError → nothing written) |
| 3.2(vi) | both layers compose; default-off route flag RETAINED | `_reject_if_oob_confirm_route_disabled` untouched; composition proven by matrix tests (flag OFF → fail-closed zero-DB; flag ON → advisory + unchanged authority) |
| 3.2(vii) | Amendment A: stale handler docstring updated in the same diff | `_oob_db_lookup_and_record_advisory` + `_reject_if_oob_confirm_route_disabled` + `receive_oob_callback` docstrings rewritten honestly (removed semantics kept auditable in R2 dossiers) |

Persistence shape: `advisory_evidence TEXT NOT NULL DEFAULT '[]'` column
(DDL + PRAGMA-guarded legacy ALTER + alembic 0005 + INSERT/SELECT
round-trip). Clobber-safety: `save_finding` unions persisted records by
correlation token (V10 P1-10 class protection) — a stale in-memory
snapshot cannot drop persisted advisory records.

Tests: T-04/T-05 markers removed in the same commit (R4); Amendment C
fixture fix (`save_finding` returns None — R2-V NF-04). New matrix
`tests/test_r3_e1_advisory.py` (10 tests): 204 parity (RF-03), idempotency
(RF-04), invalid-token zero-writes, malformed → handled 400 + no partial
state, flag OFF/ON composition, consumer-neutrality static trace
(advisory_evidence referenced ONLY by model/db/demotion handler), and the
hardened T-05 inventory as a composition assertion.

Known consequence (registered for M2, validator NOT thawed): the frozen
validator poll `_poll_for_oob_callback` waits for `Tool-Confirmed` and now
times out by design; OOB validation outcomes surface as advisory records
only (C6-listed parity test documents this).

---

## DOSSIER E-2 — builder-level fail-closed rejection (commit 89330a0)

Ruling clauses (§3.3) → implementation:

| Clause | Requirement | Landed as |
|---|---|---|
| §3.3 | earliest composition point ALL entry surfaces traverse REJECTS when spine mode resolves disabled | `build_graph` (graph/builder.py) raises `UnsupportedLegacyOnlyModeError` before `StateGraph(...)` composition, with operator-visible SDD §8 rollback text |
| §3.3 | no legacy-only continuation on any path | rejection precedes graph construction — no surface can compose or run legacy-only |
| §3.3 | node-level raise stays as defense-in-depth | modern_spine_integration.py node raise UNTOUCHED (sub-scope compliance) |
| §3.3 | default-enabled path regression-tested vs baseline | `tests/test_r3_e2_builder_rejection.py::test_default_enabled_path_regression_vs_baseline` + full suite (3131 pass) |
| §3.3 | SDD §8 rollback-flag independence asserted | fresh-interpreter test: `WEBPENT_MODERN_SPINE=0` → COMPATIBILITY_LEGACY with `MODERN_SPINE_ENABLED=True` (composition unaffected); `UNSUPPORTED_LEGACY_ONLY` → disabled (RED-1 P-3.2 re-asserted) |

All entry surfaces verified: rejection parametrized over the four surface
modules binding `build_graph` (builder, cli.commands, workers.pentest_worker,
api.app). T-06 marker removed in the same commit (R4) — the hardened net
(AST raise-node + comment-stripped substring) passes on the fixed tree.

---

## DOSSIER E-4 — entrypoint truthfulness, mechanism (b) (commit 83447b8; probe artifact scripts/e4_probe_d3.py)

Mechanism decision record: D3_E4_PROBE_REPORT.md (probe P1 falsified
option (a) — LangGraph drops undeclared input keys, so state-threaded
entrypoints cannot reach the node and PentestState is frozen; option (c)
was already removed by the ruling after RED-1 falsified its premise).

Ruling clauses (§3.4) → implementation:

| Clause | Requirement | Landed as |
|---|---|---|
| 3.4(i) | PROBE FIRST, documented | scripts/e4_probe_d3.py + work/r3_evidence/D3_* (P1 real-graph crash + undeclared-key drop; P2 in-process drift raises; P3 cross-process invisible; P4 surface detectability) |
| 3.4(ii) | mechanism (b): explicit env var at editable orchestration surfaces + fail-closed derivation in the node | `WEBPENT_ENTRYPOINT` set by worker.py→"worker", server.py→"api", webpent-cli.sh→"cli" (all EDITABLE root surfaces, verified not in the 695 manifest); frozen call sites untouched |
| 3.4(ii) | priority truthful > derivable > fail-closed; NEVER a silent wrong-label fallback | `_derive_entrypoint`: explicit state value (KNOWN_ENTRYPOINTS-validated) → env var (validated) → `python -m webpent.cli` __main__ derivation → loud `ProductionSpineError`; the `or "direct_invoke"` fallback REMOVED (pinned by `test_silent_fallback_is_gone`) |
| 3.4(ii) | node's existing spine-disabled raise untouched | yes — only the entrypoint derivation lines changed (sub-scope met) |
| 3.4(iii) | in-process drift registry limitation documented | D3 P2/P3; carried into EIR v7 known limitations + M2 register |

Tests: `tests/test_r3_e4_entrypoint.py` (9 tests): per-surface verbatim
labels (cli/api/worker/direct_invoke), state-pinned priority, unknown
state/env fail-closed, -m derivation, underivable rejection, fallback-gone,
launch-surface wiring. T-03 updated to the truthful-label contract (rider
R4); T-03b (hardened, real) unchanged — the env var is not a state setter.
Harness honesty: conftest declares the test process's truthful label
("direct_invoke" — tests DO invoke nodes directly in-process).

C8 note: the g02 dynamic-resolution identity SET and ORDER are unchanged
(the derivation uses direct attribute access; the two pre-existing
getattr(updated, ...) sites keep their relative positions); the recorded
artifact was regenerated via the documented v4 line-drift regen only.
