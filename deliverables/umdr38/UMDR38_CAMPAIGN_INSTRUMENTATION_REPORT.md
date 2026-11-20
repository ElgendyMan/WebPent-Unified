# UM-DR-38 — Campaign Instrumentation Report

Generated: 2026-11-17T12:43:50.732413+00:00 — from the release-revision campaign records.

## The §7.2 repairs (each regression-pinned)

* **A. Monkeypatch lifecycle** — before: the script patched production functions and never restored them, so sequential campaigns in one process stacked wrappers, duplicated tracing and inflated CausalGuard/verification counts. After: the REVERSIBLE `campaign_instrumentation` context manager restores every original by identity in `finally`, and each campaign installs its single layer over the ORIGINALS. Pinned by tests/test_umdr38_campaign_instrumentation.py (exactly one layer; closure references the true original; full restoration; no stacking across two sequential campaigns).
* **B. Authoritative final state** — before: the funnel was computed from a tee'd last-write merge of the update stream (documented as an approximation). After: the ACTUAL final graph state is read via `graph.get_state(config)` while the run context (and its checkpointer) is open — reducers applied by LangGraph. Measured in this release run: 3/3 campaigns authoritative; the merge survives only as an explicitly labeled fallback.
* **E. Cleanup** — the lab server and the out-of-scope origin are closed in `finally`; a failed campaign leaves no running servers and no shared state.
* **F. Redaction** — the recorded invocations carry cookie/session values redacted (synthetic lab credentials; the run itself used the real values).
* **C. Assertions** — every campaign record now carries source_commit, tree_sha, tree_clean, python version, lockfile digest, execution mode, request budget + issued requests, discovered endpoints/candidate resources, observed identities, authorization relationships, hypothesis counts, CausalGuard verdicts (typed `GuardedAdjudication.guard_result.verdict` — recorded as CONFIRMED), ProofBundle ids and replay outcomes — with candidate/awaiting/confirmed kept strictly distinct.

## Measured results (release revision)

| Run | Requests | Confirmed | Guard verdicts | Replay passed | Out-of-scope | Final state |
|---|---|---|---|---|---|---|
| 1 | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 2 | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 3 | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |

All invariants held in all runs: the enforced admin boundary never confirmed, the missing resource never confirmed, public routes never confirmed, the decoy never confirmed, and the out-of-scope origin received ZERO requests (proven from its own request log).

## Phase 5 — one lab version

A single authoritative constant `LAB_VERSION = "1.6.0"` now feeds the lab HTTP response, every per-run record and the combined record (previously 1.5.0 in records vs 1.6.0 in responses). Pinned by a test that serves a REAL lab instance and asserts the served version equals the constant.
