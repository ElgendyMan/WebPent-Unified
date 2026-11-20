# UM-DR-38.1 — Acceptance Integrity Report (Phase 4)

Generated: 2026-11-17T04:58:58.439794+00:00.

## The reported defect and its fix

The UM-DR-38 published matrix carried `G38-07: exit_code = 1` with `status = PASS` — the generator hardcoded the status while computing the exit code. The fixed generator derives EVERY status through one canonical rule (exit 0 -> PASS; exit != 0 -> FAIL; not run -> NOT_RUN; genuine external dependency -> BLOCKED), aggregates G38-07 over all 13 mandatory gates and G38-12 over the security set (any member failure = FAIL), computes the counts from the matrix elements, and REFUSES with a non-zero exit while FAIL or NOT_RUN gates exist. Regression tests pin exit 0/1/2/null/blocked and the exact defect: G38-07 cannot be PASS when ruff-ratchet exits 1.

## Current matrix consistency

* recorded counts: {"PASS": 30, "BLOCKED_EXTERNAL_DEPENDENCY": 2}
* recomputed from elements: {"PASS": 30, "BLOCKED_EXTERNAL_DEPENDENCY": 2}
* consistent: **True**
* G38-07: status **PASS** with exit_code 0 (aggregate over the 13 mandatory gates)

## Final decision (computed, not chosen)

**COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED** — from the decision rule in scripts/umdr38_closure.py (_final_decision), never because the work took long.
