# UM-DR-46 — Phase 0 closeout (P0.1 → P0.5)

Starting point: `main` = `v0.44.0` = `umdr45-convergence` = `7f3807a`
(verified by `git ls-remote` at mission start: HEAD/main and both tags
resolve to `7f3807a214d8748a687f4759d6d05625564ec098`). Work branch:
`feature/umdr46-ultimate-researcher-brain`. All work in this window is
local until the owner delivers the `actions:write` token (mission §0.5
token law) — push count so far: **0**.

Status vocabulary per KB §9 (PASS/FAIL/SKIPPED/BLOCKED/NOT_RUN/
NOT_VERIFIED/PARTIAL).

---

## P0.1 — open PR #1 (`security/umdr34-origin-scope-hardening`) — PASS

**Decision: CLOSE (not merge), with the branch preserved as its archive
tag. Owner signature required to execute the close on GitHub (token
pending).**

Evidence (content-level diff verification, this window):

* The branch is 5 commits ahead / 70 behind `main` (merge-base
  `989c49b`).
* `deliverables/umdr45/patch_id_equivalence.json` classifies all 5
  commits as `UNIQUE_PATCH` with `trunk_commits: []` — never merged by
  patch-id; the repo's own release notes state the content reached the
  trunk via the restructured `WebPent_UNIFIED/` upload commits.
* Per-commit content verification against today's `main`:
  * `4795f02` (UMDR-33 start) — **absorbed**: all 7 umdr33 docs
    byte-identical; all 6 test files + scripts present on main.
  * `94f17d9` (v0.40.0 UMDR34) — **absorbed**: all 10 umdr34 docs
    byte-identical; scope package on main is the branch version plus
    the later UM-DR-44 B1 fix (strictly stronger).
  * `699c177` (reject ambiguous paths and port zero) — **absorbed
    byte-identical in logic**: `src/webpent/shared/engagement_scope.py`
    (`_AMBIGUOUS_PATH_TOKENS`, 8-round bounded re-decode, port
    `is None` contract with `1..65535` validation) + both regression
    tests (`tests/test_v63_vip_security_regression.py` ambiguous-path
    and port-zero tests, 0/0 diff) + a SECOND stronger enforcement
    layer the PR never had (`scope/authority.py` two-argument
    `_path_is_ambiguous` deny reason `scope_path_ambiguous`).
  * `1556900` (CI runner pin ubuntu-24.04) — **absorbed**: main's
    `.github/workflows/ci.yml` pins `runs-on: ubuntu-24.04` on both
    jobs, same comment.
  * `2d107b4` (lockfile sync 0.40.0) — **superseded**: main is
    `pyproject 0.40.1 == uv.lock 0.40.1` (a later in-sync state); the
    desync the commit fixed does not exist on main.
* Merging a 70-behind branch would regress the trunk; the content is
  already fully there. The branch itself is preserved as tag
  `archive/security-umdr34-origin-scope-hardening-155690053341`
  (archive-never-delete policy).

**Action pending token:** close PR #1 with a comment referencing this
section.

## P0.2 — RC-8 / RC-9 / RC-10 — PASS (decisions recorded)

Read on the trunk (register of record:
`deliverables/umdr39/ROOT_CAUSE_REGISTER.md`; status trail in
`deliverables/umdr45/D_TRACK_REGISTER.md` §D4 — RC-8/9
PARTIALLY_COMPLETE, RC-10 NOT_STARTED owner-decision):

* **RC-8 (rabbit-hole stopping — per-branch new-evidence delta) →
  FOLDED into Phase F + Phase I.** The four bounded axes exist and are
  enforced; the register's own unmet acceptance (a measured
  stop-decision when a branch produces no new evidence) becomes the
  Phase C explored-space counting gate ("no repeated test without new
  information — measured") and the Phase I QC metric ("requests
  without knowledge gain"). The fold is faithful: same acceptance
  criterion, now with a measured gate.
* **RC-9 (four divergent knowledge models) → FOLDED into Phase A/B
  with the decision recorded: `knowledge/target_knowledge.py` v1
  RETIRES to an AppModel projection.** Phase A makes the Security
  Knowledge Graph the contradiction-preserving SSOT (extend-not-
  rewrite: the AppModel already preserves contradictions and gates
  confidence by provenance — `appmodel/models.py`); v1 becomes a
  read-only projection instead of a competing overwrite-on-conflict
  store. Zero data loss, one authority.
* **RC-10 (orphaned autonomous stack: hunt_orchestrator /
  hunt_runtime / hunt_discovery / ScopedHuntMemory) → REMAINS an
  owner entry-point decision.** Recommendation recorded: wire the
  stack only if Phase F's autonomous-experimentation loop requires its
  primitives; otherwise classify it formally as library-complete
  dormant (the B10 pattern already provides the structural gate
  pattern for documented-dormant units). Not promoted, not deleted.

## P0.3 — the 5 unwired agents (44/5 map) — PASS (executed)

Decision record: `deliverables/umdr45/agent_decision_register.json`
(54 units: 44 KEEP wired / 8 KEEP-DORMANT / 2 RETIRE-CANDIDATE).
Executed per the mission's "zero pending" with the owner's blanket
execution order as the signature (commit `043b512`):

| Unit | Register decision | Execution in this window |
| --- | --- | --- |
| `agents/specialists/` (passive_planner) | RETIRE-CANDIDATE, zero importers | **REMOVED** — zero importers re-verified (src/tests/scripts, incl. string/dynamic reference scan; only historical audit JSON artifacts mention the path); advisory-only module (proposals, no execution/authorization/promotion authority); full content preserved at tag `umdr45-convergence` |
| `agents/team.py` | RETIRE-CANDIDATE, zero importers | **REMOVED** — same verification; advisory-only role-contract registry |
| `agents/tenant_isolation/` | KEEP-DORMANT, 1 test importer | **FOLDED into Phase A/J** — tenant/identity confusion becomes a first-class SKG query surface (the battery's `tenant_confusion` family measures the gap it will close) |
| `agents/chain_planner/` | KEEP-DORMANT, B10 documented RETAIN | **NO CHANGE** — B10 decision already executed and structurally gated (`tests/test_umdr44_b10_wrapper_decision.py`) |
| `agents/oauth_hunter/` | KEEP-DORMANT, B10 documented RETAIN | **NO CHANGE** — same B10 gate |

## P0.4 — GOVERNANCE_INDEX + LICENSE — PASS

* `deliverables/umdr46/GOVERNANCE_INDEX.md` created: the UM-DR-33 →
  UM-DR-46 decision index with durable proof anchors (tags, JSON
  registers, code, tests, ZIP paths), companion to the UM-DR-45
  authorities map. Note: the mission brief stated "GOVERNANCE_INDEX
  does not exist"; the UM-DR-45 window had in fact delivered an
  authorities-map governance index (`deliverables/umdr45/
  GOVERNANCE_INDEX.md`). The 46 index adds the per-mission decision
  layer and cross-references it — no duplication.
* LICENSE (owner decision: MIT confirmed): repo-root `LICENSE`
  verified as the canonical MIT text ("Copyright (c) 2026 WebPent
  Team"); `WebPent_UNIFIED/pyproject.toml` declares
  `license = { text = "MIT" }` — consistent. Open item flagged for the
  owner (KB §5.7): the placeholder contact
  `security@example.com` in package metadata awaits owner-approved
  replacement.

## Documentation cleanliness law — PASS (commit `4f8ba58`)

All 117 legacy `umd*.md` files (UMDR-29 → 44 windows) removed from the
working tree; archived copies complete inside the `umdr45-convergence`
release ZIP (`umdr45-docs/`) and in git history. Verified before
deletion: zero executable references (no test, CI step, Makefile
target, or CI-run script reads any `umd*.md`); all `.json` evidence
files the CI gates read (BUILD_INFO honesty-gate input, acceptance
matrices, umdr43c outputs) intentionally preserved.

## P0.5 — BASELINE BENCHMARK — see `BASELINE_REPORT.md`

The critical gate: the trunk measured AS SHIPPED before any Phase A+
code. Six family labs × vulnerable/secure × 3 campaigns through the
official entrypoint, cookie-authenticated, subprocess-isolated,
ground-truth-scored. Numbers, per-family tables and honest notes:
`BASELINE_REPORT.md` (generated from `BASELINE_METRICS.json`).

Notable context for reading the baseline: the UM-DR-45 window DID
execute an X-track benchmark (`deliverables/umdr45/X_TRACK_BENCHMARK.
json`) — the mission brief's "zero measurement numbers ever" premise
was outdated on that point. The 45 X-track measured battery A (CLI
surface on labsuite targets) at recall 0.0 with the query-param
authentication wiring gap documented by measurement, and battery B
(the internal labsuite engine) at precision/recall 1.0. The 46
baseline removes the authentication confounder (cookie channel) and
extends coverage to the six mission-named families — it is the
baseline every Phase A+ improvement will be measured against.

## What remains open / residual risks

1. **Push blocked on the `actions:write` token** (mission §0.5 law):
   all commits are local on the feature branch; PR #1 close + branch
   push + 3-green gate await the token. Pushes so far: 0.
2. Phase A+ implementation (SKG, researcher brain, hypothesis engine,
   …) — designed in the mission, not started in this window.
3. The in-process campaign-degradation observation (recorded in
   `BASELINE_REPORT.md` honest notes) is queued for the Phase I QC
   agenda.
4. Placeholder contact `security@example.com` awaits owner-approved
   replacement (P0.4 open item).
