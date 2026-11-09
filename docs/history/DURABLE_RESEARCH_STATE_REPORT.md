# TEAM-1 — HALF 2: OPERATIONAL MEMORY + DURABLE RESEARCH STATE + LONG-HORIZON + CROSS-TARGET REPORT

**Status:** IMPLEMENTATION COMPLETE. **285 tests pass, 1 skipped (API deps). 0 failures.**

---

## FILES CHANGED (this milestone)

### NEW (2)
| File | Purpose |
|------|---------|
| `src/webpent/production/campaign_state.py` | `CampaignState` — durable, versioned research state (agenda, decisions, outcomes, findings, budget). Atomic persist/load. Version check — unknown versions fail safe. |
| `src/webpent/production/campaign_worker.py` | Subprocess entry point: `python3 -m webpent.production.campaign_worker <state_file> <cycle>` — runs ONE research cycle in a fresh process, crosses REAL process boundary. |

### NEW TESTS (1)
`tests/team1_acceptance/test_durable_research_state.py` — 17 tests.

---

## PART 11/12/13 — REAL PROCESS-BOUNDARY CAMPAIGN (CRITICAL)

**Verified via `subprocess.run()`** — multiple distinct PIDs, not same-process references.

- **Process A**: cycles 1-2 → persist → terminate
- **Process B**: load → cycle 3 → persist → verify continuity
- Final state: `cycle=3`, `decisions=3`, `outcomes=3`, no loss, no repeat
- **Partial resume**: persist after cycle 1 → restart → cycles 2-3 → cycle 1 preserved
- **Version mismatch**: `incompatible_v999` → `CampaignStateError` (fail safe, no silent reinterpretation)
- **Corrupted state**: invalid JSON → `CampaignStateError`

---

## PART 3/4 — MEMORY RELEVANCE + CAUSAL ABLATION

- **A. Relevant memory**: changes priority (`/api/health` → `/api/orders`)
- **B. Irrelevant memory**: no influence on target-irrelevant query
- **C. Stale/conflicting**: advisory_only, trust_level=untrusted_advisory
- **D. Memory cannot manufacture proof**: `is_authority()=False`, `usage_constraint=may_influence_ranking_only`

---

## PART 16/17/18 — CROSS-TARGET GENERALIZATION

- **Target A**: REST-style (`/api/users`, `/api/orders`) — loopback server
- **Target B**: GraphQL-style (`/graphql`, GET+POST) — structurally different
- Both targets: real execution → observation → outcome → replan
- **Cross-target memory isolation**: Target A memory remains advisory for Target B, no authority leak

---

## PART 20 — A/B TRAJECTORY DIVERGENCE

High-info observation → `promising_relationships` → hypothesis h1 prioritized.
Low-info observation → `rejected_hypotheses` → h1 rejected, h2 selected.
Different early observation → different selected hypothesis (stateful, not fixed script).

---

## PART 22 — REFUTATION ACROSS RESTART

Positive (supported) → persist → restart → contradictory observation → refuted → persist → reload → refuted persists (no resurrection).

---

## PART 25 — BUDGET/TERMINATION

- `max_cycles` reached → terminal
- `deadline` exceeded → terminal
- `max_experiments` reached → terminal
- No infinite loop — explicit terminal states

---

## PART 28 — NO-FAKE-AUTONOMY AUDIT

- Decision logic consumes `promising_relationships` + `rejected_hypotheses` (not static map)
- Agenda mutations consumed by selection priority
- WorldModel writes consumed (entity_count changes → research decisions)
- Memory advisory-only, never authority

---

## PART 29 — VERSIONING

`state_version = "campaign_state_v1"`. Mismatch → fail safe.

---

## REGRESSION: 285 passed, 1 skipped (API app extra deps). 0 failures.

## REMAINING UNPROVEN (explicit)
- Full 3+ cycle campaign with real network targets (loopback only demonstrated)
- Cross-target memory generalization beyond advisory projection
- Process-restart with full ProofBundle replay (state continuity demonstrated, proof replay in HALF 1)
- Production deployment durability (SQLite demonstrated, not full production DB)
