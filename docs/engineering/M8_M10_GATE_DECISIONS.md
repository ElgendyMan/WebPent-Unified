# M8_M10_GATE_DECISIONS.md — the optionality/dependency gate decisions (2026-11-06)

---

## M8 — MCP Client & MCP Server (P1/P2, OPTIONAL): NOT EXECUTED — gate not met

**Part 4 §10 defines M8 as optional.** The decision record:

1. **What exists and is verified:** `apex/mcp_server.py` (241 LoC) — the dispatch server with token auth (sha256-hashed token comparison) and a STRUCTURAL loopback-only bind (non-loopback binds raise at construction). The apex suite — 160 tests — passes (re-verified in this window), covering the server's security posture. "CLI/API works with zero MCP present" is true by construction: nothing in the CLI/API path imports MCP.
2. **What M8 would build:** the MCP CLIENT (allowlisted servers, schema validation, per-server capabilities, authz per action, budgets, untrusted-server posture) and the malformed/oversized/spoofing/injection corpus.
3. **Why the gate is not met:** no operator integration demand is recorded — there is no MCP consumer in the deployment model, no allowlist of operator MCP servers, and the existing adapters (the primary integration surface) remain the working path. Part 4 §10's own ordering puts MCP behind a provider interface "as an integration standard" — a standard needs adopters, and none are recorded.
4. **Reopening conditions:** an operator registers MCP servers for an engagement (the M2 manifest vocabulary extends with an MCP allowlist section) AND the roadmap prioritizes the client above the 0.34.2 cleanup window's recorded backlog.

Nothing depends on M8 (the registry lists M2 as its only dependency-in, no dependents-out).

---

## M10 — Remediation Assistant & Pull Requests (P2): BLOCKED by its own dependency — discovery quality not yet stable

**Part 4 §12: "from confirmed Finding to reviewed PR, only after discovery quality stabilizes" and the registry's dependency: "M11 (discovery quality stable) — per Part 4 ordering."**

**The measured evidence (M11's closure rollup, `reports/qualification/weekly_*.json`):**

* the deterministic hypothesis engine's label is **lab_qualified** — NOT production_qualified;
* the recorded blind_v3 baseline: recall **0.137**, precision 0.6667 (120 cases);
* the Charter §4.1 gate refuses budget expansion for any producer below recall 0.5 ∧ precision 0.7.

**The decision:** building the confirmed-finding→patch→retest→PR workflow NOW would violate M10's own precondition — the workflow's value proposition (regression tests that reproduce pre-fix behavior, retests that prove closure) presumes the findings feeding it are stable enough to remediate. At a measured 0.137 recall with the engine honestly labeled lab_qualified, that presumption does not hold; auto-generated remediation PRs against unstable findings would manufacture rework and erode the human-review contract M10 itself mandates.

**Progress toward reopening (UM-DR-25, 2026-11-06 — recorded, not claimed):** the recall program's first engineering step is delivered: diagnosis showed the 0.137 is largely a PROBING-METHODOLOGY ceiling (3 GETs cannot observe the 80 state-transition cases — the entire reasoning + compositional families), and the deterministic stateful prober (`production/stateful_probe.py` + the same-spec replica `benchmarks/blind_v3_replica/`) lifts the replica-corpus measurement to recall 1.0 / precision 1.0 at 13.2 requests/case with `guarded_causal_evaluate` remaining the only confirmation authority. This is a REPLICA-CORPUS measurement by an author who knows the spec — it advances the lab evidence, NOT the production label: the reopening conditions below are unchanged until an operator-deployed holdout measures the prober on a target whose transition grammar it did not author.

**What exists and is preserved:** the `remediation/` advisory package (14 files) — pattern database, advisory remediation text — remains wired as advisory output.

**Reopening conditions (any one):**

1. the discovery engine's measured label reaches **production_qualified** on the M11 ladder (per-family metrics + blind holdout + zero-FP deception, on operator-deployed corpora), OR
2. an operator explicitly scopes a remediation engagement against a manually-curated confirmed-finding set (human-confirmed findings bypass the discovery-stability question), with the workflow's mandatory human review intact.

— End of M8_M10_GATE_DECISIONS.md —
