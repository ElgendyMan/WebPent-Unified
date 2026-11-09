# D-J — P7 ROOT-CAUSE REPORT (NF-L0-01)

**Sprint:** M2-impl — window REOPENED per Dispatch #009-A (Amendment A1, P0 escalation intake)
**Work package:** WP-J (mandatory; completes before WP-I and before window close)
**Finding:** NF-L0-01 — Silent incomplete-chain success (exit 0 with `production_trace.complete=false`)
**Status:** ROOT-CAUSED — Interpretation **B** settled with local reproduction evidence
**Zero external-target interaction; all targets are local synthetic stand-ins.**

---

## 1. The manifestation

Lab observation (LCS-0, P7 — a single documented hunt attempt against an
in-scope local target):

- Process **exit code 0**;
- `production_trace.complete = false` in the run's artifacts;
- Expected: a loud spine failure. Actual: silent zero-exit with an
  incomplete trace.

## 2. Local reproduction (WP-J(a)) — SUCCESS

The exact lab command shape was replayed locally:

```
webpent.cli hunt --target http://127.0.0.1:8977 \
    --scope scope.yaml --engagement-id p7repro-01 \
    --artifact-root artifacts/p7repro-01 --time-budget 180 ...
```

Reproduction environment (harness mirrored to `scripts/m2a_p7_repro/`,
evidence in `deliverables/m2a_evidence/p7/`):

- **Synthetic local target:** static HTTP server on `127.0.0.1:8977`
  (`target_server.py`) — in-scope per the program-scope file `scope.yaml`
  (parsed by the real `webpent.scope.parser`; scope enabled, not halted).
- **LLM stand-in:** a local OpenAI-compatible endpoint
  (`fake_llm_server.py`) registered through the normal LOCAL provider
  settings (`local_llm_url`/`local_llm_api_key`/`local_llm_enabled`) — the
  same configuration surface a real deployment uses. The endpoint was
  never reached for I/O; the run's LLM budget was consumed by planner/
  advisory accounting (`stderr: "LLM call budget exhausted before provider
  I/O: calls=6 max=6"`), driving the hunter into its **documented
  planner-fallback path** (`planner_output_invalid` → `planner_fallback`,
  recorded as named graph events).

Observed result — **identical in shape to the lab P7**:

| Field | Value |
|---|---|
| exit code | **0** |
| `production_trace.complete` | **False** |
| `missing_required_stages` | `world_model_mutation, research_decision, bounded_tool_execution, observation, outcome_recording, causal_guard_evaluation, proof_bundle_creation, promotion_decision` (8 of 12) |
| `stages_seen` | `audit_event, audit_finalization, deep_recon, entrypoint_resolve, flag_resolution, replan, spine_activation` |
| candidates | 6 generated / 1 executable / 0 confirmed |
| graph events | 26 (hunter graph ran to normal completion) |
| exceptions on the path | **none** (see §4) |
| operator summary | printed as JSON by the CLI; campaign_summary.json written |

The run is, from every component's perspective, a **normal completion**.

## 3. Root cause (WP-J(b)) — the completion gate does not exist

### 3.1 Intended semantics of the trace

`src/webpent/production/production_spine.py`:

- `:234-243` — `ProductionTrace` docstring: *"The final trace digest
  proves the chain executed end-to-end. **Missing stages → trace
  incomplete.**"*;
- `:274-280` — `required_stages()`: 12 stages
  (`entrypoint_resolve, spine_activation, deep_recon, world_model_mutation,
  research_decision, bounded_tool_execution, observation,
  outcome_recording, replan, causal_guard_evaluation,
  proof_bundle_creation, promotion_decision`);
- `:281-286` — `is_complete()` computes `(complete, missing)`;
- `:294-307` — `summary()` embeds both faithfully.

The trace machinery is honest. The defect is downstream.

### 3.2 Where `complete=false` is written (and ignored)

`src/webpent/agents/hunter_runner.py` — `run_hunter_campaign`:

- `:661-662` — constructs `ProductionSpineConfig(engagement_id=…,
  target_url=execution_target, entrypoint="direct_invoke")` and resolves
  the spine via `resolve_production_spine(config)`;
- `:683-688` — records `deep_recon` after the governed crawl;
- `:816-855` — `exploit_callback` is the **only** driver of the
  orchestrator's validation loop (`orchestrator.
  run_autonomous_validation_campaign(…)` at `:832`, followed by
  `_sync_observed_production_trace` at `:833`). It runs only when the
  hunter graph's planner emits a decision that maps into the governed
  candidate catalog with budget remaining;
- `:897-911` — the hunter graph completes; a final trace sync;
- `:1029-1068` — the `summary` dict is built; `"production_trace":
  production_trace.summary()` is embedded at `:1066`;
- `:1069-1076` — `campaign_summary.json` written; the function **returns
  the summary unconditionally**. There is **no** `is_complete()` consult
  anywhere between trace population and return.

`src/webpent/cli/commands.py` — `hunt` (`--target` branch):

- `:1279-1291` — the try/except around `run_hunter_campaign` is LOUD
  (`Hunter campaign blocked: …` + `typer.Exit(1)`); **it never fired** in
  the reproduction because nothing raised;
- `:1292-1293` — `console.print_json(result["summary"] …)` then `return`
  → Typer exits **0**.

**Root cause statement:** the exit-0 site is
`cli/commands.py:1292-1293`; the incomplete-trace fact is computed and
carried faithfully (`production_spine.py:294-307` →
`hunter_runner.py:1066`) and then **consulted by nobody**. There is no
exception-swallowing wrapper on this path — the run is a legitimate,
crash-free completion whose chain never executed its validation loop. The
honesty defect is a **missing completion gate**, not a swallowed
exception.

### 3.3 Why 8 of 12 stages were missing

The orchestrator's validation loop is the sole generator of the missing
stages (`world_model_mutation` … `promotion_decision`). In the
reproduction, the LLM budget was exhausted by planner/advisory accounting
before any governed decision was dispatched, so `exploit_callback` was
never invoked, so `run_autonomous_validation_campaign` never ran, so the
trace recorded only the recon-stage prefix. The lab's run reached the same
terminal state (whatever route its planner took to "no governed decision
dispatched"); the defect and the fix are identical either way.

### 3.4 The scan path is the same class (WP-J(b) sweep input)

A `webpent.cli scan --url http://127.0.0.1:8977 --no-llm --skip-recon`
replay completed with **exit 0** and the green **"Engagement Completed"**
panel while emitting **zero** chain-state information on any operator
stream (no trace, no campaign-lane status; the WP-E skip warning did not
fire because the lane did not take the instrumented skip path). The
consumer-side chain-state check is absent on the whole CLI operator
surface (`hunt --target`, `scan` full-graph, `scan --adapter-free`) —
folded into WP-I's fix scope.

## 4. Interpretation settled (WP-J(c)) — **B, with a refinement**

**Interpretation A** (spine failed as diagnosed — NF-M2-01 transport
death — and an exception-swallowing wrapper converted it to exit 0) is
**REFUTED for the P7 path**:

1. No exception was raised anywhere on the reproduced path — the CLI's
   own loud catch (`commands.py:1289-1291`) never fired; the hunter
   graph's documented advisory fallbacks (`hunter_graph.py:273, 372, 404,
   486`) each record a named event and none swallowed a failure because
   none occurred;
2. NF-M2-01's mechanism does not apply here: the hunt `--target` path
   **never enters the graph campaign lane and never reads
   `_modern_orchestrator` from state**. It resolves the spine directly
   through the shared factory (`hunter_runner.py:661-662`). The
   transport-death diagnosis concerned the compiled-graph campaign lane —
   a different surface that WP-B/WP-C already repaired.

**Interpretation B** is **CONFIRMED**: the operator surface reaches the
spine through a path the audit series never covered — the hunter runner
is a **direct spine consumer** (`entrypoint="direct_invoke"`), running
its own bounded graph (`run_hunter_graph`), not the compiled 35-node
graph. The spine **ran** (entrypoint_resolve + spine_activation +
deep_recon recorded), and the trace is incomplete **for another reason**:
the validation loop legitimately never executed, and **no component on
the operator path treats "trace incomplete" as a failure**.

Refinement to B's wording: nothing was swallowed — the operator surface
never *looked* at the chain state in the first place. This makes the fix
strictly additive (consumer-side gate), with no thaw of the runner
required.

## 5. Escalation (WP-J(c) mandate) — missed production path

Per WP-J(c), Interpretation B requires an immediate escalation:

1. **Missed production paths (confirmed, evidence above):**
   - `agents/hunter_runner.py` (`hunt --target`) — direct spine consumer,
     outside the M1/M2/RED-2 audit-series coverage (which covered the
     compiled-graph campaign lane);
   - `production/autonomous_recon.py:89,206` (`scan --adapter-free`) —
     same class, same gap;
   - `workers/pentest_worker.py` — drives the *covered* graph, but its
     completion status (`status="completed"`) ignores chain markers — the
     same honesty gap with a different mechanism.
2. **Thaw impact:** NONE for WP-I. The exit-code gate lives at the
   CLI/worker boundary — exactly the conditional grant of WP-I(c).
   `hunter_runner.py` and `autonomous_recon.py` remain frozen; their
   summaries already carry the trace, so the consumer-side gate reads
   what already exists.
3. **Surface coverage for the verification cycle:** the hunter and
   adapter-free-recon surfaces need through-path chain coverage in the
   verification cycle (this reopens surface coverage per WP-J(c)) — the
   WP-I contract tests land the operator-surface through-path coverage
   the amendment demands (A11). The lab evidence archive (LCS-0b B1) is
   **not** requested: local reproduction succeeded.

## 6. Did `target_url` reach the factory on that path? — YES

`hunter_runner.py:661` builds `ProductionSpineConfig` with the
operator-supplied `--target` (normalized), and `:662`
`resolve_production_spine(config)` consumed it: the reproduced trace
carries `entrypoint_resolve` + `spine_activation` + a `config_digest`,
and the program-scope gate evaluated the target before any of it
(`program_scope.enabled=true`, `halted=false` in the summary). The factory
was reached; the chain *after* the factory is what silently stopped.

## 7. Register updates

| ID | Disposition |
|---|---|
| NF-L0-01 | **ROOT-CAUSED** (this report). Fix = WP-I (consumer-side completion gate, contract-tested). |
| NF-L0-02 | FIXED in-window by WP-K (template class closure; `tests/team1_acceptance/test_template_contracts.py`, 10 tests). |
| NF-009A-01 | Scan-path operator invisibility of chain state (§3.4) — folded into WP-I scope. |
| NF-009A-02 | WP-F composition defect found during re-verification: the campaign-node multi-principal flag gate ran BEFORE `annotated_hyps` was bound (`builder.py`) — a flag-deny would crash the lane with `NameError` instead of failing closed. FIXED in-window (ordering repair + honest skip reason); AST-verified; M2 contract/chain-gate suites green after the fix. |

## 8. Evidence inventory

- `scripts/m2a_p7_repro/` — harness (`target_server.py`, `fake_llm_server.py`,
  `scope.yaml`, `run_p7_repro.sh`, `README.md`);
- `deliverables/m2a_evidence/p7/` — reproduction logs (exit codes, stdout/
  stderr, campaign_summary.json trace block) for both the hunt (P7 shape)
  and scan (same-class) replays;
- `deliverables/m2a_anchor_record.json`-adjacent gate state:
  `scripts/gate_frozen_delta_m2.py --phase reopened` GREEN at every commit.
