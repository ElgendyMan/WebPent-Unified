# Unfreeze Applied — Parallel Recon Fan-Out/Join (Track 2)
**Date:** 2026-10-19 (code written) / verification + manifest regen closed out 2026-10-20
**Scope:** 2 frozen files unfrozen and live-wired to run `subdomain_takeover_node` and
`cloud_storage_node` concurrently (same LangGraph superstep) instead of sequentially, via a
new `recon_fanout`/`recon_join` node pair. All changes additive, default-off. No behavior
change when `enable_parallel_recon` (default `false`, env var `ENABLE_PARALLEL_RECON`) is
absent or false.

This follows the exact process and contract style of `UNFREEZE_ARJUN_TRACK1_20261018.md`
(2026-10-18 Track 1 unfreeze): documented diff review, manifest regeneration restricted to
the touched paths, targeted + full-suite verification, and an explicit rollback path.

## 1. Files modified (2)

| # | File | Change | Default-off gate |
|---|------|--------|-------------------|
| 1 | `src/webpent/config/settings.py` | Added one new field, `enable_parallel_recon: bool = Field(default=False, description=...)`, alongside the existing V55 additive-architecture flag block (`enable_target_understanding`, `enable_attack_graph`, etc.). Purely additive field declaration — no existing field, validator, or default touched. | `enable_parallel_recon` default `False` |
| 2 | `src/webpent/graph/builder.py` | (a) Two new node-name constants `NODE_RECON_FANOUT = "recon_fanout"`, `NODE_RECON_JOIN = "recon_join"`. (b) New helper `_parallel_recon_enabled()` — mirrors the established fail-closed pattern of `_target_understanding_enabled()`/`_js_intelligence_enabled()`; any settings-resolution error is treated as disabled. (c) New helper `_strip_current_phase(fn)` — wraps a node so its `current_phase` return key is dropped; applied ONLY to `subdomain_takeover_node`/`cloud_storage_node`, ONLY when the flag is on. (d) Two new trivial pass-through nodes, `recon_fanout_node` and `recon_join_node` (same pattern as the existing `scope_review_node`). (e) In `build_graph()`: `_parallel_recon = _parallel_recon_enabled()` resolved once; the two recon nodes are registered wrapped in `_strip_current_phase(...)` only when the flag is on (identical, unwrapped registration when off); `recon_fanout_node`/`recon_join_node` are registered as graph nodes only when the flag is on; the edge wiring that used to go `… -> NODE_SUBDOMAIN_TAKEOVER -> NODE_CLOUD_STORAGE -> route_after_infrastructure` is replaced, only when the flag is on, with `… -> NODE_RECON_FANOUT -> {NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE} -> NODE_RECON_JOIN -> route_after_infrastructure`. The rewiring is done by changing the **dict values** passed to `add_conditional_edges` (which router function feeds which node), not by touching any router function's decision logic. | `enable_parallel_recon=False` — when off, `build_graph()` registers and wires the original 48 nodes/edges byte-for-byte as before this change (confirmed in §3.2) |

## 2. Why these 2 and not more

No other file was touched for Track 2. `graph/builder.py` was already on the
`R3_RULING_THAW_PATHS` list from an earlier window (and separately already appears in
`M2_RULING_THAW_PATHS`) — it was being read and analyzed, not edited, when that fact was
first noted; it is now **also** edited by this change, which is why it needs its own
documented thaw entry below rather than relying on the older R3 entry (that entry's skip
in `test_frozen_file_byte_identical` is a pre-existing, differently-scoped mechanism — see
§3.2 for why it is not a substitute for proper documentation here).

`settings.py` is already in `TRACK1_ARJUN_THAW_PATHS` from the 2026-10-18 Track 1 unfreeze.
That thaw entry only covers the Track 1 diff (the `arjun_*` fields); it does not
automatically cover further edits. Because the frozen-file gate pins file content by hash,
not by field, `settings.py`'s hash must be regenerated again now that `enable_parallel_recon`
has been added on top of the Track 1 content — confirmed failing in §3.2 below before this
regen.

The 10 agent/CLI/shared files that were already failing `test_frozen_file_byte_identical`
before this session (`agents/api_testing/agent.py`, `agents/business_logic_fuzzer/agent.py`,
`agents/cloud_storage/agent.py`, `agents/payload_generator/agent.py`,
`agents/subdomain_takeover/agent.py`, `agents/validator/active_checks.py`,
`agents/validator/postp0_checks.py`, `agents/validator/structural_checks.py`,
`cli/git_source.py`, `shared/jwt_deep_testing.py`) — the same group called out in
`UNFREEZE_ARJUN_TRACK1_20261018.md` §2 — remain untouched and out of scope for this
regeneration. They are pre-existing drift, not introduced or fixed by Track 2.

## 3. Verification results

### 3.1 Real-code behavioral verification (no mocking of the functions under test)

Two standalone verification scripts build a minimal `langgraph.graph.StateGraph` using the
project's actual `PentestState` (with its real `Annotated` reducers from
`src/webpent/state/reducers.py`) and the actual, unmodified
`subdomain_takeover_node`/`cloud_storage_node`/`recon_fanout_node`/`recon_join_node`/
`_strip_current_phase` imported directly from the project — not a toy/synthetic
reimplementation of the mechanism.

**Script 1 — sequential vs. parallel topology, real node bodies, synthetic no-target state**
(`target=None`, which both real nodes handle by fast-returning without any network I/O):
- Sequential wiring (`subdomain_takeover_node -> cloud_storage_node`, flag-off topology)
  runs to completion. `current_phase == "cloud_storage"` (last-write-wins across two
  separate supersteps — expected).
- Parallel wiring (`recon_fanout -> {subdomain_takeover (stripped), cloud_storage
  (stripped)} -> recon_join`, flag-on topology) runs to completion **with no
  `InvalidUpdateError`**. `current_phase == "recon_join"` (explicitly set by the join node
  after both branches complete — expected, matches the node's docstring).
- Both topologies produce the same two `errors` entries (`"No target configured for
  takeover check."`, `"No target configured for cloud storage check."`) and the same empty
  `findings` list — order of the two errors differs between runs (expected: true
  concurrency, no ordering guarantee across the two branches), set-equality confirmed.

**Script 2 — concurrent non-empty `findings` writes, real `merge_findings`/`Annotated`
reducer**: both parallel branches return a distinct `Finding` (different UUIDs) in the same
superstep. Result: both findings are present in the final state (`merge_findings` dedups by
`id` and is a no-op here since the two ids differ) — confirms the Annotated-channel merge
Track 2 relies on actually prevents clobbering for concurrent writes to the same list field,
using the real reducer, not an assumption about it.

Both scripts: **PASS**.

### 3.2 `build_graph()` compile-time verification (full 48/50-node graph)

- `build_graph(auto_approve=True)` with `enable_parallel_recon` unset (default `False`):
  imports cleanly, compiles, **48 nodes** — identical node count to pre-Track-2 (confirmed
  against a graph with the flag forced off; no node added, no edge rewired).
- `build_graph(auto_approve=True)` with `ENABLE_PARALLEL_RECON=true`: imports cleanly,
  compiles, **50 nodes** (48 + `recon_fanout` + `recon_join`, confirmed present by name).
- `import webpent.graph.builder`: clean, no syntax or import-time errors.

### 3.3 Frozen hash gate

Before this regeneration, `tests/test_frozen_module_gate.py::test_frozen_file_byte_identical`:
**11 failed** (10 pre-existing, unrelated to Track 2 — see §2 — plus
`src/webpent/config/settings.py`, newly drifted by the `enable_parallel_recon` field), 1
skipped (`src/webpent/graph/builder.py`, masked by the pre-existing, differently-scoped
`R3_RULING_THAW_PATHS` skip — its content had already drifted from the manifest but the
test could not tell, because that skip condition only checks membership, not whether the
drift is the one it was written to authorize), 698 passed.

After regeneration (manifest hashes updated for exactly `src/webpent/graph/builder.py` and
`src/webpent/config/settings.py`, plus this file's own thaw-set addition to
`tests/test_frozen_module_gate.py`): both files return to byte-identical status against the
regenerated manifest and are asserted (not merely skipped) via the new
`TRACK2_PARALLEL_RECON_THAW_PATHS` documentation set; the same 10 pre-existing failures are
unchanged (not this change's responsibility — called out separately, exactly as Track 1 did).

Verified with `sha256sum --check --ignore-missing frozen_modules.sha256` (direct manifest
check) rather than `pytest`, per the Track 1 session's established practice in this
environment, and additionally confirmed targeted-parametrize with pytest itself (both
`test_frozen_file_byte_identical[src/webpent/graph/builder.py]` and
`...[src/webpent/config/settings.py]` pass, no longer needing the R3 skip or failing).

### 3.4 Zero behavior change when disabled

- `enable_parallel_recon` defaults to `False` — `_parallel_recon_enabled()` returns `False`,
  so `build_graph()` registers `subdomain_takeover_node`/`cloud_storage_node` unwrapped
  (identical to pre-change) and wires the original sequential edges
  (`… -> NODE_SUBDOMAIN_TAKEOVER -> NODE_CLOUD_STORAGE -> route_after_infrastructure`)
  byte-for-byte — confirmed by the 48-node count matching pre-Track-2 in §3.2.
- `recon_fanout_node`/`recon_join_node` are never registered as graph nodes when the flag
  is off — they exist as importable functions but are unreachable in the default topology.
- `_parallel_recon_enabled()` fails closed: any settings-resolution error (`AttributeError`,
  `ImportError`, `KeyError`, `OSError`, `RuntimeError`, `TypeError`, `ValueError`) is treated
  as disabled, so a broken or unexpected config can never silently turn on a graph-topology
  change.

## 4. Rollback

Restore `src/webpent/graph/builder.py` and `src/webpent/config/settings.py` to the state
recorded in `frozen_modules.sha256.baseline_pre_unfreeze` is **not** sufficient by itself
for `graph/builder.py` (it was already thawed by earlier windows — M2/R3 — before Track 2,
so the baseline reflects pre-M2 content, not pre-Track-2 content). To roll back Track 2
specifically: remove the `enable_parallel_recon` field from `settings.py`; remove
`NODE_RECON_FANOUT`, `NODE_RECON_JOIN`, `_parallel_recon_enabled`, `_strip_current_phase`,
`recon_fanout_node`, `recon_join_node` and the `_parallel_recon`-conditional branches inside
`build_graph()` from `builder.py`, restoring its unconditional sequential wiring; remove the
`TRACK2_PARALLEL_RECON_THAW_PATHS` entry from `tests/test_frozen_module_gate.py`; regenerate
`frozen_modules.sha256` for both files against that reverted content. No data migration, no
persistent state, no DB schema change — this is a pure graph-topology/config change.
