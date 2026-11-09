# Axis 7/12 — EXISTING LAYERS (what is the one critical question per layer?)

Per-layer critical question, one each, with the answer found:

**Spine (modern_spine.py)** — "Does anything new raise into a
completed campaign?" The Wave-3 wiring wraps both touch points in
BRIDGE_GUARD (the bridge's enumerated exception tuple), satisfying the
P-1 no-broad-except rule. Answer: no. Seal verified unmoved this
sweep (d10783ec…).

**live_hunter/profile.py** — "Did anything move it?" Seal 30fd86c6…
unmoved. No.

**verdict / emulator / rehearsal** — "Any new lines in their cores?"
Isolated suites re-run in Phase 5 must match their recorded counts
(verdict 60, emulator 17+16 skipped, rehearsal 10). Checked in Phase 5.

**campaign** — "Does the historian read what it wrote, and nothing
else?" CampaignMemory._all() re-reads every record file and its brief
per recall query (O(n) file reads per query — fine at operator scale,
recorded as **F-07 LOW**). Round-trip is test-locked.

**prism** — "Does the advisor ever block?" The prism/integration.py
converters keep PRISM-L-2 (advise, never block); the module carries 5
legacy `getattr` sites that pre-date the zero-dynamic-resolution rule
(**F-06 LOW**, documented; a refactor is roadmap work, not a
mid-review fix).

**forge** — "Does the corpus ever claim more than it knows?" The
query engine's neutral-0.5 context dimension and the attribution
chain hold; the Family docstring overclaim is F-01.

**deep** — "Can a finding exist without an observed contrast?" No:
baseline-vs-probe is enforced per detector and by tests/deep.

**apex** — "Does the chain builder execute anything?" forge's
get_tool_chain_for_payloads produces ChainSteps marked advisory and
never executed in forge. Verified by test (tests/forge/
test_integration.py asserts the advisory note).

## Verdict for this axis

F-06 LOW (prism legacy getattr), F-07 LOW (memory recall cost). No
HIGH/MEDIUM findings in the existing layers.
