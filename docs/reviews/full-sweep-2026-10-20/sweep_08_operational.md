# Axis 8/12 — OPERATIONAL (does it work when a real operator drives it?)

Question: do the operator surfaces behave under real misuse, and do
failures surface honestly? Depths: (a) CLI/command behavior, (b)
error paths, (c) data longevity.

## Shallow (command surfaces)

campaign/warroom/cli.py: list/status/approve/reject only; unknown
commands and unknown campaigns return typed {"ok": False} results,
never exceptions (test-locked in tests/campaign/test_warroom.py).
forge/payload_cli.py: query/dump commands over the local corpus; no
network.

## Medium (error paths)

- deep/bridge.py: the one untyped error path found in the recent
  layers — a raw KeyError escapes finding_to_hypothesis for any
  family outside the 3-entry map (**F-02**). An operator converting a
  mixed findings list loses the whole batch to one unmapped family
  instead of a typed, per-finding rejection.
- forge/encoding_engine.py: the silent-skip path (**F-04**) is the
  inverse sin: the operator is never told that variants went missing.
- CampaignStore round-trips are lossless and CampaignMemory re-record
  updates in place — operator data survives re-runs (test-locked).

## Deep (data longevity)

Memory records and briefs are plain JSON under the store root;
nothing prunes or migrates them; record version
"campaign_memory_v1" is stamped. SQLite corpora (indexer,
outcome_tracker) are idempotent on store. No data-loss path found.

## Verdict for this axis

F-02 and F-04 are the operational findings; both are fixed in Phase 5.
