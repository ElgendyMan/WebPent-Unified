# Axis 12/12 — FUTURE (will this hold as it grows?)

Depths: (a) growth seams, (b) migration risk, (c) extinction risks.

## Shallow (growth seams)

- The three-Family-shapes situation (campaign str-Enum, forge Enum,
  DEEP strings) has two maps today; every new family added to any
  shape widens the unmapped sets silently (F-01/F-02 are the current
  instances). The durable fix is one documented mapping discipline:
  any new family lands in the maps in the same round it lands in an
  enum — enforced by the red tests added in Phase 5 (the
  unmappable-set test fails when the sets drift).
- DEEP bridge coverage: extending the map to the other 12 detectors
  is the highest-leverage future work (roadmap Week 2); each
  addition is a data line + a test, not a refactor.

## Medium (migration risk)

CampaignMemory stamps record version "campaign_memory_v1" and reads
with fixed keys — a future schema change needs a version branch in
get(). The store format is small and test-locked; migration risk is
contained. SQLite corpora (indexer/outcome_tracker) have their own
schemas with no version stamp — noted in the roadmap.

## Deep (extinction risks)

The operator-sovereignty line (no approval code path outside the
operator's CLI act) and the advisory-only line are AST/source-locked
in tests — they cannot silently erode without a red test failing.
The zero-touch seals are sha256-pinned. The project's load-bearing
honesty constraints survive future rounds by test, not by memory.

## Verdict for this axis

No new findings beyond F-01/F-02's future dimension; roadmap items
recorded (bridge extension, SQLite schema versioning).
