# Direct I/O Inventory

Generated from canonical AST scan (regenerated deliberately in Round 4,
2026-10-18: +2 records for src/webpent/production/verdict_bridge.py —
the subprocess CLI bridge to the verdict tool, RULING R4-Round4; see
docs/reviews/round4_seal_update.md and the pin comment in
tests/test_g02_direct_io_inventory.py). Regenerated again after Round
4.1: the two verdict_bridge.py records moved lines only (the
`_validate_finding_id` allowlist patch) — record and identity counts
unchanged, reviewable diff verified before regeneration. Regenerated
once more after Round 5 (Re-test Dispatch): the same two records moved
lines again (recipe capture + dispatch_retest appended) — the re-test
executor is caller-injected, so the transport surface did not grow.

- Records: 656
- Approved records: 92
- Known unapproved records pinned: 24 (21 identities)

- dynamic_resolution: 538
- safe_boundary_call: 55
- import: 33
- call: 22
- dynamic_import: 8
