# Remediation Plan — FULL SWEEP 2026-10-20 (Phase 4)

Ordered by severity. Every code fix in Phase 5 runs red-first, is its
own commit, and is verified independently (suite count, targeted
PoC re-run, and at least one check the fix's own test does not
cover).

## Executed this round (Phase 5)

| # | Finding | Fix | Red test | Independent verification |
|---|---------|-----|----------|--------------------------|
| 1 | F-01 HIGH | Correct the false "superset" docstring; pin `UNMAPPABLE_CAMPAIGN_FAMILIES` in forge/integration.py | BOLA-only phase → [] without raising; set equals exactly the 4 unmapped families | PoC re-run + full forge suite |
| 2 | F-03 MEDIUM | Replace hasattr duck-typing with a direct `isinstance(family, enum.Enum)` read | String-family hypothesis still yields bundles; source scan: no "hasattr" in forge/integration.py | grep 0 hasattr recent packages; inventory 4/4 |
| 3 | F-04 MEDIUM | Narrow `except Exception` to `(TypeError, UnicodeError)` | Encoder raising RuntimeError propagates; surrogate payload skips encodings; normal payload returns variants | grep: no broad except in recent packages; full suite |
| 4 | F-02 HIGH | Typed rejection in deep/bridge for unmapped DEEP families | Foreign finding (family "RACE_CONDITION") raises the bridge's typed error naming the family | PoC re-run shows typed error, not KeyError; deep suite |

Order chosen: forge fixes first (1-3, one package), then deep (4) —
each is a separate commit.

## Backlog (next rounds; NOT executed mid-review)

- **EXT-1** (from F-03): extend the direct-I/O scanner to count
  `hasattr` as a dynamic-resolution site, with a reviewed inventory
  diff — core touch, requires the documented escalation procedure.
- **EXT-2** (from F-02/F-06): extend deep/bridge's family map to the
  12 non-Tier-1 detectors (each needs a severity default and tests);
  refactor prism/integration.py's 5 legacy getattr sites.
- **EXT-3** (from F-08): sanitize or hash campaign/memory ids at the
  CampaignMemory write path (path-traversal hardening).
- **EXT-4** (from F-05): idiom alignment across the 8 dashboards /
  3 CLIs, and an indexer/outcome-tracker consolidation study — only
  if a future round touches those files anyway.
- **EXT-5** (from F-07): recall cache in CampaignMemory if operator
  scale ever makes O(n) reads measurable; SQLite schema version
  stamps for forge corpora.

## Explicitly not done (with reasons)

- No forge equivalents for BOLA/IDOR/AUTH_BYPASS/INFO_DISCLOSURE:
  feature addition to the corpus (protocol forbids new features in a
  review round; the pinning test keeps the divergence honest until
  then).
- No silent skipping of unmapped DEEP families: silent data loss
  violates the honesty laws.
- No scanner change: core touch without escalation.
