# UM-DR-37 Production E2E Report (Part 12)

Generated 2026-11-16T05:24:44.894368+00:00.

Three SEPARATE campaigns through the REAL
`webpent.cli.unified_hunt.run_unified_hunt`, each against a fresh
authorized-lab instance (unique campaign ids, same configuration,
recorded budgets). `artifacts/umdr37_production_campaigns.json` +
per-run files.

## Results (identical across runs)

- confirmed per run: [] —
  both real boundary violations (INV-A-101 owner-User_A read by
  User_B; INV-B-777 the reverse) through CausalGuard CONFIRMED ->
  sealed ProofBundle -> verified replay;
- None graph stages, None lab
  requests, ~Nones per run;
- discovery funnel measured 24/25 stages from the tee'd raw state
  (endpoints=None,
  candidates=None,
  guard_confirmed=None,
  bundles=None).

## Safety invariants — proven from the lab's own request log

All invariants hold in all runs: the enforced admin boundary (403,
actually exercised) never confirmed; the missing resource (404,
actually probed) never confirmed; public resources never confirmed;
every request on-origin. The funnel's replay/promotion channels report
0 by channel semantics (the access-control lane confirms inside
verify_replay_evidence; the 'promoted' channel belongs to the
research/family lane) — documented, not stretched.
