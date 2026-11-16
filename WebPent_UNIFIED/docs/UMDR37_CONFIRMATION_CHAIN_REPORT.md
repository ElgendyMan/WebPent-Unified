# UM-DR-37 Confirmation Chain Report (Part 13)

Generated 2026-11-16T05:24:44.894368+00:00.

CausalGuard is the sole confirmation authority (AST-level invariant +
confirmation matrix pinned since UM-DR-35/36.1). The legal chain
Observation -> Candidate -> CausalGuard -> ProofBundle -> Replay ->
Promotion executed INSIDE the production graph in all three campaigns:

- candidates: the access-control lane's differential findings;
- guard: adjudicated CONFIRMED on enriched production rows
  (authorization context stamped by the node — RC-4);
- bundle: sealed per finding, `evidence_bundle_id` carried in the
  summary (the dict-projection bug that blanked it is fixed);
- replay: `verified_replay` recorded per verification;
- promotion: confidence_level Tool-Confirmed — never minted outside
  the chain (family verdicts alone produce Pending candidates only).

Chain data: `UMDR37_CONFIRMATION_CHAIN.json` (per-run verifications +
confirmed findings with bundle ids). Machine evidence:
`artifacts/umdr37_production_campaigns.json`.
