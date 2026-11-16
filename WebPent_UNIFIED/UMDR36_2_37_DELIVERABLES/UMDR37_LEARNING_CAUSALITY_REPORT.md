# UM-DR-37 Learning Causality Report (G37-14)

Generated 2026-11-16T05:24:44.894368+00:00.

Two-layer honest proof:

1. **Selector level — PROVEN (deterministic)**:
   `tests/test_umdr37_learning_ablation.py` drives the REAL
   InformationGainSelector over the REAL InvestigationState with the
   same seed in both arms; the ONLY difference is the evidence channel.
   Recorded evidence lifts the affected candidate by exactly
   EVIDENCE_LIFT (0.25) and flips the next selection; contradicting
   evidence reorders downward; the supported-status lift layers on
   top. This also fixes the 36.1 script's attribute-read bugs
   (selected_experiment_id, EvidenceItem.ref/kind).

2. **Full loop — structurally limited under the stock scenario**:
   `artifacts/umdr37_learning_ablation.json` runs the real orchestrator
   twice (feedback vs evidence-channel-ablated) plus a per-decision
   counterfactual shadow. The stock pool (one experiment per
   hypothesis) leaves recorded evidence decision-inert — the artifact
   records the mechanism, the evidence that DID flow (3 items, 2
   hypotheses contradicted, 1 confirmed), and the complementary
   campaign-level ablation (umdr31: same-budget arms with/without
   evidence-channel hints select different experiments and confirm
   different outcomes).

No randomness, no environment differences: the selector-level
difference is attributable to the evidence channel alone.
