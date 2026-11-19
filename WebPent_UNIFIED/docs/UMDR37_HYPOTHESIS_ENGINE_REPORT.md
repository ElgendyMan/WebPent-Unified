# UM-DR-37 Hypothesis Engine Report

Generated 2026-11-16T05:24:44.894368+00:00.

The main Hypothesis model already carries the research contract
(preconditions, alternatives, expected_behavior, negative_control,
info_gain, risk). UM-DR-37 added the unified lifecycle VIEW
(research/lifecycle_view.py) mapping the three coexisting status
vocabularies onto GENERATED -> ... -> SUPPORTED/REFUTED/CLOSED/LEARNED,
fail-closed on unmapped statuses; EVALUATED/RANKED/SELECTED are
documented as decision-point states persisted in decision_log.

Adversarial pins (tests/test_umdr37_adversarial.py): invalid
transitions rejected (unexplored cannot resolve; refuted is terminal);
duplicates collapse on the deterministic dedupe key. Deduplication is
exact-key (analyzer by url+vuln_class; research loop by uuid5
fingerprint; families by dedupe_key) — similarity-based merging is a
documented gap, not a claim.
