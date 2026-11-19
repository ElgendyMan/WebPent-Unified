# D3 — WP-E DOSSIER: SKIP VISIBILITY
Ruling item: R7 (RED-2 P-1.4: skip was fully silent end-to-end).
Files: src/webpent/graph/builder.py (campaign node), CAMPAIGN_GUIDE.md (C9).
- Every skip/error path emits logger.warning "RESEARCH CAMPAIGN SKIPPED (operator-visible, R7): <reason>" / "RESEARCH CAMPAIGN ERROR (operator-visible, R7)": factory re-derivation failure, no_hypotheses, no_canonical_hypotheses, campaign error.
- Marker research_campaign_skipped (declared) persists to final state; docs name the log channel + marker for operators.
Tests: test_skip_is_operator_visible (marker + caplog warning both asserted).
