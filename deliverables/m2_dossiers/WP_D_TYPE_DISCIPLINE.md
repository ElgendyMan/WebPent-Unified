# D3 — WP-D DOSSIER: TYPE DISCIPLINE
Ruling item: R4.
Files: src/webpent/production/advisory_registration.py; src/webpent/graph/builder.py
- canonicalize_campaign_hypothesis: mapping-only; id from id/hypothesis_id (non-empty str); vulnerability_class upper-cased str (default from state); path/method/api_type/engagement_id/source/advisory_ref str-coerced-else-reject; information_value numeric-or-reject; advisory_kwargs mapping-or-reject; ALL extra fields DROPPED (hostile payloads cannot ride to AVI).
- Campaign dispatch: every channel element canonicalized; rejections counted (research_campaign_hypotheses_rejected) + loud warning; empty-after-canonicalization -> skip marker no_canonical_hypotheses.
- AVI compatibility: canonical form preserves exactly the fields run_research_campaign reads (id/vulnerability_class/path/method + advisory extras).
Tests: test_canonicalizer_accepts_canonical_and_rejects_hostile; exit gate (dispatch succeeded with canonical advisory hypothesis).
