# Axis 6/12 — FORGE (the proposal, reviewed adversarially)

Question: is FORGE legal, quality-gated, contextual, learning,
synthesizing, and attribution-honest? Depths: (a) pipeline inventory,
(b) law-by-law audit, (c) failure-mode sweep.

## Shallow (pipeline inventory)

Ingest → normalize → quality-gate → index → query → contextualize →
evolve/adversarial → outcome-track → synthesize, plus the operator
surfaces (payload_cli, payload_dashboard) and integration.py. All 20
modules have matching test files in tests/forge/ (17 test modules +
conftest).

## Medium (law-by-law audit)

- Legal/attribution (FORGE-L-7 ATTRIBUTION_IS_SACRED): PayloadAttribution
  is a required field of every stored payload; ingester preserves it;
  sources.py pins license + trust per source (payloadsallthethings
  MIT 0.95 … waf_bypass_lists CC0 0.80). The license set includes
  hacktricks CC-BY-NC — ingested but marked; the query engine does
  not filter by license (a payload gated by the quality rules may
  still surface NC-licensed text into a report). Documented residual
  risk; the corpus never copies NC text into generated artifacts —
  it references payload strings, which is the corpus's stated use.
- Quality gate: reject-first ordering (malware → deprecated →
  high-risk-without-impact → trust floor → expert-review →
  auto_accept → review) matches the spec verbatim; tested
  (tests/forge/test_quality_gate.py).
- Context: Contextualizer adapts raw payload strings per TargetContext;
  the integration layer reads the campaign Phase's hypotheses — where
  F-01 (silent family drop) lives.
- Learning: outcome_tracker records successes/failures per payload
  and feeds the indexer's success-rate arithmetic; evolution proposes
  candidates from real failures (no invention: FORGE-L-1).
- Synthesis: synthesizer composes existing corpus payloads, carries
  attribution of the parents; no invention path.

## Deep (failure-mode sweep)

- encoding_engine.generate_variants wraps every encoder in a bare
  `except Exception: continue` — an encoder with an internal bug
  (TypeError on a legal input) disappears silently and the corpus
  quietly returns fewer variants. All 17 encoders are total over
  `str`; only contract violations (non-str) and lone-surrogate
  Unicode failures can raise. → **F-04 MEDIUM** (fail-loud fix).
- forge/integration.py:93 uses `hasattr(h.family, "value")` —
  dynamic attribute resolution that the direct-I/O scanner does not
  count (it counts `getattr`). A policy blind spot inside the package
  the policy was written for. → **F-03 MEDIUM**.
- Zero network confirmed: the only urllib import in forge is
  urllib.parse (pure string work). No socket, no http client. The
  ingester takes pre-fetched strings only.

## Verdict for this axis

Two MEDIUM findings (F-03, F-04). The attribution, quality and
learning chains hold.
