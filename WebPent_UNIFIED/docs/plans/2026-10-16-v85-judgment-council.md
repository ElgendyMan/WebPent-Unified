# Plan v85 — The Judgment Council (JC)

Preamble (L-5): goal, in-scope, out-of-scope, DoD.

Goal: implement the full Judgment Council proposal (12 units, 4 waves) as
`src/webpent/jc/` + `src/webpent/cli/jc.py` + `config/jc/*.yaml`, advisory-only
(JC-L-1), fully deterministic (JC-L-2), zero network (L-2), transparent (L-4).

Out of scope: any execution authority, any LLM in the verdict path, any network.

DoD (from the proposal's success criteria):
1. 7 advocates + skeptic + judge working (Waves 1-2).
2. Every verdict carries full reasoning (all advocates' views, challenges, dissent).
3. Dissent register stored + accuracy computed.
4. Calibration report available after 20 decisions (min-samples guard).
5. Bias detector covers 5 documented patterns.
6. Council memory finds similar cases (context hash deterministic).
7. Explainer 3 levels (one-liner / summary / full) + markdown + json.
8. Override protocol logged + accuracy tracked.
9. Dashboard + full CLI (`webpent jc ...`) + capped redacted audit log.
10. Determinism proven (same session inputs -> same verdict).
11. Suite monotonic: >= +150 tests, zero drops.
12. Zero network calls from `jc/*`; advisory-only proof.

Tasks (repro-first discipline applies to every bug found):

### Task 1 (U-JC-1): the chamber
Files: src/webpent/jc/__init__.py, src/webpent/jc/contracts.py,
src/webpent/jc/chamber.py, config/jc/council.yaml, tests/jc/test_u_jc_1.py.
Evidence/Evidence/Argument dataclasses in contracts.py; CouncilSession +
CouncilChamber with deterministic session_id (sha256 of canonical
question+context), min_advocates/require_skeptic/require_judge from
config/jc/council.yaml (defaults if missing), logical time limit, close()
returns Verdict. Tests: 7 named tests.

### Task 2 (U-JC-2): the advocates
Files: src/webpent/jc/advocates.py, tests/jc/test_u_jc_2.py.
Advocate ABC + 7 default advocates (Tactician/Observer/Adapter/Historian/
Strategist/Resilient/Economist) mapping the 7 existing brain layers onto
injected context keys (L-2: nothing fetched). Each returns Argument | None
(abstain). Tests: 6 named + per-advocate conformance.

### Task 3 (U-JC-3): the skeptic
Files: src/webpent/jc/skeptic.py, tests/jc/test_u_jc_3.py.
Skeptic with 7 documented bias flags, mandatory alternative_hypothesis,
challenge_severity in [0, 0.9], deterministic. Tests: 7 named.

### Task 4 (U-JC-4): the evidence weigher
Files: src/webpent/jc/weigher.py, tests/jc/test_u_jc_4.py.
Weight = source_reliability x recency_factor x specificity_factor x
corroboration_factor, all components exposed (L-4). Tests: 5 named.

### Task 5 (U-JC-5): the judge + verdict engine
Files: src/webpent/jc/verdict.py, src/webpent/jc/judge.py,
config/jc/verdict_rules.yaml, tests/jc/test_u_jc_5.py.
AdvocateScore = sum(weighted evidence) x (1 - challenge_severity);
Confidence = top/sum x (1 - max severity); tiers high/medium/low;
tie -> escalate; dissent recorded. Tests: 8 named.

### Task 6 (U-JC-6): the dissent register
Files: src/webpent/jc/dissent.py, tests/jc/test_u_jc_6.py.
Append-only JSONL; link_outcome; accuracy per advocate; persistent-minority
detection; lesson candidates export. Tests: 6 named.

### Task 7 (U-JC-7): the confidence calibrator
Files: src/webpent/jc/calibration.py, config/jc/calibration.yaml,
tests/jc/test_u_jc_7.py.
Brier score, 0.1-wide buckets, drift detection, adjust() gated on >= 20
samples. Tests: 6 named.

### Task 8 (U-JC-8): the bias detector
Files: src/webpent/jc/bias_detector.py, tests/jc/test_u_jc_8.py.
5 patterns: systemic confirmation, recency dominance, anchor stickiness,
silent veto, majority tyranny; min data points; deterministic. Tests: 6 named.

### Task 9 (U-JC-9): the council memory
Files: src/webpent/jc/memory.py, tests/jc/test_u_jc_9.py.
context_hash = sha256 of canonical context; exact/similar retrieval (top-k);
pattern detection after 5; retention 180 days (bounded). Tests: 6 named.

### Task 10 (U-JC-10): the reasoning explainer
Files: src/webpent/jc/explainer.py, tests/jc/test_u_jc_10.py.
3 levels (one-liner/summary/full) + markdown + json; deterministic.
Tests: 6 named.

### Task 11 (U-JC-11): the override protocol
Files: src/webpent/jc/override.py, config/jc/override_policy.yaml,
tests/jc/test_u_jc_11.py.
full/partial/advisory override; reason required; JSONL log; outcome linking;
operator accuracy. Tests: 5 named.

### Task 12 (U-JC-12): dashboard + CLI
Files: src/webpent/jc/dashboard.py, src/webpent/cli/jc.py,
tests/jc/test_u_jc_12.py, tests/jc/test_jc_integration.py.
`webpent jc` commands (sessions/verdicts/calibration/bias/override/
dashboard/digest), capped redacted audit log like cli/econ.py. Tests: 6 named
+ integration (laws: advisory-only, no LLM, zero network, determinism sweep).

### Task 13: gate + docs + packaging
Version 0.8.3 -> 0.9.0; CHANGELOG entry; README status; traceability row;
full pytest (expect >= 2799 passed), ruff clean on all new files, direct-IO
inventory unchanged; rebuild + verify ZIP.
