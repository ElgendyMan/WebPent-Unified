# Verification — FORGE Wave-1 + DEEP Tier-1, then the BRIDGE round

Round: THE FORGE Wave-1 (5 MVP units) + THE DEEP FAMILIES Tier-1
(U-DEEP-7 Mass Assignment, U-DEEP-5 Host Header Injection, U-DEEP-18
Web Cache Deception).

Method: red-first TDD. All 75 new tests were written and confirmed red
(`ModuleNotFoundError: No module named 'webpent.forge'`) before any
implementation line existed. No test was weakened to pass; where the
implementation was wrong, the implementation changed.

## What was added

FORGE (`src/webpent/forge/`, 8 modules):
- `schemas.py` — Family enum, frozen dataclasses (PayloadAttribution,
  SourceConfig, QualitySignal, NormalizedPayload, TargetContext,
  ScoredPayload, IngestReport, StoredOutcome).
- `sources.py` — the 8 registered sources with the spec's trust scores
  and licenses (payloadsallthethings 0.95/MIT, hacktricks 0.90/CC-BY-NC,
  seclists 0.90/MIT, hackerone_disclosures 0.85/API-terms, exploitdb
  0.85/GPLv2, nvd 0.80/public-domain, pentest_cheatsheets 0.75,
  waf_bypass_lists 0.80/CC0).
- `normalizer.py` — published marker tables (families, polyglot groups,
  tech, WAF, context, obfuscation, common patterns); deterministic
  sha256-derived 16-hex ids; 5 documented encodings; complexity ladder.
- `quality_gate.py` — spec rules verbatim, reject-first ordering
  (malware → deprecated → high-risk-without-impact → trust floor →
  expert-review → auto_accept → review).
- `indexer.py` — SQLite corpus: attributions + payloads +
  payload_target_tech/waf/context/encodings/outcomes (6 payload tables
  + attributions) and the spec's 6 indices; idempotent store (existing
  ids are refreshed, never duplicated); outcome success-rate arithmetic.
- `ingester.py` — one documented parser per source shape; PRE-FETCHED
  strings only; dedup by deterministic id; attribution preserved on
  every payload; dry_run default.
- `query_engine.py` — published ranking arithmetic
  `score = context*0.4 + quality*0.3 + success*0.2 + novelty*0.1` with
  a transparent breakdown per hit; deterministic ordering
  (score desc, payload_id asc); neutral-0.5 context dimension for
  payloads that declare no requirement (the corpus never claims more
  than it knows); find_polyglots / find_chained.

DEEP (`src/webpent/deep/`, 4 modules):
- `mass_assignment.py` — MASS_ASSIGN_PAYLOADS verbatim (5 subfamilies);
  STATE OVER STRING: a finding requires the server to accept/reflection
  the injected field values or flip privileged state; strict-422
  endpoints produce zero findings; baseline + probe recorded in
  evidence; family="MASS_ASSIGNMENT", confidence, statement,
  success_indicator on every finding.
- `host_header.py` — HOST_HEADER_PAYLOADS verbatim (4 subfamilies);
  CONTEXT OVER CONTENT: reset links, redirect Location, cache-key
  poisoning (probe then clean follow-up), internal-routing auth bypass
  (clean 4xx → probe 2xx); severities per spec (critical/high/high/
  medium); every sub-family compared against a clean baseline.
- `cache_deception.py` — CACHE_DECEPTION_PATHS / STATIC_EXTS /
  CACHE_DECEPTION_HEADERS verbatim; crafted_paths() = 3 endpoints ×
  7 extensions; finding only on body equality (cookie-bearing vs
  cookie-less) AND a documented sensitivity check on the shared body.

## Governing constraints honored

- Zero-touch core: `src/webpent/production/modern_spine.py` seal
  `ef551212eb2a3583…ade31` and `src/webpent/live_hunter/profile.py`
  seal `30fd86c61156e7a5…5b663` unchanged (sha256 verified after the
  round).
- Zero live network from core: FORGE ingests caller-provided
  pre-fetched strings; DEEP detectors take `send` as an injected
  callable. Neither package imports socket/http client libraries.
- Zero auto-exploitation: detectors report advisory findings only
  (evidence + statement + success_indicator); no exploit execution.
- Direct-I/O: no `getattr`/`hasattr` dynamic indirection anywhere in
  the new packages (audited by grep).
- No new code lines in the 3 isolated packages: verdict/, emulator/,
  rehearsal/ untouched (suites re-run and identical).
- Suite monotonic: 3,943 → 4,018 collected (+75: 48 FORGE + 27 DEEP;
  mass_assignment carries one corpus-contract test beyond the spec's
  ten, additive only).

## Results

- `python3 -m pytest tests/forge tests/deep -q` → 75 passed, 0 failed.
- `python3 -m pytest tests -q` → 4,018 passed, 0 failed (181s).
- `python3 verify_all.py` → 145 PASS, 0 FAIL.
- verdict suite → 60 passed. emulator suite → 17 passed, 16 skipped
  (docker/emulator not running). rehearsal suite → 10 passed.

## Deferred (by the spec's own rule: no new family before the existing
ones prove themselves on a real target)

FORGE Waves 2-4 (Tailor/Alchemist/Learning/Armory), DEEP remaining 15
families, SAML and Deserialization (optional units).

# Round 2 — the BRIDGE (advisory-only)

Round: wire the two new packages into the existing brains — DEEP
findings into Prism evidence + campaign Hypotheses, FORGE ranked hits
into advisory probe strategies — with zero new families and zero
core touch.

Method: red-first again. tests/bridge/ (14 tests) written first and
confirmed red (`ModuleNotFoundError: webpent.forge.bridge` /
`webpent.deep.bridge`) before any implementation line.

## What was added

- `src/webpent/deep/bridge.py` — pure conversions:
  - `DEEP_FAMILY_TO_CAMPAIGN`: the documented family map
    (MASS_ASSIGNMENT→AUTH_BYPASS, HOST_HEADER_INJECTION→
    AUTH_BYPASS, CACHE_DECEPTION→INFO_DISCLOSURE).
  - `severity_of` / `findings_to_hypotheses`: deterministic
    critical-first ordering on finding-intrinsic keys (identical
    output for any input permutation).
  - `finding_to_hypothesis`: one finding → ONE disposable campaign
    Hypothesis; cost bounded by construction (1 request, 0 LLM
    calls, 2s); the finding's own statement, success indicator and
    payload ride inside the strategy; "advisory" marker on every
    strategy; deterministic hypothesis ids.
  - `finding_to_evidence_profile`: full-dimension EvidenceProfile —
    source "probe", signal "direct_response", reproducibility
    "deterministic", corroboration "single_source", rationale =
    the finding's statement; sha256 evidence hash (PRISM-L-1: no
    invented evidence).
  - `finding_to_prism_finding`: wraps profiles into a Prism Finding
    (PRISM-L-2: the Prism advises, it never blocks).
- `src/webpent/forge/bridge.py` — pure conversions:
  - `ranked_for`: ranked corpus hits for one family against one
    TargetContext (published score arithmetic, unchanged).
  - `probe_strategy`: advisory-only text strategy; every payload
    line carries source + license + score (FORGE-L-7
    ATTRIBUTION_IS_SACRED); a payload with no attribution raises
    rather than passing anonymously; empty corpus → empty string;
    deterministic.

Test-note (on the round's honesty): two of the red tests were
corrected before going green, in the tests' favor or toward the
sealed contracts — (1) `repr(payload)` on the left of an `in` check
(the payload is a dict; the assertion previously raised TypeError
before testing anything); (2) the Prism-confirmation scenario now
requires the two validators to have INDEPENDENTLY REPRODUCED the
probe's finding (corroboration independent_multiple), which is both
what the scorer's published arithmetic needs for "confirmed" and the
more honest corroboration semantics. No prism/scorer file or config
was touched; the probe profile itself stays single_source.

## Results (round 2)

- `python3 -m pytest tests/bridge -q` → 16 passed, 0 failed.
- `python3 -m pytest tests -q` → 4,034 passed, 0 failed (180s).
  Monotonic: 4,018 → 4,034 (+16).
- `python3 verify_all.py` → 145 PASS, 0 FAIL.
- Seals unmoved: modern_spine.py ef551212…ade31, profile.py
  30fd86c6…5b663 (sha256 re-verified after the round).
- Isolated packages identical: verdict 60 passed; emulator 17 passed
  16 skipped; rehearsal 10 passed.
- Zero network: both bridge modules are pure functions over
  in-memory objects; no socket/http imports anywhere in forge/ or
  deep/.

## Still deferred (same rule: no new family before proof on a real
target)

FORGE Waves 2-4 (Tailor/Alchemist/Learning/Armory), DEEP remaining
15 families, SAML and Deserialization (optional units).

---

# Round 3 — FORGE Wave-2 + DEEP Tier-2

Trigger: the user declared the standing deferral rule satisfied
("تم إثبات الاتنين" — both proven packages, FORGE and DEEP, had done
round-2 work end to end), so the round proceeded under the same laws
(red-first TDD, zero touch on the three isolated cores, zero live
network from core, advisory-only, suite monotonic, seals unmoved).

## What was added

FORGE Wave-2 (4 units, 41 tests):
- U-FORGE-7 Contextualizer (`forge/contextualizer.py`) — ADAPTATION_RULES
  verbatim from the spec (json / html_attribute / javascript / xml /
  cloudflare / akamai / aws_waf); spec examples reproduced exactly
  (`\u003cscript\u003e…`, `scr<script>ipt`, img/onerror, template
  literal). Unknown context raises.
- U-FORGE-8 Encoding Engine (`forge/encoding_engine.py`) — all 17
  ENCODINGS documented, variants exclude the identity, failures never
  raise into the caller (needs_testing stays the honest flag).
- U-FORGE-13 Outcome Tracker (`forge/outcome_tracker.py`) — PayloadOutcome
  (11 fields, frozen) round-trips through the indexer's own SQLite
  connection (`_SCHEMA` attaches `outcome_records`; no new connection
  object, no core edit).
- U-FORGE-14 Evolution Engine (`forge/evolution.py`) — success +0.05,
  siblings ×0.5, context keys +0.1, WAF-failure susceptibility mark,
  candidates only when ≥5 outcomes AND success ratio ≤0.2 and they are
  stored needs_testing=1, never as proven. Four tables attached to the
  same connection the same way.

DEEP Tier-2 (3 units, 32 tests):
- U-DEEP-10 JWT Advanced (`deep/jwt_advanced.py`) — 7 sub-families;
  alg:none in 4 casings; alg-confusion carries a REAL HMAC-SHA256
  computed with the operator-supplied public-key material (nothing
  fabricated); kid/jku/x5u/jwk/header-injection merge into the original
  header and keep the original signature; detection is ACCEPTANCE OVER
  STRUCTURE: probe accepted (success status) AND identical to an
  accepted baseline. A rejected baseline yields no findings by design —
  with nothing accepted to compare against, no crafted token can be
  shown accepted "where the original's acceptance cannot explain it".
- U-DEEP-13 NoSQL Injection (`deep/nosql_injection.py`) — 3 corpus
  groups; the six documented operators ($ne/$gt/$gte/$regex/$where/
  $expr) probed against a clean-credential baseline; STATE OVER STRING:
  auth_bypass requires the auth state to actually flip (200 + body
  change where baseline was rejected), blind_timing requires an elapsed
  anomaly over the threshold (1500 ms vs 50 ms baseline in evidence).
- U-DEEP-14 Prototype Pollution (`deep/prototype_pollution.py`) —
  server_side (3: `__proto__`, `constructor.prototype`, combined) /
  client_query (3) / client_fragment (1, `#`-prefixed) / client_json (1);
  immediate pollution = privileged key in the probe response; persistent
  pollution = clean probe response but privileged key on a clean
  follow-up (subfamily `server_side_persistent`, severity critical).

Test-note (on the round's honesty): one red test was corrected before
going green — the JWT fixture server checked local HMAC verification
before the key-source takeover headers, which made jku/x5u/jwk
structurally unreachable (a server that trusts client-supplied key
sources accepts on their presence; that trust IS the modeled flaw, so
the check order was moved). On the implementation side, acceptance was
tightened to require a success response identical to an accepted
baseline, which removes the false-positive where every probe "matches"
a rejected baseline on a hardened server.

## Results (round 3)

- `python3 -m pytest tests -q` → 4,107 passed, 0 failed (177s).
  Monotonic: 4,034 → 4,107 (+73: FORGE 41 + DEEP 32).
- `python3 verify_all.py` → 145 PASS, 0 FAIL.
- Seals unmoved: modern_spine.py ef551212…ade31, profile.py
  30fd86c6…5b663 (sha256 re-verified after the round).
- Isolated packages identical: verdict 60 passed; emulator 17 passed
  16 skipped; rehearsal 10 passed.
- Zero network: the suite's only outbound attempts are fixture hosts
  (example.com / example.test) asserted to fail — no core module opens
  a socket.

## Still deferred (same rule: proof on a real target gates the next wave)

FORGE Wave-3/4 (Mutation U-FORGE-10, Armory/Learning surfaces), DEEP
Race Conditions (U-DEEP-1), Business Logic (U-DEEP-3), Request
Smuggling (U-DEEP-4), SAML (U-DEEP-12), Deserialization (U-DEEP-15).

---

# Round 4 — FORGE Wave-3 + DEEP Tier-3

## What was added (FORGE Wave-3, 4 units — 40 tests)

- U-FORGE-9 Chaining (`forge/chaining.py`) — 5 chain types verbatim
  (polyglot `javascript:X//`, double_encoding quote-twice `→ %2527`,
  split_payload across params, prefix_bypass, context_break
  `</script><script>`); every variant is a NormalizedPayload with the
  origin's attribution preserved (L-3). Split of a single-token payload
  splits mid-token (`mid = (len+1)//2`) so the two fragments are
  distinct and still reconstruct the raw.
- U-FORGE-10 Mutation Engine (`forge/mutation.py`) — MUTATIONS verbatim
  (4 single-pass + tag_alternatives 5 + alert_alternatives 3 +
  operator_swap 2×3 + sql_injection_variants 5), MUTATION_SEED = 1337
  for deterministic case_change, single-pass first then structural
  replacements named after what they replace, sorted by predicted
  quality, top-N.
- U-FORGE-11 Novel Synthesizer (`forge/synthesizer.py`) — SQLI grammar
  verbatim (5×4×5×5×3 = 1,500 combinations), documented validity filter
  (the quote-context conflict rule), dedup, `limit` cap; every
  synthesized payload is honesty-marked `source="forge-synthesis"`,
  `original_source="synthesized"`, `license="generated"` — nothing
  synthesized may pose as ingested (L-1 applies to the corpus, not to
  the operator's own generation).
- U-FORGE-12 Adversarial Generator (`forge/adversarial.py`) —
  WAF_BYPASSES per WAF (cloudflare 5 / akamai 3 / aws_waf 2 / imperva
  2), each entry a deterministic transform of the raw payload; the
  canonical `<script>alert(1)</script>` reproduces the spec examples
  exactly; unknown WAF yields nothing rather than a guess.

## What was added (DEEP Tier-3, 2 units — 21 tests)

- U-DEEP-12 SAML (`deep/saml.py`) — 4 sub-families verbatim (XSW,
  comment injection, signature stripping, XXE in SAML); enterprise-only,
  canary-modeled; ACCEPTANCE OVER STRUCTURE: a manipulated response is
  a finding only when the ACS accepts it (authenticates an identity or
  content the baseline's signature coverage/entity handling should have
  prevented); rejected baseline → no findings by design. XXE is
  effect-based: resolved canary content appearing in the response but
  never in the submitted XML.
- U-DEEP-15 Deserialization (`deep/deserialization.py`) — 6 language
  signatures verbatim (Java ysoserial `AC ED 00 05`, PHP PHPGGC `O:`/
  `a:`, Python pickle `80 04 95`, .NET ysoserial.net base64
  `AAEAAAD/`, Ruby Marshal `04 08`, Node.js node-serialize
  `_$$ND_FUNC$$_`); identify() by decoded magic bytes / base64 prefix /
  raw marker; canary-only probing — no gadget chains, no
  ysoserial/PHPGGC payloads; EFFECT OVER ECHO: rce_side_effect
  (executed marker never echoed), error_timing (elapsed ≥ 500 ms on a
  serializer error), response_diff (error shape where baseline was
  clean). A verbatim echo is explicitly not an effect.

Test-note (on the round's honesty): two red tests were corrected before
going green — (1) the operator-swap subfamily name must follow the
implementation's template `operator_{old}_to_{new}` with `old="="`,
i.e. `operator_=_to_LIKE` (the test's `operator_=to_LIKE` was the
typo); (2) the mutation fixture carried `attribution=None` and then
asserted on `variant.attribution.original_source`, which crashes on the
correct None-propagation — the fixture now carries a real
PayloadAttribution like the chaining tests do via the ingested corpus.
Separately, the deserialization implementation initially used two
`getattr(probe, "elapsed_ms", ...)` sites, which would have added two
dynamic_resolution records to the direct-I/O inventory; the documented
convention (direct attribute access on injected response objects, as in
nosql_injection.py) was applied instead so the recorded artifact stays
byte-identical without regeneration.

## Results (round 4)

- `PYTHONPATH=src python3 -m pytest tests -q` → 4,169 passed, 0 failed
  (181s). Monotonic: 4,107 → 4,169 (+62: FORGE 41 + DEEP 21, with the
  U-FORGE-9/10 test files recovered from the interrupted continuation
  counted in the round's total).
- `python3 verify_all.py` → 145 PASS, 0 FAIL.
- Seals unmoved: modern_spine.py ef551212…ade31, profile.py
  30fd86c6…5b663 (sha256 re-verified after the round).
- Isolated packages identical: verdict 60 passed; emulator 17 passed
  16 skipped; rehearsal 10 passed.
- Construction-authority gate: OK — `ModernOrchestrator(` appears only
  in production_spine.py and the approved 25-file allowlist.
- Direct-I/O inventory: no drift; artifact untouched
  (656 records, pins 24/21 unchanged).
- Zero network: the suite's only outbound attempts are fixture hosts
  (example.test / lab.example.com) asserted to fail — no core module
  opens a socket.

## Still deferred (same rule: proof on a real target gates the next wave)

FORGE Wave-4 (Armory/Learning surfaces), DEEP Race Conditions
(U-DEEP-1), Business Logic (U-DEEP-3), Request Smuggling (U-DEEP-4),
DOM Clobbering (U-DEEP-16) and beyond.

## Round 5 — DEEP Tier-4 (U-DEEP-1, U-DEEP-3, U-DEEP-4, U-DEEP-16)

### Scope (declared before implementation, red-first)

Four DEEP units, 38 tests, all transport-injected (zero network, no
raw sockets), all advisory (DEEP-L-8), all state/effect-gated:

- U-DEEP-1 Race Conditions (10 tests): single-packet burst modeled
  via `burst_id` on the injected send; sub-families state_bypass
  (coupon), balance_manipulation, inventory, email_verification,
  file_upload, rate_limit. Detection principle EFFECT OVER STATE: a
  finding needs N successes where the sequential control
  (burst_id=None) gives exactly 1 AND a tracked numeric state field
  moved between first and last response. Idempotent reads that
  succeed N times are explicitly not findings.
- U-DEEP-3 Business Logic (10 tests): spec corpus of seven
  assumption types (server_trust / range / workflow / uniqueness /
  state / time / ownership); six finding sub-families (price_override,
  negative_quantity, refund_exceeds_payment, currency_confusion,
  coupon_reuse, workflow_skip). Every probe requires the effect to
  have taken hold (client price actually charged, refund exceeded the
  payment, currency mismatch honored, coupon paid twice, step 5
  confirmed) — acceptance alone is never a finding.
- U-DEEP-4 Request Smuggling (10 tests): five spec combos verbatim
  (CL.TE / TE.CL / TE.TE / H2.CL / H2.TE) plus WAF-obfuscation
  bypass plans. Detection via three effect channels only: response
  contamination (smuggled canary in a response it was never part
  of), timing diff against the clean baseline (>= 500ms), and
  desync-specific server error. Probe plan is raw-header metadata on
  the injected send — no TCP control is exercised.
- U-DEEP-16 DOM Clobbering (8 tests): corpus verbatim (3 global_vars
  / 2 attributes / 1 nested). EFFECT OVER ECHO: a payload is a
  finding only when the modeled client script's behavior changed
  (window.config hijacked and followed), never on reflection.

### Honesty notes (round 5)

- One red-test-driven correction during implementation: the
  sequential control must reach the injected send with
  `burst_id=None`; the first draft of `execute_attack` substituted
  the default burst marker for None, which made the sequential
  control indistinguishable from a burst (test_sequential_control_
  no_finding caught it; `RacePayload.burst_id` became `str | None`
  and the plan now passes the control through verbatim).
- No `getattr`-with-default on injected response objects anywhere in
  the four new modules — the direct-attribute-access convention was
  applied from the start, so the direct-I/O inventory artifact stays
  byte-identical without regeneration.

### Results (round 5)

- `PYTHONPATH=src python3 -m pytest tests -q` → 4,207 passed, 0
  failed (179s). Monotonic: 4,169 → 4,207 (+38: race 10 + logic 10 +
  smuggling 10 + clobbering 8).
- `python3 verify_all.py` → 145 PASS, 0 FAIL.
- Seals unmoved: modern_spine.py ef551212…ade31, profile.py
  30fd86c6…5b663.
- Isolated packages identical: verdict 60 passed; emulator 17 passed
  16 skipped; rehearsal 10 passed.
- Construction-authority gate: OK (subset re-run 40 passed; included
  in the full-suite count).
- Direct-I/O inventory: no drift (artifact byte-identical, pins
  24/21 unchanged).
- Zero network: fixture hosts (example.test / lab.example.com) are
  the only outbound attempts and are asserted to fail through the
  egress proxy — no new module opens a socket.

## Still deferred (same rule: proof on a real target gates the next wave)

FORGE Wave-4 (Armory/Learning surfaces), DEEP Rate Limit Bypass
(U-DEEP-2), Client-Side Path Traversal (U-DEEP-17) and beyond.

**Correction (Round 6, documentation error):** the previous section
listed U-DEEP-18 Cache Deception as deferred. That was stale —
U-DEEP-18 is fully implemented (`src/webpent/deep/cache_deception.py`)
and green (8 tests) within the 4,207. It was never deferred; the list
above was wrong and is corrected here and in the Round 6 section
below.

## Round 6 — DEEP Tier-5: the last two deferred DEEP units

Scope: U-DEEP-2 Rate Limit Bypass Engine and U-DEEP-17 Client-Side
Path Traversal — the only DEEP units from the spec's 18 that were
genuinely still missing once the stale list was corrected. Same laws
as every round: red-first, zero touch on the tool's core and the
spine/profile seals, zero live network, advisory-only findings
(DEEP-L-8).

**U-DEEP-2 — `src/webpent/deep/rate_limit_bypass.py`**
(`tests/deep/test_rate_limit_bypass.py`, 8 tests). Corpus verbatim:
RATE_LIMIT_BYPASSES with the four techniques (header_rotation with
the seven client-supplied IP headers in spec order, session_rotation,
http2_batching, concurrency) and four sub-families (login, password
reset, 2FA, API). EFFECT OVER STATE: a bypass is only a finding when
the rotated burst passes (100 of 100) where the same limiter's
sequential control measurably closed; a rotated header alone is not
evidence. Batching and concurrency are modeled as shape attributes
on the plan (requests_per_stream, instant_parallelism) — the
single-packet modeling discipline of U-DEEP-1, not a socket opened.

Honesty notes:

- No-false-positive floor (MEANINGFUL_LIMIT_FLOOR = 5): a window
  that closes after fewer than five sequential requests is a
  per-action counter, not a rate limit — rotation defeating it is
  the expected behavior of any client, so analyze() returns None
  even when the burst passes (tested with a quota-2 limiter).
- The sequential control is measured against the same limiter on
  the same state (after the attack window, measured once and
  cached), so the comparison is like-for-like; on a hardened
  limiter (socket-keyed) the burst passes only the quota and
  analyze() returns None.

**U-DEEP-17 — `src/webpent/deep/client_path_traversal.py`**
(`tests/deep/test_client_path_traversal.py`, 8 tests). Corpus
verbatim in spec order: the seven crafted paths (dot segments, empty
segment, single- and double-encoded dots, semicolon), labeled into
four sub-families (dot_segment, empty_segment, double_encoding,
semicolon; double_encoding high). EFFECT OVER ECHO: a payload is a
finding only when the router actually rendered the guarded route
(direct /admin blocked, crafted path reached through the router's
own normalization); if the baseline itself is reachable there is no
guard and scan() returns empty.

Results:

- Suite: 4,207 → **4,223** (monotonic, +16: 8 + 8).
- verify_all: 145/145 PASS (V6 DX-FINAL UNIFIED AUDIT PASSED).
- Seals: src/webpent/production/modern_spine.py
  ef551212eb2a3583f6d7af14b46f58c32afe9b4c67c5da6e08d4f7aece9ade31;
  src/webpent/live_hunter/profile.py
  30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663 —
  both unmoved.
- Isolated packages unchanged: verdict 60 passed; emulator 17
  passed, 16 skipped; rehearsal 10 passed.
- Construction-authority gate: OK (3 passed explicitly; included in
  the full-suite count).
- Zero network: the egress-proxy report shows only the by-design
  fixture-host attempts (lab.example.com / example.test); no new
  module opens a socket.

## Still deferred (same rule: proof on a real target gates the next wave)

FORGE Wave-4 (Armory/Learning surfaces) and beyond. With Round 6,
all 18 DEEP units of the spec are implemented and green.

## Round 7 — FORGE Wave-4/5/6 (U-FORGE-15, U-FORGE-16, U-FORGE-17, U-FORGE-18)

### Scope (declared before implementation, red-first)

The last four FORGE units of the spec — 27 tests, closing THE FORGE
entirely (all 18 FORGE + all 18 DEEP units now implemented and
green):

- U-FORGE-15 Cross-Target Transfer
  (`src/webpent/forge/cross_target.py`,
  `tests/forge/test_cross_target.py`, 8 tests). Similarity as the
  Jaccard overlap of tech:/waf:/ctx: profile items; threshold 0.7
  (spec) below which transfer() returns None; carries ONLY payloads
  with a recorded success on the source target — failures never
  transfer; factor = similarity × 0.7, always weaker than direct
  success; boosts stored once per (payload, target) — idempotent;
  effective_score = base quality + boost.
- U-FORGE-16 Payload CLI (`src/webpent/forge/payload_cli.py`,
  `tests/forge/test_payload_cli.py`, 6 tests). The spec's full
  command surface verbatim: ingest, find, adapt, mutate,
  synthesize, waf-bypass, corpus status/stats/export, attribution,
  license-report. argv in, structured CLIResult out — no real
  terminal, no real network; find/adapt/mutate/synthesize/
  waf-bypass drive the real engines (PayloadQueryEngine via
  list_all + filters, Contextualizer, mutation, synthesizer).
- U-FORGE-17 Payload Dashboard
  (`src/webpent/forge/payload_dashboard.py`,
  `tests/forge/test_payload_dashboard.py`, 5 tests). The spec's
  sections: Totals, By Family (counts + percentages), By Quality,
  By Complexity (freshness buckets), Learning (total outcomes,
  success rate, top performer). Read-only over the indexer and the
  OutcomeTracker — never mutates either.
- U-FORGE-18 Integration Layer (`src/webpent/forge/integration.py`,
  `tests/forge/test_integration.py`, 8 tests). The one advisory
  surface between THE FORGE and ORACLE/PRISM/APEX/DOJO/CAMPAIGN:
  get_payloads_for_phase (real Phase/Hypothesis → family →
  QueryEngine → Contextualizer → PayloadBundle), limit respected,
  get_tool_chain_for_payloads (real APEX ChainStep/ToolChain, one
  per bundle, explicit advisory note), enrich_oracle_with_payloads
  (payload_suggestions section keyed by family),
  feed_outcome_to_prism (forwards a copy to PRISM's sink),
  get_payloads_for_scenario (DOJO Scenario family → payloads),
  explain_payload_choice (attribution-aware). The layer holds no
  transport: no send, no execute — tested explicitly.

Honesty notes:

- Endpoint filter: NormalizedPayload carries no target_endpoints
  field, so `find --endpoint` gates on whether the corpus carries
  endpoint annotations at all; on an unannotated corpus the flag
  passes through as a no-op rather than silently emptying results.
- Freshness buckets use FRESH_DAYS = 60 / RECENT_DAYS = 90
  (fresh < 60, recent < 90, stable >= 90 days since ingestion);
  unattributed payloads land in stable (age unknown, treated
  conservatively).
- Top performer ranks by total successes first (spec intent:
  the payload that actually proved most), not by raw rate — a
  1/1 payload does not outrank 2/3.
- One false-positive transport signal fixed at source, not by
  editing the artifact: the first full run showed 3 new direct-I/O
  inventory records, all `getattr` defensive calls in the new
  files tripping the scanner. Removed the getattr calls (direct
  attribute access / try-except), returning the scan to exactly
  656 records with zero drift and zero artifact edits.
- synthesizer.generate returns VulnClass payloads (models.findings),
  not forge Family — the CLI normalizes them to Family.SQLI
  NormalizedPayload records for corpus display.

Results:

- Suite: 4,223 → **4,250** (monotonic, +27: 8 + 6 + 5 + 8).
- verify_all: 145/145 PASS (V6 DX-FINAL UNIFIED AUDIT PASSED).
- Seals: src/webpent/production/modern_spine.py
  ef551212eb2a3583f6d7af14b46f58c32afe9b4c67c5da6e08d4f7aece9ade31;
  src/webpent/live_hunter/profile.py
  30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663 —
  both unmoved.
- Isolated packages unchanged: verdict 60 passed; emulator 17
  passed, 16 skipped; rehearsal 10 passed.
- Construction-authority gate: OK (3 passed explicitly; included in
  the full-suite count).
- Direct-I/O inventory: 656 records, zero drift, artifact untouched.
- Zero network: the egress-proxy report shows only the by-design
  fixture-host attempts (lab.example.com / example.test); no new
  module opens a socket.

## Spec completion

With Round 7, every unit of both spec documents is implemented and
green: all 18 DEEP units (Rounds 3-6) and all 18 FORGE units
(Rounds 2-3, 7). No spec deferrals remain. The standing rule is
unchanged: proof on a real target gates any further wave, and
everything shipped here stays advisory — selection, adaptation and
evidence, with use gated by the tool's laws.
