# Axis 5/12 — DEEP FAMILIES (the proposal, reviewed adversarially)

Question: is DEEP FAMILIES feasible, integrated, and honest about
what it detects? Depths: (a) detector inventory vs spec, (b)
integration into campaign/prism, (c) detection logic soundness.

## Shallow (inventory vs spec)

15 detectors shipped under src/webpent/deep/ (race_condition,
business_logic, smuggling, saml, deserialization, dom_clobbering,
jwt_advanced, nosql_injection, prototype_pollution, rate_limit_bypass,
client_path_traversal, mass_assignment, host_header, cache_deception,
+ the bridge), matching the DEEP Tiers 1-4 recorded in
docs/verification_forge_deep.md (U-DEEP-1..18 minus the spec's
explicitly deferred web entries). Test files exist per detector in
tests/deep/.

## Medium (integration) — PoC executed

The integration story breaks at the bridge: only the three Tier-1
finding types are importable/convertible by deep/bridge.py. The other
12 detectors produce findings that cannot cross into the campaign
(principled probe hypotheses) or the prism (evidence profiles):
`finding_to_hypothesis` raises a raw KeyError on their family strings.
DEEP is an island for 80% of its families. → **F-02 HIGH**.

## Deep (detection logic soundness)

Spot-audit of the soundness pattern across detectors: every finding
requires a recorded baseline-vs-probe contrast (state over string in
mass_assignment, clean-4xx → probe-2xx in host_header, body equality
plus a sensitivity check in cache_deception) and every detector takes
`send` as an injected callable — zero network imports in the package
(verified: only urllib.parse appears, unused for transport). The
detection logic does not claim what it did not observe. Severity
mapping lives in the bridge with a documented default per family.

The soundness pattern is uniform and test-enforced (tests/deep/ has
17 test modules). No fabricated-evidence path found.

## Verdict for this axis

One HIGH finding (F-02: bridge coverage gap). The detectors
themselves are sound and honestly bounded.
