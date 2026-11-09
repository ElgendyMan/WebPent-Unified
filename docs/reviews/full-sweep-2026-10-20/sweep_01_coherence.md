# Axis 1/12 — COHERENCE (does one part contradict another?)

Question: do the modules, enums, docstrings and cross-layer maps of
the recent layers (forge, deep, campaign, prism) agree with each
other? Depths: (a) imports and enums, (b) cross-layer maps, (c)
docstring claims vs mechanics.

## Shallow (imports/enums)

All four recent packages import cleanly; no circular imports. Three
Family shapes exist by design (campaign str-Enum 8 members,
forge Enum 10 members, DEEP free strings) with two documented maps
(deep/bridge.py DEEP_FAMILY_TO_CAMPAIGN; forge/integration.py
name-based lookup). The maps themselves are where coherence breaks.

## Medium (cross-layer maps) — PoC executed

`get_payloads_for_phase` (forge/integration.py:90) maps campaign
hypothesis families into forge Family by
`Family[family_name.upper()]` and `continue`s on KeyError. PoC: of
the campaign's 8 families only SQLI, SSRF, XSS, SSTI map; BOLA, IDOR,
AUTH_BYPASS and INFO_DISCLOSURE are silently dropped — a phase
hunting pure access-control bugs gets zero payloads with no signal
that the corpus was never asked. → **F-01**.

`deep/bridge.py` `finding_to_hypothesis` does
`DEEP_FAMILY_TO_CAMPAIGN[finding.family]` with a 3-entry map (Tier-1
only). PoC: family strings of the other 12 detectors (race conditions,
smuggling, deserialization, SAML, JWT, NoSQL, prototype pollution,
DOM clobbering, rate-limit bypass, client path traversal, business
logic) hit a raw KeyError. → **F-02**.

## Deep (docstring claims vs mechanics)

forge/schemas.py:15-22 claims forge Family is "a superset of the
campaign layer's families". Mechanically false (PoC: campaign-only
members AUTH_BYPASS, BOLA, IDOR, INFO_DISCLOSURE; forge-only CMD_INJECTION,
LFI, OPEN_REDIRECT, PATH_TRAVERSAL, RCE, XXE). The false claim is
what made the silent drop in get_payloads_for_phase look safe. →
folded into **F-01**.

## Verdict for this axis

Two findings (F-01 HIGH, F-02 HIGH). The rest of the surface (forge
→ apex/prism/oracle/dojo integration, campaign ↔ spine bridge) is
coherent with its documentation.
