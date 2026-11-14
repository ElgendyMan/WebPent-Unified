# Findings — FULL SWEEP 2026-10-20 (Phase 3)

Format per finding: description → PoC → root cause → fix options →
red test → independent verification. Every code fix is executed
red-first in Phase 5 as its own commit; findings marked "documented"
are plan items, not mid-review code changes.

---

## F-01 — HIGH — forge Family map silently drops half the campaign's families, and the docstring that justified it is false

**Description.** `forge/integration.py::get_payloads_for_phase` maps
campaign hypothesis families into forge Family via
`Family[family_name.upper()]` and silently `continue`s on KeyError.
Only 4 of the campaign's 8 families (SQLI, SSRF, XSS, SSTI) map;
BOLA, IDOR, AUTH_BYPASS and INFO_DISCLOSURE are dropped without any
signal. forge/schemas.py:15 documents forge Family as "a superset of
the campaign layer's families", which the PoC disproves — the false
claim is what made the silent drop look intentional.

**PoC (executed).** `campaign-only members: ['AUTH_BYPASS', 'BOLA',
'IDOR', 'INFO_DISCLOSURE']; mappable: ['SQLI','SSRF','XSS','SSTI'];
superset claim holds: False`.

**Root cause.** The two enums were written in different rounds with
different missions; the integration was written against the docstring
instead of the set algebra.

**Fix options.**
1. (CHOSEN) Correct the docstring; pin the divergence with an
   explicit `UNMAPPABLE_CAMPAIGN_FAMILIES` constant in
   forge/integration.py and a red test that (a) requires
   get_payloads_for_phase to return [] for a BOLA-only phase without
   raising and (b) requires the constant to cover exactly the
   campaign families with no forge counterpart — so the set can
   never silently drift again.
2. Add forge equivalents for BOLA/IDOR/AUTH_BYPASS/INFO_DISCLOSURE —
   rejected mid-review: that is a feature addition to the corpus.
3. Raise on unmappable families — rejected: a mixed phase would
   crash; skipping is the honest advisory behavior once documented.

**Red test.** New test in tests/forge/test_integration.py: BOLA
hypothesis → empty bundles, no exception; UNMAPPABLE set ==
{"BOLA","IDOR","AUTH_BYPASS","INFO_DISCLOSURE"} exactly.

**Verification.** Full forge suite + the new test green; grep confirms
the corrected docstring; suite count monotonic.

---

## F-02 — HIGH — deep/bridge covers only Tier-1: 12 of 15 DEEP families have no path into campaign/prism, and the failure is a raw KeyError

**Description.** `deep/bridge.py::finding_to_hypothesis` looks up
`DEEP_FAMILY_TO_CAMPAIGN[finding.family]` in a 3-entry map
(MASS_ASSIGNMENT, HOST_HEADER_INJECTION, CACHE_DECEPTION). Any other
DEEP family string raises a raw KeyError; the other 12 detectors'
findings cannot be converted at all.

**PoC (executed).** `DEEP_FAMILY_TO_CAMPAIGN.get("RACE_CONDITION")
→ None (KeyError at finding_to_hypothesis)`; same for SMUGGLING,
DESERIALIZATION.

**Root cause.** The bridge was built in the Tier-1 round and never
extended as Tiers 2-4 landed; the KeyError path was never chosen,
it is the absence of a decision.

**Fix options.**
1. (CHOSEN, mid-review) Fail typed: unknown DEEP family in
   `finding_to_hypothesis` raises the bridge's own documented error
   class with the family name in the message, instead of a bare
   KeyError. Red test: a foreign finding with family
   "RACE_CONDITION" raises the typed error naming the family.
2. (ROADMAP, not mid-review) Extend the map to all 15 families —
   real feature work for the next round, listed in the plan; each
   addition needs its own severity default and tests.
3. Skip unmapped findings silently — rejected: silent data loss is
   the exact sin the honesty laws forbid.

**Red test.** tests/deep/test_bridge.py (or the bridge's existing
test file): pytest.raises with the typed error, message contains
"RACE_CONDITION".

**Verification.** deep suite green; PoC re-run shows the typed error,
not KeyError.

---

## F-03 — MEDIUM — `hasattr` duck-typing in forge/integration.py:93; the verification document's "zero hasattr" claim is false

**Description.** The direct-I/O policy counts every `getattr` as a
dynamic-resolution site; `hasattr` is the same duck-typing class and
is not counted by the scanner. One live site:
`families = {h.family.value.lower() if hasattr(h.family, "value") else str(h.family).lower() ...}`.
The verification document claims "no getattr/hasattr dynamic
indirection anywhere in the new packages" — written from a
getattr-only grep.

**PoC.** Grep: exactly one `hasattr` in the four recent packages
(forge/integration.py:93); scanner counts getattr only
(src/webpent/shared/direct_io_inventory.py normalizes "getattr"
calls, never hasattr).

**Root cause.** The audit tooling and the audit claim both keyed on
the getattr token; hasattr slipped through the policy's wording
("dynamic attribute resolution") and its tooling alike.

**Fix options.**
1. (CHOSEN) Replace the hasattr branch with a direct type check
   (`isinstance(family, enum.Enum)` → `.value`, else `str(family)`),
   plus a red test: a hypothesis whose family is a plain string still
   yields bundles, and the module source contains no "hasattr".
   Changing the scanner itself is core work — escalated as a roadmap
   item (EXT-1), not done mid-review.
2. Also fix the scanner to count hasattr — core touch, needs the
   documented escalation procedure; roadmap.
3. Leave it and reword the doc — rejected: the code should meet the
   policy, not the policy the code.

**Red test.** tests/forge/test_integration.py: string-family
hypothesis produces bundles; source scan asserts "hasattr" absent
from forge/integration.py.

**Verification.** Forge suite green; grep 0 hasattr in the recent
packages; inventory test 4/4 (no new getattr introduced by the fix).

---

## F-04 — MEDIUM — `except Exception` in forge/encoding_engine.py:77 silently swallows encoder bugs

**Description.** `generate_variants` wraps all 17 encoders in
`try/except Exception: continue`. All 17 encoders are total over
`str`; the only legitimate raise paths are contract violations
(non-str input → TypeError) and lone-surrogate Unicode failures
(UnicodeError, e.g. base64 on "\ud800"). An internal encoder bug
(any other exception) disappears and the corpus quietly returns
fewer variants.

**PoC.** Code inspection: the broad tuple hides any RuntimeError/
KeyError from an encoder body; ENCODINGS table (lines 33-51) shows
every encoder is a pure str→str function.

**Root cause.** Defensive catch-all written before the encoder
contract ("total over str") was pinned.

**Fix options.**
1. (CHOSEN) Narrow to `except (TypeError, UnicodeError): continue`
   with a comment naming the contract; unexpected exceptions now
   propagate (fail loud). Red test: an encoder raising RuntimeError
   propagates out of generate_variants; lone-surrogate payload still
   skips the affected encodings without crashing the loop.
2. Validate input type up front and drop the try entirely — rejected:
   UnicodeError from lone surrogates is input-dependent, not a type
   violation.
3. Log-and-continue — rejected: no logging surface exists in the
   package and adding one is scope creep.

**Red test.** tests/forge/test_encoding_engine.py: monkeypatched
encoder raising RuntimeError propagates; surrogate payload skips
encodings silently; normal payloads produce all documented variants.

**Verification.** Forge suite green; grep shows no bare
`except Exception` in the recent packages.

---

## F-05 — LOW — idiom-level duplication across operator surfaces (documented)

Eight dashboards and three CLI surfaces share one idiom; forge's
indexer and outcome_tracker overlap on payload-effectiveness history.
No behavioral duplication. Consolidation would cross package
boundaries for zero behavioral gain. **Action: documented here and in
the plan's backlog; no mid-review refactor.**

## F-06 — LOW — prism/integration.py carries 5 legacy `getattr` sites (documented)

Pre-dates the zero-dynamic-resolution rule; the module is an existing
layer with its own laws. **Action: roadmap item (EXT-2), not a
mid-review fix.**

## F-07 — LOW — CampaignMemory recall re-reads every record file per query (documented)

O(n) JSON + brief reads per recall; correct and test-locked, just not
cached. Fine at operator scale. **Action: roadmap note.**

## F-08 — LOW — campaign-id path hardening note (documented)

CampaignMemory derives record filenames from memory ids
(`f"mem-{campaign_id}.json"`); internally generated ids are safe, but
a future caller feeding an attacker-influenced campaign_id could
write outside the store root. **Action: roadmap hardening item
(EXT-3): sanitize or hash ids at the write path.**

---

## Severity totals

HIGH: 2 (F-01, F-02) — both code-fixed red-first this round.
MEDIUM: 2 (F-03, F-04) — both code-fixed red-first this round.
LOW: 4 (F-05..F-08) — documented with roadmap actions; no mid-review
code change (refactors and core-touching fixes are out of scope for
a review round per the protocol).
