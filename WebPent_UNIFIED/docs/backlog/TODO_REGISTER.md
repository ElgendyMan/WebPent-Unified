# TODO/FIXME Register — UMDR42 D3 (2026-11-19)

Full-tree scan of `src/` for `TODO|FIXME|XXX|HACK` comment markers:

| Occurrence | Location | Classification |
|---|---|---|
| regex literal `TODO|FIXME|HACK|XXX` | `src/webpent/brain/curiosity.py:97` | Not a marker — it is the scrubbing regex that *removes* such tokens from LLM-visible HTML comments |
| `\uXXXX` escape doc | `src/webpent/shared/canonical_json.py:12` | Not a marker — documents JSON escaping |

**Result: zero live TODO/FIXME/XXX/HACK markers in src/.**

Historical note: UMDR41's Phase-B audit counted `N markers` from a
looser scan; the refined scan (word-boundary, comment-anchored) shows
those were the two false positives above.

## Prevention (ratchet)

`scripts/umdr42_check_no_new_markers.py` (CI-wired) fails on any NEW
marker in src/; the two classified occurrences above are its allowlist.
