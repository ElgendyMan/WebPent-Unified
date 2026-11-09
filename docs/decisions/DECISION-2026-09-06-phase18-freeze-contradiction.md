# Decision Record — Phase 18 Freeze Contradiction (v1.8.3 → v1.8.4)

**Date:** 2026-09-06
**Decided by:** Mohamed (project owner), provided explicitly in chat
**Applied by:** Claude (executing agent), same session
**Master plan reference:** Part A.1, options (a)/(b)/(c)

## The contradiction
Re-running `goed_v1_8_4/full_regression_v184.py` this session (not trusting the pre-existing
report — it turned out to be stale, see main status report) showed 4 files frozen by
`docs/archive/goed-v1.8.3/freeze_manifest.json` have changed on disk:
`src/webpent/cqa_v2/replay_verifier.py`, `src/webpent/llm_researcher/tool_boundary.py`,
`src/webpent/llm_researcher/providers/__init__.py`, `src/webpent/llm_researcher/providers/factory.py`.

## Decision: (a) RE-FREEZE — DOCUMENTED
Mohamed selected option (a), with these explicit constraints:
1. The v1.8.3 freeze (`docs/archive/goed-v1.8.3/freeze_manifest.json`) is historical and
   **immutable** — it is NOT rewritten, NOT re-hashed, NOT touched in any way to retroactively
   include v1.8.4 changes.
2. A **new**, separate freeze is created at `docs/archive/goed-v1.8.4/` covering only the 4
   changed paths, each with a one-line documented reason and a hash.
3. Phase 2/3/5 changes (real-provider hard gate, ProviderPool/failover, replay integrity fix)
   are kept as-is — none of them are reverted.
4. Phase 18's verification logic is updated so that: the historical v1.8.3 freeze is confirmed
   byte-for-byte unchanged (PASS), AND the new v1.8.4 freeze is internally consistent (PASS),
   AND the v1.8.4 freeze is never represented as if it were the original v1.8.3 freeze.

## What was NOT authorized by this decision
- Freezing `src/webpent/llm_researcher/providers/pool.py` (a genuinely new file, not one of the
  4 changed paths) was not part of this decision and was not done — see provenance doc.
- Nothing about the separately-discovered missing delivery artifact
  (`WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip`, category `delivery_v183`) was decided here.
  That is a new, distinct finding surfaced when Phase 18 was re-run this session, not covered by
  the master plan text or by this decision, and remains an open item for Mohamed.

## Artifacts produced under this decision
- `docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json`
- `docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_PROVENANCE.json`
- `docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_DIFF.md`
- `docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_VERIFICATION.json`
- `docs/archive/goed-v1.8.4/SHA256SUMS`
- Updated `goed_v1_8_4/full_regression_v184.py` (freeze-source logic now checks the 4 superseded
  paths against the v1.8.4 freeze instead of failing them against v1.8.3 forever)
