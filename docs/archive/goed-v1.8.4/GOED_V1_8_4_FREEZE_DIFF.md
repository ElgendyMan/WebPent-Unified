# GOED v1.8.4 Freeze Diff — 4 Superseded Files

**Decision applied:** RE-FREEZE (DOCUMENTED), chosen explicitly by Mohamed.
**Governing record:** `docs/decisions/DECISION-2026-09-06-phase18-freeze-contradiction.md`
**Historical v1.8.3 freeze:** untouched, still at `docs/archive/goed-v1.8.3/freeze_manifest.json`
(re-verified byte-identical this session — see verification report in this same directory).

## Important limitation, stated up front

The v1.8.3 freeze only ever stored SHA-256 hashes + sizes, not the actual source blobs, and
no `.git` history exists anywhere in this snapshot. That means a true line-by-line diff against
the frozen v1.8.3 version of each file **cannot be reconstructed** in this session — there is
nothing to diff against, only a hash to confirm inequality. Everything below is grounded in
(a) what the *current* code's own docstrings/comments say about itself, and (b) existing
runtime evidence already in `reports/goed_v1_8_4/`. It describes *what the current code does
and why it plausibly changed*, not a verified byte-diff. Treat it as strong circumstantial
evidence, not a courtroom-grade diff.

---

### 1. `src/webpent/cqa_v2/replay_verifier.py`
- v1.8.3 frozen hash: `1c853557...06913` (3446 bytes)
- v1.8.4 current hash: `2a9a4bf3...42ef3` (4364 bytes, +918 bytes)
- **What the current module docstring says:** replay success under v1.8.4 is STRICT — it now
  requires `verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`
  together. A previously-CONFIRMED case with seal equality alone but a failed strict check now
  downgrades to INCONCLUSIVE (`replay_valid=False`). The docstring is explicit that "seal
  equality ALONE does NOT prove replay success" — read as a direct fix to a prior weaker check.
- No dedicated re-run report for this file specifically exists in `reports/goed_v1_8_4/`.

### 2. `src/webpent/llm_researcher/tool_boundary.py`
- v1.8.3 frozen hash: `f0280303...2dcf` (7056 bytes)
- v1.8.4 current hash: `4c2ef961...4c1f8` (9119 bytes, +2063 bytes)
- **What the current code comments say (found in-place, not paraphrased from elsewhere):** an
  "SSRF GUARD (added — Phase 14 finding)" closes a bypass where `httpx.Client(base_url=...)`
  only prepends `base_url` for *relative* paths — an absolute URL supplied in tool-call params
  was sent as-is, verified empirically able to reach hosts like `169.254.169.254` (cloud metadata
  IP) regardless of the intended target. The fix requires the requested host to match the
  client's configured `base_url` host.
- This is a security fix. Per Mohamed's decision and Part A.1(c) of the master plan, it is kept
  regardless of which freeze option was chosen.

### 3. `src/webpent/llm_researcher/providers/__init__.py`
- v1.8.3 frozen hash: `d92fc36b...618fe` (657 bytes)
- v1.8.4 current hash: `fce1fcd4...ced750` (763 bytes, +106 bytes)
- **Current content:** now also imports/re-exports `ProviderPool, LLMRouter, ProviderSlot,
  SlotStatus, FailureCategory` from a new sibling module, `pool.py` (328 lines, did not exist
  under v1.8.3 — see provenance doc). This is what makes provider failover possible.
- **Corroborating evidence:** `reports/goed_v1_8_4/failover_integrity_test.json` already shows
  8/8 failover scenarios passing (healthy, rate-limit-then-recover, quota-exhausted-no-recovery,
  auth-invalid-permanent, timeout-escalates-to-circuit-breaker, and 3 more). Pre-existing report,
  not re-run this session (no network needed — flagged in the main status update as something
  that could be re-run on request for a fresher timestamp).

### 4. `src/webpent/llm_researcher/providers/factory.py`
- v1.8.3 frozen hash: `fc6ec994...f6df` (3860 bytes)
- v1.8.4 current hash: `89715707...8f3a1` (4849 bytes, +989 bytes)
- **Current content:** adds one new function, `get_provider_status()` (line 78), which is
  imported by the sibling `__init__.py` above. The pre-existing v1.8.3 strict real-API gate
  functions (`get_provider`, `get_provider_from_env`, `get_runtime_gate_status`) are still
  present with the same gate docstring language ("STRICT RUNTIME GATE... no silent downgrade
  to Mock").
- **Not verified:** whether the internal logic of those three pre-existing functions changed at
  all beyond the new addition — no old-source copy exists to diff against. Flagged, not asserted.

---

## What this diff does NOT cover
- `src/webpent/llm_researcher/providers/pool.py` — new file, not a freeze violation by
  definition, but not yet formally frozen either. See provenance doc for why it was left alone.
- The missing `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip` delivery artifact — unrelated to
  these 4 files, a separate open item for Mohamed (see main status report).
