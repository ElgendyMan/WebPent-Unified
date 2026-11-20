# Unfreeze Applied — Arjun Hidden-Parameter Discovery (Track 1)
**Date:** 2026-10-18
**Scope:** 6 frozen files unfrozen and live-wired to add in-scope, default-off, fail-safe
hidden-HTTP-parameter discovery (`arjun`) as a new recon tool, surfaced through the crawler
into hypothesis generation. All changes additive, default-off. No behavior change when
`WEBPENT_ARJUN_ENABLED` (default `false`) is absent or false.

This follows the exact process and contract style of
`UNFREEZE_APPLIED_REPORT_20261005.md` (2026-10-05 unfreeze) and
`scripts/gate_frozen_delta.py` (R3 ruling thaw mechanism): documented diff review,
manifest regeneration restricted to the touched paths, full-suite verification, and
an explicit rollback path. Unlike the R3 window, this is not a mid-window delta —
the manifest is regenerated directly for these 6 files, the same way the 2026-10-05
unfreeze closed out.

## 1. Files modified (6)

| # | File | Change | Default-off gate |
|---|------|--------|-------------------|
| 1 | `src/webpent/tools/utils/subprocess.py` | Added `"arjun"` to `_EXECUTABLE_MANIFEST` allowlist (one new frozenset entry). No other line changed. | n/a — allowlist entry only takes effect when `run_arjun` is actually invoked, which is itself gated below |
| 2 | `src/webpent/tools/registry.py` | Added `("webpent.tools.recon", "arjun")` to the hardcoded `auto_discover()` module list (one new tuple). No other line changed. | n/a — lazy import only; registers the tool, does not run it |
| 3 | `src/webpent/shared/tool_adapters.py` | Added `_arjun_target_runner()` (lazy-imports `run_arjun`) and one new `"arjun": ToolAdapter(...)` entry in `builtin_adapters()`. Purely additive. | n/a — adapter is only reached if a caller explicitly selects the `"arjun"` tool |
| 4 | `src/webpent/config/settings.py` | Added `arjun_path`, `arjun_enabled` (`AliasChoices` incl. `WEBPENT_ARJUN_ENABLED`), `arjun_wordlist_path`, `arjun_max_endpoints`, `arjun_timeout`, `arjun_request_timeout` fields. Purely additive field declarations. | `arjun_enabled` default `False` |
| 5 | `src/webpent/agents/crawler/agent.py` | Inserted one new block in `crawler_node`, after `curated_endpoints` is finalized and before the existing surface-security block. Reads `settings.arjun_enabled`; if off, the block is skipped entirely (control flow identical to before this change). If on, probes up to `arjun_max_endpoints` curated endpoints (prioritizing those with query strings or matching form actions) via `run_arjun`, writes results to `crawled_data["discovered_parameters"]`. Wrapped in `try/except Exception` — any failure degrades to `{}`, never raises into the graph. | `arjun_enabled=False` |
| 6 | `src/webpent/agents/hypothesis_analyzer/agent.py` | Added `_discovered_parameter_hypotheses()` (reuses the existing `_PARAM_NAME_SIGNALS` table and `_matches_param_name()` boundary matcher — no new classification logic, no new heuristics). Added one line extracting `crawled_data.get("discovered_parameters")` and one line adding `_discovered_parameter_hypotheses(...)` to the existing `generic_signals` list inside the per-URL loop. | Empty when `discovered_parameters` is absent/empty (i.e., when arjun is disabled or found nothing) — identical output to before this change |

## 2. Why these 6 and not more

`graph/builder.py` and the other recon-chain agent files (`subdomain_takeover`,
`cloud_storage`, `javascript_intelligence`, `waf_detector`, `target_understanding`,
`api_testing`, `business_logic_fuzzer`, `payload_generator`, `validator/*`,
`cli/git_source.py`, `shared/jwt_deep_testing.py`) were **not touched** by this work and
are **not included** in this regeneration. The 10 files in that second group were
already failing `test_frozen_file_byte_identical` in the delivered project tree before
any edit in this session — confirmed by diffing against the Track 1 patch
(`webpent_arjun_parameter_discovery_patch.zip`), which contains exactly the 6 files
above plus 2 new files (`tools/recon/arjun.py`, `tests/test_vip_arjun_parameter_discovery.py`)
and 2 doc files (`pyproject.toml`, `README.md`, which are not in the frozen manifest).
That pre-existing drift is outside this change's scope and is called out separately
rather than silently absorbed into this regeneration.

`graph/builder.py` is already on the `R3_RULING_THAW_PATHS` list from an earlier
window and was read (not edited) during this work's analysis phase — see
Track 2 notes below.

## 3. Verification results

### 3.1 New test suite
`tests/test_vip_arjun_parameter_discovery.py`: **21/21 PASS** — wrapper-level scope/
validation/parsing behavior (12 tests), `crawler_node` integration incl. disabled-by-
default and failure-degrades-safely paths (4 tests), `hypothesis_analyzer` signal-reuse
and cap behavior (5 tests).

### 3.2 Frozen hash gate
Before regeneration: `test_frozen_module_gate.py` — **16 failed** (6 from this change +
10 pre-existing, see §2), 694 passed.
After regeneration (manifest hashes updated for exactly the 6 files above, plus this
file's own thaw-set addition to `test_frozen_module_gate.py`): the 6 files return to
byte-identical status against the regenerated manifest; the 10 pre-existing failures
are unchanged (not this change's responsibility to fix) and are reported separately.

### 3.3 Zero behavior change when disabled
- `arjun_enabled` defaults to `False` — `crawler_node`'s new block is skipped before
  any import of `run_arjun`, so the control-flow path is byte-identical to pre-change
  for any caller that does not set `WEBPENT_ARJUN_ENABLED=true`.
- `discovered_parameters` is absent from `crawled_data` when arjun is disabled or finds
  nothing, so `_discovered_parameter_hypotheses()` always returns `[]` in that case —
  `hypothesis_node`'s existing `generic_signals` composition is unchanged in output.
- `run_arjun` itself refuses out-of-scope hosts and malformed URLs before any subprocess
  call (mirrors `run_ffuf`/`run_katana`), and never raises into the crawler (caught and
  logged, loop continues).

## 4. Rollback

Restore the 6 files to the state recorded in `frozen_modules.sha256.baseline_pre_unfreeze`
(unaffected by this regeneration — only the live `frozen_modules.sha256` manifest and
`test_frozen_module_gate.py`'s thaw-set were touched) and remove the `TRACK1_ARJUN_THAW_PATHS`
entry from `test_frozen_module_gate.py`. No data migration, no persistent state, no DB schema
change.
