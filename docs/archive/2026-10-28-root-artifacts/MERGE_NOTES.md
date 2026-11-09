# WebPent — comprehensive merge record

## Included snapshots

This archive combines the original Causal/v61 snapshot, the v21 project snapshot, the intermediate merged archive, and the newly supplied full-project snapshot. The newly supplied full-project snapshot is the base for paths present in more than one archive; its versions were retained for divergent same-path files. Unique files from the intermediate archive were added, including causal-reasoning modules and tests.

## Merge rules

- Same-path files appear once. For the 68 paths that differed between the intermediate archive and the latest snapshot, the latest snapshot was retained.
- Unique paths from the intermediate archive were added; generated `src/webpent.egg-info/` metadata was not reintroduced.
- `.env.example` combines the broader prior settings with settings introduced by the latest snapshot: 102 unique variable names, with duplicate assignments removed. Shared keys use the latest snapshot's example value. It contains no real configured credentials.
- `pyproject.toml` and `uv.lock` are retained from the latest snapshot. The lock was checked against that project configuration.
- `credentials_template.json` is retained from the latest snapshot; the prior intermediate template's extra example API-key field was not copied.
- The older uppercase `docs/DIRECT_IO_INVENTORY.md` was retained as `docs/DIRECT_IO_INVENTORY_G02_LEGACY.md` to avoid a case-insensitive filename collision with the latest snapshot's `docs/direct_io_inventory.md`. References inside historical reports remain as originally recorded.
- Executable permissions were restored on all 10 `.sh` scripts; the source ZIPs had dropped these mode bits even though the quickstart invokes scripts directly.
- A static conflict audit compared the 68 divergent same-path files with the previous intermediate merge. In shared Python files, the only prior-only symbols were the private `_resolve_url` helpers in `api_testing` and `structural_checks` and `_b64url` in `postp0_checks`; the current tree uses the shared URL resolver / `urljoin` and JWT helpers in `shared/jwt_deep_testing.py`. No prior-only public class/function symbols were found. This checks symbol presence, not full behavioral equivalence.
- The 78 prior-only Python files under `src/webpent/` are retained. A source-import scan found no extra undeclared third-party dependency names, but the causal-reasoning addition remains an optional integration layer: the supplied mainline graph does not invoke it automatically, as documented in `src/webpent/causal_reasoning_v2/INTEGRATION.md`.

## Verification and known limitations

- Final ZIP integrity test: passed.
- Python syntax compilation using Python 3.12: passed for `src`, `tests`, and `scripts`.
- `bash -n` on every `.sh` script: passed.
- `uv lock --check`: passed.
- The latest input's 708-entry `frozen_modules.sha256` is preserved unchanged. Its direct checksum check reports 11 mismatches; the supplied `TEAM1_MERGE_NOTES.md` identifies the pending re-freeze/review process and explicitly flags `src/webpent/shared/jwt_deep_testing.py` as an undocumented change. The manifest was not silently regenerated because it is a trust-control baseline.
- The 13-file authority manifest also has one mismatch at `src/webpent/agents/validator/active_checks.py`. Both manifests remain as supplied, so these checks are **not green** in this package.
- Read-only G-02 scan found 729 source records versus 658 in `docs/direct_io_inventory.json` (71-record drift). The pinned test allows 18 unapproved identities, while this merged source tree has 23; five additional identities are in `agents/validator/family_checks.py`, `causal_reasoning_v2/integration_layer.py`, and `families/execution_node.py`. The direct-I/O contract helper reports 22 violations (artifact drift plus unapproved sites). These findings are policy-gate failures, not proof by themselves that a network request bypasses runtime guards; the flagged code must be reviewed before any inventory/pin is updated.
- The latest snapshot alone already scans to 660 records against its 658-record artifact; the prior intermediate tree scanned to 722 against 653. The merged tree retains the extra transport sites from that earlier merge. No approvals or hashes were manufactured to make the checks green.
- The supplied `scripts/verify_campaign.sh` still compares the frozen manifest against a hardcoded 695 files although the manifest has 708 entries. It also treats missing JWT/AUDIT/CELERY keys as warnings rather than a failing preflight. Do not rely on its “READY” result until those checks are reviewed and corrected.
- The full pytest suite and live startup were not rerun on this newly combined tree: `pytest` is not installed in the isolated validation environment. Test results included in input reports refer to those snapshots, not this archive.
- File inventory reconciliation against all three supplied ZIPs found no missing project files. The six omitted paths are generated `src/webpent.egg-info/` metadata; this note is the only newly added path.
- Exact-content files that exist at different source paths were not deleted: several are historical reports, exports, or compatibility copies, and removing them without source-level dependency review could break references or erase provenance.

This ZIP is a comprehensive file-level merge, not a claim that every runtime path has been independently certified.
