# Size Comparison (UM-DR Phase B, measured)

Measured with git ls-tree at 458a973~1 (before) vs 458a973 (after).

| metric | before | after | delta |
|---|---|---|---|
| tracked files | 4,996 | 4,985 | −11 |
| tracked payload | 137.2 MB | 135.2 MB | −2.0 MB |
| git object DB | 44.8 MiB pack | unchanged | 0 (no history rewrite) |

* The cleanup removed ~2.0 MB of root duplicates (the 1.88 MB AVI
  runtime JSON is the bulk) and 11 root files; the moved artifacts
  remain tracked at their archive paths.
* **No history rewrite**: deleted files remain in history; the pack
  and the three preserved bundles are unchanged.
* The real win is structural: the application root now carries only
  canonical entries; the historical material lives exclusively in
  the dated archives.
* Remaining root report families (FABRIC_*, etc.) are recorded as
  follow-up candidates — no broad-rule deletion.
