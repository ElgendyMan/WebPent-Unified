# bbscout integration source manifest

This manifest describes the external bbscout source tree included in the combined integration archive. The source is **not vendored or committed** in the WebPent Git repository; its archive copy is produced from the reviewed extraction tree at release time.

| Field | Value |
|---|---|
| Source tree | `webpent_bbscout_integration/bbscout` |
| Tree file count | 62 |
| Deterministic tree SHA-256 | `528b2deb987edc38cea5fbca9d199ecc12e765fef81a76fbc4193cbb2212bbd3` |
| Network behavior | Provider fixtures are offline-only; no live provider smoke was run |
| Secret policy | No private keys, provider credentials, cookies, `.env`, database, cache, or runtime state included |
| Verification | `ruff check src tests scripts`; `PYTHONPATH=src pytest -q`; offline provider registry smoke |

The tree contains the signing, package verification, ingestor trust-map enforcement, provider-neutral fixture registry, four provider fixture datasets, tests, and the offline registry check. Bugcrowd, Intigriti, and YesWeHack are fixture-only in this release; no live support or authorization is claimed for them. The HackerOne adapter is read-only and its live network path is intentionally not exercised in this session because no separate provider authorization and credentials were supplied. No provider can submit reports or test targets through this integration.

Verification snapshot (2026-08-23 UTC): `uv run --with pytest --with pytest-asyncio pytest -q` returned `36 passed`; a static provider scan found network code only in `hackerone.py` (`urlopen` in the read-only GET request path), and no write-method calls in provider modules. The complete stdout/stderr and exit markers are stored in `docs/evidence/v97/phase3/`.

The source hash is a release input and must be recomputed if any file in the external bbscout tree changes.
