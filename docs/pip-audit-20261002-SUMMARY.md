# pip-audit refresh — 2026-10-02

Previous audit: `docs/pip-audit-v97-20260823.json` (2026-08-23) — over a month
stale per the fix plan's Phase 3 instruction. This refresh was run against
the **pinned versions in `uv.lock`** using `pip-audit --no-deps` (metadata
check against the OSV database only — no packages were actually installed,
since the project's full dependency graph, including `torch`/`langgraph`,
is too heavy to resolve in this review environment). Three platform/self
entries were excluded because they cannot resolve on this audit host
regardless of vulnerabilities (`pywin32` — Windows-only; `backports-asyncio-runner`
— requires Python <3.12; `webpent` — the project's own package, not a real
PyPI dependency).

**Result: 30 known vulnerabilities across 5 packages.**

| Package | Pinned | Vulns | Fix available |
|---|---|---|---|
| `pyjwt` | 2.13.0 | 13 | Yes — 2.14.0 (most), 2.15.0 (one) |
| `pypdf` | 6.16.1 | 8 | Yes — 6.17.0 to 6.19.0 depending on CVE |
| `chromadb` | 1.5.9 | 5 | **No fix published yet** (as of this audit) |
| `urllib3` | 2.7.0 | 3 | Yes — 2.8.0 |
| `oauthlib` | 3.3.1 | 1 | Yes — 4.0.0 (major version bump) |

## Priority recommendation

1. **`pyjwt` 2.13.0 → 2.14.0** — highest priority. This project is
   auth-focused (`src/webpent/production/context_authority.py`,
   `decision_token` minting, etc.) and JWT handling is exactly the kind of
   dependency where a known CVE is most likely to be directly exploitable.
   13 open advisories against the pinned version is a lot; worth bumping
   first and running the auth test suite (`tests/team1_acceptance/test_sprint_i2_*`)
   against it before anything else.
2. **`urllib3` 2.7.0 → 2.8.0** — low-risk, widely-used transitive dependency,
   patch-version bump, unlikely to break anything.
3. **`pypdf` 6.16.1 → 6.19.0** — used by the reporter module
   (`src/webpent/reporter/`); check `reporter/export.py` and
   `reporter/bounty_report.py` still produce valid PDFs after the bump,
   since several minor versions are being skipped.
4. **`oauthlib` 3.3.1 → 4.0.0`** — a major-version bump; do not do this as
   part of a routine dependency refresh. Needs its own changeset and test
   pass, since major versions can have breaking API changes.
5. **`chromadb` 1.5.9`** — no fix version exists yet upstream as of this
   audit. Nothing to bump to. Re-check on the next scheduled audit; until
   then, this is a tracked, accepted risk rather than actionable today.

## What this does NOT replace

This is a metadata-only audit (pinned version strings checked against OSV),
not a verification that the actual installed environment matches `uv.lock`,
and not a test run after any version bump. Per the original fix plan
(Phase 8), an actual `pytest` run in an environment with the real
dependencies installed is still required to confirm none of these bumps
(especially `pyjwt`) regress anything — that has not been done here.
