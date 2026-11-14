# VIP Autonomous Bug Hunter — Execution Scope

Source: `/home/ubuntu/upload/التدقيقالشاملالنهائيلـWebPentوتحويلهإلىVIPAutonomousBugHunter.md`

## P0 release blockers

1. Enforce secure authentication and reject auth-off on public bind.
2. Fix global-admin versus tenant-scoped-admin authorization.
3. Move token revocation and reauthentication vault state to shared storage.
4. Add atomic resume consume-once plus worker dedupe/lease.
5. Make the Playwright guard transactional and fail-closed.
6. Unify OriginPolicy across HTTPX, Playwright, WebSocket, raw socket, and OOB transports.
7. Upgrade dependencies with the 17 advisories and do not silently bypass pip-audit.
8. Remove top-5 as a coverage ceiling.
9. Build a Surface Evidence Graph and coverage ledger.
10. Add IDOR/BOLA, tenant isolation, CSV, XSLT, and Elasticsearch-plugin validators.

## P1 capability targets

Header-aware SQLi, JWT claim mutation, redirect-chain differentials, OAuth workflow/state/PKCE, export/Blade sinks, backup/info disclosure, Laravel debug classification, frontend SBOM, XML/XSLT OOB evidence correlation, and two-identity authenticated workflows.

## Acceptance targets from the audit

No collection errors; every agent has a schema, owner, and failure taxonomy; every scan publishes a coverage summary; zero scope violations; zero duplicate side effects; 100% evidence contract completeness before confirmation; at least 15/20 WAPTLab classes confirmed or evidence-reviewable; at least 85% worker critical-path coverage; and reproducible CI/local results.

## First implementation slice

The first slice hardens auth-off/public-bind and disables JWT issuance from `/token` while auth is disabled. Existing loopback development bypass remains available and is covered by regression tests. The remaining P0 items require separate controlled slices because they affect persistence, distributed workers, browser policy, and dependency compatibility.
