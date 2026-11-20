# Browser Hunter Sprint — Changelog

## Added

- Added bounded Playwright `BrowserFarm` with browser/context/page budgets, campaign isolation, navigation throttling, halt checks, and cleanup.
- Added redacted `TrafficInterceptor` for request/response observation, header masking, response placeholders, and JSON shape metadata.
- Added queryable sanitized `StateGraph` for rendered pages, forms, API calls, authentication transitions, and structural route metadata.
- Added M4-alias `BrowserAuthHandler` that accepts credentials only through an injected provider and records masked evidence.
- Added deterministic `JSAnalyzer` for endpoint candidates, hidden routes, source-map references, technology hints, and masked secret-like signals.
- Added bounded `BrowserCrawler` and the reproducible Juice Shop Browser Hunter runner.
- Added browser intelligence as an advisory-only projection in the Planner and governed hunter runner.
- Hardened Planner endpoint parsing for method-prefixed routes and fail-closed rejection of malformed individual hypotheses.
- Added direct-I/O approvals for the reviewed Playwright browser entry points and regenerated the inventory.

## Validation

- Browser Hunter focused regressions: 20 passed in the post-campaign focused run.
- Frozen manifest: 13 files verified unchanged.
- Direct-I/O inventory: 606 records, 20 pinned unapproved known-gap records, inventory test passed.
- Acceptance rounds: 20/20 in each of three rounds.
- Security gates: all five exit 0.
- Live campaign: 3 rendered pages, 33 routes, 100 bundles, 300 JS endpoint candidates, 1 real `gpt-5-mini` call, $0.00494350 actual cost, audit verified.
- Full suite: 2,100 passed, 8 failed, 0 skipped out of 2,108. The release report preserves the eight failures and does not claim a clean full-suite pass.

## Explicit non-claims

The run produced zero confirmed/promoted and zero refuted findings. The incomplete production trace and missing M4 identity binding prevented a trustworthy end-to-end vulnerability claim. No synthetic finding, fake ProofBundle, fabricated refutation, or fabricated browser traffic was added.
