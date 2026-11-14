# Hunt Notes — http://127.0.0.1:8082/WebGoat

- Campaign: `generalization-20261002t0201z-webgoat`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 3 routes and prepared 2 governed candidates. (sha256:45f9bb9b09f1dbf84a755529c84c7d1439ba808e2e1daae5bfb247c1e39af9bd) `event:5782d4c561f11a89f03bda1b`

## Curiosity Flags

- [curiosity] Detected 0 structural anomaly flags. (sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945) `event:4269ad960f965dfeaed4c1a2`

## Attempts

- [exploiter] Delegated XSS candidate through governed AVI. (h_recon_xss_bda2eae8db8d) `event:8595d53ce8df53e6ea97cd21`
- [validator] REFLECTED XSS (CLIENT-SIDE SCRIPT INJECTION) verdict: inconclusive; governed result requires further evidence. (h_recon_xss_bda2eae8db8d) `event:865af0273e6cb5f7caca89ec`
- [validator] SQL INJECTION (AUTH BYPASS / ERROR- OR UNION-BASED) verdict: inconclusive; governed result requires further evidence. (h_recon_sqli_5ecc742e53e9) `event:1a5eb72c6c4d29108de6d0e9`

## Confirmed Findings

- None recorded.

## Refuted Attempts

- None recorded.

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
