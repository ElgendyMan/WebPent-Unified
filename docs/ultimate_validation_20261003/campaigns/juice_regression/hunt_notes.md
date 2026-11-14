# Hunt Notes — http://127.0.0.1:3000

- Campaign: `regression-juice-live-20261003`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 35 routes and prepared 2 governed candidates. (sha256:a7b58a679b751dc24e801f05233c8086531d54c74586f058a20c221275995a94) `event:6dca14d94e7ec8c78496b254`

## Curiosity Flags

- [curiosity] Detected 30 structural anomaly flags. (sha256:50701f8be8891bfa8a73a2c4adff28e7b556c24e781759978315c7cec679253f) `event:aa9dcea9ffb704c5349479b4`

## Attempts

- [validator] IDOR verdict: inconclusive; governed result requires further evidence. (hunter_h_000_sha256:74445) `event:376238fd783d9a2f6d22c418`
- [exploiter] Delegated concrete INFO_DISCLOSURE GET request triple through governed AVI. (h_recon_info_disclosure_35cd05fe1ef1) `event:977e7ba071efa1ddaac1b540`
- [validator] INFO_DISCLOSURE verdict: inconclusive; governed result requires further evidence. (h_recon_info_disclosure_35cd05fe1ef1) `event:aa027a91c9a60c061bcca8da`
- [validator] UNAUTHENTICATED ACCESS / AUTH BYPASS verdict: inconclusive; governed result requires further evidence. (hunter_h_001_sha256:180b9) `event:16f73c3d566db5a8c4a74414`
- [validator] INFORMATION DISCLOSURE (API SPEC) verdict: inconclusive; governed result requires further evidence. (hunter_h_002_sha256:e9843) `event:e0f95e412f441e1ac23f5774`

## Confirmed Findings

- None recorded.

## Refuted Attempts

- None recorded.

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
