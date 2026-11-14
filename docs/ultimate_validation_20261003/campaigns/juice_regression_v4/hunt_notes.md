# Hunt Notes — http://127.0.0.1:3000

- Campaign: `regression-juice-live-v4-20261003`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 35 routes and prepared 2 governed candidates. (sha256:ebdc34910195913da0db808fbb8204ff6e962002ce7dd923f6f61926c2bfd2ba) `event:15c369898291a5dad6499fde`

## Curiosity Flags

- [curiosity] Detected 30 structural anomaly flags. (sha256:50701f8be8891bfa8a73a2c4adff28e7b556c24e781759978315c7cec679253f) `event:aa9dcea9ffb704c5349479b4`

## Attempts

- [exploiter] Delegated concrete IDOR GET request triple through governed AVI. (h_recon_idor_026e8149b12c) `event:84795c07bc8e51c685d888eb`
- [exploiter] Delegated concrete BOLA GET request triple through governed AVI. (h_recon_bola_835522d13bc8) `event:060314ca0211a98cef121bc8`

## Confirmed Findings

- [validator] IDOR verdict: confirmed; PromotionPipeline PROMOTED. (proof_bundle_4764ac6a736c456b80223db4db87afaa) `event:1243b95635520080abe9ebb7`
- [validator] INFORMATION DISCLOSURE / BROKEN ACCESS CONTROL verdict: confirmed; PromotionPipeline PROMOTED. (proof_bundle_e4a830ba1b61442a9007a2e4336d1266) `event:563819afc9d47d6e4c7199b2`
- [validator] IDOR/BOLA verdict: confirmed; PromotionPipeline PROMOTED. (proof_bundle_17421ddd49e84b26b59f540586af284d) `event:593607c1fd937491af7bbbf3`

## Refuted Attempts

- None recorded.

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
