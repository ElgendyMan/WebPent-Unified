# Hunt Notes — http://127.0.0.1:3000

- Campaign: `regression-juice-live-v3-20261003`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 35 routes and prepared 4 governed candidates. (sha256:42f7b58358bb662d19b8092f90a2aa6bdbec14862118b379ffa77eb235f6c39d) `event:c830a483775ccb2d02fd1bc1`

## Curiosity Flags

- [curiosity] Detected 30 structural anomaly flags. (sha256:50701f8be8891bfa8a73a2c4adff28e7b556c24e781759978315c7cec679253f) `event:aa9dcea9ffb704c5349479b4`

## Attempts

- [exploiter] Delegated concrete BOLA GET request triple through governed AVI. (h_recon_bola_835522d13bc8) `event:060314ca0211a98cef121bc8`
- [exploiter] Delegated concrete IDOR GET request triple through governed AVI. (h_recon_idor_026e8149b12c) `event:84795c07bc8e51c685d888eb`
- [exploiter] Delegated concrete INFO_DISCLOSURE GET request triple through governed AVI. (h_recon_info_disclosure_35cd05fe1ef1) `event:977e7ba071efa1ddaac1b540`
- [validator] INFO_DISCLOSURE verdict: inconclusive; governed result requires further evidence. (h_recon_info_disclosure_35cd05fe1ef1) `event:aa027a91c9a60c061bcca8da`
- [validator] OPEN_REDIRECT verdict: inconclusive; governed result requires further evidence. (h_recon_open_redirect_0bfdbcc9eb06) `event:ae1177356164f7f11db97f0b`

## Confirmed Findings

- [validator] BOLA verdict: confirmed; PromotionPipeline PROMOTED. (proof_bundle_2f1464d825a34b32821a6368e9d85855) `event:4ff2777162b90f53ff75b456`
- [validator] IDOR verdict: confirmed; PromotionPipeline PROMOTED. (proof_bundle_c1ef4542aeed48ed94b92c555e1d4dcc) `event:f5b891d5abb01f16d40a885d`

## Refuted Attempts

- None recorded.

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
