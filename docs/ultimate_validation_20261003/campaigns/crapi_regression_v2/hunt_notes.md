# Hunt Notes — http://127.0.0.1:8888

- Campaign: `regression-crapi-live-v2-20261003`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 29 routes and prepared 4 governed candidates. (sha256:e0fb10f980ed3dbd9bf34216cd755819e76db64f9ed5f69eb0e17c9a2bfe0e11) `event:b75c69c04c1caed84311d6c0`

## Curiosity Flags

- [curiosity] Detected 28 structural anomaly flags. (sha256:82ddfc6aa314b99970c36be28543d701e518553c93799da82abece0f7fde948c) `event:5af78327db5aced27951dbd9`

## Attempts

- [exploiter] Delegated concrete IDOR GET request triple through governed AVI. (h_recon_idor_026e8149b12c) `event:84795c07bc8e51c685d888eb`
- [validator] IDOR verdict: blocked; baseline_not_successful status=None. (h_recon_idor_026e8149b12c) `event:c49af282e7dcf1b18abb4a77`
- [exploiter] Delegated concrete INFO_DISCLOSURE GET request triple through governed AVI. (h_recon_info_disclosure_35cd05fe1ef1) `event:977e7ba071efa1ddaac1b540`
- [validator] INFO_DISCLOSURE verdict: inconclusive; governed result requires further evidence. (h_recon_info_disclosure_35cd05fe1ef1) `event:aa027a91c9a60c061bcca8da`
- [validator] OPEN_REDIRECT verdict: inconclusive; governed result requires further evidence. (h_recon_open_redirect_0bfdbcc9eb06) `event:ae1177356164f7f11db97f0b`
- [exploiter] Delegated concrete XSS GET request triple through governed AVI. (h_recon_xss_1f2f1da92312) `event:5e7ba5ccc3b1b2623564a194`
- [validator] XSS verdict: inconclusive; governed result requires further evidence. (h_recon_xss_1f2f1da92312) `event:aec3f5e708af71e92203e974`

## Confirmed Findings

- None recorded.

## Refuted Attempts

- None recorded.

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
