# Hunt Notes — http://127.0.0.1:8888

- Campaign: `generalization-phase5-fixed-crapi`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 20 routes and prepared 4 governed candidates. (sha256:2a38cdbbf2d11c82e899ec2e21623b991dcc7adb2110b8b35d960a6c402d795d) `event:94d2db8dd0f6bf02c11770a1`

## Curiosity Flags

- [curiosity] Detected 23 structural anomaly flags. (sha256:3dc24bd14bbf6fab50811961c1c4aeb700650304076e801cbb890b23d621c6ba) `event:2d7f96fb926de0f536b0f787`

## Attempts

- [exploiter] Delegated INFO_DISCLOSURE candidate through governed AVI. (h_recon_info_disclosure_35cd05fe1ef1) `event:3a5a97aa1dc2b3655d968ef1`
- [validator] INFO_DISCLOSURE verdict: inconclusive; governed result requires further evidence. (h_recon_info_disclosure_35cd05fe1ef1) `event:aa027a91c9a60c061bcca8da`
- [exploiter] Delegated OPEN_REDIRECT candidate through governed AVI. (h_recon_open_redirect_0bfdbcc9eb06) `event:9acf2ee63a0116ac36ae0cfd`
- [exploiter] Delegated SSRF candidate through governed AVI. (h_recon_ssrf_97bb4b0faafb) `event:7f7f7227af9b4d5d002e42fd`
- [exploiter] Delegated XSS candidate through governed AVI. (h_recon_xss_1f2f1da92312) `event:ce7407960930be163ae730c3`
- [validator] XSS verdict: inconclusive; governed result requires further evidence. (h_recon_xss_1f2f1da92312) `event:aec3f5e708af71e92203e974`

## Confirmed Findings

- None recorded.

## Refuted Attempts

- [validator] OPEN_REDIRECT verdict: refuted; deterministic validator refuted. (h_recon_open_redirect_0bfdbcc9eb06) `event:2f4acdcbf0ac0e8c8321afde`
- [validator] SSRF verdict: refuted; deterministic validator refuted. (h_recon_ssrf_97bb4b0faafb) `event:0b032a10907a0015968e4c3a`

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
