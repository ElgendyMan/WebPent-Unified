# Hunt Notes — http://127.0.0.1:3000

- Campaign: `generalization-phase5-fixed-juice_shop`
- Content policy: sanitized structural evidence only

## Authentication

- None recorded.

## Interesting Endpoints

- [planner] Crawled 25 routes and prepared 4 governed candidates. (sha256:c112103ca5a430182fa60668a60dc0688723685559b0ae358663e6089e5fd5fa) `event:611bc99b1d536983bd93b2ef`

## Curiosity Flags

- [curiosity] Detected 22 structural anomaly flags. (sha256:4d7e66fb37fce527480ae6ab1aca042de14bf47d2ea1e290f43c59c46d2ce616) `event:f472ef4da784d3b764e291b0`

## Attempts

- [exploiter] Delegated INFO_DISCLOSURE candidate through governed AVI. (h_recon_info_disclosure_35cd05fe1ef1) `event:3a5a97aa1dc2b3655d968ef1`
- [validator] INFO_DISCLOSURE verdict: inconclusive; governed result requires further evidence. (h_recon_info_disclosure_35cd05fe1ef1) `event:aa027a91c9a60c061bcca8da`
- [exploiter] Delegated OPEN_REDIRECT candidate through governed AVI. (h_recon_open_redirect_0bfdbcc9eb06) `event:9acf2ee63a0116ac36ae0cfd`
- [exploiter] Delegated SSRF candidate through governed AVI. (h_recon_ssrf_97bb4b0faafb) `event:7f7f7227af9b4d5d002e42fd`
- [validator] SSRF verdict: inconclusive; governed result requires further evidence. (h_recon_ssrf_97bb4b0faafb) `event:2ba50593f6636183c36870bb`

## Confirmed Findings

- None recorded.

## Refuted Attempts

- [validator] OPEN_REDIRECT verdict: refuted; deterministic validator refuted. (h_recon_open_redirect_0bfdbcc9eb06) `event:2f4acdcbf0ac0e8c8321afde`

## Hypotheses

- None recorded.

## Chains to Explore

- None recorded.
