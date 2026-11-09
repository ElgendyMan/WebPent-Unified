# P10 external source findings

## Scope

These findings support independent ground-truth sourcing for the local OWASP Juice Shop benchmark. They do not constitute reviewer approval of WebPent results.

## Sources

1. OWASP project page: https://owasp.org/www-project-juice-shop/
2. Official repository challenge catalog: https://github.com/juice-shop/juice-shop/blob/master/data/static/challenges.yml
3. Official companion guide solutions: https://help.owasp-juice.shop/appendix/solutions.html

## Verified facts

- OWASP describes Juice Shop as an intentionally insecure web application used for security training, awareness demos, CTFs, and as a guinea pig for security tools.
- OWASP states that Juice Shop covers vulnerabilities from the OWASP Top Ten and other real-world security flaws.
- The official project page identifies the stack as Node.js, Express, and Angular and notes that the application includes JavaScript-heavy frontend and REST APIs.
- The official repository contains a machine-readable `data/static/challenges.yml` catalog with challenge names, categories, keys, difficulty, hints, and mitigation references.
- The official catalog is an independent source for challenge identity and category mapping, but catalog metadata alone is not a target-backed causal oracle and must not be used as proof of a live finding.
- The official companion guide is a documentation source for challenge solution context; it must be used only to derive bounded, safe workflow/oracle specifications and not to retain raw exploit payloads or secrets.

## P10 decision

The sources can support independent case identity/category mapping. They cannot replace the required reviewer approval, safe oracle readiness, three isolated live runs, or strict ProofBundle verification/replay. Cases requiring authentication bypass, OTP/MFA/CAPTCHA bypass, secret extraction, or unsafe state mutation remain out of scope under the project safety contract unless a separate approved safe oracle exists.

## Redaction

No raw response bodies, headers, cookies, tokens, credentials, or exploit payloads are retained in this note.

## Additional source review

- The official companion guide states that its challenge solutions assume a locally running application on the default local port and identifies the guide release compatibility. This supports local-only execution context, but the solution pages contain spoilers and are not themselves proof artifacts.
- The companion guide exposes separate sections for Injection, Broken Authentication, Sensitive Data Exposure, Improper Input Validation, Broken Access Control, Security Misconfiguration, XSS, and Unvalidated Redirects. These sections can support category-level mapping review.
- The companion guide includes local lab references such as `/ftp`, `/metrics`, `/.well-known/security.txt`, REST API paths, and frontend routes. These references are candidate surfaces only; each must be independently validated against the exact pinned image and must not be promoted from documentation to a live oracle without a safe adapter.
- The raw official catalog is the canonical machine-readable source for challenge records. The local catalog snapshot must be pinned by hash because challenge sets and descriptions can change across releases.

## Safety interpretation

The official guide includes active challenge-solving instructions. This project retains only metadata and conceptual source findings. No challenge solution payload, secret, credential, cookie, raw response, or external callback is copied into the P10 artifacts.

## Source-level route review

The official repository commit reviewed was `1618a611b173b4bf114028e6e02549950606e29d` from a shallow clone. The source-level review identified the following bounded candidate surfaces:

| Candidate challenge key | Category | Source-level surface | Safe execution posture |
|---|---|---|---|
| directoryListingChallenge | Sensitive Data Exposure | file-server route | GET-only candidate; exact file identity must be pinned and oracle must be redacted |
| forgottenBackupChallenge | Sensitive Data Exposure | file-server route | GET-only candidate; source confirms a backup-file branch, but no raw file content may be retained |
| misplacedSignatureFileChallenge | Observability Failures | file-server route | GET-only candidate; source confirms a misplaced-file branch, but no file body may be stored |
| exposedMetricsChallenge | Observability Failures | `/metrics` route | GET-only candidate; status/shape digest only |
| deprecatedInterfaceChallenge | Security Misconfiguration | upload route | Requires file upload and is not currently safe under the no-upload/no-mutation profile |
| errorHandlingChallenge | Security Misconfiguration | error middleware | Requires a controlled error-inducing request; candidate only until a bounded, non-destructive oracle is approved |
| redirectCryptoCurrencyChallenge | Unvalidated Redirects | `/redirect` route | Candidate requires redirect behavior; external destinations must not be contacted and only local/no-follow observation is allowed |
| privacyPolicyProofChallenge | Security through Obscurity | privacy-proof route | GET-only candidate, but it proves challenge state rather than a conventional vulnerability; requires explicit benchmark policy approval |
| hiddenImageChallenge | Security through Obscurity | server-side challenge hook | Depends on feedback content/state and is not a safe passive route candidate |
| localXssChallenge | XSS | frontend search component | Existing allowlisted typed-search workflow; no account action or persistent mutation |
| exposedMetricsChallenge | Observability Failures | `/metrics` | Passive read-only candidate; category is not among the current seven planned classes |
| securityPolicyChallenge | Security Misconfiguration | `/security.txt` | Passive GET candidate if added to ground truth; source confirms the endpoint check |

The source confirms route-level implementation intent, but source code and documentation do not establish live target proof. Any benchmark case remains unapproved until its exact image, route, oracle, and independent review record are frozen.
