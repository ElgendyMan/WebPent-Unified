# WebPent VIP Integration Decision Matrix

**Author:** Manus AI
**Date:** 2026-08-20
**Review scope:** Local source review and deterministic tests only. No WAPTLab, Juice Shop, or external target was contacted or modified during this review.

## Decision policy

This matrix distinguishes **code reuse**, **isolated runtime integration**, and **import-only observation**. A license-compatible project is not automatically safe to integrate: WebPent must remain the sole authority for target scope, identity context, action authorization, execution budgets, validator routing, negative controls, ProofBundle sealing, and reporting. No external output can create a Finding or Tool-Confirmed result by itself.

> **Adopt** means that a bounded integration is accepted in WebPent’s architecture. It does not mean that the external project’s scanner, exploit engine, database, or report authority is copied into WebPent.

> **Defer** means that the project may be evaluated later behind the WebPent execution plane after source pinning, health checks, timeout/cancellation handling, redaction, fixture tests, and target-backed ablation. **Reject** means that code reuse or direct authority is not accepted in this release; a future isolated process adapter may still require separate legal and engineering review.

## Matrix

| # | Project | Upstream/license basis | Decision | Rationale | Adapter/runtime status |
|---:|---|---|---|---|---|
| 1 | [PentestGPT](https://github.com/GreyDGL/PentestGPT) | MIT metadata on the upstream repository [5] | **Reject as authority; retain ideas only** | LLM reasoning can be useful for hypothesis generation, but unrestricted tool choice, exploit execution, or report authority would bypass WebPent policy. | No external PentestGPT code or executor imported. WebPent’s bounded LLM contracts and deterministic ActionAuthority remain the implementation. |
| 2 | [Rekono](https://github.com/pablosnt/rekono) | GPL-3.0 metadata on the upstream repository [6] | **Reject code reuse; legal review required** | GPL-3.0 obligations and the project’s platform-level authority make direct code reuse inappropriate for this release. Independently implemented lifecycle and recovery ideas may be studied without copying code. | No Rekono adapter. No source copied. |
| 3 | [OWASP Nettacker](https://github.com/OWASP/Nettacker) | Apache-2.0; the official repository declares Apache-2.0 [1] | **Adopt narrowly as import-only** | Nettacker produces useful event/service/CVE-shaped records, but its scanner, modules, database, reports, and network authority must not become WebPent authorities. | `src/webpent/shared/nettacker_adapter.py` accepts captured JSON-compatible output only. It is bounded, redacts unsafe fields, labels CVEs as enrichment-only, binds imports to ActionAuthority/SQLiteActionLedger, and projects surfaces as `needs_validator`. No Nettacker execution is imported. |
| 4 | [AutoPentestX](https://github.com/Gowtham-Darkseid/AutoPentestX/tree/c324bc5b8aa68b549652c403fd674b142617f211) | Pinned source audit and license review recorded in the AutoPentestX integration documents | **Adopt narrowly as import-only** | The orchestrator, exploit paths, persistence, and report authority would duplicate or bypass WebPent controls. Only already-captured records are useful as untrusted enrichment. | `autopentestx_adapter.py` is implemented and locally tested with redaction, same-origin checks, provenance, ledger context, malformed-input fail-closed behavior, and AST no-direct-I/O guards. |
| 5 | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Apache-2.0; the official repository declares Apache-2.0 [2] | **Defer isolated adapter** | ZAP is valuable for passive/active web scanning, but its process/API lifecycle, alert taxonomy, context/scope, and session handling need explicit translation into WebPent evidence and policy contracts. | No ZAP adapter accepted in this release. A future adapter must use ActionExecutor, bounded API/process calls, redacted alert import, cancellation, and validator replay; ZAP cannot publish confirmations directly. |
| 6 | [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana) | MIT; the official repository declares MIT [3] | **Adopt native wrapper; retain canonical facade** | Katana is appropriate for bounded discovery, but headless mode, browser state, response storage, and scope must remain controlled by WebPent. | Existing `run_katana` wrapper and canonical tool facade remain in place. Surface records are discovery-only and require family validators. No new authority is added. |
| 7 | [Playwright](https://github.com/microsoft/playwright) / [Crawlee](https://github.com/apify/crawlee) | Playwright and Crawlee upstream repositories publish permissive Apache-2.0 licensing | **Defer browser adapter** | Browser automation is high-value for authenticated workflows and DOM/XHR discovery, but it requires Chromium qualification, cookie/session custody, download limits, navigation scope, and deterministic replay. | Browser capability discovery and workflow models exist; a production browser execution adapter is not yet accepted. Browser/OOB/authenticated qualification remains residual. |
| 8 | [Schemathesis](https://github.com/schemathesis/schemathesis) | MIT metadata on the upstream repository [9] | **Defer isolated adapter** | Property-based API testing can improve body-bearing and schema coverage, but generated cases must be bounded, authorization-aware, replayable, and separated from confirmation. | No Schemathesis adapter. WebPent-native API/GraphQL contracts remain authoritative until an adapter has fixtures, limits, negative controls, and ablation evidence. |
| 9 | [REST-Attacker](https://github.com/RUB-NDS/REST-Attacker) | LGPL-3.0 metadata on the upstream repository [10] | **Defer; legal review required** | The copyleft boundary and research-oriented execution model require legal review before code reuse or distribution. Its generated attacks cannot be treated as proof without WebPent causal validation. | No adapter or source reuse. A future isolated integration must be separately approved and must import only bounded, redacted results. |
| 10 | [Wapiti](https://github.com/wapiti-scanner/wapiti) | GPL-2.0; the official repository declares GPL-2.0 [4] | **Reject code reuse; defer isolated integration** | Wapiti is feature-rich and supports many web attack classes, but GPL-2.0 and its payload/attack-module execution model make direct integration unsuitable for this release. | No Wapiti adapter. A future process boundary would need legal review, explicit destructive-action denial, output redaction, and WebPent validator replay. |
| 11 | [Dalfox](https://github.com/hahwul/dalfox) | MIT metadata on the upstream repository [11] | **Defer isolated adapter** | Dalfox can provide XSS discovery/enrichment, but an “XSS found” line is not confirmation. Reflection, storage, execution context, and negative-control evidence must be validated by WebPent. | No Dalfox adapter. Existing XSS validation contracts remain the only promotion path. |
| 12 | [mitmproxy](https://github.com/mitmproxy/mitmproxy) | MIT metadata on the upstream repository [12] | **Defer traffic adapter** | Traffic interception can improve workflow and API discovery, but it creates high-risk custody issues for cookies, authorization headers, request bodies, and certificates. | No mitmproxy adapter. Future work requires explicit consent, bounded capture, secret redaction before persistence, session isolation, and replay-safe evidence. |
| 13 | [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) | MIT metadata on the upstream repository [13]; templates are a separate content supply chain | **Adopt native wrapper; keep findings validator-gated** | Nuclei is useful for deterministic checks, but template severity, matcher output, and CVE labels are not proof by themselves. Template provenance and destructive-template policy must remain explicit. | Existing `run_nuclei` wrapper and canonical facade remain. No Nuclei record can promote a Finding without WebPent causal signal, negative control, and ProofBundle. |
| 14 | [ProjectDiscovery HTTPx](https://github.com/projectdiscovery/httpx) | MIT metadata on the upstream repository [14] | **Adopt native wrapper** | HTTP service probing is a bounded recon capability when scope, pacing, redirects, and output size are controlled. | Existing `run_httpx` wrapper and canonical facade remain. Results are observations only and do not count as confirmation or campaign attempts. |
| 15 | [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) | MIT metadata on the upstream repository [15] | **Adopt as bounded recon wrapper** | Subdomain results are useful for attack-surface enrichment but require same-origin/scope filtering and must never expand authorization implicitly. | Existing native tool boundary remains the authority. Imported names require WebPent scope checks before entering the surface graph. |
| 16 | GraphQL security utilities, including [Escape Technologies’ curated list](https://github.com/Escape-Technologies/awesome-graphql-security) | No single upstream project or license; each utility must be reviewed independently | **Defer category; use WebPent-native validator** | “GraphQL utilities” is an ecosystem category rather than one distributable project. Mixed licenses and heterogeneous payload/transport behavior make blanket reuse unsafe. | No third-party GraphQL code imported. WebPent-native GraphQL discovery/validation contracts remain authoritative; each future utility needs an individual license and behavior audit. |

## Current implementation boundary

The adopted items do not create a second execution plane. Nettacker and AutoPentestX are explicitly **import-only**. Katana, Nuclei, HTTPx, and Subfinder remain behind existing WebPent wrappers and policy checks; their outputs are observations or enrichment until WebPent validators independently establish causal evidence. Browser, API property-testing, ZAP, Wapiti, Dalfox, and traffic interception remain deferred because local source presence is not runtime qualification.

The Nettacker adapter is intentionally narrower than a scanner integration. It accepts a bounded event payload, supports common exported containers (`events`, `results`, `records`, `logs`, and `findings`), strips command/request/payload/secret-shaped fields, preserves source provenance, represents timeout/incomplete envelopes as `partial`, and returns `failed` for malformed input. Its surface projection accepts only same-origin HTTP(S) URLs and routes every node to `needs_validator`.

## Acceptance requirements for deferred integrations

Before any deferred project is promoted, the integration must provide a pinned source or binary identity, an explicit license decision, a capability-manifest record, ActionAuthority/ActionLedger binding, bounded timeout and concurrency, cancellation and cleanup semantics, secret redaction, malformed/partial output handling, AST or process-boundary checks, deterministic fixtures, and a target-backed ablation. A tool output that merely names a CVE, severity, payload, or “vulnerable” state is never sufficient for Tool-Confirmed status.

## Verification snapshot

| Check | Result in this loop |
|---|---:|
| Nettacker adapter tests | 10 passed |
| Full project pytest | 991 passed, 0 failures |
| Ruff | Pass |
| Compileall | Pass |
| Unified `verify_all.py` | 145 pass / 0 fail |
| WAPTLab and Juice Shop contact | None; skipped by explicit requirement |

## References

[1]: https://github.com/OWASP/Nettacker "OWASP Nettacker repository and Apache-2.0 metadata"
[2]: https://github.com/zaproxy/zaproxy "OWASP ZAP repository and Apache-2.0 metadata"
[3]: https://github.com/projectdiscovery/katana "ProjectDiscovery Katana repository and MIT metadata"
[4]: https://github.com/wapiti-scanner/wapiti "Wapiti repository and GPL-2.0 metadata"
[5]: https://github.com/GreyDGL/PentestGPT "PentestGPT repository"
[6]: https://github.com/pablosnt/rekono "Rekono repository"
[7]: https://github.com/microsoft/playwright "Microsoft Playwright repository"
[8]: https://github.com/apify/crawlee "Apify Crawlee repository"
[9]: https://github.com/schemathesis/schemathesis "Schemathesis repository"
[10]: https://github.com/RUB-NDS/REST-Attacker "REST-Attacker repository"
[11]: https://github.com/hahwul/dalfox "Dalfox repository"
[12]: https://github.com/mitmproxy/mitmproxy "mitmproxy repository"
[13]: https://github.com/projectdiscovery/nuclei "ProjectDiscovery Nuclei repository"
[14]: https://github.com/projectdiscovery/httpx "ProjectDiscovery HTTPx repository"
[15]: https://github.com/projectdiscovery/subfinder "ProjectDiscovery Subfinder repository"
[16]: https://github.com/Escape-Technologies/awesome-graphql-security "Curated GraphQL security utilities list"
