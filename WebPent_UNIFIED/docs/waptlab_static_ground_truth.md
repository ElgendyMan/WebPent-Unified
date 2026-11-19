# WAPTLab Static Ground Truth

**Target source:** `selimwdev/WAPTLab`, commit `00de7bdb25a45938eb1b3d6711bf342c7cefb7b7`.

This document records source-level evidence only. It is not a live exploit report. Live confirmation requires the Docker target; the sandbox Docker build was blocked by the missing iptables `raw` table, so the later mock results are labeled separately.

| # | Campaign | Static evidence and expected surface |
|---:|---|---|
| 1 | Header-assisted SQLi | `XffLog`/header logging and query construction are present in the application source; the campaign is mapped to header/query/logging surfaces. |
| 2 | CSV ingestion SQLi | `CsvImportController` processes uploaded rows and contains a string-built SQL path for `values` inserts, while other inserts use prepared statements. |
| 3 | JWT-encoded path traversal | `CrmController::viewCsv()` decodes a JWT `path` payload and concatenates it with `storage_path('app/')` without canonicalization before `response()->file()`. |
| 4 | Double-slash open redirect | Redirect surfaces are present in OAuth/redirect flows; the mock reproduces `//host` handling for detector coverage. |
| 5 | OAuth redirect URI validation | `OauthController::approve()` accepts `redirect_uri`, performs a naive suffix-based host check, and ultimately uses `redirect()->away()`. |
| 6 | Download IDOR | `CrmController::downloadRow($id)` reads `storage/app/crm_rows/{id}.json` and returns it without an ownership check; the route is `/crm/download/{id}`. |
| 7 | Tenant context switching | Dashboard and dashboard-data routes derive `$db` from the query string and use it to choose the Elasticsearch index; the route family is `/dashboard?db=` and `/api/dashboard/data?db=`. |
| 8 | Training-email SSTI | `TemplateController` is a defensive/simulated path: it validates and replaces an allow-listed set of placeholders rather than compiling arbitrary Blade. The README campaign remains a coverage target, but source evidence is not sufficient to call arbitrary SSTI live. |
| 9 | Export-flow SSTI | `CrmController::exportData()` detects `{{`/`{!!` and calls `Blade::render($value, $context)` on user-controlled row values before rendering the export view. |
| 10 | Swagger URL SSRF | `/swagger_ui` accepts `url`/`configUrl`, validates only URL syntax, blocks some IPv4 private literals, then performs cURL with redirects enabled. IPv6 loopback handling returns a deterministic marker. |
| 11 | Image-fetch SSRF | `UserProfileController::fetchImageFromUrl()` accepts a URL, performs weak initial hostname filtering, follows redirects with cURL, and reports final URL information. |
| 12 | Stored profile XSS | Profile update stores user-controlled `description`; the profile view renders description with an unescaped Blade expression (`{!! !!}`). |
| 13 | Quoted-field XSS | Profile `name`/`email` are stored and rendered in form/attribute contexts; the campaign targets malformed quoting and context-specific encoding. |
| 14 | Elasticsearch snapshot traversal | `/elasticsearch` URL-decodes the path, validates a snapshot name, preserves the remainder, forwards the URL, and emits a marker when `..` remains in the post-snapshot path. |
| 15 | Public backup disclosure | The repository contains backup/artifact surfaces expected to be reachable without authentication; the mock exposes `.env`, `composer.lock.bak`, log, and SQL backup paths as non-secret markers. |
| 16 | Laravel debug mode | Runtime compose explicitly overrides `APP_DEBUG` to false, and `.env.example` also sets false; this campaign therefore requires environment/runtime evidence and must not be claimed solely from source. The mock exposes a debug-shaped error only for detector coverage. |
| 17 | Outdated frontend component | `package.json`/`package-lock.json` and built assets are the source of truth for dependency/version review; the mock exposes a versioned JavaScript asset for passive JS intelligence. |
| 18 | Exposed Elasticsearch dependency | Compose publishes Elasticsearch ports and the service advertises version metadata; the original compose also contains a broad host-root mount, which is a deployment risk. The mock emits an Elasticsearch-like `Server` header. |
| 19 | OOB XXE | `ParseXmlRequests` enables `LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR`; `CsvImportController` also parses XML with external entity/DTD resolution. This is a concrete parser sink, but OOB confirmation requires a callback-capable live target. |
| 20 | XSLT/XXE injection | `CsvImportController` accepts XML/XSLT input, enables entity/DTD features, and invokes `XSLTProcessor->transformToXML()`, giving a concrete `document()`/copy-of processing surface. |

## Runtime boundary

The repository was cloned unchanged. Docker and Compose were installed, but the image build could not create Docker's bridge endpoint because the sandbox kernel lacks the iptables `raw` table. No WAPTLab source file was modified. Therefore, this document intentionally distinguishes static source evidence from mock validation and does not mark any vulnerability as live-confirmed.
