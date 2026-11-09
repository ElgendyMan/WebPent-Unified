# src/webpent/remediation/verification_steps.py
"""webpent.remediation.verification_steps

Post-fix verification checklists per class, written for the human who
applied the fix.

ADVISORY-ONLY and explicitly NOT executed by the framework: these are
instructions for a person verifying a remediation. The framework never
re-tests a target from this module; the only re-testing that happens in
WebPent runs through the deterministic validators and sealed proof bundles
in the normal hunt loop. Each checklist asks for three things: the
class-specific retest, the negative control staying clean, and a
regression test so the fix cannot silently regress.

Unmapped classes return an empty list, honestly.
"""

from __future__ import annotations

from webpent.models.findings import VulnClass
from webpent.remediation.patterns_db import get_pattern

_CHECKLISTS: dict[VulnClass, tuple[str, ...]] = {
    VulnClass.XSS: (
        "retest: submit script-bearing values on the affected route and "
        "confirm they render as text in every context (body, attribute, JS)",
        "negative control: previously clean routes stay clean",
        "regression: add an output-encoding test for the sink that fired",
    ),
    VulnClass.SQLI: (
        "retest: submit query-syntax values on the affected parameter and "
        "confirm the response is unchanged from a benign value",
        "negative control: valid queries still return correct results",
        "regression: add a parameterization lint/test over the changed "
        "query construction",
    ),
    VulnClass.SSRF: (
        "retest: submit internal and metadata URLs and confirm they are "
        "blocked before any connection is attempted",
        "negative control: allowlisted destinations still work",
        "regression: add a destination-allowlist unit test",
    ),
    VulnClass.LFI: (
        "retest: request traversal and absolute paths and confirm refusal",
        "negative control: legitimate resources still load",
        "regression: pin the id-to-resource map in a test",
    ),
    VulnClass.RFI: (
        "retest: submit remote URLs and confirm the include path rejects "
        "them",
        "negative control: local templates still render",
        "regression: test the path-construction helper",
    ),
    VulnClass.RCE: (
        "retest: submit evaluation syntax and confirm it is stored or "
        "rejected as data",
        "negative control: allowed operations still execute",
        "regression: test the operation lookup table",
    ),
    VulnClass.SSTI: (
        "retest: submit template syntax and confirm it renders as text",
        "negative control: legitimate render variables still display",
        "regression: test that user data never joins the template string",
    ),
    VulnClass.OPEN_REDIRECT: (
        "retest: submit external next targets and confirm the safe "
        "default is used",
        "negative control: internal targets still redirect correctly",
        "regression: test the same-origin validator",
    ),
    VulnClass.XXE: (
        "retest: submit XML with external entities and confirm they do "
        "not resolve",
        "negative control: valid documents still parse",
        "regression: assert parser flags in a construction test",
    ),
    VulnClass.CSRF: (
        "retest: post the state change without a token and confirm "
        "refusal",
        "negative control: requests carrying the session's token succeed",
        "regression: test token validation on the changed endpoint",
    ),
    VulnClass.DESERIALIZATION: (
        "retest: submit crafted serialized bytes and confirm the format "
        "is rejected",
        "negative control: legitimate payloads still process",
        "regression: test the schema validation layer",
    ),
    VulnClass.PATH_TRAVERSAL: (
        "retest: submit traversal sequences and absolute paths and "
        "confirm containment refusal",
        "negative control: files inside the base directory still open",
        "regression: test the containment check directly",
    ),
    VulnClass.COMMAND_INJECTION: (
        "retest: submit shell metacharacters and confirm they arrive as "
        "literal arguments",
        "negative control: legitimate operations still succeed",
        "regression: assert shell=False (or equivalent) in a test",
    ),
    VulnClass.NOSQL_INJECTION: (
        "retest: submit operator structures and confirm they are cast "
        "to scalars or rejected",
        "negative control: normal documents still match",
        "regression: test the scalar-casting helper",
    ),
    VulnClass.INFO_DISCLOSURE: (
        "retest: request the affected surfaces and confirm sensitive "
        "fields and stack traces are absent",
        "negative control: the intended fields are still returned",
        "regression: pin the response projection in a test",
    ),
    VulnClass.RACE_CONDITION: (
        "retest: send the constrained request concurrently and confirm "
        "exactly one success",
        "negative control: sequential requests behave as before",
        "regression: add a concurrency test over the locked path",
    ),
    VulnClass.IDOR: (
        "retest: request another user's object and confirm refusal",
        "negative control: the owner's request still succeeds",
        "regression: add a cross-user authorization test",
    ),
    VulnClass.AUTH_BYPASS: (
        "retest: reach the protected surface without credentials and "
        "confirm refusal",
        "negative control: legitimate authentication still works",
        "regression: test the removed bypass path explicitly",
    ),
    VulnClass.MASS_ASSIGNMENT: (
        "retest: add a privileged field to the request and confirm it "
        "is dropped",
        "negative control: allowed fields still persist",
        "regression: pin the field allowlist in a test",
    ),
    VulnClass.REQUEST_SMUGGLING: (
        "retest: send ambiguous-framing requests and confirm rejection "
        "at the edge",
        "negative control: well-formed requests still pass",
        "regression: add a framing-validation test to the proxy config "
        "pipeline",
    ),
    VulnClass.BRUTE_FORCE: (
        "retest: exceed the attempt threshold and confirm blocking with "
        "a generic response",
        "negative control: a correct credential within limits succeeds",
        "regression: test the limiter configuration",
    ),
    VulnClass.CAPTCHA: (
        "retest: replay or skip the challenge and confirm refusal",
        "negative control: a fresh human-solved challenge succeeds",
        "regression: test single-use consumption of the challenge",
    ),
    VulnClass.WEAK_SESSION: (
        "retest: confirm sessions are invalidated on logout, password "
        "change, and privilege change",
        "negative control: active sessions stay valid across normal use",
        "regression: test rotation on privilege change",
    ),
    VulnClass.CSP: (
        "retest: attempt inline/remote script execution and confirm the "
        "policy blocks it in enforcing mode",
        "negative control: first-party scripts still load",
        "regression: pin the CSP header in a response test",
    ),
    VulnClass.JAVASCRIPT: (
        "retest: feed the former sink untrusted data and confirm safe "
        "rendering",
        "negative control: intended dynamic behavior still works",
        "regression: add a DOM-safety test for the changed component",
    ),
    VulnClass.CRYPTOGRAPHY: (
        "retest: confirm the weak primitive no longer appears in any "
        "encryption or signing path",
        "negative control: data encrypted before the change is still "
        "readable per the migration plan",
        "regression: assert primitive and mode choices in a test",
    ),
    VulnClass.API_ISSUE: (
        "retest: call the affected API version unauthenticated and "
        "cross-tenant and confirm refusal",
        "negative control: the main application's flows are unchanged",
        "regression: apply the shared policy test suite to the API "
        "version",
    ),
    VulnClass.SUBDOMAIN_TAKEOVER: (
        "retest: resolve the subdomain and confirm it no longer points "
        "at claimable infrastructure",
        "negative control: active services still resolve correctly",
        "regression: add a DNS-reconciliation check",
    ),
    VulnClass.CLOUD_STORAGE_EXPOSURE: (
        "retest: attempt anonymous listing and reading and confirm "
        "refusal",
        "negative control: authorized application access still works",
        "regression: pin the access policy in infrastructure tests",
    ),
    VulnClass.JWT_WEAKNESS: (
        "retest: present a token with tampered claims and a token with "
        "an unsigned header; both must be refused",
        "negative control: legitimately issued tokens still verify",
        "regression: test the verification call site's pinned algorithm",
    ),
    VulnClass.JWT_KEY_CONFUSION: (
        "retest: present a token signed with public-key material as an "
        "HMAC secret and confirm refusal",
        "negative control: correctly signed tokens still verify",
        "regression: assert the algorithm pin at every verification site",
    ),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: (
        "retest: call snapshot/repository endpoints unauthenticated and "
        "confirm refusal",
        "negative control: the application's cluster access still works",
        "regression: add an auth-required check to the cluster config "
        "tests",
    ),
    VulnClass.XSLT_INJECTION: (
        "retest: submit a stylesheet with extension functions and "
        "document() calls and confirm both are refused",
        "negative control: allowlisted stylesheets still transform",
        "regression: test the allowlist and processor flags",
    ),
    # UM-DR-25: blind OOB + privilege-differential families.
    VulnClass.BLIND_SSRF: (
        "retest: plant a fresh OOB token and confirm NO callback "
        "arrives inside the evidence window",
        "negative control: a known-fetchable URL still triggers a "
        "callback (the observer works)",
        "regression: assert outbound destinations are allowlisted",
    ),
    VulnClass.XXE_OOB: (
        "retest: submit XML with an external entity at the "
        "collaborator domain and confirm no callback",
        "negative control: well-formed internal XML still parses",
        "regression: assert DTD processing stays disabled",
    ),
    VulnClass.BLIND_SQLI: (
        "retest: submit the callback/delay payload and confirm no "
        "execution signal",
        "negative control: legitimate queries return in normal "
        "time",
        "regression: assert the query is parameterized",
    ),
    VulnClass.PRIVILEGE_DIFFERENTIAL: (
        "retest: the low-privilege principal is refused on the "
        "restricted resource",
        "negative control: the privileged principal still reads it "
        "and the blanket-restricted control still refuses the "
        "low-privilege one",
        "regression: assert the authorization check runs on this "
        "read path",
    ),

    # ULTIMATE PLAN 2026-10-27 (proposals 1/7).
    VulnClass.BUSINESS_LOGIC: (
        "retest: submit the manipulated total and confirm the server "
        "re-derives it from the pinned price table",
        "negative control: legitimate discounted orders still price "
        "correctly",
        "regression: add a boundary test pinning the server-side "
        "pricing rule",
    ),
    VulnClass.MULTI_STEP_AUTH_BYPASS: (
        "retest: replay stage-one completion against the session-issue "
        "endpoint and confirm rejection",
        "negative control: the full flow still issues sessions",
        "regression: add a state-machine test asserting every stage "
        "before issue",
    ),
    VulnClass.TENANT_ISOLATION: (
        "retest: cross-tenant id lookups return not-found, not data",
        "negative control: same-tenant lookups still work",
        "regression: add a data-access test with a two-tenant fixture",
    ),
    VulnClass.EXPLOIT_CHAIN: (
        "retest: walk the previously-confirmed chain end to end and "
        "confirm it breaks at the fixed link",
        "negative control: each link's own fix holds individually",
        "regression: add the chain as a documented test scenario",
    ),
    VulnClass.OAUTH: (
        "retest: unsigned and wrong-key tokens are rejected at the "
        "decision point",
        "negative control: correctly-signed tokens still pass",
        "regression: add signature/audience/state verification tests",
    ),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: (
        "retest: __schema queries on production return the disabled "
        "response",
        "negative control: legitimate operations still resolve",
        "regression: add a config test asserting introspection off "
        "outside dev",
    ),
    VulnClass.GRAPHQL_BATCHING_ABUSE: (
        "retest: an oversized query array is rejected at validation",
        "negative control: within-cap batches still execute",
        "regression: pin the batch cap in a gateway test",
    ),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: (
        "retest: misspelled fields return generic errors",
        "negative control: developer environments keep suggestions if "
        "configured",
        "regression: add an error-shape test on the public endpoint",
    ),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: (
        "retest: an over-deep query is rejected before any resolver "
        "runs",
        "negative control: the deepest legitimate query still passes",
        "regression: pin the depth/complexity limits in tests",
    ),
    VulnClass.PROTOTYPE_POLLUTION: (
        "retest: __proto__/constructor keys are stripped or rejected "
        "at the parser",
        "negative control: legitimate nested JSON still merges",
        "regression: add parser and merge-helper pollution tests",
    ),
    VulnClass.OAUTH_MISCONFIGURATION: (
        "retest: foreign-host and prefix-matched redirect URIs are "
        "rejected",
        "negative control: the exact registered URI still works",
        "regression: add exact-match and state-validation tests",
    ),
    VulnClass.CACHE_POISONING: (
        "retest: poisoned X-Forwarded-* input never reaches the "
        "cached body",
        "negative control: the cache still serves legitimate variants",
        "regression: add a key/strip test for every unkeyed header "
        "read",
    ),
    VulnClass.WEB_CACHE_DECEPTION: (
        "retest: suffix-trick paths on authenticated routes are never "
        "cached",
        "negative control: genuine static assets still cache",
        "regression: add a no-store assertion for authenticated "
        "responses",
    ),
}


def checklist(vuln_class: VulnClass | str) -> list[str]:
    """Human verification steps for a class; empty when unmapped."""
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return []
    if get_pattern(vuln_class) is None:
        return []
    return list(_CHECKLISTS[vuln_class])
