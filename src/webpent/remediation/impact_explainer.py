# src/webpent/remediation/impact_explainer.py
"""webpent.remediation.impact_explainer

Business-impact narratives and interim mitigations per class.

ADVISORY-ONLY: the impact text explains, in business terms, what a
successfully exploited finding of this class would cost, and the interim
mitigations are containment a human operator can apply today (WAF rules,
feature flags, credential rotation) while the real fix lands. Nothing here
executes, contacts anything, or claims a specific finding's impact: the
text is class-level, and the finding's own severity decides ordering in
the reports built on top.

Unmapped classes get an honest empty result with a reason.
"""

from __future__ import annotations

from webpent.models.findings import VulnClass
from webpent.remediation.patterns_db import get_pattern

_IMPACTS: dict[VulnClass, tuple[str, tuple[str, ...]]] = {
    VulnClass.XSS: (
        "Account takeover of your users: the injected script runs with "
        "each victim's session, so one stored payload can harvest "
        "credentials or transact as every user who views it.",
        ("deploy a WAF rule blocking script-bearing parameters on the "
         "affected route",),
    ),
    VulnClass.SQLI: (
        "Full database compromise: reads, modifications, and, on most "
        "engines, file access and lateral movement from the database "
        "host.",
        ("restrict the database account to the minimum operations the "
         "application needs",),
    ),
    VulnClass.SSRF: (
        "Internal network access from your server's position: cloud "
        "credentials, admin panels, and internal APIs that were never "
        "meant to be reachable.",
        ("egress-restrict the affected service to required destinations "
         "only",),
    ),
    VulnClass.LFI: (
        "Source code and configuration exposure, and code execution "
        "where uploads are included.",
        ("make the affected endpoint return a fixed error until "
         "patched",),
    ),
    VulnClass.RFI: (
        "Remote code execution on the server: the attacker controls "
        "what the machine runs.",
        ("take the affected endpoint offline until patched",),
    ),
    VulnClass.RCE: (
        "Server takeover: arbitrary code at the application's privilege "
        "level, typically the first step to full environment compromise.",
        ("isolate the affected host and rotate every credential it "
         "held",),
    ),
    VulnClass.SSTI: (
        "Server takeover through the template engine's execution "
        "surface.",
        ("block template syntax in the affected parameter at the WAF",),
    ),
    VulnClass.OPEN_REDIRECT: (
        "Phishing credibility: attacks against your users arrive from "
        "your own trusted domain.",
        ("strip unrecognized next/redirect parameters at the edge",),
    ),
    VulnClass.XXE: (
        "File disclosure and internal request capability from any "
        "endpoint parsing attacker XML.",
        ("disable entity resolution immediately on the affected parser",),
    ),
    VulnClass.CSRF: (
        "State changes performed as your users without their consent: "
        "profile changes, transfers, grants.",
        ("set SameSite=Lax/Strict on session cookies now",),
    ),
    VulnClass.DESERIALIZATION: (
        "Remote code execution wherever attacker-controlled bytes are "
        "deserialized.",
        ("disable the deserializing endpoint until the format is "
         "replaced",),
    ),
    VulnClass.PATH_TRAVERSAL: (
        "Arbitrary file read or write on the application host, "
        "including configuration and secrets.",
        ("restrict the affected endpoint's filesystem scope",),
    ),
    VulnClass.COMMAND_INJECTION: (
        "Arbitrary command execution at the service account's level.",
        ("isolate the host and audit what the service account could "
         "reach",),
    ),
    VulnClass.NOSQL_INJECTION: (
        "Authentication bypass and unscoped document access in the "
        "affected stores.",
        ("cast request fields to scalars before any query uses them",),
    ),
    VulnClass.INFO_DISCLOSURE: (
        "Reconnaissance gift: internals disclosed here shorten every "
        "other attack against you.",
        ("turn off verbose errors and strip debug headers in the "
         "affected responses",),
    ),
    VulnClass.RACE_CONDITION: (
        "Financial and quota integrity: limits and balances can be "
        "spent twice by concurrency alone.",
        ("add a temporary per-account idempotency lock on the affected "
         "operation",),
    ),
    VulnClass.IDOR: (
        "Cross-tenant data exposure: one user reads or modifies "
        "another's objects, quietly and at scale.",
        ("enforce an ownership filter on the affected endpoints "
         "immediately",),
    ),
    VulnClass.AUTH_BYPASS: (
        "Unauthenticated access to privileged surfaces: the control "
        "you believe protects an area does not exist for an attacker.",
        ("restrict the affected path at the edge pending a real fix",),
    ),
    VulnClass.MASS_ASSIGNMENT: (
        "Privilege escalation through crafted request fields on "
        "registration or profile updates.",
        ("drop unknown fields at the framework binding layer now",),
    ),
    VulnClass.REQUEST_SMUGGLING: (
        "Cache poisoning and control bypass for every user behind the "
        "affected proxy chain.",
        ("reject ambiguous framing (CL+TE) at the frontend",),
    ),
    VulnClass.BRUTE_FORCE: (
        "Credential compromise at automation speed for every account "
        "without a limit.",
        ("enable progressive rate limiting on the affected endpoints",),
    ),
    VulnClass.CAPTCHA: (
        "Machine-speed abuse of any flow the check was protecting: "
        "registration, voting, password reset.",
        ("add server-side one-time challenge validation",),
    ),
    VulnClass.WEAK_SESSION: (
        "Session hijacking that survives logout and password changes, "
        "defeating the user's own recovery steps.",
        ("invalidate all active sessions and rotate the session secret",),
    ),
    VulnClass.CSP: (
        "Exploit-amplification: every future injection on these pages "
        "becomes a working XSS with no extra step.",
        ("add a restrictive CSP in report-only mode today, enforcing "
         "after review",),
    ),
    VulnClass.JAVASCRIPT: (
        "Client-side compromise inside your origin, invisible to "
        "server-side logging.",
        ("replace dangerous DOM sinks with safe text APIs",),
    ),
    VulnClass.CRYPTOGRAPHY: (
        "Confidentiality of everything the primitive protects: "
        "tokens, sessions, or data at rest.",
        ("rotate the affected keys and re-encrypt with a standard "
         "AEAD scheme",),
    ),
    VulnClass.API_ISSUE: (
        "Silent control bypass: attackers route around the hardened "
        "web app through a weaker API version.",
        ("disable the affected API version until its controls match",),
    ),
    VulnClass.SUBDOMAIN_TAKEOVER: (
        "Trusted-subdomain content control: cookie-scoped attacks "
        "against your users and email reputation damage.",
        ("remove the dangling DNS record now",),
    ),
    VulnClass.CLOUD_STORAGE_EXPOSURE: (
        "Bulk data exposure: everything in the bucket is public, "
        "including what users assume is private.",
        ("block public access at the account level immediately",),
    ),
    VulnClass.JWT_WEAKNESS: (
        "Complete identity forgery: any claim, any user, any role, "
        "without a secret.",
        ("re-issue all tokens under a verified scheme and invalidate "
         "old ones",),
    ),
    VulnClass.JWT_KEY_CONFUSION: (
        "Complete identity forgery through algorithm confusion, "
        "without knowing any secret.",
        ("pin the algorithm per issuer at every verification site",),
    ),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: (
        "Full-cluster data access: indexes, documents, and snapshots "
        "read or restored by an unauthenticated caller.",
        ("enable security on the cluster and restrict its bind "
         "address now",),
    ),
    VulnClass.XSLT_INJECTION: (
        "Code execution or arbitrary file read through the XSLT "
        "processor.",
        ("disable extension functions and document resolution on the "
         "processor",),
    ),
    # UM-DR-25: blind OOB + privilege-differential families.
    VulnClass.BLIND_SSRF: (
        "Blind server-side request forgery: internal services can "
        "be reached and probed even when responses never return.",
        ("allowlist outbound destinations and block the callback "
         "path now",),
    ),
    VulnClass.XXE_OOB: (
        "External entity processing: internal files and services "
        "are readable through the XML parser.",
        ("disable DTD processing and external entity resolution",),
    ),
    VulnClass.BLIND_SQLI: (
        "Blind SQL injection: the query layer executes attacker "
        "input even without reflected output.",
        ("parameterize the query and remove string-built SQL",),
    ),
    VulnClass.PRIVILEGE_DIFFERENTIAL: (
        "Cross-principal access: a low-privilege principal reads "
        "restricted resources a proven control says they cannot "
        "reach.",
        ("enforce the same authorization decision on every read "
         "path, not only the UI routing",),
    ),

    # ULTIMATE PLAN 2026-10-27 (proposals 1/7).
    VulnClass.BUSINESS_LOGIC: (
        "Direct financial loss: manipulated prices, discounts, or "
        "quotas are charged or granted exactly as the attacker shaped "
        "them, and the discrepancy often reconciles silently.",
        ("re-price server-side from pinned tables until the boundary "
         "fix ships",),
    ),
    VulnClass.MULTI_STEP_AUTH_BYPASS: (
        "Full account takeover: the attacker holds a session the "
        "application itself issued, so every in-app action appears "
        "legitimate in the audit trail.",
        ("rate-limit and alert on session-issue requests that skip a "
         "stage",),
    ),
    VulnClass.TENANT_ISOLATION: (
        "Cross-tenant breach of every record reachable through the "
        "unfiltered lookup — regulatory exposure (GDPR data transfers "
        "between controllers) on top of the direct data loss.",
        ("add an emergency tenant predicate at the data-access layer",
         "rotate any tenant-scoped tokens that were exposed",),
    ),
    VulnClass.EXPLOIT_CHAIN: (
        "The chain's impact is the top link's impact: individually "
        "acceptable findings compose into critical outcomes, which is "
        "why severity must be re-scored per confirmed chain.",
        ("break the cheapest link first — usually the redirect or the "
         "leak — then retest the full path",),
    ),
    VulnClass.OAUTH: (
        "Authentication bypass at the decision point: whatever the "
        "token unlocks (data scopes, identity assertions) is granted "
        "without proof.",
        ("reject unsigned/unsig-verifiable tokens at the gateway",
         "alert on tokens with unfamiliar key ids",),
    ),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: (
        "Complete attack-surface disclosure: hidden fields, deprecated "
        "operations, and admin-adjacent types are enumerated without "
        "a single invalid request.",
        ("disable introspection at the gateway rule layer",
         "review hidden fields for their own missing authorization",),
    ),
    VulnClass.GRAPHQL_BATCHING_ABUSE: (
        "Rate-limit collapse: the attacker's effective volume scales "
        "with batch size, so per-user limits and cost budgets both "
        "miss.",
        ("cap accepted batch size at the schema validation layer",),
    ),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: (
        "Silent surface enumeration: undocumented fields (often admin "
        "or internal) are discovered one typo at a time, feeding the "
        "next, sharper attack.",
        ("strip suggestion text from production error responses",),
    ),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: (
        "Availability loss: one request fans out into exponential "
        "resolver work, stalling the endpoint for every user.",
        ("apply a temporary WAF rule rejecting over-deep queries",
         "scale resolver timeouts down so deep queries fail fast",),
    ),
    VulnClass.PROTOTYPE_POLLUTION: (
        "Logic corruption for every user of the affected runtime: one "
        "polluted key silently changes validation, routing, or "
        "authorization behavior process-wide.",
        ("block __proto__/constructor keys at the parser boundary",
         "audit merge helpers for reachability from request bodies",),
    ),
    VulnClass.OAUTH_MISCONFIGURATION: (
        "Authorization-code theft and account takeover: the flow "
        "itself delivers the code or token to the attacker's host.",
        ("switch redirect matching to exact-match against the "
         "registration list",),
    ),
    VulnClass.CACHE_POISONING: (
        "Every visitor of the cached path receives the attacker's "
        "content in your origin's name — stored-XSS scale impact from "
        "a single request.",
        ("strip X-Forwarded-* input at the edge until the key/strip "
         "fix ships",),
    ),
    VulnClass.WEB_CACHE_DECEPTION: (
        "Private authenticated content is served unauthenticated from "
        "your own cache — the exposure persists until the cache entry "
        "expires.",
        ("purge cached copies of the affected authenticated routes",
         "mark authenticated responses no-store at the edge",),
    ),
}

_GENERIC_IMPACT = (
    "Impact depends on what the affected component protects; fix the "
    "underlying weakness and re-assess."
)


def business_impact(vuln_class: VulnClass | str) -> dict[str, object]:
    """Impact narrative plus interim mitigations; honest when unmapped."""
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return {"impact": _GENERIC_IMPACT, "interim_mitigations": [],
                    "known": False}
    if get_pattern(vuln_class) is None:
        return {"impact": _GENERIC_IMPACT, "interim_mitigations": [],
                "known": False}
    impact, mitigations = _IMPACTS[vuln_class]
    return {
        "impact": impact,
        "interim_mitigations": list(mitigations),
        "known": True,
    }
