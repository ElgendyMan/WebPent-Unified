# src/webpent/remediation/context_guide.py
"""webpent.remediation.context_guide

Context guidance: when a weakness class is tolerable, risky, or dangerous
depending on where it appears.

ADVISORY-ONLY reference text keyed by ``VulnClass``. The same technical
weakness has very different real-world risk depending on context: a
reflected-value sink in an admin-only page is not the same exposure as the
same sink on the public landing page. This module states those tiers so a
developer can prioritize honestly. It never inspects a target and never
executes anything; it renders static tiers for a class the caller supplies.

For an unmapped class the structure is returned with empty tiers and an
explicit note, so callers can render an honest "no guidance" instead of
inventing context claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webpent.models.findings import VulnClass
from webpent.remediation.patterns_db import get_pattern


@dataclass(frozen=True)
class ContextTier:
    """Acceptable / warning / dangerous contexts for one class."""

    acceptable: tuple[str, ...] = field(default_factory=tuple)
    warning: tuple[str, ...] = field(default_factory=tuple)
    dangerous: tuple[str, ...] = field(default_factory=tuple)
    note: str = ""


_TIERS: dict[VulnClass, ContextTier] = {
    VulnClass.XSS: ContextTier(
        acceptable=(
            "static templates with no user data in the render path",
            "user data rendered exclusively through a context-aware "
            "auto-escaping engine",
        ),
        warning=(
            "user data reaches an admin-facing page only",
            "rich-text input accepted with a server-side sanitizer "
            "that is not covered by regression tests",
        ),
        dangerous=(
            "user data reflected into public pages without encoding",
            "stored payloads visible to other users (comments, "
            "profiles, uploads)",
            "DOM sinks fed from URL fragments or postMessage",
        ),
        note="Stored, cross-user reflections are the exploitable tier; "
        "a self-only reflection is a finding to fix, not an incident.",
    ),
    VulnClass.SQLI: ContextTier(
        acceptable=(
            "all queries parameterized or built through a query builder",
        ),
        warning=(
            "dynamic ORDER BY / column names with a strict allowlist",
        ),
        dangerous=(
            "any string concatenation of request data into a query",
            "stored procedures assembled from concatenated input",
        ),
    ),
    VulnClass.SSRF: ContextTier(
        acceptable=(
            "outbound fetches restricted to a static internal allowlist",
        ),
        warning=(
            "fetches of user URLs restricted by hostname allowlist "
            "without DNS-rebinding protection",
        ),
        dangerous=(
            "user-controlled URLs fetched with redirects followed",
            "fetchers reachable from cloud hosts (metadata endpoint "
            "in range)",
        ),
    ),
    VulnClass.LFI: ContextTier(
        dangerous=(
            "user-controlled paths reach include/require or file reads",
            "uploads directory readable as code",
        ),
        warning=("path handling via framework router with escaping only",),
    ),
    VulnClass.RFI: ContextTier(
        dangerous=(
            "include path accepts remote URLs at all",
            "URL wrappers enabled with user input in the path",
        ),
    ),
    VulnClass.RCE: ContextTier(
        dangerous=(
            "any eval, exec, or dynamic-deserialize path fed from "
            "request data",
            "deserialization of user-controlled bytes",
        ),
        warning=("expression engines fed user data with sandboxing",),
        acceptable=("all dynamic evaluation paths removed",),
    ),
    VulnClass.SSTI: ContextTier(
        dangerous=(
            "user data concatenated into the template string",
            "template name chosen from request data",
        ),
        acceptable=("user data passed only as render variables",),
    ),
    VulnClass.OPEN_REDIRECT: ContextTier(
        dangerous=(
            "redirect target taken from the request with no validation",
            "redirect used in an authentication or email flow (phishing "
            "laundering)",
        ),
        warning=("referrer-only validation",),
        acceptable=("redirect targets from a fixed allowlist",),
    ),
    VulnClass.XXE: ContextTier(
        dangerous=(
            "XML from users parsed with entity resolution enabled",
            "SOAP/DOCX endpoints on legacy parsers",
        ),
        acceptable=("parsers built with entities disabled and no network",),
    ),
    VulnClass.CSRF: ContextTier(
        dangerous=(
            "state-changing endpoints without a token or SameSite "
            "protection",
            "CORS reflecting arbitrary origins with credentials",
        ),
        warning=("token issued but not bound to the session",),
        acceptable=("per-session tokens plus SameSite=Strict/Lax cookies",),
    ),
    VulnClass.DESERIALIZATION: ContextTier(
        dangerous=(
            "pickle/marshal/native deserialization of request bytes",
            "deserialized data reaching class instantiation",
        ),
        warning=("deserialization of authenticated-only traffic",),
        acceptable=("data-only formats (JSON) with schema validation",),
    ),
    VulnClass.PATH_TRAVERSAL: ContextTier(
        dangerous=(
            "user names or paths joined onto storage roots without "
            "containment checks",
            "download/preview endpoints taking raw paths",
        ),
        acceptable=("random server-generated storage keys, id lookups only",),
    ),
    VulnClass.COMMAND_INJECTION: ContextTier(
        dangerous=(
            "shell=True (or equivalent) with any request-derived argument",
            "string-built commands from filenames or URLs",
        ),
        acceptable=("argument-vector execution with no shell involved",),
    ),
    VulnClass.NOSQL_INJECTION: ContextTier(
        dangerous=(
            "document/array request bodies merged into queries",
            "string-built queries for aggregation stages",
        ),
        acceptable=("scalar casting and typed drivers only",),
    ),
    VulnClass.INFO_DISCLOSURE: ContextTier(
        dangerous=(
            "stack traces, versions, or keys returned to anonymous "
            "callers",
            "API responses containing other users' fields",
        ),
        warning=("verbose errors in authenticated contexts",),
        acceptable=("deliberate public documentation of public metadata",),
    ),
    VulnClass.RACE_CONDITION: ContextTier(
        dangerous=(
            "check-then-use over money, quotas, or one-time tokens "
            "without locking",
            "email/2FA verification flows consumable concurrently",
        ),
        acceptable=("atomic transactions or per-key locks on every "
            "check-then-use",),
    ),
    VulnClass.IDOR: ContextTier(
        dangerous=(
            "object access by raw identifier with no ownership check",
            "export/report endpoints deriving scope from the request "
            "alone",
        ),
        warning=("ownership enforced in UI but not server-side",),
        acceptable=("server-side scope derived from the session on every "
            "object read",),
    ),
    VulnClass.AUTH_BYPASS: ContextTier(
        dangerous=(
            "default credentials, magic headers, or debug endpoints "
            "reachable in production",
            "authentication skipped on internal-seeming paths",
        ),
        acceptable=("fail-closed auth middleware on every route",),
    ),
    VulnClass.MASS_ASSIGNMENT: ContextTier(
        dangerous=(
            "request body bound onto privileged models (users, orders, "
            "payments)",
        ),
        warning=("field allowlists without regression tests",),
        acceptable=("explicit field binding with tests",),
    ),
    VulnClass.REQUEST_SMUGGLING: ContextTier(
        dangerous=(
            "proxy chain with mixed HTTP/1.1 and HTTP/2 framing rules",
            "frontends forwarding ambiguous requests",
        ),
        acceptable=("single canonical parser per hop, ambiguity rejected",),
    ),
    VulnClass.BRUTE_FORCE: ContextTier(
        dangerous=(
            "login, reset, and OTP endpoints with no attempt limits",
            "limits keyed only by a spoofable value",
        ),
        warning=("limits reset by account-lockout DoS possible",),
        acceptable=("progressive limits with generic responses",),
    ),
    VulnClass.CAPTCHA: ContextTier(
        dangerous=(
            "client-side-only human checks",
            "challenges reusable across requests",
        ),
        acceptable=("server-issued, single-use, session-bound challenges",),
    ),
    VulnClass.WEAK_SESSION: ContextTier(
        dangerous=(
            "sessions not invalidated on logout or password change",
            "predictable or short session tokens",
        ),
        acceptable=("rotation on privilege change with server-side "
            "invalidation",),
    ),
    VulnClass.CSP: ContextTier(
        dangerous=(
            "no CSP on pages rendering user data",
            "unsafe-inline/unsafe-eval scripts anywhere",
        ),
        warning=("CSP present but allowing broad hosts",),
        acceptable=("nonce- or hash-based script policy, object-src none",),
    ),
    VulnClass.JAVASCRIPT: ContextTier(
        dangerous=(
            "innerHTML/eval fed from URL fragments, postMessage, or "
            "cross-window data",
        ),
        warning=("third-party scripts with broad DOM access",),
        acceptable=("textContent/safe APIs for all untrusted data",),
    ),
    VulnClass.CRYPTOGRAPHY: ContextTier(
        dangerous=(
            "hardcoded keys, ECB mode, static IVs",
            "custom primitives in authentication paths",
        ),
        acceptable=("standard library AEAD with managed key rotation",),
    ),
    VulnClass.API_ISSUE: ContextTier(
        dangerous=(
            "unauthenticated or under-authorized API versions",
            "verbose API errors and mass-response fields",
        ),
        acceptable=("shared auth/filtering policy across all versions",),
    ),
    VulnClass.SUBDOMAIN_TAKEOVER: ContextTier(
        dangerous=(
            "dangling DNS records pointing at claimable services",
            "wildcard DNS with unclaimed targets",
        ),
        acceptable=("DNS inventory reconciled against live services",),
    ),
    VulnClass.CLOUD_STORAGE_EXPOSURE: ContextTier(
        dangerous=(
            "anonymous listing or reading on buckets holding user data",
            "bucket policies with wildcard principals",
        ),
        acceptable=("public access blocked at account level; public "
            "assets isolated",),
    ),
    VulnClass.JWT_WEAKNESS: ContextTier(
        dangerous=(
            "signature verification skipped or algorithm accepted from "
            "the token",
        ),
        warning=("long-lived tokens without revocation",),
        acceptable=("pinned algorithm, short TTL, server-side revocation",),
    ),
    VulnClass.JWT_KEY_CONFUSION: ContextTier(
        dangerous=(
            "one verification call site accepting both HMAC and "
            "asymmetric algorithms",
        ),
        acceptable=("algorithm pinned server-side per issuer",),
    ),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: ContextTier(
        dangerous=(
            "cluster APIs reachable without authentication from any "
            "network",
        ),
        warning=("authenticated but over-privileged snapshot roles",),
        acceptable=("auth enabled, private bind, snapshot roles scoped",),
    ),
    VulnClass.XSLT_INJECTION: ContextTier(
        dangerous=(
            "attacker-supplied stylesheets compiled with extension "
            "functions enabled",
        ),
        acceptable=("stylesheets from a versioned internal set only",),
    ),
    # UM-DR-25: blind OOB + privilege-differential families.
    VulnClass.BLIND_SSRF: ContextTier(
        dangerous=("any URL from user input fetched server-side",),
        acceptable=("destination-allowlisted fetches with no "
                    "redirect following",),
    ),
    VulnClass.XXE_OOB: ContextTier(
        dangerous=("XML parsing with DTDs and external entities "
                    "enabled",),
        acceptable=("DTD processing disabled on every parser",),
    ),
    VulnClass.BLIND_SQLI: ContextTier(
        dangerous=("SQL assembled by string concatenation",),
        acceptable=("parameterized statements only",),
    ),
    VulnClass.PRIVILEGE_DIFFERENTIAL: ContextTier(
        dangerous=("authorization enforced only on navigation/UI "
                    "routes",),
        acceptable=("the same server-side decision on every read "
                    "path",),
    ),

    # ULTIMATE PLAN 2026-10-27 (proposals 1/7).
    VulnClass.BUSINESS_LOGIC: ContextTier(
        acceptable=("server-side totals from pinned price tables",),
        warning=("workflow state machines with client-visible steps",),
        dangerous=("client-supplied prices, discounts, or totals",),
        note="Business rules must be enforced server-side at the "
             "boundary, never reconstructed from client data.",
    ),
    VulnClass.MULTI_STEP_AUTH_BYPASS: ContextTier(
        acceptable=("session issued only after every stage verifies",),
        warning=("stage-skipping for remembered devices",),
        dangerous=("session issue reachable with a stage skipped",),
        note="The completion proof of a multi-stage flow must be "
             "server-side state, not the absence of an error.",
    ),
    VulnClass.TENANT_ISOLATION: ContextTier(
        acceptable=("every data access carries a tenant predicate",),
        warning=("tenant filtered only in the UI or serializer",),
        dangerous=("object lookups by id with no tenant filter",),
        note="Tenant isolation belongs in the data-access layer where "
             "it cannot be forgotten by a new code path.",
    ),
    VulnClass.EXPLOIT_CHAIN: ContextTier(
        acceptable=("each finding fixed at its own boundary",),
        warning=("low-severity findings on the same trust path",),
        dangerous=("chained paths confirmed end to end",),
        note="Chains are fixed link by link; retest the whole path "
             "after the last link closes.",
    ),
    VulnClass.OAUTH: ContextTier(
        acceptable=("signature, audience, and state all verified",),
        warning=("token shape checked, one artifact unverified",),
        dangerous=("any JWT-shaped token accepted",),
        note="An OAuth decision is only as good as the artifacts it "
             "verified — presence of a token proves nothing.",
    ),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: ContextTier(
        acceptable=("introspection off in production",),
        warning=("introspection behind authentication",),
        dangerous=("open __schema on the public endpoint",),
        note="Turn introspection off in production; schema docs are "
             "for the team, not the internet.",
    ),
    VulnClass.GRAPHQL_BATCHING_ABUSE: ContextTier(
        acceptable=("batch size capped and counted per query",),
        warning=("batches allowed but rate-limited per request",),
        dangerous=("unbounded query arrays in one request",),
        note="Rate limits must count operations, not requests, or "
             "batching becomes a limit bypass.",
    ),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: ContextTier(
        acceptable=("generic validation errors in production",),
        warning=("suggestions enabled for logged-in developers",),
        dangerous=("did-you-mean echoes on public errors",),
        note="Suggestion text is a field-name oracle; strip it from "
             "production error responses.",
    ),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: ContextTier(
        acceptable=("depth and complexity limits reject early",),
        warning=("limits high enough to pass normal traffic only",),
        dangerous=("no depth/complexity guard before execution",),
        note="Reject over-deep queries before any resolver runs; "
             "limits are a availability control, not a style choice.",
    ),
    VulnClass.PROTOTYPE_POLLUTION: ContextTier(
        acceptable=("merge libraries with __proto__ protection",),
        warning=("path-set APIs on user-shaped keys",),
        dangerous=("recursive merge of raw request bodies",),
        note="Block __proto__ and constructor keys at the JSON parser "
             "boundary and in every merge helper.",
    ),
    VulnClass.OAUTH_MISCONFIGURATION: ContextTier(
        acceptable=("exact-match registered redirect URIs + state",),
        warning=("prefix or scheme-relative URI matching",),
        dangerous=("arbitrary absolute redirect_uri accepted",),
        note="Redirect URIs match exactly against a per-client "
             "registration; state is mandatory and single-use.",
    ),
    VulnClass.CACHE_POISONING: ContextTier(
        acceptable=("unkeyed inputs never reach the rendered body",),
        warning=("cache present; unkeyed headers read for routing",),
        dangerous=("cached body rendered from X-Forwarded-* input",),
        note="Everything that shapes a cacheable response must be in "
             "the cache key or stripped before render.",
    ),
    VulnClass.WEB_CACHE_DECEPTION: ContextTier(
        acceptable=("authenticated routes marked no-store",),
        warning=("extension-based cacheability rules",),
        dangerous=("authenticated pages cached via suffix tricks",),
        note="Authenticated content is never cacheable regardless of "
             "the path's file extension.",
    ),

}

_UNMAPPED_NOTE = (
    "No context guidance exists for this class yet; do not guess tiers."
)


def context_guidance(vuln_class: VulnClass | str) -> dict[str, object]:
    """Tier structure for a class; empty tiers plus a note when unmapped."""
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return {
                "acceptable": [], "warning": [], "dangerous": [],
                "note": _UNMAPPED_NOTE, "known": False,
            }
    tier = _TIERS.get(vuln_class)
    if tier is None or get_pattern(vuln_class) is None:
        return {
            "acceptable": [], "warning": [], "dangerous": [],
            "note": _UNMAPPED_NOTE, "known": False,
        }
    note = tier.note or (
        "Acceptable means the weakness cannot be reached from untrusted "
        "input in this context; dangerous means an external attacker can "
        "reach it as-is."
    )
    return {
        "acceptable": list(tier.acceptable),
        "warning": list(tier.warning),
        "dangerous": list(tier.dangerous),
        "note": note,
        "known": True,
    }
