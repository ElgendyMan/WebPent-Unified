"""Phase templates and hypothesis patterns (supports U-CAMPAIGN-2).

The planner does not invent hypotheses from nothing: each family has a
fixed library of hypothesis PATTERNS — statement shapes, success and
failure indicators, probe strategies — assembled deterministically
into concrete hypotheses with ids and estimates.

L-9 note: template selection is pure lookup; two plans from the same
thesis are byte-identical.
"""
from __future__ import annotations

from dataclasses import dataclass

from webpent.campaign.schemas import Family

# How many hypotheses a typical family phase carries (the pivot
# threshold defaults to this — declared up front, L-6).
TYPICAL_HYPOTHESIS_COUNT = 5


@dataclass(frozen=True)
class HypothesisPattern:
    """One reusable hypothesis shape for a family."""

    statement: str
    success_indicator: str
    failure_indicator: str
    probe_strategy: str
    estimated_requests: int = 50
    estimated_llm_calls: int = 2
    estimated_duration_seconds: int = 30


FAMILY_HYPOTHESIS_PATTERNS: dict[Family, list[HypothesisPattern]] = {
    Family.BOLA: [
        HypothesisPattern(
            statement="Object endpoints accept sequential/guessable ids "
                      "without object-level authorization checks",
            success_indicator="Another tenant's/user's object returned",
            failure_indicator="403/404 with proper object scoping",
            probe_strategy="Enumerate object ids across two authorized "
                           "contexts and diff responses",
        ),
        HypothesisPattern(
            statement="Mass-assignment on create/update endpoints accepts "
                      "privileged fields",
            success_indicator="Server accepts and persists a privileged field",
            failure_indicator="Field ignored or rejected",
            probe_strategy="Add suspected privileged fields to update payloads",
        ),
        HypothesisPattern(
            statement="UUID-keyed objects leak through secondary endpoints "
                      "(export, share, embed)",
            success_indicator="Object reachable via secondary route",
            failure_indicator="Secondary routes enforce the same authz",
            probe_strategy="Locate export/share/embed routes for known objects",
        ),
        HypothesisPattern(
            statement="Method-based authz gap: write verbs skip object checks",
            success_indicator="PUT/PATCH/DELETE succeeds on foreign object",
            failure_indicator="All verbs uniformly scoped",
            probe_strategy="Replay GET-authorized object with write verbs",
        ),
    ],
    Family.IDOR: [
        HypothesisPattern(
            statement="Numeric resource ids on user-scoped endpoints are "
                      "enumerable cross-account",
            success_indicator="Foreign resource payload returned",
            failure_indicator="Authorization error on foreign ids",
            probe_strategy="Increment/decrement ids on user-scoped resources",
        ),
        HypothesisPattern(
            statement="Nested resources trust the parent id alone "
                      "(/users/{a}/orders/{b})",
            success_indicator="Child of another parent returned",
            failure_indicator="Parent-child relationship enforced",
            probe_strategy="Cross parent ids with child ids",
        ),
        HypothesisPattern(
            statement="Report/export/download endpoints authorize by "
                      "knowing the filename/id",
            success_indicator="Another user's export downloads",
            failure_indicator="Download denied for foreign ids",
            probe_strategy="Collect export links, swap ids across accounts",
        ),
        HypothesisPattern(
            statement="Soft-deleted/archived records remain readable by id",
            success_indicator="Deleted object still returned",
            failure_indicator="Deleted objects purged from reads",
            probe_strategy="Delete a record, then re-read it by id",
        ),
    ],
    Family.SQLI: [
        HypothesisPattern(
            statement="String parameters reach a query parser without "
                      "parameterization (error-based reachable)",
            success_indicator="SQL error text or boolean-differentiable "
                              "responses",
            failure_indicator="Uniform responses, no parser artifacts",
            probe_strategy="Type-juggling and boolean payloads on string params",
        ),
        HypothesisPattern(
            statement="Order-by/column-name parameters are interpolated",
            success_indicator="Column error reveals query shape",
            failure_indicator="Order parameter whitelisted",
            probe_strategy="Send invalid column/order values and observe errors",
        ),
        HypothesisPattern(
            statement="Search/filter endpoints concatenate user input into "
                      "LIKE clauses",
            success_indicator="Wildcard/quote input changes row set in "
                              "parser-visible ways",
            failure_indicator="Input sanitized",
            probe_strategy="Quote/wildcraft probes on search parameters",
        ),
        HypothesisPattern(
            statement="Legacy endpoints (older API versions) skipped the "
                      "parameterization migration",
            success_indicator="Older version endpoint vulnerable where "
                              "current is not",
            failure_indicator="Uniform protection across versions",
            probe_strategy="Diff payloads across API versions",
        ),
    ],
    Family.SSRF: [
        HypothesisPattern(
            statement="URL-accepting features (webhook, import, fetch "
                      "preview) reach internal ranges",
            success_indicator="Internal-only endpoint observable via the feature",
            failure_indicator="Egress allowlist enforced",
            probe_strategy="Point URL features at loopback/link-local "
                           "references and observe fetches",
        ),
        HypothesisPattern(
            statement="Redirect-following on fetched URLs bypasses the "
                      "allowlist",
            success_indicator="Fetch lands on disallowed host via redirect",
            failure_indicator="Redirects re-validated",
            probe_strategy="Allowlisted host redirecting to internal target",
        ),
        HypothesisPattern(
            statement="DNS rebinding window exists between resolution "
                      "and fetch",
            success_indicator="Second resolution reaches internal address",
            failure_indicator="Pin-checked connections",
            probe_strategy="Short-TTL DNS names alternating records",
        ),
        HypothesisPattern(
            statement="Document/URL metadata processors fetch attacker URLs",
            success_indicator="Processor fetches from internal context",
            failure_indicator="Metadata processing blocks network fetches",
            probe_strategy="Upload documents with external references",
        ),
    ],
    Family.XSS: [
        HypothesisPattern(
            statement="Reflected values land in HTML body without "
                      "context-aware encoding",
            success_indicator="Markup executes in victim context",
            failure_indicator="Output encoded",
            probe_strategy="Context-specific probe strings on reflected params",
        ),
        HypothesisPattern(
            statement="Stored user content renders raw in admin-facing views",
            success_indicator="Payload executes in the admin's session",
            failure_indicator="Admin views encode content",
            probe_strategy="Store markers in content fields, review admin views",
        ),
        HypothesisPattern(
            statement="Client-side template injection in search/preview features",
            success_indicator="Template expression evaluates",
            failure_indicator="Template engine sandboxed or absent",
            probe_strategy="Template syntax probes in client-rendered fields",
        ),
        HypothesisPattern(
            statement="File-upload names/types render unencoded in listings",
            success_indicator="Filename markup executes in listing views",
            failure_indicator="Names sanitized in listings",
            probe_strategy="Upload files with probe-bearing names",
        ),
    ],
    Family.AUTH_BYPASS: [
        HypothesisPattern(
            statement="Admin routes authorize by obscurity (hidden, not gated)",
            success_indicator="Admin route responds to authenticated "
                              "non-admin",
            failure_indicator="Role gate enforced on hidden routes",
            probe_strategy="Enumerate admin paths against low-privilege session",
        ),
        HypothesisPattern(
            statement="Token/cookie value manipulation flips role claims",
            success_indicator="Forged claim grants elevated access",
            failure_indicator="Signature verification holds",
            probe_strategy="Weak-secret and alg-confusion probes on tokens",
        ),
        HypothesisPattern(
            statement="Password-reset/2FA flows trust client-controlled "
                      "identifiers",
            success_indicator="Reset/2FA step completes for another account",
            failure_indicator="Server-side identity binding",
            probe_strategy="Manipulate user identifiers in reset/2FA steps",
        ),
        HypothesisPattern(
            statement="Leaked credentials (oracle signal) are live on "
                      "edge/legacy portals",
            success_indicator="Leaked pair authenticates",
            failure_indicator="Leaked pairs rejected/expired",
            probe_strategy="Test leaked-signal pairs ONLY on targets the "
                           "operator explicitly authorized for this",
        ),
    ],
    Family.SSTI: [
        HypothesisPattern(
            statement="User input reaches a server-side template engine "
                      "(email templates, PDF/report generation)",
            success_indicator="Template expression evaluates server-side",
            failure_indicator="Input treated as data only",
            probe_strategy="Template-syntax probes in template-rendered fields",
        ),
        HypothesisPattern(
            statement="Theme/customization features compile user templates",
            success_indicator="Custom template executes expressions",
            failure_indicator="Custom templates restricted to markup",
            probe_strategy="Submit probe expressions through theme editors",
        ),
        HypothesisPattern(
            statement="Error pages render user-controlled paths through the "
                      "template engine",
            success_indicator="Expression in path evaluates on error page",
            failure_indicator="Paths escaped in error rendering",
            probe_strategy="Probe-bearing 404 paths",
        ),
    ],
    Family.INFO_DISCLOSURE: [
        HypothesisPattern(
            statement="Debug/error modes expose stack traces and "
                      "configuration in responses",
            success_indicator="Trace/config content returned",
            failure_indicator="Generic errors only",
            probe_strategy="Malformed requests to trigger error paths",
        ),
        HypothesisPattern(
            statement="Directory listing or backup artifacts reachable on "
                      "legacy subdomains",
            success_indicator="Listing/backup file exposed",
            failure_indicator="No listings or backups exposed",
            probe_strategy="Common backup/listing paths on legacy hosts",
        ),
        HypothesisPattern(
            statement="API documentation/debug endpoints exposed "
                      "unauthenticated",
            success_indicator="Docs/debug surface reachable",
            failure_indicator="Docs gated",
            probe_strategy="Standard docs/debug path enumeration",
        ),
        HypothesisPattern(
            statement="Response headers/metadata leak internal topology "
                      "(internal hosts, versions, frameworks)",
            success_indicator="Internal details in headers/bodies",
            failure_indicator="Sanitized responses",
            probe_strategy="Header/metadata review across endpoint classes",
        ),
    ],
}


def patterns_for(family: Family) -> list[HypothesisPattern]:
    """The family's hypothesis library (deterministic lookup)."""
    return FAMILY_HYPOTHESIS_PATTERNS.get(family, [])
