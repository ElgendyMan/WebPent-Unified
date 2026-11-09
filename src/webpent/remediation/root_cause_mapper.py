# src/webpent/remediation/root_cause_mapper.py
"""webpent.remediation.root_cause_mapper

Root-cause classification for the smart remediation editor.

ADVISORY-ONLY: this module maps an existing ``VulnClass`` to the deeper
engineering mistake that produces it, so a fix addresses the cause rather
than the symptom. It never inspects a target, executes anything, or
promotes a finding; its entire input is a vulnerability class that an
existing finding already carries.

The four root causes are deliberately few. Every mapped class falls into
exactly one primary cause; some classes honestly carry secondary causes.
``UNKNOWN`` has no cause: the honest answer for an unclassified finding is
"no guidance", not a guess.
"""

from __future__ import annotations

from enum import Enum

from webpent.models.findings import VulnClass


class RootCause(str, Enum):
    """The engineering mistake behind a vulnerability class."""

    MISSING_VALIDATION = "missing_validation"
    INPUT_TRUST = "input_trust"
    EXECUTION_ORDER = "execution_order"
    STATE_MANAGEMENT = "state_management"


# Primary cause first, secondary causes after. Total over every VulnClass
# member except UNKNOWN; UNKNOWN is deliberately absent.
_CLASS_CAUSE: dict[VulnClass, tuple[RootCause, ...]] = {
    VulnClass.XSS: (RootCause.INPUT_TRUST,),
    VulnClass.SQLI: (RootCause.INPUT_TRUST,),
    VulnClass.SSRF: (RootCause.INPUT_TRUST,),
    VulnClass.LFI: (RootCause.INPUT_TRUST,),
    VulnClass.RFI: (RootCause.INPUT_TRUST,),
    VulnClass.RCE: (RootCause.INPUT_TRUST,),
    VulnClass.SSTI: (RootCause.INPUT_TRUST,),
    VulnClass.XXE: (RootCause.INPUT_TRUST,),
    VulnClass.XSLT_INJECTION: (RootCause.INPUT_TRUST,),
    # UM-DR-25: blind OOB + privilege-differential families.
    VulnClass.BLIND_SSRF: (RootCause.INPUT_TRUST, RootCause.MISSING_VALIDATION,),
    VulnClass.XXE_OOB: (RootCause.INPUT_TRUST, RootCause.MISSING_VALIDATION,),
    VulnClass.BLIND_SQLI: (RootCause.INPUT_TRUST,),
    VulnClass.PRIVILEGE_DIFFERENTIAL: (RootCause.MISSING_VALIDATION, RootCause.STATE_MANAGEMENT,),
    VulnClass.NOSQL_INJECTION: (RootCause.INPUT_TRUST,),
    VulnClass.COMMAND_INJECTION: (RootCause.INPUT_TRUST,),
    VulnClass.PATH_TRAVERSAL: (RootCause.INPUT_TRUST,),
    VulnClass.JAVASCRIPT: (RootCause.INPUT_TRUST,),
    VulnClass.DESERIALIZATION: (RootCause.INPUT_TRUST,),
    VulnClass.OPEN_REDIRECT: (RootCause.MISSING_VALIDATION,),
    VulnClass.CSRF: (RootCause.MISSING_VALIDATION,),
    VulnClass.IDOR: (RootCause.MISSING_VALIDATION,),
    VulnClass.AUTH_BYPASS: (RootCause.MISSING_VALIDATION,),
    VulnClass.MASS_ASSIGNMENT: (RootCause.MISSING_VALIDATION,),
    VulnClass.BRUTE_FORCE: (RootCause.MISSING_VALIDATION,),
    VulnClass.CAPTCHA: (RootCause.MISSING_VALIDATION,),
    VulnClass.CSP: (RootCause.MISSING_VALIDATION,),
    VulnClass.API_ISSUE: (RootCause.MISSING_VALIDATION,),
    VulnClass.INFO_DISCLOSURE: (RootCause.MISSING_VALIDATION,),
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: (RootCause.MISSING_VALIDATION,),
    VulnClass.JWT_WEAKNESS: (RootCause.MISSING_VALIDATION,),
    VulnClass.JWT_KEY_CONFUSION: (RootCause.EXECUTION_ORDER,),
    VulnClass.REQUEST_SMUGGLING: (RootCause.EXECUTION_ORDER,),
    VulnClass.RACE_CONDITION: (RootCause.STATE_MANAGEMENT, RootCause.EXECUTION_ORDER),
    VulnClass.WEAK_SESSION: (RootCause.STATE_MANAGEMENT,),
    VulnClass.SUBDOMAIN_TAKEOVER: (RootCause.STATE_MANAGEMENT,),
    VulnClass.CLOUD_STORAGE_EXPOSURE: (RootCause.STATE_MANAGEMENT,),

    # ULTIMATE PLAN 2026-10-27 (proposals 1/7): family + detector classes.
    VulnClass.BUSINESS_LOGIC: (RootCause.MISSING_VALIDATION,),
    VulnClass.MULTI_STEP_AUTH_BYPASS: (RootCause.EXECUTION_ORDER, RootCause.MISSING_VALIDATION),
    VulnClass.TENANT_ISOLATION: (RootCause.MISSING_VALIDATION,),
    VulnClass.EXPLOIT_CHAIN: (RootCause.EXECUTION_ORDER,),
    VulnClass.OAUTH: (RootCause.MISSING_VALIDATION,),
    VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE: (RootCause.MISSING_VALIDATION,),
    VulnClass.GRAPHQL_BATCHING_ABUSE: (RootCause.MISSING_VALIDATION,),
    VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK: (RootCause.MISSING_VALIDATION,),
    VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS: (RootCause.MISSING_VALIDATION,),
    VulnClass.PROTOTYPE_POLLUTION: (RootCause.INPUT_TRUST,),
    VulnClass.OAUTH_MISCONFIGURATION: (RootCause.MISSING_VALIDATION,),
    VulnClass.CACHE_POISONING: (RootCause.EXECUTION_ORDER,),
    VulnClass.WEB_CACHE_DECEPTION: (RootCause.STATE_MANAGEMENT,),
    VulnClass.CRYPTOGRAPHY: (RootCause.STATE_MANAGEMENT,),
}

_CAUSE_EXPLANATION: dict[RootCause, str] = {
    RootCause.MISSING_VALIDATION: (
        "A required control was never applied: an authorization check, a "
        "token check, an allowlist, or a rate limit is absent on a path "
        "that needs one. The fix is to add the control at the boundary, "
        "not to patch individual inputs."
    ),
    RootCause.INPUT_TRUST: (
        "Attacker-controlled data reaches an interpreter (SQL, shell, "
        "template, serializer, URL fetcher) without separation between "
        "code and data. The fix is parameterization or context-aware "
        "encoding at the sink, plus allowlist validation at entry."
    ),
    RootCause.EXECUTION_ORDER: (
        "The flaw lives in the sequence of operations: two components "
        "interpret the same bytes differently, or a check runs at the "
        "wrong point relative to the use of its result. The fix is a "
        "single canonical parse or a check placed before the use."
    ),
    RootCause.STATE_MANAGEMENT: (
        "Durable or shared state outlives the assumptions that created "
        "it: sessions, abandoned infrastructure, permissions, or keys. "
        "The fix is lifecycle ownership: expire, revoke, re-own, or "
        "rotate the state itself."
    ),
}


def causes(vuln_class: VulnClass | str) -> tuple[RootCause, ...] | None:
    """All root causes for a class; ``None`` when the class has none.

    ``None`` is reserved for UNKNOWN (or any value outside the enum): an
    unclassified finding gets no invented cause.
    """
    if isinstance(vuln_class, str):
        try:
            vuln_class = VulnClass(vuln_class)
        except ValueError:
            return None
    return _CLASS_CAUSE.get(vuln_class)


def classify(vuln_class: VulnClass | str) -> RootCause | None:
    """The primary root cause for a class, or ``None`` when unmapped."""
    all_causes = causes(vuln_class)
    return all_causes[0] if all_causes else None


def explain(cause: RootCause) -> str:
    """Human explanation of what the root cause means and how it is fixed."""
    return _CAUSE_EXPLANATION[cause]


def classes_for_cause(cause: RootCause) -> list[VulnClass]:
    """Every class whose primary cause is ``cause`` (stable enum order)."""
    return [cls for cls, pair in _CLASS_CAUSE.items() if pair[0] is cause]
