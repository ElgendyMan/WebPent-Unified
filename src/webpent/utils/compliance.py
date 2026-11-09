# src/webpent/utils/compliance.py
"""webpent.utils.compliance

V5 Sprint 11 — Compliance mapping utility.

Auto-tags findings with industry-standard compliance references based on
their ``vuln_class``. The mapping covers OWASP Top 10 (2021), CWE, and
PCI-DSS v4.0.

Usage::

    from webpent.utils.compliance import tag_finding

    finding.compliance_tags = tag_finding(finding.vuln_class)
"""

from __future__ import annotations

import contextlib
from typing import Any

from webpent.models.findings import VulnClass

# ===========================================================================
# Compliance reference database
# ===========================================================================
# Each vuln_class maps to a list of compliance tags. The tags follow the
# format ``<STANDARD>-<ID>:<YEAR>`` where applicable.
#
# Sources:
#   - OWASP Top 10 2021: https://owasp.org/Top10/
#   - CWE: https://cwe.mitre.org/
#   - PCI-DSS v4.0: https://www.pcisecuritystandards.org/
_COMPLIANCE_MAP: dict[str, list[str]] = {
    VulnClass.XSS.value: [
        "OWASP-A03:2021",  # Injection (XSS was folded into A03 in 2021)
        "CWE-79",          # Improper Neutralization of Input During Web Page Generation
        "PCI-DSS-6.5.7",   # XSS
    ],
    VulnClass.SQLI.value: [
        "OWASP-A03:2021",  # Injection
        "CWE-89",          # SQL Injection
        "PCI-DSS-6.5.1",
    ],
    VulnClass.SSRF.value: [
        "OWASP-A10:2021",  # Server-Side Request Forgery
        "CWE-918",         # SSRF
        "PCI-DSS-6.5.10",
    ],
    VulnClass.RCE.value: [
        "OWASP-A03:2021",  # Injection (OS command injection)
        "CWE-78",          # OS Command Injection
        "PCI-DSS-6.5.1",
    ],
    VulnClass.LFI.value: [
        "OWASP-A01:2021",  # Broken Access Control
        "CWE-22",          # Path Traversal
        "CWE-98",          # PHP File Inclusion
        "PCI-DSS-6.5.4",
    ],
    VulnClass.RFI.value: [
        "OWASP-A01:2021",
        "CWE-98",
        "PCI-DSS-6.5.4",
    ],
    VulnClass.SSTI.value: [
        "OWASP-A03:2021",  # Injection
        "CWE-1336",        # Template Injection
        "CWE-94",          # Code Injection
        "PCI-DSS-6.5.1",
    ],
    VulnClass.OPEN_REDIRECT.value: [
        "OWASP-A01:2021",  # Broken Access Control
        "CWE-601",         # Open Redirect
        "PCI-DSS-6.5.10",
    ],
    VulnClass.XXE.value: [
        "OWASP-A05:2021",  # Security Misconfiguration
        "CWE-611",         # XXE
        "PCI-DSS-6.5.10",
    ],
    VulnClass.CSRF.value: [
        "OWASP-A01:2021",  # Broken Access Control
        "CWE-352",         # CSRF
        "PCI-DSS-6.5.5",
    ],
    VulnClass.DESERIALIZATION.value: [
        "OWASP-A08:2021",  # Software and Data Integrity Failures
        "CWE-502",         # Deserialization of Untrusted Data
        "PCI-DSS-6.5.10",
    ],
    VulnClass.PATH_TRAVERSAL.value: [
        "OWASP-A01:2021",
        "CWE-22",          # Path Traversal
        "PCI-DSS-6.5.4",
    ],
    VulnClass.COMMAND_INJECTION.value: [
        "OWASP-A03:2021",
        "CWE-78",          # OS Command Injection
        "PCI-DSS-6.5.1",
    ],
    VulnClass.INFO_DISCLOSURE.value: [
        "OWASP-A05:2021",  # Security Misconfiguration
        "CWE-200",         # Information Exposure
        "PCI-DSS-6.5.10",
    ],
    VulnClass.UNKNOWN.value: [],
}


def get_compliance_tags(vuln_class: str) -> list[str]:
    """Return the compliance tags for a given vulnerability class.

    Args:
        vuln_class: The ``vuln_class`` string from a :class:`Finding`
            (e.g. ``"sqli"``, ``"xss"``). Accepts both the enum value
            and the enum object.

    Returns:
        A list of compliance tag strings (e.g.
        ``["OWASP-A03:2021", "CWE-89", "PCI-DSS-6.5.1"]``). Returns an
        empty list if the vuln_class is not in the map.
    """
    # Normalize: accept both VulnClass enum and raw string.
    if isinstance(vuln_class, VulnClass):
        vc = vuln_class.value
    elif isinstance(vuln_class, str):
        vc = vuln_class.lower().strip()
    else:
        return []
    return list(_COMPLIANCE_MAP.get(vc, []))


def tag_finding(finding: Any) -> list[str]:
    """Return the compliance tags for a Finding object.

    Convenience wrapper that extracts ``finding.vuln_class`` and
    delegates to :func:`get_compliance_tags`.

    Args:
        finding: A :class:`webpent.models.findings.Finding` instance
            (or any object with a ``vuln_class`` attribute).

    Returns:
        A list of compliance tag strings.
    """
    # LangGraph checkpoint round-trips may deserialize Pydantic Findings
    # into plain dictionaries.  Keep report generation and resumed scans
    # equivalent to fresh in-memory runs instead of silently returning no
    # compliance mapping for dict-shaped findings.
    if isinstance(finding, dict):
        vc = finding.get("vuln_class")
    else:
        vc = getattr(finding, "vuln_class", None)
    if vc is None:
        return []
    return get_compliance_tags(vc)


def apply_compliance_tags(finding: Any) -> Any:
    """Mutate a Finding in-place to populate its compliance_tags field.

    V5 Sprint 11: Called by the validator/hypothesis agents after a
    finding is created. Returns the same finding object for chaining.

    Args:
        finding: A :class:`Finding` instance with a ``compliance_tags``
            field. The field is overwritten with the mapped tags.

    Returns:
        The same finding object (mutated in-place via setattr).
    """
    tags = tag_finding(finding)
    # Pydantic V2 models are immutable by default, but model_copy
    # is the canonical way to "mutate". We use setattr for non-
    # Pydantic objects and return the finding for Pydantic callers
    # to handle via model_copy if needed.
    with contextlib.suppress(AttributeError, TypeError):
        object.__setattr__(finding, "compliance_tags", tags)
    return finding
