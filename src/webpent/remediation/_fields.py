# src/webpent/remediation/_fields.py
"""webpent.remediation._fields

Shared field parsing for the remediation package (internal).

Every advisory module needs the same two decisions about a finding's
fields: what severity does it carry, and what vulnerability class. Those
decisions were previously duplicated with three different behaviors, so
they now live here once.

Honesty contract, identical for every caller:

- ``as_severity`` accepts the string form or a ``Severity`` instance and
  returns ``None`` for anything else, never a guess.
- ``as_vuln_class`` accepts the string form or a ``VulnClass`` instance
  (``str(VulnClass.X)`` is ``"VulnClass.X"`` in Python 3.12, so a raw
  ``str()`` call corrupts enum-carried findings; this module reads
  ``.value`` instead) and returns ``None`` for garbage. ``UNKNOWN`` is an
  honest absence, not a class: it also returns ``None``, and callers count
  that in ``skipped_unclassified``.
"""

from __future__ import annotations

from webpent.models.findings import Severity, VulnClass

# Fix effort per class as a letter estimate (S/M/L): how much engineering
# work the typical correct fix for this class takes. UNKNOWN is absent by
# design: unclassified findings are skipped, never estimated.
EFFORT: dict[VulnClass, str] = {
    VulnClass.XSS: "M", VulnClass.SQLI: "M", VulnClass.SSRF: "M",
    VulnClass.LFI: "S", VulnClass.RFI: "S", VulnClass.RCE: "L",
    VulnClass.SSTI: "S", VulnClass.OPEN_REDIRECT: "S",
    VulnClass.XXE: "S", VulnClass.CSRF: "M",
    VulnClass.DESERIALIZATION: "L", VulnClass.PATH_TRAVERSAL: "M",
    VulnClass.COMMAND_INJECTION: "M", VulnClass.NOSQL_INJECTION: "M",
    VulnClass.INFO_DISCLOSURE: "S", VulnClass.RACE_CONDITION: "L",
    VulnClass.IDOR: "M", VulnClass.AUTH_BYPASS: "M",
    VulnClass.MASS_ASSIGNMENT: "S", VulnClass.REQUEST_SMUGGLING: "L",
    VulnClass.BRUTE_FORCE: "S", VulnClass.CAPTCHA: "M",
    VulnClass.WEAK_SESSION: "M", VulnClass.CSP: "S",
    VulnClass.JAVASCRIPT: "M", VulnClass.CRYPTOGRAPHY: "L",
    VulnClass.API_ISSUE: "M", VulnClass.SUBDOMAIN_TAKEOVER: "S",
    VulnClass.CLOUD_STORAGE_EXPOSURE: "S", VulnClass.JWT_WEAKNESS: "M",
    VulnClass.JWT_KEY_CONFUSION: "S",
    VulnClass.ELASTICSEARCH_SNAPSHOT_TRAVERSAL: "S",
    VulnClass.XSLT_INJECTION: "S",
}

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}


def as_severity(value: object) -> Severity | None:
    """The finding's severity, or ``None`` when it carries none."""
    if value is None:
        return None
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value))
    except ValueError:
        return None


def as_vuln_class(value: object) -> VulnClass | None:
    """The finding's class, or ``None`` when it has none worth claiming.

    ``None`` is returned for: a missing field, an unparseable string, and
    ``VulnClass.UNKNOWN`` (an honest absence, never a class). A
    ``VulnClass`` instance is read through ``.value`` so enum-carried
    findings resolve like string-carried ones.
    """
    if value is None:
        return None
    if isinstance(value, VulnClass):
        parsed = value
    else:
        try:
            parsed = VulnClass(str(value))
        except ValueError:
            return None
    if parsed is VulnClass.UNKNOWN:
        return None
    return parsed


__all__ = ["EFFORT", "SEVERITY_WEIGHT", "as_severity", "as_vuln_class"]
