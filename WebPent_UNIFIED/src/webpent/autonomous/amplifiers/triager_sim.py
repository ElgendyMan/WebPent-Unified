"""Triager simulation mode (v82, Layer 2 / Task 7).

Simulates a platform triager's rejection heuristics *offline*: a finding
is compared against a seeded knowledge base of public rejection patterns
(duplicate-prone and N/A-prone shapes) and, when it resembles one, the
report says so explicitly — "resembles N rejected patterns because...".

Advisory only: the output is a prediction for the operator, never a
blocking decision and never a finding modification. The pattern base is
seeded, in-file, and deterministic; a bad finding shape yields an empty
prediction, not an exception.
"""

from __future__ import annotations

import re
from typing import Any

from webpent.autonomous.hunt_contracts import redact

# Seeded rejection patterns: (pattern_id, kind, field, regex, reason).
# Kinds: "duplicate" (reported constantly, expect dup) and "na"
# (commonly closed as not-applicable).
_REJECTION_PATTERNS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "dup-xss-reflected-generic",
        "duplicate",
        "vuln_class",
        r"^(xss|reflected[\s_-]?xss)$",
        "reflected XSS on a single generic input is reported extremely often",
    ),
    (
        "dup-open-redirect-generic",
        "duplicate",
        "vuln_class",
        r"^open[\s_-]?redirect$",
        "generic open redirects are usually marked duplicate",
    ),
    (
        "dup-missing-header",
        "duplicate",
        "vuln_class",
        r"^(missing[\s_-]?(?:security[\s_-]?)?header|csp|hsts)$",
        "missing-header reports without exploit impact are frequent dupes",
    ),
    (
        "na-self-xss",
        "na",
        "vuln_class",
        r"^self[\s_-]?xss$",
        "self-XSS is typically closed as not applicable",
    ),
    (
        "na-logout-csrf",
        "na",
        "vuln_class",
        r"^logout[\s_-]?csrf$",
        "logout CSRF is typically closed as not applicable",
    ),
    (
        "na-version-disclosure",
        "na",
        "vuln_class",
        r"^version[\s_-]?disclosur",
        "version disclosure alone is typically not applicable",
    ),
    (
        "na-no-impact",
        "na",
        "impact",
        r"^$",
        "empty impact description invites an N/A closure",
    ),
)

_MAX_FINDINGS = 32


def _field_text(finding: dict[str, Any], field: str) -> str:
    value = finding.get(field)
    if value is None:
        return ""
    return str(value).strip().lower()


def simulate_triager(finding: dict[str, Any]) -> dict[str, Any]:
    """Predict likely triager closures for one finding; advisory only."""
    if not isinstance(finding, dict):
        return {"prediction": "unknown", "matches": [], "advisory": True}
    matches: list[dict[str, str]] = []
    for pattern_id, kind, field, regex, reason in _REJECTION_PATTERNS:
        try:
            if re.search(regex, _field_text(finding, field)):
                matches.append(
                    {
                        "pattern_id": pattern_id,
                        "kind": kind,
                        "field": field,
                        "reason": reason,
                    }
                )
        except re.error:  # pragma: no cover - seeded patterns are valid
            continue
    kinds = {m["kind"] for m in matches}
    if "na" in kinds:
        prediction = "likely_na"
    elif "duplicate" in kinds:
        prediction = "likely_duplicate"
    else:
        prediction = "clean"
    return {
        "finding_id": redact(str(finding.get("finding_id", "")))[:120],
        "prediction": prediction,
        "matches": matches,
        "advisory": True,
    }


def triage_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Batch prediction over bounded findings."""
    predictions = [simulate_triager(item) for item in list(findings)[:_MAX_FINDINGS]]
    summary: dict[str, int] = {}
    for item in predictions:
        summary[item["prediction"]] = summary.get(item["prediction"], 0) + 1
    return {"predictions": predictions, "summary": summary, "advisory": True}
