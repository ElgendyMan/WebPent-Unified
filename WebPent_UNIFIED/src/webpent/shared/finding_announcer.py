# src/webpent/shared/finding_announcer.py
"""Instant one-line announcement of CONFIRMED findings.

Ultimate plan 2026-10-27, proposal 12 (output clarity), phase 2:

"لحظة ما finding يترقى لـCONFIRMED، طباعة سطر واحد فوري — المستخدم
ميستناش ساعة عشان يعرف إن فيه critical finding."

The unified hunt CLI installs this announcer on the findings channel:
every NEW confirmed finding (CRITICAL/HIGH get the loud form) is
printed to stderr the moment it is observed in the graph stream —
not held back for the final report.

Contracts:

* Display-only, append-only bookkeeping: never mutates the finding,
  never influences validation or routing.
* Redaction-safe: prints only the finding's class, severity, and the
  already-redacted location/endpoint field — never parameter values,
  never evidence bodies (the project's redaction posture applies to
  terminal output exactly as it applies to reports).
* Degrades to a no-op when the flag is off, so legacy runs are
  byte-identical.
"""

from __future__ import annotations

import sys
from typing import Any, IO, Mapping

__all__ = ["FindingAnnouncer", "_announce_line"]

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _announce_line(finding: Any) -> str:
    """Build the one-line announcement (pure, redaction-safe)."""
    if isinstance(finding, Mapping):
        get = finding.get
    else:
        def get(key: str, default: Any = None) -> Any:  # noqa: ANN001
            return getattr(finding, key, default)

    severity = str(get("severity", "UNKNOWN")).upper()
    vuln_class = str(get("vulnerability_class", get("vuln_class", "unknown")))
    location = str(get("url", get("endpoint", get("location", ""))))[:120]
    icon = "🔴" if severity in {"CRITICAL", "HIGH"} else "🟠"
    arrow = f" في {location}" if location else ""
    return f"{icon} {severity}: {vuln_class}{arrow} (evidence مؤكد)"


class FindingAnnouncer:
    """Announce newly-CONFIRMED findings as single stderr lines.

    The announcer remembers which finding identities it has already
    announced (by finding id when available, else by a bounded
    class+location fingerprint) so re-observations of the same finding
    during the run are not re-printed.
    """

    def __init__(self, *, stream: IO[str] | None = None, enabled: bool = True) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._enabled = enabled
        self._announced: set[str] = set()

    def observe_findings(self, findings: list[Any] | tuple[Any, ...]) -> None:
        """Scan the findings channel; print each NEW confirmed finding."""
        if not self._enabled or not findings:
            return
        for finding in findings:
            if isinstance(finding, Mapping):
                status = str(finding.get("validation_status", "")).upper()
                identity = str(finding.get("id") or finding.get("finding_id") or "")
                severity = str(finding.get("severity", "UNKNOWN")).upper()
                vuln = str(finding.get("vulnerability_class", "unknown"))
                location = str(finding.get("url") or finding.get("endpoint") or "")[:120]
            else:
                status = str(getattr(finding, "validation_status", "")).upper()
                identity = str(
                    getattr(finding, "id", None)
                    or getattr(finding, "finding_id", None)
                    or ""
                )
                severity = str(getattr(finding, "severity", "UNKNOWN")).upper()
                vuln = str(getattr(finding, "vulnerability_class", "unknown"))
                location = str(
                    getattr(finding, "url", None)
                    or getattr(finding, "endpoint", None)
                    or ""
                )[:120]
            if status != "CONFIRMED":
                continue
            if not identity:
                identity = f"{vuln}@{location}"
            if identity in self._announced:
                continue
            self._announced.add(identity)
            # Only the loud severities interrupt the progress bar —
            # MEDIUM/LOW confirmed findings are counted by the progress
            # renderer without a dedicated line (noise control).
            if severity in {"CRITICAL", "HIGH"}:
                self._stream.write("\n" + _announce_line(finding) + "\n")
                self._stream.flush()

    @property
    def announced_count(self) -> int:
        """How many distinct confirmed findings have been announced."""
        return len(self._announced)
