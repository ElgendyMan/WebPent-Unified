# src/webpent/integrations/notifications/daily_digest.py
"""Daily digest buffer and builder (PROPOSALS_ULTIMATE_V3 §4).

The plan's rule: below-threshold findings are NOT pushed immediately —
they accumulate in a local buffer and go out as ONE summary when the
operator asks (or at campaign close). There are deliberately NO timers
and NO background daemon: the tool is not a resident service, so the
buffer is a JSONL file the caller reads and pushes on demand.

Fail-closed like the rest of §4: ``DailyDigestBuffer.load`` validates
every line (JSON, schema, types) and refuses the whole file on the
first bad line rather than silently skipping — a corrupt buffer must
not become a silent data hole in the digest.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from webpent.models.findings import Finding

from webpent.integrations.notifications.dispatch import SEVERITY_ORDER, severity_rank

__all__ = [
    "DigestEntry",
    "DailyDigestBuffer",
    "build_digest",
    "render_text",
]

TOP_EVIDENCE_DEFAULT = 3


@dataclass
class DigestEntry:
    """One buffered finding, reduced to what a digest line needs."""

    finding_id: str
    title: str
    severity: str
    vuln_class: str
    created_at: str
    engagement_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "created_at": self.created_at,
            "engagement_id": self.engagement_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DigestEntry":
        """Fail-closed: unknown keys, missing keys, or bad types refuse."""
        if not isinstance(data, dict):
            raise ValueError("digest_entry_not_an_object")
        required = {"finding_id", "title", "severity", "vuln_class", "created_at"}
        unknown = set(data) - required - {"engagement_id"}
        if unknown:
            raise ValueError(f"digest_entry_unknown_fields: {sorted(unknown)}")
        missing = required - set(data)
        if missing:
            raise ValueError(f"digest_entry_missing_fields: {sorted(missing)}")
        for key in data:
            if not isinstance(data[key], str):
                raise ValueError(f"digest_entry_bad_type: {key}")
        try:
            severity_rank(data["severity"])
        except ValueError as exc:
            raise ValueError(f"digest_entry_unknown_severity: {data['severity']!r}") from exc
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            severity=data["severity"],
            vuln_class=data["vuln_class"],
            created_at=data["created_at"],
            engagement_id=data.get("engagement_id", ""),
        )

    @classmethod
    def from_finding(cls, finding: Finding, *, engagement_id: str = "") -> "DigestEntry":
        return cls(
            finding_id=str(finding.id),
            title=str(finding.title),
            severity=str(getattr(finding, "severity", "info")),
            vuln_class=str(getattr(finding, "vuln_class", "n/a")),
            created_at=str(getattr(finding, "created_at", "")),
            engagement_id=engagement_id,
        )


class DailyDigestBuffer:
    """Append-only JSONL buffer of digest entries (local disk, no daemon)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def add_entry(self, entry: DigestEntry) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    def add_finding(self, finding: Finding, *, engagement_id: str = "") -> None:
        self.add_entry(DigestEntry.from_finding(finding, engagement_id=engagement_id))

    def entries(self) -> list[DigestEntry]:
        """Load all entries; the first bad line refuses the whole file."""
        if not self.path.exists():
            return []
        out: list[DigestEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(DigestEntry.from_dict(json.loads(line)))
                except (ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"digest_buffer_bad_line:{lineno}:{exc}") from exc
        return out


def build_digest(
    entries: list[DigestEntry],
    *,
    top_k: int = TOP_EVIDENCE_DEFAULT,
) -> dict[str, Any]:
    """Pure digest: counts by severity and class, top-k notable findings.

    Top-k ranks by severity (highest first), then by recency
    (created_at descending) — deterministic, advisory only.
    """
    counts_by_severity: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    counts_by_class: dict[str, int] = {}
    for entry in entries:
        counts_by_severity[entry.severity] = counts_by_severity.get(entry.severity, 0) + 1
        counts_by_class[entry.vuln_class] = counts_by_class.get(entry.vuln_class, 0) + 1

    def _sort_key(entry: DigestEntry) -> tuple[int, str]:
        return (severity_rank(entry.severity), entry.created_at)

    top = sorted(entries, key=_sort_key, reverse=True)[: max(0, int(top_k))]
    return {
        "total": len(entries),
        "counts_by_severity": counts_by_severity,
        "counts_by_vuln_class": dict(sorted(counts_by_class.items(), key=lambda kv: -kv[1])),
        "top_findings": [e.to_dict() for e in top],
    }


def render_text(digest: dict[str, Any]) -> str:
    """Human-readable one-block summary for posting to any platform."""
    lines = [f"📋 Daily digest — {digest.get('total', 0)} finding(s)"]
    by_sev = digest.get("counts_by_severity", {})
    parts = [f"{sev}: {by_sev[sev]}" for sev in SEVERITY_ORDER if by_sev.get(sev)]
    if parts:
        lines.append("By severity — " + ", ".join(parts))
    by_class = digest.get("counts_by_vuln_class", {})
    if by_class:
        lines.append("By class — " + ", ".join(f"{k}: {v}" for k, v in by_class.items()))
    top = digest.get("top_findings", [])
    if top:
        lines.append("Top findings:")
        for entry in top:
            lines.append(f"  • [{entry['severity'].upper()}] {entry['title']}")
    return "\n".join(lines)
