# src/webpent/integrations/notifications/formatters/discord.py
"""Discord formatter: Finding -> Discord webhook embed payload (V3 §4).

Pure: returns the platform-native dict; sending is dispatch's job.
Documented caps: embed description 700 chars, field values 300 chars
(Discord hard-limits embeds; the full finding stays in the bundle).
"""

from __future__ import annotations

from typing import Any

from webpent.models.findings import Finding

DESCRIPTION_CAP = 700
PAYLOAD_CAP = 300

_SEVERITY_COLOR = {
    "info": 0x808080,
    "low": 0x4CAF50,
    "medium": 0xFFC107,
    "high": 0xFF9800,
    "critical": 0xF44336,
}


def _short(value: str, cap: int) -> str:
    value = (value or "").strip()
    if len(value) <= cap:
        return value
    return value[: cap - 1] + "…"


def format_discord(finding: Finding) -> dict[str, Any]:
    """Build the Discord webhook payload for one finding."""
    severity = str(getattr(finding, "severity", "info"))
    color = _SEVERITY_COLOR.get(severity, 0x808080)
    fields: list[dict[str, Any]] = [
        {"name": "Severity", "value": severity, "inline": True},
        {"name": "Class", "value": str(getattr(finding, "vuln_class", "n/a")), "inline": True},
    ]
    url = str(getattr(finding, "url", "") or "")
    if url:
        fields.append({"name": "URL", "value": _short(url, PAYLOAD_CAP), "inline": False})
    payload = str(getattr(finding, "payload", "") or "")
    if payload:
        fields.append({"name": "Payload", "value": f"`{_short(payload, PAYLOAD_CAP)}`", "inline": False})
    embed: dict[str, Any] = {
        "title": finding.title,
        "description": _short(finding.description, DESCRIPTION_CAP),
        "color": color,
        "fields": fields,
        "footer": {"text": f"webpent · {finding.id}"},
    }
    if url:
        embed["url"] = url
    return {"content": f"🔔 **[{severity.upper()}]** {finding.title}", "embeds": [embed]}
