# src/webpent/integrations/notifications/formatters/slack.py
"""Slack formatter: Finding -> Slack incoming-webhook payload (V3 §4).

Pure: returns the platform-native dict; sending is dispatch's job.
Documented caps: description truncated to 700 chars in the attachment
text, payload evidence to 300 chars in a field — Slack renders long
blocks poorly and the full finding stays in the evidence bundle.
"""

from __future__ import annotations

from typing import Any

from webpent.models.findings import Finding

DESCRIPTION_CAP = 700
PAYLOAD_CAP = 300

_SEVERITY_COLOR = {
    "info": "#808080",
    "low": "#4caf50",
    "medium": "#ffc107",
    "high": "#ff9800",
    "critical": "#f44336",
}


def _short(value: str, cap: int) -> str:
    value = (value or "").strip()
    if len(value) <= cap:
        return value
    return value[: cap - 1] + "…"


def format_slack(finding: Finding) -> dict[str, Any]:
    """Build the Slack incoming-webhook payload for one finding."""
    severity = str(getattr(finding, "severity", "info"))
    color = _SEVERITY_COLOR.get(severity, "#808080")
    fields: list[dict[str, Any]] = [
        {"title": "Severity", "value": severity, "short": True},
        {"title": "Vulnerability class", "value": str(getattr(finding, "vuln_class", "n/a")), "short": True},
    ]
    url = str(getattr(finding, "url", "") or "")
    if url:
        fields.append({"title": "URL", "value": _short(url, PAYLOAD_CAP), "short": False})
    tool = str(getattr(finding, "tool_name", "") or "")
    if tool:
        fields.append({"title": "Tool", "value": _short(tool, PAYLOAD_CAP), "short": True})
    payload = str(getattr(finding, "payload", "") or "")
    if payload:
        fields.append({"title": "Payload", "value": f"`{_short(payload, PAYLOAD_CAP)}`", "short": False})
    return {
        "text": f"[{severity.upper()}] {finding.title}",
        "attachments": [
            {
                "color": color,
                "title": finding.title,
                "text": _short(finding.description, DESCRIPTION_CAP),
                "fields": fields,
                "footer": f"webpent · {finding.id}",
            }
        ],
    }
