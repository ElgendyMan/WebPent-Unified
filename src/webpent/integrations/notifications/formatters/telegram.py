# src/webpent/integrations/notifications/formatters/telegram.py
"""Telegram formatter: Finding -> Telegram sendMessage payload (V3 §4).

Pure: returns the platform-native dict (chat_id filled by dispatch from
TELEGRAM_CHAT_ID); sending is dispatch's job. parse_mode HTML with
documented escaping — every dynamic value passes through ``escape_html``
so a payload containing ``<script>`` can never break the message.
"""

from __future__ import annotations

from html import escape
from typing import Any

from webpent.models.findings import Finding

DESCRIPTION_CAP = 700
PAYLOAD_CAP = 300


def escape_html(value: str) -> str:
    """Escape a dynamic value for Telegram parse_mode=HTML."""
    return escape((value or ""), quote=False)


def _short(value: str, cap: int) -> str:
    value = (value or "").strip()
    if len(value) <= cap:
        return value
    return value[: cap - 1] + "…"


def format_telegram(finding: Finding, *, chat_id: str = "") -> dict[str, Any]:
    """Build the Telegram sendMessage payload for one finding."""
    severity = escape_html(str(getattr(finding, "severity", "info")))
    lines = [
        f"🔔 <b>[{severity.upper()}]</b> {escape_html(finding.title)}",
        "",
        escape_html(_short(finding.description, DESCRIPTION_CAP)),
        "",
        f"<b>Severity:</b> {severity}",
        f"<b>Class:</b> {escape_html(str(getattr(finding, 'vuln_class', 'n/a')))}",
    ]
    url = str(getattr(finding, "url", "") or "")
    if url:
        lines.append(f"<b>URL:</b> {escape_html(_short(url, PAYLOAD_CAP))}")
    payload = str(getattr(finding, "payload", "") or "")
    if payload:
        lines.append(f"<b>Payload:</b> <code>{escape_html(_short(payload, PAYLOAD_CAP))}</code>")
    lines.append("")
    lines.append(f"<i>webpent · {escape_html(str(finding.id))}</i>")
    body: dict[str, Any] = {"text": "\n".join(lines), "parse_mode": "HTML"}
    if chat_id:
        body["chat_id"] = chat_id
    return body
