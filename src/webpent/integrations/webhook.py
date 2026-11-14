# src/webpent/integrations/webhook.py
"""webpent.integrations.webhook

V5 Sprint 11 — Enterprise webhook / ticketing integration.

Pushes actionable findings (``"Tool-Confirmed"`` and
``"Needs Human Review"``) to external systems via HTTP webhook. The
payload format is compatible with Slack incoming webhooks, Discord
webhooks, and Jira REST API (with minor adaptation by the receiver).

Usage::

    import asyncio
    from webpent.integrations.webhook import push_to_webhook, maybe_push_finding

    # Direct push (async):
    await push_to_webhook(finding, "https://hooks.slack.com/services/...")

    # Settings-gated push (respects WEBHOOK_ENABLED + WEBHOOK_URL):
    await maybe_push_finding(finding)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.models.findings import Finding

# V6 Absolute-Flawless P0 FIX (Async SSRF Bypass): webhook.py was using
# a raw httpx.AsyncClient, bypassing the SSRF guard installed by
# make_safe_httpx_client. The webhook URL is attacker-controllable
# (set via WEBHOOK_URL), so an attacker could point it at internal
# services (169.254.169.254, redis:6379, etc.) and exfiltrate data
# via the webhook push. We now route through make_safe_httpx_async_client
# which installs BOTH the redirect-block event hook AND the
# DNS-pinning transport — same defence-in-depth as the sync paths.
from webpent.shared.http import make_safe_httpx_async_client

logger = logging.getLogger(__name__)

# Only findings with these confidence_levels are pushed — lower-priority
# findings (AI-Assessed, Pending) are not actionable enough to warrant
# a webhook notification.
_ACTIONABLE_CONFIDENCE_LEVELS = frozenset({"Tool-Confirmed", "Needs Human Review"})


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize the exact JSON bytes that are sent to the webhook."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _webhook_signature(payload_bytes: bytes, secret: str) -> str:
    """Return the transport header value for the payload HMAC."""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"HMAC-SHA256={digest}"


def _format_slack_payload(finding: Finding) -> dict[str, Any]:
    """Format a finding as a Slack incoming-webhook payload.

    Slack expects a JSON object with a ``text`` field (and optionally
    ``blocks`` for rich formatting). We use a simple attachment-style
    message that works with both Slack and Discord (Discord accepts
    Slack-style payloads on their webhook URLs).
    """
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵",
    }
    sev = str(finding.severity).lower()
    emoji = severity_emoji.get(sev, "⚪")

    compliance_str = ", ".join(finding.compliance_tags) if finding.compliance_tags else "none"

    text = (
        f"{emoji} *WebPent Finding: {finding.title}*\n"
        f"*Severity:* {sev.upper()}\n"
        f"*Confidence:* {finding.confidence_level}\n"
        f"*Vuln Class:* {finding.vuln_class}\n"
        f"*URL:* {finding.url}\n"
        f"*Compliance:* {compliance_str}\n"
        f"*Tool:* {finding.tool_name}\n"
    )
    if finding.business_impact:
        text += f"*Business Impact:* {finding.business_impact}\n"
    if finding.payload:
        text += f"*Payload:* `{finding.payload[:200]}`\n"
    if finding.evidence_hash:
        text += f"*Evidence SHA-256:* `{finding.evidence_hash[:32]}…`\n"

    return {"text": text}


def _format_jira_payload(finding: Finding) -> dict[str, Any]:
    """Format a finding as a Jira REST API issue-creation payload.

    Jira expects a nested ``fields`` object with ``summary``,
    ``description``, ``issuetype``, and (optionally) ``labels``.
    """
    compliance_labels = list(finding.compliance_tags) if finding.compliance_tags else []
    severity_label = f"severity-{finding.severity}".lower()
    confidence_label = f"confidence-{finding.confidence_level}".lower().replace(" ", "-")

    description = (
        f"h2. Vulnerability Details\n"
        f"*URL:* {finding.url}\n"
        f"*Vuln Class:* {finding.vuln_class}\n"
        f"*Confidence Level:* {finding.confidence_level}\n"
        f"*Tool:* {finding.tool_name}\n\n"
        f"h2. Description\n{finding.description}\n\n"
    )
    if finding.business_impact:
        description += f"h2. Business Impact\n{finding.business_impact}\n\n"
    if finding.payload:
        description += f"h2. Payload\n{{code}}{finding.payload}{{code}}\n\n"
    if finding.reasoning:
        description += f"h2. Reasoning / Audit Trail\n{finding.reasoning}\n\n"
    if finding.evidence_hash:
        description += f"h2. Evidence Hash (SHA-256)\n{finding.evidence_hash}\n"

    return {
        "fields": {
            "project": {"key": "SEC"},  # Default security project key
            "summary": f"[WebPent] {finding.title}",
            "description": description,
            "issuetype": {"name": "Bug"},
            "labels": [*compliance_labels, severity_label, confidence_label],
            "priority": {"name": _severity_to_jira_priority(str(finding.severity))},
        }
    }


def _severity_to_jira_priority(severity: str) -> str:
    """Map WebPent severity to Jira priority name."""
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    return mapping.get(severity.lower(), "Medium")


def _detect_webhook_type(webhook_url: str) -> str:
    """Detect the webhook type from the URL.

    Returns one of "slack", "discord", "jira", or "generic". The
    detection is based on the URL hostname.
    """
    try:
        host = (urlparse(webhook_url).hostname or "").lower()
    except Exception:
        return "generic"
    if "hooks.slack.com" in host:
        return "slack"
    if "discord.com" in host or "discordapp.com" in host:
        return "discord"
    if "atlassian.net" in host or "jira" in host:
        return "jira"
    return "generic"


def format_finding_payload(finding: Finding, webhook_url: str) -> dict[str, Any]:
    """Format a finding into the payload appropriate for the webhook type.

    V5 Sprint 11: Auto-detects the webhook type from the URL and
    returns the corresponding payload. Slack and Discord share the
    same simple ``{"text": "..."}`` format; Jira uses the REST API
    issue-creation format; generic webhooks get a structured JSON
    payload with all finding fields.
    """
    wtype = _detect_webhook_type(webhook_url)
    if wtype in ("slack", "discord"):
        return _format_slack_payload(finding)
    if wtype == "jira":
        return _format_jira_payload(finding)
    # Generic webhook — full structured payload.
    return {
        "event": "webpent_finding",
        "finding": {
            "id": str(finding.id),
            "campaign_id": getattr(finding, "campaign_id", None),
            "title": finding.title,
            "severity": str(finding.severity),
            "confidence_level": finding.confidence_level,
            "vuln_class": finding.vuln_class,
            "vulnerability_type": str(finding.vuln_class),
            "route": getattr(finding, "route", None) or finding.url,
            "url": finding.url,
            "tool_name": finding.tool_name,
            "payload": finding.payload,
            "business_impact": finding.business_impact,
            "compliance_tags": finding.compliance_tags,
            "evidence_hash": finding.evidence_hash,
            "reasoning": finding.reasoning,
            "cvss_score": finding.cvss_score,
        },
    }


async def push_to_webhook(finding: Finding, webhook_url: str) -> bool:
    """Push a single finding to a webhook URL.

    V5 Sprint 11/P0-5: Async function that formats the finding according to
    the webhook type (Slack/Discord/Jira/generic), signs the exact JSON
    bytes with HMAC-SHA256, and transmits them through the SSRF-hardened
    client with TLS certificate verification enabled. Returns True on
    success, False on failure.

    Args:
        finding: The :class:`Finding` to push. Only findings with
            ``confidence_level`` in ``{"Tool-Confirmed",
            "Needs Human Review"}`` should be pushed — the caller is
            responsible for filtering (see :func:`maybe_push_finding`).
        webhook_url: The webhook endpoint URL.

    Returns:
        ``True`` if the webhook accepted the request (HTTP 2xx),
        ``False`` otherwise.
    """
    if not webhook_url:
        logger.debug("push_to_webhook: empty webhook_url — skipping")
        return False

    settings = get_settings()
    secret = settings.webhook_secret.get_secret_value()
    if not secret:
        logger.error("Webhook push refused: WEBHOOK_SECRET is required for signed delivery")
        return False
    payload = format_finding_payload(finding, webhook_url)
    payload_bytes = _canonical_payload_bytes(payload)
    headers = {
        "Content-Type": "application/json",
        "X-WebPent-Signature": _webhook_signature(payload_bytes, secret),
    }

    try:
        # V6 Absolute-Flawless: use the SSRF-hardened async client.
        # The webhook URL comes from settings (operator-controlled),
        # but defence-in-depth still applies — the client blocks
        # redirects to internal networks AND pins DNS to prevent
        # rebinding TOCTOU races. This is the async equivalent of
        # make_safe_httpx_client used by the sync validator paths.
        async with make_safe_httpx_async_client(
            timeout=settings.webhook_timeout, verify=True
        ) as client:
            resp = await client.post(webhook_url, content=payload_bytes, headers=headers)
        if 200 <= resp.status_code < 300:
            logger.info(
                "Webhook push succeeded for finding %s (%s) → %d",
                finding.id,
                finding.title,
                resp.status_code,
            )
            return True
        logger.warning(
            "Webhook push failed for finding %s: HTTP %d — %s",
            finding.id,
            resp.status_code,
            resp.text[:200],
        )
        return False
    except Exception as exc:
        logger.warning("Webhook push error for finding %s: %s", finding.id, exc)
        return False


async def maybe_push_finding(finding: Finding) -> bool:
    """Settings-gated webhook push for a single finding.

    V5 Sprint 11: Checks ``Settings.webhook_enabled`` and
    ``Settings.webhook_url``. If either is falsy, returns False without
    making a network request. Only pushes findings whose
    ``confidence_level`` is in the actionable set.

    Args:
        finding: The :class:`Finding` to push.

    Returns:
        ``True`` if the finding was pushed successfully, ``False``
        otherwise (including when the integration is disabled).
    """
    settings = get_settings()
    if not settings.webhook_enabled or not settings.webhook_url:
        return False
    if finding.confidence_level not in _ACTIONABLE_CONFIDENCE_LEVELS:
        return False
    return await push_to_webhook(finding, settings.webhook_url)


async def push_findings_batch(findings: list[Finding], webhook_url: str) -> dict[str, bool]:
    """Push a batch of findings to a webhook.

    V5 Sprint 11: Filters to actionable findings, then pushes each
    concurrently. Returns a dict mapping finding ID to success/failure.

    Args:
        findings: The list of findings to push.
        webhook_url: The webhook endpoint URL.

    Returns:
        A dict ``{finding_id_str: bool}`` indicating per-finding
        success.
    """
    import asyncio

    actionable = [f for f in findings if f.confidence_level in _ACTIONABLE_CONFIDENCE_LEVELS]
    if not actionable:
        return {}

    settings = get_settings()
    semaphore = asyncio.Semaphore(settings.webhook_max_concurrency)

    async def _bounded_push(finding: Finding) -> bool:
        async with semaphore:
            return await push_to_webhook(finding, webhook_url)

    tasks = [_bounded_push(finding) for finding in actionable]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out: dict[str, bool] = {}
    for finding, result in zip(actionable, results, strict=False):
        if isinstance(result, Exception):
            out[str(finding.id)] = False
        else:
            out[str(finding.id)] = bool(result)
    return out
