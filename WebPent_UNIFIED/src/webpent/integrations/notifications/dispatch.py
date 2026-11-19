# src/webpent/integrations/notifications/dispatch.py
"""Notification dispatch with fail-soft per-platform sending (V3 §4).

The pipeline, fail-closed in order:

  1. flag gate — ``enable_notifications`` False raises before anything
     else (no formatter runs, no endpoint is resolved, no ledger row);
  2. ledger — a real ``request_ledger`` is mandatory, like every other
     network-touching surface;
  3. severity gate — findings under ``notify_min_severity`` (default
     ``high``) are NOT sent immediately; they are counted (and handed
     to the caller's digest buffer when one is provided);
  4. per channel, per finding: resolve the endpoint from the
     ENVIRONMENT ONLY (``SLACK_WEBHOOK_URL``, ``DISCORD_WEBHOOK_URL``,
     ``TELEGRAM_BOT_TOKEN`` + ``TELEGRAM_CHAT_ID``), format, ledger the
     send event, then send.

PRIVACY (written into the module, not just the plan): webhook endpoints
are secrets. They are read from the environment only, never returned in
a report entry, never written to a log, and never placed in the ledger
verbatim — the ledger row records ``notify://<platform>#<8-hex digest
of the endpoint>`` so sends stay auditable without storing the secret.
Endpoints also never enter the evidence bundle (dispatch produces
reports, not findings).

FAIL-SOFT: one platform failing (exception, non-2xx, missing secret)
never breaks the campaign loop — it becomes a report entry and
dispatch continues. The flag gate and the ledger gate are the only
hard failures. ``send_fn(url, payload) -> bool`` is injected; the
default POSTs JSON over HTTPS (plain HTTP allowed only for loopback
hosts so local test fixtures work). The module owns no scheduling and
no retries: one attempt per channel/finding.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from webpent.models.findings import Finding

__all__ = [
    "NOTIFICATION_PLATFORMS",
    "SEVERITY_ORDER",
    "NotificationError",
    "DispatchEntry",
    "DispatchReport",
    "severity_rank",
    "severity_gate",
    "notifications_refusal",
    "dispatch",
]

NOTIFICATION_PLATFORMS = frozenset({"slack", "discord", "telegram"})

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

SEND_TIMEOUT_SECONDS = 10.0


class NotificationError(ValueError):
    """Raised when notifications cannot proceed fail-closed."""


def severity_rank(severity: str) -> int:
    """Rank of a severity bucket; unknown buckets fail closed."""
    try:
        return SEVERITY_ORDER.index(str(severity).strip().lower())
    except ValueError as exc:
        raise NotificationError(
            f"notifications_unknown_severity: {severity!r}"
        ) from exc


def severity_gate(finding: Finding, min_severity: str) -> bool:
    """True when the finding may be sent immediately (at/above threshold).

    Pure and fail-closed: an unknown threshold or an unknown finding
    severity raises rather than silently passing or dropping.
    """
    return severity_rank(str(getattr(finding, "severity", ""))) >= severity_rank(min_severity)


def notifications_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_notifications:
        return "notifications_flag_off"
    return None


@dataclass
class DispatchEntry:
    """One send attempt's outcome (never contains the endpoint)."""

    platform: str
    finding_id: str
    status: str  # sent | failed | ledger_refused | skipped_no_secret | unknown_platform
    detail: str = ""


@dataclass
class DispatchReport:
    """What one dispatch run did, plus what it deliberately did not."""

    entries: list[DispatchEntry] = field(default_factory=list)
    sent: int = 0
    suppressed_below_threshold: int = 0
    suppressed_findings: list[Finding] = field(default_factory=list)


def _endpoint_digest(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:8]


def _endpoint_for(platform: str) -> str | None:
    """Resolve the endpoint from the environment only, or None.

    The secret never lands in a return value the caller logs — callers
    should treat it as use-once. Telegram needs both its bot token and
    a chat id.
    """
    if platform == "slack":
        return os.environ.get("SLACK_WEBHOOK_URL") or None
    if platform == "discord":
        return os.environ.get("DISCORD_WEBHOOK_URL") or None
    if platform == "telegram":
        token = os.environ.get("TELEGRAM_BOT_TOKEN") or ""
        chat = os.environ.get("TELEGRAM_CHAT_ID") or ""
        if not token or not chat:
            return None
        return f"https://api.telegram.org/bot{token}/sendMessage"
    return None


def _chat_id_for(platform: str) -> str:
    if platform == "telegram":
        return os.environ.get("TELEGRAM_CHAT_ID") or ""
    return ""


def _default_send(endpoint: str, payload: dict[str, Any]) -> bool:
    """POST the payload as JSON; True only on an HTTP 2xx.

    HTTPS only — except loopback hosts, which local test fixtures use.

    M1-A (M-5): the POST goes through the ONE authoritative safe
    transport (SSRF pinning + private-IP blocklist + rate ceiling)
    instead of a raw ``urlopen`` — a mistyped or hostile env-configured
    endpoint can no longer make the framework fetch internal URLs.
    Fail-open on error is preserved (notification delivery is
    best-effort).
    """
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("https", "http"):
        return False
    loopback_endpoint = (
        parsed.scheme == "http"
        and parsed.hostname in ("127.0.0.1", "localhost", "::1")
    )
    if parsed.scheme == "http" and not loopback_endpoint:
        return False
    if not parsed.netloc:
        return False
    try:
        from webpent.shared.http import (
            clear_loopback_trusted_endpoint,
            make_safe_httpx_client,
            set_loopback_trusted_endpoint,
        )

        # M1-C (UM-DR-12): the scheme rule above documents loopback as an
        # allowed local receiver, but the safe transport's blocklist vetoed
        # it at connect time (M-5 latent regression). For a loopback
        # endpoint only, set the transport's loopback-trusted exemption
        # around the single POST; non-loopback http and every private
        # non-loopback host stay blocked exactly as M-5 pinned them.
        loopback_token = (
            set_loopback_trusted_endpoint() if loopback_endpoint else None
        )
        try:
            with make_safe_httpx_client(
                timeout=float(SEND_TIMEOUT_SECONDS), follow_redirects=False
            ) as client:
                response = client.post(
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                return 200 <= response.status_code < 300
        finally:
            if loopback_token is not None:
                clear_loopback_trusted_endpoint(loopback_token)
    except Exception:
        return False


def _format_payload(platform: str, finding: Finding, chat_id: str) -> dict[str, Any]:
    if platform == "slack":
        from webpent.integrations.notifications.formatters.slack import format_slack

        return format_slack(finding)
    if platform == "discord":
        from webpent.integrations.notifications.formatters.discord import format_discord

        return format_discord(finding)
    if platform == "telegram":
        from webpent.integrations.notifications.formatters.telegram import format_telegram

        return format_telegram(finding, chat_id=chat_id)
    raise NotificationError(f"notifications_unknown_platform: {platform!r}")


def dispatch(
    findings: list[Finding],
    *,
    ledger: Any,
    send_fn: Callable[[str, dict[str, Any]], bool] | None = None,
    digest_buffer: Any | None = None,
    engagement_id: str = "",
) -> DispatchReport:
    """Send above-threshold findings to every configured channel.

    Fail-soft per channel; fail-closed on the flag gate, a missing
    ledger, or unknown severities/thresholds. When ``digest_buffer``
    is given, below-threshold findings are appended there (their
    destination per the plan: the daily digest only).
    """
    from webpent.config.settings import get_settings

    if not get_settings().enable_notifications:
        raise NotificationError("notifications_flag_off")
    if ledger is None or not hasattr(ledger, "record"):
        raise NotificationError("notifications_ledger_required")
    send = send_fn if send_fn is not None else _default_send
    settings = get_settings()
    min_severity = settings.notify_min_severity
    channels = list(settings.notify_channels or [])

    report = DispatchReport()
    for finding in findings:
        try:
            passes = severity_gate(finding, min_severity)
        except NotificationError:
            raise
        if not passes:
            report.suppressed_below_threshold += 1
            report.suppressed_findings.append(finding)
            if digest_buffer is not None:
                digest_buffer.add_finding(finding, engagement_id=engagement_id)
            continue
        for platform in channels:
            report.entries.append(
                _dispatch_one(finding, platform, ledger, send, engagement_id)
            )
    report.sent = sum(1 for e in report.entries if e.status == "sent")
    return report


def _dispatch_one(
    finding: Finding,
    platform: str,
    ledger: Any,
    send: Callable[[str, dict[str, Any]], bool],
    engagement_id: str,
) -> DispatchEntry:
    """One channel/finding send attempt. Never raises (fail-soft)."""
    finding_id = str(finding.id)
    if platform not in NOTIFICATION_PLATFORMS:
        return DispatchEntry(platform, finding_id, "unknown_platform",
                             detail="not a documented platform")
    endpoint = _endpoint_for(platform)
    if endpoint is None:
        return DispatchEntry(platform, finding_id, "skipped_no_secret",
                             detail="endpoint env var not set")
    try:
        payload = _format_payload(platform, finding, _chat_id_for(platform))
    except NotificationError as exc:
        return DispatchEntry(platform, finding_id, "failed", detail=str(exc))
    try:
        recorded = ledger.record(
            "POST",
            f"notify://{platform}#{_endpoint_digest(endpoint)}",
            engagement_id=engagement_id,
            flags="notify",
        )
    except Exception:  # noqa: BLE001 — ledger failure must not bypass
        recorded = False
    if not recorded:
        return DispatchEntry(platform, finding_id, "ledger_refused",
                             detail="request ledger refused the send event")
    try:
        ok = bool(send(endpoint, payload))
    except Exception as exc:  # noqa: BLE001 — one platform must not break the loop
        return DispatchEntry(platform, finding_id, "failed",
                             detail=f"send_error: {type(exc).__name__}")
    if not ok:
        return DispatchEntry(platform, finding_id, "failed",
                             detail="platform returned non-2xx or transport error")
    return DispatchEntry(platform, finding_id, "sent")
