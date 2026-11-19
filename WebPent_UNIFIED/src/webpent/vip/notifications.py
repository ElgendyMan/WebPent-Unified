# src/webpent/vip/notifications.py
"""webpent.vip.notifications — Track 11, item 8: confirmation notifications.

Roadmap contract (المسار 11، البند 8):

    إشعارات: إرسال تنبيه إلى قناة يختارها المستخدم عند تأكيد finding،
    دون إرسال تفاصيل حساسة افتراضيًا.

    ("Notifications: send an alert to a user-chosen channel when a
    finding is CONFIRMED, without sending sensitive details by
    default.")

What already existed vs what was missing
----------------------------------------
``webpent.integrations.webhook`` (V5 Sprint 11) already provides the
transport: HMAC-signed, SSRF-hardened pushes to Slack/Discord/Jira/
generic webhooks, settings-gated by ``WEBHOOK_ENABLED``/``WEBHOOK_URL``.
What was missing is the actual TRACK-11 contract:

1. **A trigger at confirmation time** — ``maybe_push_finding`` had zero
   call sites on the confirmation paths (the only caller was the
   cost-alerts dispatcher for a different purpose).
2. **Redaction-first payloads** — the generic webhook format included
   the attack ``payload`` and full ``reasoning``; the roadmap forbids
   sensitive details BY DEFAULT.
3. **Persistence-safe dispatch** — notifications must never block,
   slow down, or break the DB write path that just confirmed a finding.
4. **Idempotency** — repeated saves of the same finding must not
   re-notify.

This module closes those four gaps:

* :func:`build_notification_payload` — redaction-first payload builder
  (identifier fields always; payload/reasoning only behind an explicit
  opt-in flag).
* :class:`ConfirmationNotifier` — a bounded queue + single daemon
  worker thread. ``notify_finding_confirmed`` never blocks the caller:
  it enqueues (or drops with a warning counter when full) and returns.
* :func:`notify_confirmation_transition` — the one call the DB layer
  makes on a CONFIRMED transition; fully guarded, disabled unless
  ``WEBHOOK_ENABLED`` (webhook channel) or ``NOTIFICATION_FILE_PATH``
  (file channel) is configured.
* Idempotency via a bounded notified-id registry (no re-notify for the
  same finding id).
* A severity threshold (``notification_min_severity``) so noisy low
  buckets can be silenced.

Channels are user-chosen via settings — webhook and/or a local JSONL
inbox file. Nothing is enabled by default; no external request is ever
made for a disabled channel.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.models.findings import Finding

logger = logging.getLogger(__name__)

__all__ = [
    "build_notification_payload",
    "build_operational_alert_payload",
    "ConfirmationNotifier",
    "get_confirmation_notifier",
    "notify_finding_confirmed",
    "notify_confirmation_transition",
    "reset_confirmation_notifier",
]

#: Severity rank used by the min-severity threshold filter.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Bounded registry of finding ids already dispatched (idempotency).
_NOTIFIED_IDS_CAP = 10_000


def build_notification_payload(
    finding: Finding,
    *,
    include_details: bool = False,
    event: str = "finding_confirmed",
) -> dict[str, Any]:
    """Redaction-first notification payload.

    Always included (identifier/summary fields only): finding id, title,
    severity, vuln_class, url, confidence level, campaign/engagement ids,
    tool name, and timestamps. These let a human decide whether to open
    the report — they do not leak exploit material.

    Included ONLY with ``include_details=True`` (explicit operator
    opt-in): the exact attack ``payload``, ``reasoning``, and
    ``business_impact``. Evidence bundles and raw request/response data
    are NEVER included in notifications by this module — the report is
    the evidence surface, not the notification channel.
    """
    payload: dict[str, Any] = {
        "event": event,
        "finding_id": str(finding.id),
        "title": finding.title,
        "severity": str(getattr(finding.severity, "value", finding.severity)),
        "vuln_class": str(getattr(finding.vuln_class, "value", finding.vuln_class)),
        "confidence_level": finding.confidence_level,
        "url": finding.url,
        "tool_name": finding.tool_name,
        "campaign_id": getattr(finding, "campaign_id", None),
        "thread_id": getattr(finding, "thread_id", None),
        "evidence_hash": finding.evidence_hash,
        "notified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if include_details:
        payload["payload"] = finding.payload
        payload["reasoning"] = finding.reasoning
        payload["business_impact"] = finding.business_impact
    return payload


def build_operational_alert_payload(
    *,
    event: str,
    severity: str,
    summary: str,
    redact_fn: Any = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Redaction-first payload for OPERATIONAL alerts (Track 11.1, 0.26.0).

    The confirmation notifier was Finding-shaped only, so the CEM watch
    changes (asset monitoring) had no path to the user's chosen channel
    — alerts lived and died in digest files. This payload builder keeps
    the same contract: identifier/summary fields only, every string
    through the caller's redaction function (``hunt_contracts.redact``
    for CEM), no raw response bodies, no credentials, no evidence.
    """
    clean = redact_fn if redact_fn is not None else (lambda value: value)
    payload: dict[str, Any] = {
        "event": str(clean(event))[:60],
        "severity": str(clean(severity))[:12],
        "summary": str(clean(summary))[:300],
        "notified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if extra:
        # Bounded, redacted identifier fields only.
        payload["details"] = {
            str(clean(str(k)))[:40]: str(clean(str(v)))[:120]
            for k, v in list(extra.items())[:8]
        }
    return payload


class ConfirmationNotifier:
    """Fire-and-forget dispatcher for confirmation notifications.

    Design constraints (all mandatory):

    * **Never blocks the caller** — ``submit`` enqueues and returns; the
      queue is bounded and overflows by DROPPING (with a warning
      counter), because a notification is strictly less important than
      the persistence path that produced it.
    * **Fail-safe** — every channel dispatch is individually guarded; a
      channel failure logs a warning and never propagates.
    * **Idempotent** — a finding id is dispatched at most once per
      process lifetime (bounded registry).
    * **Disabled by default** — with no channels configured the worker
      is not even started and submit is a no-op.
    """

    def __init__(
        self,
        *,
        webhook_url: str = "",
        webhook_enabled: bool = False,
        file_path: str | Path | None = None,
        include_details: bool = False,
        min_severity: str = "low",
        queue_maxsize: int = 256,
        webhook_secret: str = "",
        webhook_timeout: float = 10.0,
    ) -> None:
        self._webhook_url = (webhook_url or "").strip()
        self._webhook_enabled = bool(webhook_enabled) and bool(self._webhook_url)
        raw_file = str(file_path or "").strip()
        # Path("") normalizes to "." — an operator left the channel unset,
        # never write an inbox into the process working directory.
        if raw_file in {"", "."}:
            self._file_path = None
        else:
            self._file_path = Path(raw_file).expanduser()
        self._include_details = bool(include_details)
        self._min_rank = _SEVERITY_RANK.get(str(min_severity).strip().lower(), 1)
        self._webhook_secret = webhook_secret or ""
        self._webhook_timeout = float(webhook_timeout)
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=max(1, queue_maxsize))
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        self._notified_ids: dict[str, None] = {}  # ordered set (insertion order)
        self.stats = {"enqueued": 0, "dropped": 0, "dispatched": 0, "failed": 0, "suppressed": 0}

    # ------------------------------------------------------------------
    # public API (caller side — persistence-safe)
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self._webhook_enabled or self._file_path is not None

    def notify_finding_confirmed(self, finding: Finding) -> bool:
        """Queue one confirmation notification. Never raises, never blocks.

        Returns True when the event was enqueued, False when suppressed
        (disabled / below threshold / duplicate) or dropped (queue full).
        """
        try:
            if not self.enabled:
                return False
            with self._lock:
                key = str(finding.id)
                if key in self._notified_ids:
                    self.stats["suppressed"] += 1
                    return False
                severity = str(getattr(finding.severity, "value", finding.severity)).lower()
                if _SEVERITY_RANK.get(severity, 1) < self._min_rank:
                    self.stats["suppressed"] += 1
                    return False
                # Reserve the id NOW (before enqueue) so concurrent saves
                # of the same finding cannot double-notify.
                self._notified_ids[key] = None
                while len(self._notified_ids) > _NOTIFIED_IDS_CAP:
                    self._notified_ids.pop(next(iter(self._notified_ids)))
            payload = build_notification_payload(finding, include_details=self._include_details)
            self._ensure_worker()
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                # Bounded queue overflow: drop loudly, never block, and
                # release the reservation so a later save can retry.
                self.stats["dropped"] += 1
                with self._lock:
                    self._notified_ids.pop(str(finding.id), None)
                logger.warning(
                    "notifications: queue full — dropped confirmation event for %s",
                    finding.id,
                )
                return False
            self.stats["enqueued"] += 1
            return True
        except Exception:  # noqa: BLE001 — notifications must never break persistence
            logger.warning("notifications: submit failed (ignored)", exc_info=True)
            return False

    def notify_operational_alert(
        self,
        *,
        event: str,
        severity: str,
        summary: str,
        redact_fn: Any = None,
        extra: dict[str, Any] | None = None,
        dedupe_key: str = "",
    ) -> bool:
        """Queue one OPERATIONAL alert through the same channels (0.26.0).

        Track 11.1 wiring: CEM watchtower CRITICAL/SIGNAL-HIGH change
        alerts reach the user-chosen webhook/file channel with the same
        redaction-first, bounded, never-blocking contract as finding
        confirmations. Idempotency key is the ``dedupe_key`` (e.g. the
        alert digest) so the same alert is not re-sent on every cycle.
        Severity threshold applies; disabled channels suppress silently.
        """
        try:
            if not self.enabled:
                return False
            with self._lock:
                key = str(dedupe_key or f"{event}:{summary}")
                if key in self._notified_ids:
                    self.stats["suppressed"] += 1
                    return False
                if _SEVERITY_RANK.get(str(severity).strip().lower(), 1) < self._min_rank:
                    self.stats["suppressed"] += 1
                    return False
                self._notified_ids[key] = None
                while len(self._notified_ids) > _NOTIFIED_IDS_CAP:
                    self._notified_ids.pop(next(iter(self._notified_ids)))
            payload = build_operational_alert_payload(
                event=event,
                severity=severity,
                summary=summary,
                redact_fn=redact_fn,
                extra=extra,
            )
            self._ensure_worker()
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                self.stats["dropped"] += 1
                with self._lock:
                    self._notified_ids.pop(key, None)
                logger.warning(
                    "notifications: queue full — dropped operational alert %s", key
                )
                return False
            self.stats["enqueued"] += 1
            return True
        except Exception:  # noqa: BLE001 — notifications must never break callers
            logger.warning("notifications: operational alert submit failed (ignored)", exc_info=True)
            return False

    def drain_for_tests(self, timeout: float = 5.0) -> None:
        """Block until the queue is fully drained (test helper)."""
        self._queue.join()

    def close(self) -> None:
        if self._worker is not None:
            self._queue.put(None)
            self._worker.join(timeout=5.0)
            self._worker = None

    # ------------------------------------------------------------------
    # worker side (dispatch)
    # ------------------------------------------------------------------
    def _ensure_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._run, name="webpent-notifications", daemon=True
            )
            self._worker.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._dispatch(item)
            finally:
                self._queue.task_done()

    def _dispatch(self, payload: dict[str, Any]) -> None:
        ok_any = False
        if self._webhook_enabled:
            try:
                ok = self._push_webhook(payload)
                ok_any = ok_any or ok
            except Exception as exc:  # noqa: BLE001
                self.stats["failed"] += 1
                logger.warning("notifications: webhook dispatch failed: %s", exc)
        if self._file_path is not None:
            try:
                self._append_file(payload)
                ok_any = True
            except Exception as exc:  # noqa: BLE001
                self.stats["failed"] += 1
                logger.warning("notifications: file dispatch failed: %s", exc)
        if ok_any:
            self.stats["dispatched"] += 1

    def _push_webhook(self, payload: dict[str, Any]) -> bool:
        """Send via the existing hardened webhook transport (sync bridge).

        Reuses ``webpent.integrations.webhook``'s signed, SSRF-hardened
        POST — one transport, one security posture. The generic payload
        here is OUR redaction-first body (never the legacy
        details-carrying format).
        """
        import asyncio
        import hashlib
        import hmac as hmac_mod

        from webpent.shared.http import make_safe_httpx_async_client

        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._webhook_secret:
            digest = hmac_mod.new(
                self._webhook_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-WebPent-Signature"] = f"sha256={digest}"

        async def _post() -> int:
            async with make_safe_httpx_async_client(
                timeout=self._webhook_timeout, verify=True
            ) as client:
                resp = await client.post(self._webhook_url, content=body, headers=headers)
                return int(resp.status_code)

        status = asyncio.run(_post())
        ok = 200 <= status < 300
        if not ok:
            self.stats["failed"] += 1
            logger.warning(
                "notifications: webhook HTTP %d for %s",
                status,
                payload.get("finding_id"),
            )
        return ok

    def _append_file(self, payload: dict[str, Any]) -> None:
        """Append one JSONL row to the local notification inbox."""
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        with self._file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


_singleton: ConfirmationNotifier | None = None
_singleton_lock = threading.Lock()


def get_confirmation_notifier() -> ConfirmationNotifier:
    """Process-wide notifier built from current settings (lazy singleton)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            from webpent.config.settings import get_settings

            settings = get_settings()
            raw_file_path = str(getattr(settings, "notification_file_path", "") or "")
            _singleton = ConfirmationNotifier(
                webhook_url=str(getattr(settings, "webhook_url", "") or ""),
                webhook_enabled=bool(getattr(settings, "webhook_enabled", False)),
                file_path=raw_file_path or None,
                include_details=bool(getattr(settings, "notification_include_details", False)),
                min_severity=str(getattr(settings, "notification_min_severity", "low")),
                queue_maxsize=int(getattr(settings, "notification_queue_maxsize", 256)),
                webhook_secret=getattr(settings, "webhook_secret", None).get_secret_value()
                if getattr(settings, "webhook_secret", None)
                else "",
                webhook_timeout=float(getattr(settings, "webhook_timeout", 10.0)),
            )
        return _singleton


def reset_confirmation_notifier() -> None:
    """Drop the singleton (tests / settings reload)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            import contextlib

            with contextlib.suppress(Exception):
                _singleton.close()
        _singleton = None


def notify_finding_confirmed(finding: Finding) -> bool:
    """Module-level convenience wrapper (persistence-safe)."""
    return get_confirmation_notifier().notify_finding_confirmed(finding)


def notify_confirmation_transition(
    *,
    new_status: str,
    old_status: str | None,
    finding: Finding,
) -> bool:
    """The DB-layer hook: notify when a finding BECOMES confirmed.

    Called from ``save_finding`` and ``mark_oob_confirmed`` exactly when
    the state-machine status transitions INTO ``CONFIRMED``. All failure
    modes are swallowed (logged) — this must never break persistence.
    """
    try:
        from webpent.memory.db import STATUS_CONFIRMED

        if str(new_status) != STATUS_CONFIRMED or str(old_status) == STATUS_CONFIRMED:
            return False
        return notify_finding_confirmed(finding)
    except Exception:  # noqa: BLE001
        logger.warning("notifications: confirmation hook failed (ignored)", exc_info=True)
        return False
