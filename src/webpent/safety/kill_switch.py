# src/webpent/safety/kill_switch.py
"""Kill switch (2026-10-25 Proposal 10, control 2).

A shared state that freezes live operations within seconds of an
operator's POST: ``engage(reason)`` flips an in-process event that
every governor checks on acquire (``RequestRateGovernor.acquire``
checks it before yielding a live permit), so a freeze lands in the
same request cycle — well inside the ≤5s requirement, with no polling.

Multi-process propagation is best-effort Redis pub/sub: ``engage``
publishes to a fixed channel and a lazily-started daemon subscriber
applies remote engage/release events to the local state. Redis being
down or absent never blocks the local switch — the local event is the
authority for this process, and the subscriber is opportunistic
fanout. Fail-open for the fanout, fail-closed for the check itself.

The state lives in-process (deliberately): the kill switch is a
safety interlock, not shared mutable config. A worker that restarts
starts UNENGAGED — an operator re-issues the freeze if they still
need it, and the API returns the engagement audit so nothing is
silently lost.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

__all__ = [
    "engage",
    "release",
    "engaged",
    "status",
    "ensure_redis_subscriber",
]

_CHANNEL = "webpent:kill_switch"
KILL_SWITCH_PROPAGATION_S = 5.0  # documented bound for fanout, best-effort

_lock = threading.Lock()
_publish_lock = threading.Lock()
_seq = 0
_engaged_at: float | None = None
_engaged_reason: str = ""
_engaged_operator: str = ""

_subscriber_started = threading.Event()


def engage(reason: str, *, operator: str = "") -> None:
    """Freeze live operations. idempotent; keeps the FIRST reason."""
    global _engaged_at, _engaged_reason, _engaged_operator, _seq
    with _lock:
        if _engaged_at is not None:
            return  # already engaged — first reason is the audit record
        _engaged_at = time.time()
        _engaged_reason = str(reason or "unspecified")
        _engaged_operator = str(operator or "")
        _seq += 1
        # Payload captured INSIDE the lock: the v3.0 defect read the
        # reason/operator back outside it, so a concurrent release()
        # could blank them mid-read and ship a torn engage event. The
        # seq number also lets _apply_remote drop stale replays.
        payload = {
            "engaged": True,
            "reason": _engaged_reason,
            "operator": _engaged_operator,
            "seq": _seq,
        }
    # Serialized: publish order must match state-transition order, or a
    # release could reach remote processes before the engage that
    # logically preceded it.
    with _publish_lock:
        _publish(payload)


def release() -> None:
    """Unfreeze. Operator-initiated; idempotent."""
    global _engaged_at, _engaged_reason, _engaged_operator, _seq
    with _lock:
        if _engaged_at is None:
            return
        _engaged_at = None
        _engaged_reason = ""
        _engaged_operator = ""
        _seq += 1
        payload = {"engaged": False, "seq": _seq}
    with _publish_lock:
        _publish(payload)


def engaged() -> bool:
    """THE check every governor makes on acquire. Never raises."""
    with _lock:
        return _engaged_at is not None


def status() -> dict[str, Any]:
    with _lock:
        engaged_now = _engaged_at is not None
        return {
            "engaged": engaged_now,
            "reason": _engaged_reason,
            "operator": _engaged_operator,
            "engaged_age_seconds": (
                round(max(0.0, time.time() - _engaged_at), 1) if _engaged_at is not None else None
            ),
        }


def _publish(payload: dict[str, Any]) -> None:
    """Best-effort Redis fanout. Absent Redis = local switch still holds."""
    try:
        if _subscriber_started.is_set() or os.environ.get("REDIS_URL") or os.environ.get(
            "CELERY_BROKER_URL"
        ):
            import redis  # type: ignore[import-not-found]

            url = os.environ.get("REDIS_URL") or os.environ.get("CELERY_BROKER_URL")
            client = redis.Redis.from_url(url, socket_connect_timeout=1.0, socket_timeout=1.0)
            client.publish(_CHANNEL, json.dumps(payload))
    except Exception:  # noqa: BLE001 — fanout is opportunistic
        pass


def _apply_remote(payload: bytes) -> None:
    """Apply a remote engage/release event to local state."""
    global _engaged_at, _engaged_reason, _engaged_operator
    try:
        event = json.loads(payload)
    except Exception:  # noqa: BLE001
        return
    with _lock:
        if event.get("engaged"):
            if _engaged_at is None:
                _engaged_at = time.time()
                _engaged_reason = str(event.get("reason") or "remote")
                _engaged_operator = str(event.get("operator") or "remote")
        else:
            _engaged_at = None
            _engaged_reason = ""
            _engaged_operator = ""


def ensure_redis_subscriber() -> None:
    """Start the daemon subscriber once per process. Never raises.

    Called lazily by the safety status snapshot when the kill switch
    flag is on; the subscriber only exists if a Redis URL is available
    and the ``redis`` package is importable.
    """
    if _subscriber_started.is_set():
        return
    _subscriber_started.set()
    url = os.environ.get("REDIS_URL") or os.environ.get("CELERY_BROKER_URL")
    if not url:
        return

    def _listen() -> None:
        _listen_loop(url)

    threading.Thread(target=_listen, name="webpent-kill-switch-sub", daemon=True).start()


def _listen_loop(url: str) -> None:
    """Subscribe-and-apply loop with reconnect (testable seam).

    Exposed at module level so the reconnect behavior can be exercised
    without a real Redis. Runs until the process dies.
    """
    import redis  # type: ignore[import-not-found]

    backoff = 1.0
    while True:
        try:
            client = redis.Redis.from_url(
                url, socket_connect_timeout=1.0, socket_timeout=5.0
            )
            pubsub = client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(_CHANNEL)
            backoff = 1.0  # a successful subscribe resets the backoff
            for message in pubsub.listen():
                if message and message.get("type") == "message":
                    _apply_remote(message.get("data") or b"")
        except Exception:  # noqa: BLE001 — subscriber is opportunistic
            pass
        # Redis dropped (or never came up): the v3.0 defect exited
        # the thread permanently, so this process silently stopped
        # receiving remote engages/releases for the rest of its
        # life. Reconnect with capped exponential backoff instead —
        # the kill switch must never rot quietly.
        time.sleep(backoff)
        backoff = min(backoff * 2.0, 30.0)
