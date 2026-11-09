"""Operational amplifiers (v82, Layer 3 / Tasks 10-12).

Three pure analyzers over operator-supplied observations:

* ``temporal`` — timestamped observations (status/size/timestamp) reveal
  deploy windows and periodic patterns (cron-like hour clustering).
* ``rate_limit_map`` — 429/limit-header observations per endpoint build a
  rate-limit map; endpoints never seen limited are flagged "unbounded?"
  suspects. Header-manipulation bypass probing belongs to the operator's
  gated execution; here it is advisory classification only.
* ``session_topology`` — before/after cookie sets across login and logout
  reveal session-fixation indicators (same session cookie value surviving
  authentication) and concurrent-session/riding hints. Pure diffing; no
  requests are made here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

MAX_OBSERVATIONS = 256
MAX_ENDPOINTS = 32
MAX_EVENTS = 128
MAX_SESSION_EVENTS = 32


# -- Task 10: temporal intelligence ---------------------------------------


def _hour_of(ts: Any) -> int | None:
    """Accept 'HH:MM'/'HH' strings or epoch-ish floats; None otherwise."""
    if isinstance(ts, str):
        head = ts.strip().split(":")[0]
        if head.isdigit() and 0 <= int(head) <= 23:
            return int(head)
        return None
    if isinstance(ts, (int, float)):
        return int(ts) % 24
    return None


def temporal_profile(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect periodic hour clustering and size/status shifts over time."""
    if not isinstance(observations, list) or not observations:
        return {"signals": [], "hour_histogram": {}, "advisory": True}
    obs = [o for o in observations[:MAX_OBSERVATIONS] if isinstance(o, dict)]
    hours = Counter()
    for item in obs:
        hour = _hour_of(item.get("ts"))
        if hour is not None:
            hours[hour] += 1
    histogram = {str(hour): count for hour, count in sorted(hours.items())}
    total = sum(hours.values())
    signals: list[dict[str, Any]] = []
    if total >= 4:
        # Periodic window: an hour holding >= half the observations.
        peak_hour, peak_count = hours.most_common(1)[0]
        if peak_count >= max(2, 0.5 * total):
            signals.append(
                {
                    "kind": "periodic_window",
                    "hour": peak_hour,
                    "share": round(peak_count / total, 2),
                    "note": "activity clusters in one hour — cron/deploy window suspect",
                }
            )
    # Deploy window: a sharp size shift between the first and second half.
    sizes = [item.get("size") for item in obs if isinstance(item.get("size"), (int, float))]
    if len(sizes) >= 4:
        half = len(sizes) // 2
        first, second = sizes[:half], sizes[half:]
        if first and second:
            ratio = (sum(second) / len(second)) / max(1e-9, (sum(first) / len(first)))
            if ratio > 1.5 or ratio < 0.67:
                signals.append(
                    {
                        "kind": "response_size_shift",
                        "ratio": round(ratio, 2),
                        "note": (
                            "average response size shifted mid-series — "
                            "deploy/change window suspect"
                        ),
                    }
                )
    return {"signals": signals, "hour_histogram": histogram, "advisory": True}


# -- Task 11: rate-limit cartography ---------------------------------------


def _endpoint_of(url: str) -> str:
    parts = urlsplit(str(url or ""))
    if not parts.scheme or not parts.hostname:
        return redact(str(url or ""))[:120]
    return f"{parts.scheme.lower()}://{parts.netloc}{parts.path}"[:200]


def rate_limit_map(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Map observed limiting behavior per endpoint.

    Each observation: ``url``, ``status`` (int), and optional
    ``limit_headers`` (dict, e.g. X-RateLimit-Remaining).
    """
    if not isinstance(observations, list):
        return {"map": {}, "unbounded_suspects": [], "advisory": True}
    per: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"requests": 0, "limited": 0, "limit_headers_seen": 0}
    )
    for item in observations[:MAX_OBSERVATIONS]:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        endpoint = _endpoint_of(str(item["url"]))
        entry = per[endpoint]
        entry["requests"] += 1
        status = item.get("status")
        if status == 429:
            entry["limited"] += 1
        headers = item.get("limit_headers")
        if isinstance(headers, dict) and headers:
            entry["limit_headers_seen"] += 1
    bounded_map = dict(list(per.items())[:MAX_ENDPOINTS])
    suspects = [
        endpoint
        for endpoint, entry in bounded_map.items()
        if entry["requests"] >= 3 and entry["limited"] == 0 and entry["limit_headers_seen"] == 0
    ]
    return {
        "map": bounded_map,
        "unbounded_suspects": suspects[:MAX_ENDPOINTS],
        "advisory": True,
    }


# -- Task 12: session topology ---------------------------------------------


def _cookie_values(cookies: Any) -> dict[str, str]:
    if not isinstance(cookies, dict):
        return {}
    return {redact(str(k))[:64]: redact(str(v))[:128] for k, v in cookies.items()}


def session_topology(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Diff session cookies across lifecycle events (advisory indicators).

    Each event: ``phase`` in {"pre_login", "post_login", "post_logout",
    "switch_user"} and ``cookies`` (dict).
    """
    if not isinstance(events, list):
        return {"indicators": [], "phases_seen": [], "advisory": True}
    phases: dict[str, dict[str, str]] = {}
    for event in events[:MAX_SESSION_EVENTS]:
        if not isinstance(event, dict):
            continue
        phase = redact(str(event.get("phase") or "")).strip().lower()
        if phase in {"pre_login", "post_login", "post_logout", "switch_user"}:
            phases[phase] = _cookie_values(event.get("cookies"))
    indicators: list[dict[str, Any]] = []
    pre = phases.get("pre_login", {})
    post = phases.get("post_login", {})
    # Fixation: a session-type cookie with the same value before and after
    # authentication.
    for name, value in pre.items():
        is_session = "sess" in name.lower() or "sid" in name.lower()
        if is_session and post.get(name) == value and value:
                indicators.append(
                    {
                        "kind": "session_fixation_suspect",
                        "cookie": name,
                        "note": "same session cookie value before and after authentication",
                        "advisory": True,
                    }
                )
    # Riding hint: post_login cookies identical to switch_user cookies
    # (no re-issue when identity changed).
    switch = phases.get("switch_user", {})
    if switch and post and switch == post:
        indicators.append(
            {
                "kind": "session_riding_suspect",
                "note": "cookies unchanged after user switch — no re-issue observed",
                "advisory": True,
            }
        )
    # Logout: session cookie surviving logout.
    out = phases.get("post_logout", {})
    for name, value in post.items():
        is_session = "sess" in name.lower() or "sid" in name.lower()
        if is_session and out.get(name) == value and value:
                indicators.append(
                    {
                        "kind": "incomplete_logout_suspect",
                        "cookie": name,
                        "note": "session cookie value unchanged after logout",
                        "advisory": True,
                    }
                )
    return {
        "indicators": indicators[:MAX_SESSION_EVENTS],
        "phases_seen": sorted(phases),
        "advisory": True,
    }
