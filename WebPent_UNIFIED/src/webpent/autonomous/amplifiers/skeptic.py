"""Self-adversarial validation — the internal devil's advocate (v82,
Layer 2 / Task 6).

Before a candidate finding is trusted, the skeptic attacks it with four
independent doubts, each backed by a re-probe the operator's injected
double performs:

* caching doubt: the same probe with a fresh cache-buster parameter must
  reproduce the signature,
* statistical doubt: repeating the probe must reproduce the signature at
  least twice out of three,
* session doubt: the probe from a fresh session must reproduce the
  signature (rules out "only my session sees this"),
* timing doubt: a fast retry must still reproduce it (rules out
  rate-limit-window artifacts).

Every check is executed through the injected ``reprobe`` callable; the
skeptic itself never touches the network and never mints a request of
its own. Verdict is ``upheld`` (every doubt survived), ``self_refuted``
(any doubt failed), or ``inconclusive`` (a check could not run). The
verdict is advisory: it annotates the finding's record, and the sealed
proof pipeline remains the only promotion authority.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

REPEAT_TIMES = 3
REPEAT_MIN_HITS = 2

# reprobe(url, variant) -> truthy response body/dict when the original
# signature reproduces, falsy when it does not. Never raises past False.
Reprobe = Callable[[str, str], Any]


def _cache_busted(url: str) -> str:
    """Strip query and append a fresh cache-buster parameter."""
    parts = urlsplit(str(url or ""))
    if not parts.scheme:
        return str(url or "")
    cb = uuid.uuid4().hex[:8]
    query = f"{parts.query}&cb={cb}" if parts.query else f"cb={cb}"
    return f"{parts.scheme}://{parts.netloc}{parts.path}?{query}"


def run_skeptic_checks(
    candidate_url: str, *, reprobe: Reprobe
) -> dict[str, Any]:
    """Run the four doubts; advisory verdict with per-check reasons."""
    url = _cache_busted(str(candidate_url or ""))
    if not url:
        return {
            "verdict": "inconclusive",
            "checks": {},
            "advisory": True,
            "reason": "bad_candidate",
        }

    checks: dict[str, Any] = {}
    verdict = "upheld"

    # 1. caching doubt — the candidate is already probed with a fresh
    # cache-buster appended by _cache_busted above.
    try:
        checks["cache_buster"] = bool(reprobe(url, "cache"))
    except Exception:
        checks["cache_buster"] = False
    if not checks["cache_buster"]:
        verdict = "self_refuted"

    # 2. statistical doubt — at least REPEAT_MIN_HITS of REPEAT_TIMES.
    try:
        hits = sum(1 for _ in range(REPEAT_TIMES) if reprobe(url, "repeat"))
    except Exception:
        hits = 0
    checks["statistical_repeat"] = {
        "hits": hits, "trials": REPEAT_TIMES, "passed": hits >= REPEAT_MIN_HITS
    }
    if not checks["statistical_repeat"]["passed"]:
        verdict = "self_refuted"

    # 3. session doubt — fresh-session reproduction.
    try:
        checks["fresh_session"] = bool(reprobe(url, "fresh_session"))
    except Exception:
        checks["fresh_session"] = False
    if not checks["fresh_session"]:
        verdict = "self_refuted"

    # 4. timing doubt — immediate retry still reproduces; record latency.
    try:
        start = time.monotonic()
        checks["timing_retry"] = bool(reprobe(url, "timing"))
        checks["timing_retry_ms"] = int((time.monotonic() - start) * 1000)
    except Exception:
        checks["timing_retry"] = False
    if not checks["timing_retry"]:
        verdict = "self_refuted"

    return {
        "candidate": redact(url)[:500],
        "verdict": verdict,
        "checks": checks,
        "advisory": True,
    }
