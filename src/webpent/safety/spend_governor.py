# src/webpent/safety/spend_governor.py
"""LLM spend governor (2026-10-25 Proposal 10, control 3).

A per-engagement token counter over the ONE funnel every LLM call
passes through (``BaseLLMProvider.generate``). At the cap the LLM lane
fails CLOSED: the provider returns an error response
(``LLM_SPEND_CAP_REACHED``) instead of a completion, so every
downstream consumer falls back along its existing deterministic path
automatically — the codebase degrades to deterministic logic whenever
the LLM errors, and this control makes that degradation deliberate
instead of incidental.

Counters are in-process and per-engagement (a campaign runs in one
worker process; that is where its spend accrues). ``note_llm_response``
records usage; ``over_cap`` is the enforcement check; ``spend_snapshot``
is the read-only dashboard view.
"""
from __future__ import annotations

import threading
from dataclasses import is_dataclass, replace
from typing import Any, Iterable

from webpent.safety.request_ledger import _active_engagement_id

__all__ = [
    "SPEND_CAP_ERROR",
    "record_usage",
    "used",
    "over_cap",
    "deterministic_only",
    "note_llm_response",
    "enforce_spend_cap",
    "spend_snapshot",
    "reset",
]

SPEND_CAP_ERROR = "LLM_SPEND_CAP_REACHED"

# Hard bound on tracked engagement counters. A long-lived worker process
# would otherwise accumulate one counter per engagement forever — an
# unbounded memory leak (the v3.0 defect: counters were never evicted).
# When the bound is hit, the lowest-usage counters are evicted first:
# a genuinely active engagement re-accrues, an idle one had nothing
# worth remembering.
MAX_TRACKED_ENGAGEMENTS = 256

_lock = threading.Lock()
_counters: dict[str, int] = {}


def _evict_locked(protect: str | None = None) -> None:
    """Trim counters to the bound, evicting lowest usage first.

    ``protect`` (the counter being written right now) is never evicted:
    a live engagement must not lose its spend mid-update.
    """
    if len(_counters) <= MAX_TRACKED_ENGAGEMENTS:
        return
    keep = sorted(
        (kv for kv in _counters.items() if kv[0] != protect),
        key=lambda kv: -kv[1],
    )[: max(0, MAX_TRACKED_ENGAGEMENTS - 1)]
    kept = dict(keep)
    if protect is not None and protect in _counters:
        kept[protect] = _counters[protect]
    _counters.clear()
    _counters.update(kept)


def record_usage(engagement_id: str, tokens: int) -> int:
    """Add ``tokens`` to the engagement's counter; return the new total."""
    try:
        tokens = int(tokens)
    except Exception:  # noqa: BLE001
        return used(engagement_id)
    if tokens <= 0:
        return used(engagement_id)
    key = str(engagement_id or "unassigned")
    with _lock:
        _counters[key] = _counters.get(key, 0) + tokens
        _evict_locked(protect=key)
        return _counters[key]


def used(engagement_id: str) -> int:
    with _lock:
        return _counters.get(str(engagement_id or "unassigned"), 0)


# --- Per-tier spend accounting (PROPOSALS_ULTIMATE_V2 §9, 2026-10-30) ----
# ADDITIVE: existing counters/caps/eviction are untouched. Tier counters
# track tokens per model tier (fast/strong/unclassified) so an operator
# can see what each tier actually burned, and are bounded by the same
# MAX_TRACKED_ENGAGEMENTS policy (keyed "engagement_id|tier").

_tier_counters: dict[str, int] = {}


def record_tier_usage(
    tier: str, tokens: int, engagement_id: str | None = None
) -> int:
    """Add ``tokens`` to the (engagement, tier) counter; return the total.

    Bookkeeping only: tier counters never affect cap enforcement — the
    engagement total in :func:`record_usage` remains the single source
    of truth for the cap.
    """
    try:
        tokens = int(tokens)
    except Exception:  # noqa: BLE001
        return _tier_counters.get(_tier_key(engagement_id, tier), 0)
    if tokens <= 0:
        return _tier_counters.get(_tier_key(engagement_id, tier), 0)
    key = _tier_key(engagement_id, tier)
    with _lock:
        _tier_counters[key] = _tier_counters.get(key, 0) + tokens
        return _tier_counters[key]


def _tier_key(engagement_id: str | None, tier: str) -> str:
    return f"{str(engagement_id or 'unassigned')}|{str(tier or 'unclassified')}"


def tier_snapshot(engagement_id: str | None = None) -> dict[str, int]:
    """Tokens burned per tier for one engagement (all engagements
    aggregated by tier when ``None``)."""
    with _lock:
        if engagement_id is None:
            totals: dict[str, int] = {}
            for key, value in _tier_counters.items():
                tier = key.rsplit("|", 1)[1]
                totals[tier] = totals.get(tier, 0) + value
            return totals
        prefix = f"{str(engagement_id or 'unassigned')}|"
        return {
            key[len(prefix):]: value
            for key, value in _tier_counters.items()
            if key.startswith(prefix)
        }


def cap_from_settings() -> int:
    try:
        from webpent.config.settings import get_settings

        return max(0, int(get_settings().llm_token_cap_per_engagement))
    except Exception:  # noqa: BLE001 — no settings = no cap (flag off anyway)
        return 0


def over_cap(engagement_id: str) -> bool:
    """Enforcement check. cap <= 0 means unlimited; flag-off callers
    never reach here, but the check itself stays honest either way."""
    cap = cap_from_settings()
    if cap <= 0:
        return False
    return used(engagement_id) >= cap


def deterministic_only(engagement_id: str) -> bool:
    """True when the engagement exhausted its LLM budget (at or past cap)."""
    return over_cap(engagement_id)


def reset(engagement_id: str) -> None:
    with _lock:
        _counters.pop(str(engagement_id or "unassigned"), None)


def _usage_tokens(response: Any) -> int:
    """Best-effort token count from one response object.

    ``tokens_used``/``total_tokens`` attributes win when nonzero; the
    v3.0 defect short-circuited on the FIRST attribute regardless of
    value, and ``LLMResponse.tokens_used`` is a dataclass field that
    defaults to 0 — so a response whose provider filled only ``usage``
    was always recorded as 0 tokens and the cap never moved. A zero
    attribute falls through to the ``usage`` dict (or usage object with
    a ``total_tokens`` attribute, OpenAI-style).
    """
    for attr in ("tokens_used", "total_tokens"):
        value = getattr(response, attr, None)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    usage = getattr(response, "usage", None)
    if isinstance(usage, dict):
        return int(usage.get("total_tokens") or 0)
    total = getattr(usage, "total_tokens", None)
    if isinstance(total, int) and not isinstance(total, bool):
        return total
    return 0


def note_llm_response(response: Any, *, engagement_id: str | None = None) -> int:
    """Record the response's token usage against the active engagement."""
    tokens = _usage_tokens(response)
    return record_usage(
        engagement_id if engagement_id is not None else _active_engagement_id(), tokens
    )


def enforce_spend_cap(response: Any, *, engagement_id: str | None = None) -> Any:
    """Record usage, then fail closed at the cap.

    A successful response recorded past the cap is replaced by an error
    response of the SAME type (``replace`` on the dataclass), so callers
    see the provider error they already handle and take their
    deterministic path. Fail-soft on any unexpected shape: an
    enforcement error must never corrupt a real response.
    """
    try:
        note_llm_response(response, engagement_id=engagement_id)
        if getattr(response, "error", None):
            return response  # already failed — nothing to cap
        target = engagement_id if engagement_id is not None else _active_engagement_id()
        if not over_cap(target):
            return response
        if is_dataclass(response) and not isinstance(response, type):
            # The spend of the capped call is recorded above (note ran
            # before this branch) and MUST survive the replacement: a
            # capped response that came back with tokens_used=0 would
            # let downstream accounting undercount the real spend (the
            # v3.0 defect — the replacement discarded the usage).
            tokens = _usage_tokens(response)
            replaced = replace(
                response,
                content="",
                raw_content="",
                error=SPEND_CAP_ERROR,
                finish_reason="spend_cap_reached",
            )
            if hasattr(replaced, "tokens_used") and tokens:
                replaced.tokens_used = tokens
            return replaced
        return response
    except Exception:  # noqa: BLE001 — enforcement must not break the call
        return response


def spend_snapshot() -> list[dict[str, Any]]:
    """Read-only view for the worker dashboard, bounded."""
    with _lock:
        items: Iterable[tuple[str, int]] = list(_counters.items())
    cap = cap_from_settings()
    return [
        {
            "engagement_id": key,
            "tokens_used": value,
            "cap": cap,
            "deterministic_only": cap > 0 and value >= cap,
        }
        for key, value in sorted(items, key=lambda kv: -kv[1])[:32]
    ]
