# src/webpent/waf_evasion/adaptive.py
"""Adaptive WAF evasion (PROPOSALS_ULTIMATE_V3 §3, 2026-10-31).

A human tester whose payload is blocked does not give up and does not
brute-force: they try a different ENCODING of the same payload, and
remember which encoding worked for that target. This module does
exactly that, mechanically:

  - ``transform_registry``: a DOCUMENTED MANUAL LIST of pure
    text-to-text transforms (case, double URL encoding, SQL inline
    comments, JSON unicode escaping, space substitution). No payloads
    are invented here — the payload is the operator's/agent's; only
    its encoding is adapted.
  - ``AdaptiveClient.send_with_adaptation``: send the original; when
    the send is classified as a WAF block, walk the transforms in
    SESSION-MEMORY order (transformations that succeeded earlier in
    this session are tried first), recording every attempt in the
    request ledger.
  - ``BackoffPolicy``: on rate-limit blocks the pace drops along an
    exponential curve with a hard ceiling. Evasion here is not
    violent: total attempts per payload are bounded by
    ``waf_adaptive_max_attempts`` (default 3, hard cap 5); beyond
    that the attempt ends ``inconclusive: waf_blocked``.

ETHICAL BOUND (written into the module, not just the plan): adaptive
evasion serves AUTHORIZED testing only. Every send passes the
operator's ``scope_enforcer`` and the shared ``request_ledger``, the
kill switch is checked before anything is sent, and the transforms
never escalate payload content — they only re-encode the same content
the operator chose to send. Anything the scope refuses is refused
here too.

Flag-gated by ``enable_waf_adaptive`` (default False): with the flag
off the client raises before touching the network callable, the
ledger or the scope.
"""

from __future__ import annotations

import json

import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "transform_registry",
    "TRANSFORM_ORDER",
    "classify_waf_block",
    "BackoffPolicy",
    "AdaptiveContext",
    "AdaptiveResponse",
    "AdaptiveResult",
    "AdaptiveEvasionError",
    "waf_adaptive_refusal",
    "AdaptiveClient",
]

# Hard cap independent of settings: a mistyped cap cannot escalate
# request volume beyond five attempts per payload.
MAX_ATTEMPTS_CAP = 5

WAF_BLOCK_STATUSES = frozenset({403, 406, 429, 501})
# Documented body markers (lowercase substrings) commonly emitted by
# edge protections on an otherwise-200 or 4xx page.
WAF_BLOCK_MARKERS = (
    "request blocked",
    "access denied",
    "blocked by",
    "cloudflare",
    "rate limit",
    "too many requests",
    "forbidden",
)

MAX_BACKOFF_SECONDS = 8.0
BASE_BACKOFF_SECONDS = 0.5


class AdaptiveEvasionError(ValueError):
    """Raised when adaptive evasion cannot proceed fail-closed."""


# ---------------------------------------------------------------------------
# Transform registry: pure (str -> str), no network, fully testable.
# ---------------------------------------------------------------------------


def _toggle_case(payload: str) -> str:
    return payload.swapcase()


def _double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _sql_inline_comment(payload: str) -> str:
    # classic keyword-splitting separator: spaces become inline comments
    return payload.replace(" ", "/**/")


def _json_unicode_escape(payload: str) -> str:
    return json.dumps(payload)[1:-1]


def _space_to_percent20(payload: str) -> str:
    return payload.replace(" ", "%20")


def _space_to_plus(payload: str) -> str:
    return payload.replace(" ", "+")


TRANSFORM_ORDER: tuple[str, ...] = (
    "toggle_case",
    "double_url_encode",
    "sql_inline_comment",
    "json_unicode_escape",
    "space_to_percent20",
    "space_to_plus",
)

transform_registry: dict[str, Callable[[str], str]] = {
    "toggle_case": _toggle_case,
    "double_url_encode": _double_url_encode,
    "sql_inline_comment": _sql_inline_comment,
    "json_unicode_escape": _json_unicode_escape,
    "space_to_percent20": _space_to_percent20,
    "space_to_plus": _space_to_plus,
}

assert set(transform_registry) == set(TRANSFORM_ORDER), "registry/order drift"


# ---------------------------------------------------------------------------
# Block classification and backoff.
# ---------------------------------------------------------------------------


def classify_waf_block(status: int | None, body: str) -> str | None:
    """Classify a response as a WAF block, or None when it is not one.

    Pure and manual: a documented status set plus documented body
    markers. ``waf_detector``'s fingerprint remains the upstream
    authority; this classifier is the shared mechanical check the
    adaptive client uses per attempt.
    """
    if status is not None and int(status) in WAF_BLOCK_STATUSES:
        return f"waf_status_{int(status)}"
    text = (body or "").lower()
    for marker in WAF_BLOCK_MARKERS:
        if marker in text:
            return f"waf_body_marker:{marker}"
    return None


class BackoffPolicy:
    """Exponential backoff with a hard ceiling: 0.5, 1, 2, 4, 8, 8…"""

    def __init__(
        self,
        base: float = BASE_BACKOFF_SECONDS,
        ceiling: float = MAX_BACKOFF_SECONDS,
    ):
        if base <= 0 or ceiling < base:
            raise AdaptiveEvasionError("waf_adaptive_invalid_backoff")
        self.base = float(base)
        self.ceiling = float(ceiling)

    def delay_for_attempt(self, attempt: int) -> float:
        """Delay before retry number ``attempt`` (1-based)."""
        if attempt < 1:
            return 0.0
        return min(self.base * (2 ** (attempt - 1)), self.ceiling)


# ---------------------------------------------------------------------------
# Client.
# ---------------------------------------------------------------------------


@dataclass
class AdaptiveContext:
    """One send's context: where, how, and on whose behalf."""

    url: str
    method: str = "GET"
    engagement_id: str = ""


@dataclass
class AdaptiveResponse:
    """What the injected network callable returns (no socket here)."""

    status: int = 0
    body: str = ""


@dataclass
class AdaptiveResult:
    status: int | None = None
    body: str = ""
    transform_used: str | None = None  # None = the original payload went through
    attempts: int = 0
    blocked: bool = False
    inconclusive: str | None = None

    @property
    def success(self) -> bool:
        return self.inconclusive is None and not self.blocked


@dataclass
class AdaptiveClient:
    """Session-scoped adaptive sender with success-first memory.

    ``request_fn(payload: str) -> AdaptiveResponse`` is injected — the
    client owns no network. ``ledger`` and ``scope`` are the shared
    safety objects, mandatory like everywhere else. ``sleep_fn`` is
    injected so tests (and callers) control the clock; it defaults to
    ``time.sleep``.
    """

    request_fn: Callable[[str], AdaptiveResponse]
    ledger: Any
    scope: Any
    engagement_id: str = ""
    sleep_fn: Callable[[float], None] = time.sleep
    backoff: BackoffPolicy = field(default_factory=BackoffPolicy)
    # session memory: names of transforms that worked, most recent first
    preferred: list[str] = field(default_factory=list)

    def _memory_order(self) -> list[str]:
        ordered = [t for t in self.preferred if t in transform_registry]
        ordered += [t for t in TRANSFORM_ORDER if t not in ordered]
        return ordered

    def _remember(self, transform: str) -> None:
        if transform in self.preferred:
            self.preferred.remove(transform)
        self.preferred.insert(0, transform)

    def _send_once(
        self,
        payload: str,
        context: AdaptiveContext,
        transform: str | None,
    ) -> tuple[AdaptiveResult, str | None]:
        """One ledgered, scope-checked send. Returns (result, block)."""
        if self.scope is None or not hasattr(self.scope, "check_url"):
            raise AdaptiveEvasionError("waf_adaptive_scope_required")
        if self.ledger is None or not hasattr(self.ledger, "record"):
            raise AdaptiveEvasionError("waf_adaptive_ledger_required")
        decision = self.scope.check_url(context.url, method=context.method)
        if decision is not None and not getattr(decision, "allowed", True):
            return (
                AdaptiveResult(inconclusive="out_of_scope", blocked=False),
                None,
            )
        try:
            recorded = self.ledger.record(
                context.method,
                context.url,
                engagement_id=self.engagement_id,
                flags="waf_adaptive",
            )
        except Exception:  # noqa: BLE001 — ledger failure must not bypass
            recorded = False
        if not recorded:
            return (
                AdaptiveResult(inconclusive="ledger_refused", blocked=False),
                None,
            )
        try:
            response = self.request_fn(payload)
            if not isinstance(response, AdaptiveResponse):
                response = AdaptiveResponse(
                    status=int(getattr(response, "status", 0)),
                    body=str(getattr(response, "body", "")),
                )
        except Exception as exc:  # noqa: BLE001 — network errors are inconclusive
            return (
                AdaptiveResult(inconclusive=f"request_error: {type(exc).__name__}"),
                None,
            )
        block = classify_waf_block(response.status, response.body)
        return (
            AdaptiveResult(
                status=response.status,
                body=response.body,
                transform_used=transform,
                blocked=block is not None,
                inconclusive=None,
            ),
            block,
        )

    def send_with_adaptation(
        self,
        payload: str,
        context: AdaptiveContext,
        *,
        max_attempts: int | None = None,
    ) -> AdaptiveResult:
        """Send the original payload; adapt only when the WAF blocks.

        Attempt 1 is the original encoding. Each subsequent attempt
        applies the next transform in session-memory order. Rate-limit
        blocks pause under the backoff policy before the next attempt.
        Bounded by ``max_attempts`` (settings default, hard cap 5);
        exhaustion ends ``inconclusive: waf_blocked`` — never a retry
        storm.
        """
        from webpent.config.settings import get_settings
        from webpent.safety.kill_switch import engaged as kill_switch_engaged

        if not get_settings().enable_waf_adaptive:
            raise AdaptiveEvasionError("waf_adaptive_flag_off")
        if kill_switch_engaged():
            return AdaptiveResult(inconclusive="kill_switch_engaged")
        if max_attempts is None:
            max_attempts = get_settings().waf_adaptive_max_attempts
        try:
            attempts_allowed = int(max_attempts)
        except (TypeError, ValueError) as exc:
            raise AdaptiveEvasionError(
                f"waf_adaptive_invalid_max_attempts: {max_attempts!r}"
            ) from exc
        if attempts_allowed <= 0:
            raise AdaptiveEvasionError(
                f"waf_adaptive_invalid_max_attempts: {max_attempts!r}"
            )
        attempts_allowed = min(attempts_allowed, MAX_ATTEMPTS_CAP)

        result, block = self._send_once(payload, context, None)
        result.attempts = 1
        if not result.blocked or result.inconclusive is not None:
            return result

        attempt = 1
        for transform in self._memory_order():
            if attempt >= attempts_allowed:
                break
            attempt += 1
            if block == "waf_status_429":
                self.sleep_fn(self.backoff.delay_for_attempt(attempt - 1))
            transformed = transform_registry[transform](payload)
            result, block = self._send_once(transformed, context, transform)
            result.attempts = attempt
            if result.inconclusive is not None:
                return result
            if not result.blocked:
                self._remember(transform)
                return result
        result.transform_used = None
        result.inconclusive = "waf_blocked"
        return result


def waf_adaptive_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_waf_adaptive:
        return "waf_adaptive_flag_off"
    return None
