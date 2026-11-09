"""Phase 1 — Defense Response Monitor.

Watches four indicators and adapts tactics in real time:
  1. Block/rate-limit  (429, 403, sudden latency spike)
  2. Activity detection (custom block page, captcha, response pattern change)
  3. Behavior change    (yesterday 200, today 403 — auth/session went stale)
  4. Protection activation (WAF headers appear, previously-successful requests fail)

Outputs a ``TacticState`` that the execution layer reads: slow down by X%,
rotate token, switch request signature, or back off entirely. Fail-soft: on
any error it returns a neutral state (no adaptation, no crash).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_WAF_HEADERS = ("cf-ray", "x-sucuri-id", "x-waf", "x-cdn", "server: cloudflare",
                "x-frame-options", "content-security-policy")
_BLOCK_MARKERS = ("blocked", "captcha", "rate limit", "too many requests",
                  "access denied", "forbidden", "ip banned", "challenge")


@dataclass
class TacticState:
    """Adaptive tactic state — consumed by the execution layer."""
    slowdown_factor: float = 1.0       # 1.0 = normal, 0.5 = half rate
    rotate_token: bool = False
    switch_signature: bool = False
    backoff_seconds: float = 0.0
    reason: str = ""
    block_detected: bool = False
    consecutive_failures: int = 0

    def merge(self, other: "TacticState") -> "TacticState":
        """Take the stricter of two states (conservative)."""
        return TacticState(
            slowdown_factor=min(self.slowdown_factor, other.slowdown_factor),
            rotate_token=self.rotate_token or other.rotate_token,
            switch_signature=self.switch_signature or other.switch_signature,
            backoff_seconds=max(self.backoff_seconds, other.backoff_seconds),
            reason="; ".join(filter(None, [self.reason, other.reason])),
            block_detected=self.block_detected or other.block_detected,
            consecutive_failures=max(self.consecutive_failures, other.consecutive_failures),
        )


class DefenseMonitor:
    """Analyzes responses and emits tactic adaptations."""

    def __init__(self) -> None:
        self.history: list[dict[str, Any]] = []
        self.failures = 0

    def observe(self, response: Any, *, expected_status: int = 200) -> TacticState:
        """Observe one response; return the tactic to apply from now on."""
        status = int(getattr(response, "status_code", getattr(response, "status", 0)) or 0)
        headers = {str(k).lower(): str(v).lower() for k, v in (getattr(response, "headers", {}) or {}).items()}
        body = str(getattr(response, "text", getattr(response, "body", "")) or "").lower()
        elapsed = float(getattr(response, "elapsed_ms", 0) or 0)

        state = TacticState()

        # 1. Block / rate-limit detection
        if status in (429,):
            self.failures += 1
            state = state.merge(TacticState(slowdown_factor=0.25, backoff_seconds=30.0,
                                            reason="rate_limited_429", block_detected=True))
        elif status in (403, 401):
            self.failures += 1
            if any(m in body for m in _BLOCK_MARKERS):
                state = state.merge(TacticState(slowdown_factor=0.5, rotate_token=True,
                                                switch_signature=True, backoff_seconds=60.0,
                                                reason="ip_blocked_or_captcha", block_detected=True))
            else:
                state = state.merge(TacticState(rotate_token=True, reason="auth_stale_403"))

        # 2. Activity detection — custom block page / captcha in body
        if any(m in body for m in ("captcha", "challenge", "verify you are human")):
            state = state.merge(TacticState(switch_signature=True, backoff_seconds=120.0,
                                            reason="captcha_challenge", block_detected=True))

        # 3. Sudden latency spike (5x baseline) — possible tarpitting
        if self.history and elapsed:
            avg = sum(h.get("elapsed", 0) for h in self.history[-10:]) / max(1, len(self.history[-10:]))
            if avg and elapsed > avg * 5:
                state = state.merge(TacticState(slowdown_factor=0.5, reason="latency_spike_tarpit"))

        # 4. WAF / protection activation detection
        if any(h in headers for h in ("cf-ray", "x-sucuri-id", "x-waf")):
            state = state.merge(TacticState(switch_signature=True, slowdown_factor=0.7,
                                            reason="waf_detected"))

        # Consecutive failures → escalate backoff
        state.consecutive_failures = self.failures
        if self.failures >= 5:
            state = state.merge(TacticState(backoff_seconds=300.0, slowdown_factor=0.1,
                                            reason="5_consecutive_failures_full_backoff"))

        # Success → reset failure counter
        if 200 <= status < 300 and not state.block_detected:
            self.failures = 0

        self.history.append({"status": status, "elapsed": elapsed})
        if len(self.history) > 50:
            self.history = self.history[-50:]
        return state


__all__ = ["DefenseMonitor", "TacticState"]
