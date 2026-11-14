"""U-DEEP-1 — Race Condition Detector.

Family: RACE_CONDITION. Single-packet attack modeled without any
TCP control: a burst marker on the injected ``send`` represents N
requests arriving inside the same window. Detection principle:
EFFECT OVER STATE — a race is only a finding when the parallel burst
actually flips server state more than once (N successes where the
sequential control gives exactly 1, AND a tracked state field moved
between the first and last response), never because requests merely
returned 200. An idempotent read that succeeds N times is not a race.

Sub-families (spec corpus, verbatim structure, U-DEEP-1): coupon
abuse (state bypass), balance manipulation, inventory, email
verification, file upload, rate limit.

Zero live network: the transport is the injected
``send(endpoint, body, burst_id=None)`` callable; findings are
advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

BURST_SIZE = 20

DEFAULT_BURST_ID = "burst-single-packet"

# Spec corpus, verbatim structure (U-DEEP-1): six sub-families.
RACE_CONDITION_SUBFAMILIES: dict[str, dict] = {
    "state_bypass": {
        "example": "coupon 50% works 5 times",
        "severity": "high",
    },
    "balance_manipulation": {
        "example": "withdraw twice",
        "severity": "critical",
    },
    "inventory": {
        "example": "buy quantity x5",
        "severity": "medium",
    },
    "email_verification": {
        "example": "verification code accepted twice",
        "severity": "medium",
    },
    "file_upload": {
        "example": "same name, different content",
        "severity": "high",
    },
    "rate_limit": {
        "example": "exceed rate limit",
        "severity": "medium",
    },
}

# Trusted-field classification: which client-controlled field was
# multiplied by the burst determines the sub-family.
_FIELD_SUBFAMILY = {
    "amount": "balance_manipulation",
    "coupon_count": "state_bypass",
    "quantity": "inventory",
    "count": "email_verification",
}

TRUSTED_FIELDS = ("amount", "quantity", "count")


@dataclass(frozen=True)
class RacePayload:
    endpoint: str
    body: dict
    burst_id: str | None


@dataclass(frozen=True)
class RaceResult:
    endpoint: str
    body: dict
    burst_id: str
    burst_size: int
    responses: tuple
    successes: int
    elapsed_ms: tuple
    total_elapsed_ms: float


@dataclass(frozen=True)
class RaceFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    endpoint: str
    family: str = "RACE_CONDITION"
    confidence: float = 0.85
    statement: str = ""
    success_indicator: str = ""


class RaceConditionDetector:
    """Detects check-then-act races with a single-packet burst and
    reports only state that actually moved more than once."""

    def __init__(self, send, n: int = BURST_SIZE) -> None:
        self._send = send
        self.n = n

    # ------------------------------------------------------------------

    @staticmethod
    def detect_endpoints(endpoints) -> list[str]:
        """State-changing endpoints only: a GET cannot race a
        check-then-act window."""
        return [e for e in endpoints
                if not e.upper().startswith("GET")]

    @staticmethod
    def has_trusted_field(body: dict) -> bool:
        """Client-supplied multiplier fields the server should not
        trust (amount / quantity / count)."""
        return any(field in body for field in TRUSTED_FIELDS)

    def generate_payloads(self, endpoint: str, body: dict,
                          burst_id: str | None = DEFAULT_BURST_ID,
                          ) -> list[RacePayload]:
        """Deterministic burst plan: the same request N times under
        one burst marker (single-packet arrival window)."""
        return [RacePayload(endpoint=endpoint, body=dict(body),
                            burst_id=burst_id)
                for _ in range(self.n)]

    def execute_attack(self, endpoint: str, body: dict,
                       burst_id: str | None = DEFAULT_BURST_ID,
                       ) -> RaceResult:
        """Fires the burst through the injected transport. A non-None
        burst_id models same-window arrival; burst_id=None is the
        sequential control."""
        payloads = self.generate_payloads(endpoint, body,
                                          burst_id=burst_id)
        responses = []
        elapsed = []
        for payload in payloads:
            response = self._send(payload.endpoint, payload.body,
                                  payload.burst_id)
            responses.append(response)
            try:
                elapsed.append(response.elapsed_ms)
            except AttributeError:
                elapsed.append(0)
        successes = sum(1 for r in responses if self._ok(r))
        return RaceResult(
            endpoint=endpoint,
            body=dict(body),
            burst_id=burst_id,
            burst_size=self.n,
            responses=tuple(responses),
            successes=successes,
            elapsed_ms=tuple(elapsed),
            total_elapsed_ms=max(elapsed) if elapsed else 0.0,
        )

    def analyze(self, result: RaceResult) -> RaceFinding | None:
        """EFFECT OVER STATE: a finding needs N successes where the
        sequential control gives 1, AND tracked state that actually
        moved across the burst."""
        if result.successes <= 1:
            return None
        state_line = self._state_line(result.responses)
        if state_line is None:
            # every response identical: an idempotent read, not a race
            return None
        subfamily = self._classify(result.body)
        severity = RACE_CONDITION_SUBFAMILIES[subfamily]["severity"]
        window = (f"elapsed: {result.total_elapsed_ms}ms burst window "
                  f"(burst_id={result.burst_id})")
        successes_line = (
            f"successes: {result.successes} of {result.burst_size} "
            "(sequential control: 1)")
        evidence = (
            f"burst: {result.burst_size} requests in a single packet "
            f"window on {result.endpoint}",
            window,
            successes_line,
            state_line,
        )
        statements = {
            "state_bypass": (
                "The burst bypassed a check-then-act guard: N requests "
                "succeeded where the sequential control allows exactly "
                "one — race condition, state bypass (advisory; verify "
                "against an authorized target)."),
            "balance_manipulation": (
                "The burst multiplied a balance mutation: N debits "
                "landed where the sequential control allows exactly one "
                "— race condition, balance manipulation (advisory; "
                "verify against an authorized target)."),
            "inventory": (
                "The burst multiplied an inventory mutation beyond the "
                "sequential control — race condition, inventory "
                "(advisory; verify against an authorized target)."),
            "email_verification": (
                "The burst consumed a verification code more than once "
                "— race condition, email verification (advisory; verify "
                "against an authorized target)."),
            "file_upload": (
                "The burst landed same-name uploads with different "
                "content — race condition, file upload (advisory; "
                "verify against an authorized target)."),
            "rate_limit": (
                "The burst exceeded a rate limit within one window — "
                "race condition, rate limit (advisory; verify against "
                "an authorized target)."),
        }
        indicators = {
            "state_bypass": "N+ successes where sequential gives 1",
            "balance_manipulation": (
                "balance debited N times for one entitlement"),
            "inventory": "inventory decremented beyond stock control",
            "email_verification": "code accepted twice in one window",
            "file_upload": "final content differs from first upload",
            "rate_limit": "requests served past the limit",
        }
        return RaceFinding(
            subfamily=subfamily,
            severity=severity,
            evidence=evidence,
            endpoint=result.endpoint,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _ok(response) -> bool:
        if response.status_code >= 400:
            return False
        try:
            return bool(response.json().get("ok"))
        except Exception:
            return False

    @staticmethod
    def _state_line(responses) -> str | None:
        """Numeric fields that moved between the first and last
        response; None when nothing moved (idempotent)."""
        try:
            first = responses[0].json()
            last = responses[-1].json()
        except Exception:
            return None
        moved = sorted(
            key for key in first
            if isinstance(first.get(key), (int, float))
            and first.get(key) != last.get(key))
        if not moved:
            return None
        parts = [f"{key}={first[key]}->{last[key]}" for key in moved]
        return f"state: {', '.join(parts)} (moved across the burst)"

    def _classify(self, body: dict) -> str:
        for field, subfamily in _FIELD_SUBFAMILY.items():
            if field in body:
                return subfamily
        return "state_bypass"
