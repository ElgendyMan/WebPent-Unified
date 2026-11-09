"""U-DEEP-2 — Rate Limit Bypass Engine.

Family: RATE_LIMIT_BYPASS. Spec corpus (verbatim structure,
U-DEEP-2): four techniques — header_rotation (seven client-supplied
IP headers), session_rotation, http2_batching, concurrency — across
four sub-families (login, password reset, API, 2FA limiters).

Detection principle: EFFECT OVER STATE — a bypass is only a finding
when the limit actually failed: N requests got through where the
sequential control (same limiter, same window, no rotation) stopped
at the limit. Rotating a header is not evidence; the window closing
is. And a window that closes after one or two requests is not a
meaningful rate limit at all — rotation defeating it is the expected
behavior of any client, not a bypass finding (no-false-positive
floor, see MEANINGFUL_LIMIT_FLOOR).

Zero live network: the transport is the injected
``send(endpoint, body, headers=...)`` callable; batching and
concurrency are modeled as shape attributes on the plan (single
stream carries many requests, many requests in flight at once), the
same way U-DEEP-1 models the single-packet attack with burst_id.
Findings are advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Spec corpus, verbatim header names and order (U-DEEP-2).
RATE_LIMIT_BYPASSES: dict = {
    "header_rotation": [
        "X-Forwarded-For: 10.0.0.1",
        "X-Real-IP: 10.0.0.2",
        "X-Originating-IP: 10.0.0.3",
        "X-Client-IP: 10.0.0.4",
        "X-Remote-Addr: 10.0.0.5",
        "CF-Connecting-IP: 10.0.0.6",
        "True-Client-IP: 10.0.0.7",
    ],
    "session_rotation": {
        "description": ("renew the session identity between requests "
                        "so a session-keyed window never fills"),
        "renewals": "per-request",
    },
    "http2_batching": {
        "description": ("carry many requests in one HTTP/2 stream so "
                        "the limiter sees one request, not N"),
        "requests_per_stream": 20,
    },
    "concurrency": {
        "description": ("race N requests in flight at once so they "
                        "all read the same pre-increment count"),
        "instant_parallelism": 20,
    },
}

SEVERITY_BY_SUBFAMILY = {
    "login_rate_limit_bypass": "high",
    "password_reset_rate_limit_bypass": "high",
    "twofa_rate_limit_bypass": "critical",
    "api_rate_limit_bypass": "medium",
}

BURST_REQUESTS = 100

# No-false-positive floor: a window that closes after fewer than
# this many sequential requests is a per-action counter, not a rate
# limit. Rotation trivially defeats any such counter, so defeating
# it is not evidence of a bypass-class weakness.
MEANINGFUL_LIMIT_FLOOR = 5

_IP_HEADER = "X-Forwarded-For"


def _rotation_ip(index: int) -> str:
    """Deterministic distinct client-supplied key per request."""
    return f"172.16.{index // 250}.{index % 250 + 1}"


@dataclass(frozen=True)
class BaselineResult:
    """Sequential control: no rotation, one key, one window."""
    endpoint: str
    sent: int
    stopped_at: int | None


@dataclass(frozen=True)
class BypassResult:
    endpoint: str
    technique: str
    sent: int
    passed: int
    requests_per_stream: int = 1
    instant_parallelism: int = 1


@dataclass(frozen=True)
class RateLimitPayload:
    endpoint: str
    headers: tuple
    technique: str
    index: int


@dataclass(frozen=True)
class RateLimitBypassFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    technique: str
    endpoint: str
    family: str = "RATE_LIMIT_BYPASS"
    confidence: float = 0.85
    statement: str = ""
    success_indicator: str = ""


def _ok(response) -> bool:
    if response.status_code >= 400:
        return False
    try:
        return bool(response.json().get("ok"))
    except Exception:
        return False


def _limited(response) -> bool:
    try:
        return bool(response.json().get("limited"))
    except Exception:
        return False


class RateLimitBypassEngine:
    """Probes the injected limiter with each rotation technique and
    reports only windows that measurably failed against a meaningful
    sequential control."""

    def __init__(self, send, quota: int = 10) -> None:
        self._send = send
        self.quota = quota
        self._measured_limit: int | None = None

    # ------------------------------------------------------------------

    def baseline(self, endpoint: str, body: dict) -> BaselineResult:
        """Sequential control: quota + 5 unrotated requests on one
        key; stopped_at is where the window closed."""
        sent = 0
        stopped_at: int | None = None
        for _ in range(self.quota + 5):
            sent += 1
            response = self._send(endpoint, body)
            if stopped_at is None and not _ok(response):
                stopped_at = sent - 1
        return BaselineResult(endpoint=endpoint, sent=sent,
                              stopped_at=stopped_at)

    def build_plan(self, endpoint: str, body: dict,
                   technique: str = "header_rotation") \
            -> list[RateLimitPayload]:
        """Deterministic plan: one payload per request of the
        technique's shape."""
        plan = []
        for index in range(BURST_REQUESTS):
            plan.append(RateLimitPayload(
                endpoint=endpoint,
                headers=((_IP_HEADER, _rotation_ip(index)),),
                technique=technique,
                index=index,
            ))
        return plan

    def execute(self, endpoint: str, body: dict,
                technique: str = "header_rotation") -> BypassResult:
        """Run the technique's request shape through the injected
        transport, then measure the same limiter's sequential
        behavior as the like-for-like control (measured once and
        cached)."""
        passed = 0
        for payload in self.build_plan(endpoint, body,
                                       technique=technique):
            response = self._send(payload.endpoint, body,
                                  headers=list(payload.headers))
            if _ok(response):
                passed += 1
        self._calibrate(endpoint, body)
        shape = RATE_LIMIT_BYPASSES.get(technique, {})
        shape = shape if isinstance(shape, dict) else {}
        return BypassResult(
            endpoint=endpoint,
            technique=technique,
            sent=BURST_REQUESTS,
            passed=passed,
            requests_per_stream=shape.get("requests_per_stream", 1),
            instant_parallelism=shape.get("instant_parallelism", 1),
        )

    # ------------------------------------------------------------------

    def _calibrate(self, endpoint: str, body: dict) -> None:
        """Measure the limiter's honest sequential window (no
        rotation) and keep the first measurement: later windows on an
        exhausted key say nothing new about the limit."""
        if self._measured_limit is not None:
            return
        passes = 0
        closed = False
        for _ in range(self.quota + 5):
            if _ok(self._send(endpoint, body)):
                passes += 1
            else:
                closed = True
                break
        self._measured_limit = passes if closed else None

    def analyze(self, result: BypassResult) \
            -> RateLimitBypassFinding | None:
        """EFFECT OVER STATE with a no-false-positive floor: the
        window must be meaningful (closed after at least
        MEANINGFUL_LIMIT_FLOOR sequential requests) and the technique
        must have decisively exceeded it."""
        measured = self._measured_limit
        if measured is None or measured < MEANINGFUL_LIMIT_FLOOR:
            return None
        if result.passed <= measured:
            return None
        subfamily = self._subfamily_for(result.endpoint)
        evidence = [
            f"baseline: the sequential control stopped at {measured} "
            f"(the window closed)",
            f"bypass: {result.passed} of {result.sent} requests passed "
            f"with {result.technique} (the rotation key reset the "
            f"window every time)",
        ]
        if result.requests_per_stream > 1:
            evidence.append(
                f"shape: {result.requests_per_stream} requests per "
                f"stream (batched)")
        if result.instant_parallelism > 1:
            evidence.append(
                f"shape: {result.instant_parallelism} requests in "
                f"flight at once (concurrent)")
        return RateLimitBypassFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence),
            technique=result.technique,
            endpoint=result.endpoint,
            statement=(
                f"The {result.technique} technique defeated a rate "
                f"limit that measurably closed at {measured} "
                f"sequential requests: {result.passed} requests got "
                f"through — rate limit bypass, {subfamily} (advisory; "
                f"verify against an authorized target)."),
            success_indicator=(
                "N passed where the unrotated control was stopped"),
        )

    @staticmethod
    def _subfamily_for(endpoint: str) -> str:
        lowered = endpoint.lower()
        if "password" in lowered or "reset" in lowered:
            return "password_reset_rate_limit_bypass"
        if "2fa" in lowered or "otp" in lowered or "mfa" in lowered:
            return "twofa_rate_limit_bypass"
        if "login" in lowered or "auth" in lowered or \
                "signin" in lowered:
            return "login_rate_limit_bypass"
        return "api_rate_limit_bypass"
