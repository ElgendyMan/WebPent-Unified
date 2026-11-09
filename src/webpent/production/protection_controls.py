# src/webpent/production/protection_controls.py
"""webpent.production.protection_controls — Track 12, item 6.

Roadmap contract (المسار 12، البند 6 — التعامل مع ضوابط الحماية):

    عند رصد حظر أو تحديد معدل، يوقف النظام المحاولة أو يطلب مراجعة؛
    لا تُبنى ميزة للتهرب أو تجاوز الضوابط.

    ("When a block or rate limit is detected, the system STOPS the
    attempt or requests review; no feature is built to evade or
    circumvent the controls.")

Design
------
``detect_protection_signal`` classifies an HTTP observation (status
code, headers, body markers) into a typed signal:

* ``waf_block``        — an explicit block verdict (403/406/418 with a
  known WAF marker, or ``cf-mitigated: challenge``).
* ``rate_limit``       — 429 (with Retry-After when present) or an
  explicit quota-exhaustion body.
* ``challenge``        — an interstitial challenge page (JS/CAPTCHA).
* ``backend_throttle`` — 503/502 patterns that look like load shedding.
* ``none``             — everything else.

``evaluate_protection_policy`` maps a signal + attempt context to a
decision:

* ``HALT_ACTION_REQUEST_REVIEW`` for blocks/challenges — the attempt is
  stopped and a human review is requested. The target is NOT retried
  with a different fingerprint/identity (that would be evasion).
* ``BACKOFF_POLITE`` for rate limits — honor Retry-After (bounded), or
  a conservative default; repeated limits escalate to halt + review.
  Backoff here means "wait politely or stop", never "rotate identity".
* ``HALT_ACTION_REQUEST_REVIEW`` for backend throttling.
* The refusal list is explicit and enforced in one place
  (``FORBIDDEN_EVASIONS``): no IP rotation, no User-Agent/fingerprint
  rotation to bypass, no CAPTCHA solving, no header stripping to dodge
  WAF rules, no distributed retries to dodge rate limits. Any future
  proposal touching these is rejected at this boundary.

Everything is auditable: ``ProtectionDecision`` carries the reason and
the redacted signal snapshot, and ``append_protection_log`` writes an
append-only JSONL audit line per decision (the operations trail a
reviewer needs). Detection is deterministic and side-effect free; the
policy never invents network behavior — it only stops, waits politely,
or escalates.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "FORBIDDEN_EVASIONS",
    "ProtectionDecision",
    "ProtectionSignal",
    "ProtectionSignalKind",
    "append_protection_log",
    "detect_protection_signal",
    "evaluate_protection_policy",
]

#: Conservative default polite backoff when no Retry-After is provided.
DEFAULT_POLITE_BACKOFF_SECONDS = 60.0
#: Backoff is bounded — an absurd Retry-After halts instead of waiting.
MAX_POLITE_BACKOFF_SECONDS = 900.0
#: More than this many rate-limit events in one campaign → halt + review.
RATE_LIMIT_ESCALATION_THRESHOLD = 3


class ProtectionSignalKind(str, Enum):
    """Typed protection-control signals (detection vocabulary)."""

    NONE = "none"
    WAF_BLOCK = "waf_block"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    BACKEND_THROTTLE = "backend_throttle"


class ProtectionAction(str, Enum):
    """Policy decision vocabulary (stop / polite wait / escalate)."""

    PROCEED = "proceed"
    BACKOFF_POLITE = "backoff_polite"
    HALT_ACTION_REQUEST_REVIEW = "halt_action_request_review"


#: The roadmap's refusal list, enforced at this boundary. These are the
#: evasion techniques the platform will NEVER implement; the policy API
#: exposes no knob that can enable them.
FORBIDDEN_EVASIONS: tuple[str, ...] = (
    "ip_rotation",
    "identity_or_fingerprint_rotation",
    "captcha_solving",
    "waf_rule_dodging_headers",
    "distributed_retry_to_dodge_rate_limit",
    "payload_obfuscation_to_dodge_detection",
)

_WAF_MARKERS: tuple[str, ...] = (
    "cloudflare",
    "cf-mitigated",
    "sucuri",
    "akamai-reference",
    "imperva",
    "incapsula",
    "f5-bigip",
    "mod_security",
    "modsecurity",
    "wallarm",
    "wzws",
    "safedog",
)

_CHALLENGE_MARKERS: tuple[str, ...] = (
    "cf-challenge",
    "cf_chl",
    "just a moment",
    "checking your browser",
    "attention required",
    "captcha",
    "ddos-guard",
)

_QUOTA_MARKERS: tuple[str, ...] = (
    "rate limit",
    "rate-limit",
    "too many requests",
    "quota exceeded",
    "throttled",
)


@dataclass
class ProtectionSignal:
    """One detected protection-control signal (redacted snapshot)."""

    kind: ProtectionSignalKind
    status_code: int = 0
    source_hint: str = ""  # marker/header that matched (identifier only)
    retry_after_seconds: float | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "status_code": self.status_code,
            "source_hint": self.source_hint,
            "retry_after_seconds": self.retry_after_seconds,
            "detail": self.detail[:200],
        }


@dataclass
class ProtectionDecision:
    """Outcome of the policy evaluation (auditable, no evasion knobs)."""

    action: ProtectionAction
    signal: ProtectionSignal
    reason: str
    backoff_seconds: float = 0.0
    escalate_review: bool = False
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "signal": self.signal.as_dict(),
            "reason": self.reason,
            "backoff_seconds": self.backoff_seconds,
            "escalate_review": self.escalate_review,
            "context": dict(self.context),
        }


def detect_protection_signal(
    status_code: int = 0,
    headers: dict[str, str] | None = None,
    body_excerpt: str = "",
) -> ProtectionSignal:
    """Deterministic, side-effect-free classification of one response.

    Only status codes, headers, and identifier-level body markers are
    inspected — the body is searched for known marker substrings and
    never stored beyond the matched marker name.
    """
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    status = int(status_code or 0)
    lowered_body = str(body_excerpt or "")[:4000].lower()

    # 1. Explicit mitigation headers (authoritative when present).
    mitigated = headers.get("cf-mitigated", "").strip().lower()
    if mitigated in {"challenge", "block"}:
        kind = (
            ProtectionSignalKind.CHALLENGE
            if mitigated == "challenge"
            else ProtectionSignalKind.WAF_BLOCK
        )
        return ProtectionSignal(
            kind=kind, status_code=status, source_hint="cf-mitigated", detail=mitigated
        )

    # 2. Rate limiting (429, or explicit quota language on 403).
    retry_after = _parse_retry_after(headers.get("retry-after"))
    if status == 429:
        return ProtectionSignal(
            kind=ProtectionSignalKind.RATE_LIMIT,
            status_code=status,
            source_hint="status-429",
            retry_after_seconds=retry_after,
        )
    quota_marker = _first_marker(lowered_body, _QUOTA_MARKERS)
    if status in {403, 503} and quota_marker:
        return ProtectionSignal(
            kind=ProtectionSignalKind.RATE_LIMIT,
            status_code=status,
            source_hint=quota_marker,
            retry_after_seconds=retry_after,
        )

    # 3. Challenge pages (interstitials demanding client-side proof).
    challenge_marker = _first_marker(lowered_body, _CHALLENGE_MARKERS)
    if challenge_marker or any(k.startswith("cf-chl") for k in headers):
        return ProtectionSignal(
            kind=ProtectionSignalKind.CHALLENGE,
            status_code=status,
            source_hint=challenge_marker or "cf-chl-header",
        )

    # 4. WAF blocks: known markers on block-ish statuses.
    waf_marker = _first_marker(lowered_body, _WAF_MARKERS) or _first_marker(
        " ".join(headers.values()).lower(), _WAF_MARKERS
    )
    if status in {403, 406, 418} and (waf_marker or status == 403):
        return ProtectionSignal(
            kind=ProtectionSignalKind.WAF_BLOCK,
            status_code=status,
            source_hint=waf_marker or f"status-{status}",
        )

    # 5. Backend load-shedding patterns.
    if status in {502, 503}:
        return ProtectionSignal(
            kind=ProtectionSignalKind.BACKEND_THROTTLE,
            status_code=status,
            source_hint=f"status-{status}",
        )

    return ProtectionSignal(kind=ProtectionSignalKind.NONE, status_code=status)


def evaluate_protection_policy(
    signal: ProtectionSignal,
    *,
    attempt_context: str = "",
    rate_limit_events_so_far: int = 0,
    respect_retry_after: bool = True,
) -> ProtectionDecision:
    """Map a signal to a decision. Stops or asks for review — never evades.

    ``rate_limit_events_so_far`` lets the caller escalate: repeated
    rate-limit hits mean the polite window is not enough and the right
    answer is human review, not faster retries.
    """
    if signal.kind is ProtectionSignalKind.NONE:
        return ProtectionDecision(
            action=ProtectionAction.PROCEED,
            signal=signal,
            reason="no protection-control signal",
            context={"attempt": attempt_context},
        )

    if signal.kind in (ProtectionSignalKind.WAF_BLOCK, ProtectionSignalKind.CHALLENGE):
        return ProtectionDecision(
            action=ProtectionAction.HALT_ACTION_REQUEST_REVIEW,
            signal=signal,
            reason=(
                "protection control actively blocked or challenged the "
                "attempt — stopped and flagged for human review; no "
                "evasion is attempted (roadmap Track 12 item 6)"
            ),
            escalate_review=True,
            context={"attempt": attempt_context},
        )

    if signal.kind is ProtectionSignalKind.BACKEND_THROTTLE:
        return ProtectionDecision(
            action=ProtectionAction.HALT_ACTION_REQUEST_REVIEW,
            signal=signal,
            reason=(
                "backend appears to be shedding load — attempt stopped "
                "for human review instead of pressuring the service"
            ),
            escalate_review=True,
            context={"attempt": attempt_context},
        )

    # RATE_LIMIT
    if rate_limit_events_so_far + 1 >= RATE_LIMIT_ESCALATION_THRESHOLD:
        return ProtectionDecision(
            action=ProtectionAction.HALT_ACTION_REQUEST_REVIEW,
            signal=signal,
            reason=(
                f"rate limits persisted across "
                f"{rate_limit_events_so_far + 1} events — halting for "
                "human review rather than tuning around the control"
            ),
            escalate_review=True,
            context={"attempt": attempt_context, "rate_limit_events": rate_limit_events_so_far + 1},
        )

    backoff = DEFAULT_POLITE_BACKOFF_SECONDS
    if respect_retry_after and signal.retry_after_seconds is not None:
        backoff = min(max(0.0, signal.retry_after_seconds), MAX_POLITE_BACKOFF_SECONDS)
    retry = signal.retry_after_seconds
    if retry is not None and retry > MAX_POLITE_BACKOFF_SECONDS:
        return ProtectionDecision(
            action=ProtectionAction.HALT_ACTION_REQUEST_REVIEW,
            signal=signal,
            reason=(
                "Retry-After exceeds the polite bound "
                f"({signal.retry_after_seconds:.0f}s > "
                f"{MAX_POLITE_BACKOFF_SECONDS:.0f}s) — halting for review"
            ),
            escalate_review=True,
            context={"attempt": attempt_context},
        )
    return ProtectionDecision(
        action=ProtectionAction.BACKOFF_POLITE,
        signal=signal,
        reason="polite backoff within the operator's stated window",
        backoff_seconds=backoff,
        context={"attempt": attempt_context, "rate_limit_events": rate_limit_events_so_far + 1},
    )


def append_protection_log(
    log_path: str | os.PathLike[str],
    decision: ProtectionDecision,
    *,
    target: str = "",
    campaign_id: str = "",
) -> bool:
    """Append one redacted JSONL audit line. Never raises."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": target,
        "campaign_id": campaign_id,
        **decision.as_dict(),
    }
    try:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        return True
    except OSError:
        logger.warning("protection_controls: audit log write failed", exc_info=True)
        return False


def _parse_retry_after(raw: str | None) -> float | None:
    if not raw:
        return None
    raw = raw.strip()
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(raw)
        if when is None:
            return None
        return max(0.0, when.timestamp() - time.time())
    except Exception:  # noqa: BLE001 — a malformed header is not fatal
        return None


def _first_marker(text: str, markers: tuple[str, ...]) -> str:
    for marker in markers:
        if marker in text:
            return marker
    return ""
