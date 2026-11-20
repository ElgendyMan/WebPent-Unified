"""Typed contracts for the autonomous hunt loop.

These are orchestration/advisory data structures. They carry no execution
authority: the only thing that can turn a candidate into a confirmed finding
is the existing deterministic validator + sealed ProofBundle path.

All text that crosses a boundary here is redaction-safe: secrets are stripped
before a record is stored or serialized, matching the rest of the codebase's
untrusted-content handling.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_MAX_TEXT = 800
_MAX_LIST = 128
_SECRET_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~+/=-]{12,}"
    r"|authorization\s*[:=]\s*bearer\s+\S+"
    r"|(?:api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+)"
)


def redact(value: Any, limit: int = _MAX_TEXT) -> str:
    """Strip secret-shaped substrings and bound length."""
    text = _SECRET_RE.sub("[REDACTED_SECRET]", str(value or ""))
    return text[:limit]


def digest(value: Any) -> str:
    """Stable digest of bounded JSON-safe data."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest()


class HuntPhase(str, Enum):
    """The ordered phases of one autonomous hunt."""

    RECON = "recon"
    HYPOTHESIS = "hypothesis"
    RANK = "rank"
    EXECUTE = "execute"
    OBSERVE = "observe"
    PROVE = "prove"
    LEARN = "learn"
    REPORT = "report"


class HuntStopReason(str, Enum):
    """Why the loop stopped. Every value is explicit and typed.

    A hunt never reports success by omission: if it could not proceed it says
    exactly which bound it hit.
    """

    COMPLETED = "completed"
    ITERATION_LIMIT = "iteration_limit_reached"
    BUDGET_EXHAUSTED = "action_budget_exhausted"
    NO_NEW_READY_TASK = "no_new_ready_task"
    SAME_ACTION_REPEATED = "same_action_repeated"
    NO_NEW_EVIDENCE = "no_new_evidence"
    INFORMATION_GAIN_BELOW_THRESHOLD = "expected_information_gain_below_threshold"
    CAPABILITY_BLOCKED = "capability_blocked"
    SCOPE_DENIED = "scope_denied"
    AUTHORITY_DENIED = "authority_denied"
    NEGATIVE_CONTROL_CONTRADICTION = "negative_control_contradiction"
    AUTHORIZATION_REVOKED = "authorization_revoked_mid_hunt"
    RUNTIME_DEPENDENCIES_MISSING = "runtime_dependencies_missing"
    OPERATOR_HALT = "operator_halt"
    ERROR = "error"


class HuntOutcome(str, Enum):
    """Terminal classification of a hunt."""

    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    HALTED = "halted"


@dataclass(frozen=True)
class PhaseRecord:
    """One append-only record of a phase transition."""

    phase: HuntPhase
    status: str
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "status": redact(self.status, 80),
            "reason": redact(self.reason, 240),
            "detail": _bounded_detail(self.detail),
        }


def _bounded_detail(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in list((value or {}).items())[:_MAX_LIST]:
        name = redact(key, 80)
        if isinstance(item, Mapping):
            result[name] = _bounded_detail(item)
        elif isinstance(item, (list, tuple)):
            result[name] = [redact(part, 240) for part in list(item)[:_MAX_LIST]]
        elif isinstance(item, bool) or item is None or isinstance(item, (int, float)):
            result[name] = item
        else:
            result[name] = redact(item, 240)
    return result


__all__ = [
    "HuntOutcome",
    "HuntPhase",
    "HuntStopReason",
    "PhaseRecord",
    "digest",
    "redact",
]
