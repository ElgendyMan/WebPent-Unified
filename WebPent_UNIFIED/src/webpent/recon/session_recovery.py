"""Session expiry detection and bounded auto-recovery for hunting campaigns.

Additive module (not in the frozen manifest). Designed to be wired around any
exploiter/executor callable. It never starts network traffic itself: re-login,
re-provisioning, and M4 re-binding are delegated to injected callables so the
module is fully testable with synthetic stubs and never modifies frozen auth
code.

Fail-closed contract:
  * 3+ consecutive 401 OR 302-to-login responses -> session is declared dead.
  * At most ``max_recovery_attempts`` (default 3) recovery attempts per campaign.
  * Recovery exhaustion halts the campaign (``CampaignHalted``) — never loops.
  * Every transition emits an immutable audit event:
      session.expired -> session.recovered | session.exhausted -> campaign.halted
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AuditEvent",
    "RecoveryOutcome",
    "CampaignHalted",
    "SessionRecoveryMonitor",
    "SessionRecoveryManager",
    "is_login_redirect",
    "DEFAULT_DEAD_THRESHOLD",
    "DEFAULT_MAX_RECOVERY_ATTEMPTS",
]

DEFAULT_DEAD_THRESHOLD = 3
DEFAULT_MAX_RECOVERY_ATTEMPTS = 3

_LOGIN_PATH_TOKENS = ("login", "signin", "sign-in", "auth", "sso", "oauth", "session/new")


def is_login_redirect(status_code: int, headers: Mapping[str, str] | None = None) -> bool:
    """True when a response looks like a redirect to an authentication page."""
    if int(status_code) not in (301, 302, 303, 307, 308):
        return False
    location = ""
    if headers:
        for key, value in headers.items():
            if str(key).lower() == "location":
                location = str(value or "").lower()
                break
    if not location:
        return False
    return any(token in location for token in _LOGIN_PATH_TOKENS)


def response_looks_dead(status_code: int, headers: Mapping[str, str] | None = None) -> bool:
    """A single response that indicates an expired/dead session."""
    code = int(status_code)
    return code == 401 or code == 403 or is_login_redirect(code, headers)


@dataclass(frozen=True)
class AuditEvent:
    """Immutable, append-only audit record. Contains no secrets."""

    event_type: str
    campaign_id: str
    principal_alias: str = ""
    attempt: int = 0
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_type": str(self.event_type)[:64],
            "campaign_id": str(self.campaign_id)[:128],
            "principal_alias": str(self.principal_alias)[:64],
            "attempt": max(0, int(self.attempt)),
            "reason": str(self.reason)[:240],
            "timestamp": float(self.timestamp),
        }


@dataclass(frozen=True)
class RecoveryOutcome:
    recovered: bool
    attempts: int
    audit_events: tuple[AuditEvent, ...]
    principal_ref: Any = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "recovered": bool(self.recovered),
            "attempts": int(self.attempts),
            "reason": str(self.reason)[:240],
            "audit_events": [event.as_dict() for event in self.audit_events],
        }


class CampaignHalted(Exception):
    """Raised when recovery is exhausted and the campaign must stop."""

    def __init__(self, campaign_id: str, reason: str, audit_events: Sequence[AuditEvent] = ()) -> None:
        super().__init__(f"campaign {campaign_id} halted: {reason}")
        self.campaign_id = str(campaign_id)[:128]
        self.reason = str(reason)[:240]
        self.audit_events = tuple(audit_events)


class SessionRecoveryMonitor:
    """Counts consecutive dead-session responses; declares death at threshold."""

    def __init__(self, *, dead_threshold: int = DEFAULT_DEAD_THRESHOLD) -> None:
        self.dead_threshold = max(1, min(int(dead_threshold), 32))
        self._consecutive_dead = 0
        self.dead = False

    def record(self, status_code: int, headers: Mapping[str, str] | None = None) -> bool:
        """Record one response; return True iff the session is now declared dead."""
        if response_looks_dead(status_code, headers):
            self._consecutive_dead += 1
        else:
            self._consecutive_dead = 0
        if self._consecutive_dead >= self.dead_threshold:
            self.dead = True
        return self.dead

    def reset(self) -> None:
        self._consecutive_dead = 0
        self.dead = False

    @property
    def consecutive_dead(self) -> int:
        return self._consecutive_dead


# Callable signatures (kept loose so any frozen executor can be adapted):
LoginCallable = Callable[[str], Any]            # principal_alias -> login result with .success
ProvisionCallable = Callable[[], Any]           # () -> provisioning result with .successful_count
M4BindCallable = Callable[[Any], Any]           # provisioning result -> bound principal_ref / True
ResponseAdapter = Callable[[Any], tuple[int, Mapping[str, str]]]  # exploiter result -> (status, headers)


class SessionRecoveryManager:
    """Bounded recovery: re-login -> re-provision principals -> re-bind M4.

    All three actions are injected callables. The manager enforces the attempt
    budget and the fail-closed halt. ``resume_hypothesis_id`` records where the
    campaign should continue after a successful recovery.
    """

    def __init__(
        self,
        *,
        campaign_id: str,
        login: LoginCallable,
        provision: ProvisionCallable | None = None,
        m4_bind: M4BindCallable | None = None,
        max_recovery_attempts: int = DEFAULT_MAX_RECOVERY_ATTEMPTS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.campaign_id = str(campaign_id)[:128]
        self._login = login
        self._provision = provision
        self._m4_bind = m4_bind
        self.max_recovery_attempts = max(1, min(int(max_recovery_attempts), 16))
        self._clock = clock or time.time
        self.audit_events: list[AuditEvent] = []
        self.recovery_attempts = 0
        self.halted = False
        self.resume_hypothesis_id: str = ""

    def _emit(self, event_type: str, *, principal_alias: str = "", attempt: int = 0, reason: str = "") -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            campaign_id=self.campaign_id,
            principal_alias=principal_alias,
            attempt=attempt,
            reason=reason,
            timestamp=self._clock(),
        )
        self.audit_events.append(event)
        return event

    def mark_expired(self, *, principal_alias: str = "", reason: str = "consecutive_dead_responses") -> AuditEvent:
        return self._emit("session.expired", principal_alias=principal_alias, reason=reason)

    def set_resume_point(self, hypothesis_id: str) -> None:
        self.resume_hypothesis_id = str(hypothesis_id)[:128]

    def recover(self, *, principal_alias: str = "") -> RecoveryOutcome:
        """Attempt recovery up to the budget. Raise CampaignHalted on exhaustion."""
        if self.halted:
            raise CampaignHalted(self.campaign_id, "already_halted", tuple(self.audit_events))

        attempts = 0
        last_reason = "no_attempt_made"
        while attempts < self.max_recovery_attempts:
            attempts += 1
            self.recovery_attempts = attempts
            try:
                login_result = self._login(principal_alias)
            except Exception as exc:  # noqa: BLE001 — recovery must classify, not crash
                last_reason = f"login_exception:{type(exc).__name__}"
                continue
            if not getattr(login_result, "success", False):
                last_reason = str(getattr(login_result, "reason", "login_failed"))[:240]
                continue

            provisioned = None
            if self._provision is not None:
                try:
                    provisioned = self._provision()
                except Exception as exc:  # noqa: BLE001
                    last_reason = f"provision_exception:{type(exc).__name__}"
                    continue
                if not int(getattr(provisioned, "successful_count", 0) or 0):
                    last_reason = "provisioning_no_bound_principals"
                    continue

            principal_ref = None
            if self._m4_bind is not None:
                try:
                    principal_ref = self._m4_bind(provisioned)
                except Exception as exc:  # noqa: BLE001
                    last_reason = f"m4_bind_exception:{type(exc).__name__}"
                    continue
                if not principal_ref:
                    last_reason = "m4_bind_returned_empty"
                    continue

            self._emit(
                "session.recovered",
                principal_alias=principal_alias,
                attempt=attempts,
                reason=f"recovered_after_{attempts}_attempts",
            )
            return RecoveryOutcome(
                recovered=True,
                attempts=attempts,
                audit_events=tuple(self.audit_events),
                principal_ref=principal_ref,
                reason="recovered",
            )

        self._emit("session.exhausted", principal_alias=principal_alias, attempt=attempts, reason=last_reason)
        self._emit("campaign.halted", principal_alias=principal_alias, attempt=attempts, reason=last_reason)
        self.halted = True
        raise CampaignHalted(self.campaign_id, f"recovery_exhausted_after_{attempts}_attempts:{last_reason}", tuple(self.audit_events))
