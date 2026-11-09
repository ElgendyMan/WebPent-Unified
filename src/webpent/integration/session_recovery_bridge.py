"""Drop-in wrapper around any ExploitCallable that adds session auto-recovery.

Additive module (not in the frozen manifest). Conforms to the exploiter
callback signature consumed by frozen ``agents/hunter_graph.py``::

    exploiter(hypothesis, hunter_dict) -> result  (result has .to_dict())

so it can replace the exploiter callback at the first non-frozen call site.
Until such a site exists it is proven synthetically (honest label matches the
prior sprint). All side effects (sleep, time) are injectable so tests run
deterministically with no real network and no real waiting.

Failure handling (Part 1.3):
  * timeout (>10s)            -> one retry with exponential backoff
  * connection refused        -> campaign HALTED (no retry loop)
  * 429 rate-limited          -> pause, then resume after cooldown
  * scope violation           -> halt (reuses frozen ScopeLaw decision signal)
  * 3x 401 / 302-to-login     -> session recovery (see recon.session_recovery)
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from webpent.recon.session_recovery import (
    CampaignHalted,
    SessionRecoveryManager,
    SessionRecoveryMonitor,
)

__all__ = ["RecoveringExploiter", "ExploitResultView", "DEFAULT_TIMEOUT_SECONDS", "DEFAULT_RATE_LIMIT_COOLDOWN"]

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RATE_LIMIT_COOLDOWN = 30.0
DEFAULT_BACKOFF_BASE = 1.0


@dataclass
class ExploitResultView:
    """Normalized view of an exploiter result used by the wrapper for decisions.

    The wrapper never inspects secret material; only status code, headers, and
    an optional failure-class label are read.
    """

    status_code: int = 200
    headers: Mapping[str, str] = field(default_factory=dict)
    failure: str = ""  # "" | "timeout" | "connection_refused" | "rate_limited" | "scope_violation"
    raw: Any = None

    @classmethod
    def from_result(cls, result: Any) -> ExploitResultView:
        status = int(getattr(result, "status_code", 200) or 200)
        headers = getattr(result, "headers", None) or {}
        failure = str(getattr(result, "failure", "") or "")
        # Unfreeze fix 2026-10-05 (TEAM-RED D2): the live exploiter callback in
        # agents/hunter_runner.py returns ``ExploitationResult``, which carries
        # status/evidence/error rather than status_code/headers/failure. Derive
        # the wrapper's decision fields from that shape so dead-session / scope /
        # timeout classification actually fires. Existing attrs take precedence.
        if not failure:
            err = str(getattr(result, "error", None) or "").lower()
            if err:
                if "scope" in err:
                    failure = "scope_violation"
                elif "timeout" in err:
                    failure = "timeout"
                elif "connection_refused" in err or "connection refused" in err:
                    failure = "connection_refused"
                elif "rate_limit" in err or "429" in err:
                    failure = "rate_limited"
        evidence = getattr(result, "evidence", None)
        if isinstance(evidence, dict):
            if evidence.get("scope_blocked") and not failure:
                failure = "scope_violation"
            decision = evidence.get("decision", {})
            if isinstance(decision, dict):
                dc = int(decision.get("status_code", 0) or decision.get("status", 0) or 0)
                if dc:
                    status = dc
        return cls(status_code=status, headers=headers, failure=failure, raw=result)


# Inner exploiter signature matches frozen hunter_graph.ExploitCallable:
InnerExploiter = Callable[[Any, Mapping[str, Any]], Any]
HypothesisId = Callable[[Any], str]
SleepCallable = Callable[[float], None]


class RecoveringExploiter:
    """Wrap an inner exploiter with bounded recovery and failure policy."""

    def __init__(
        self,
        inner: InnerExploiter,
        *,
        recovery_manager: SessionRecoveryManager,
        hypothesis_id: HypothesisId | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        rate_limit_cooldown: float = DEFAULT_RATE_LIMIT_COOLDOWN,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
        max_timeout_retries: int = 1,
        sleep: SleepCallable | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._inner = inner
        self._recovery = recovery_manager
        self._hypothesis_id = hypothesis_id or (lambda h: str(getattr(h, "hypothesis_id", "") or getattr(h, "id", "")))
        self.timeout_seconds = float(timeout_seconds)
        self.rate_limit_cooldown = float(rate_limit_cooldown)
        self.backoff_base = float(backoff_base)
        self.max_timeout_retries = max(0, int(max_timeout_retries))
        self._sleep = sleep or time.sleep
        self._clock = clock or time.time
        self._monitor = SessionRecoveryMonitor(dead_threshold=3)
        self.timeout_retries_made = 0
        self.rate_limit_pauses = 0
        self.halted_reason = ""

    # -- public exploiter entry point -------------------------------------
    def __call__(self, hypothesis: Any, hunter_dict: Mapping[str, Any]) -> Any:
        hyp_id = self._hypothesis_id(hypothesis)
        if self._recovery.halted:
            raise CampaignHalted(self._recovery.campaign_id, "campaign_already_halted", tuple(self._recovery.audit_events))

        timeout_retries = 0
        while True:
            result = self._inner(hypothesis, hunter_dict)
            view = ExploitResultView.from_result(result)

            # 1.3 failure classification (checked BEFORE session classification)
            if view.failure == "scope_violation":
                self.halted_reason = "scope_violation"
                raise CampaignHalted(self._recovery.campaign_id, "scope_violation_halt", tuple(self._recovery.audit_events))
            if view.failure == "connection_refused":
                self.halted_reason = "connection_refused"
                raise CampaignHalted(self._recovery.campaign_id, "target_down_connection_refused_halt", tuple(self._recovery.audit_events))
            if view.failure == "rate_limited" or view.status_code == 429:
                self.rate_limit_pauses += 1
                self._sleep(self.rate_limit_cooldown)
                continue  # resume same hypothesis after cooldown
            if view.failure == "timeout":
                if timeout_retries < self.max_timeout_retries:
                    timeout_retries += 1
                    self.timeout_retries_made += 1
                    self._sleep(self.backoff_base * (2 ** (timeout_retries - 1)))
                    continue
                # timeout budget exhausted -> treat as target failure, halt
                self.halted_reason = "timeout_exhausted"
                raise CampaignHalted(self._recovery.campaign_id, "timeout_retry_exhausted_halt", tuple(self._recovery.audit_events))

            # 1.1 session-dead classification
            dead = self._monitor.record(view.status_code, view.headers)
            if not dead:
                return result  # healthy response -> campaign continues

            # Session declared dead: recover and resume from this hypothesis.
            self._recovery.set_resume_point(hyp_id)
            self._recovery.mark_expired(reason=f"consecutive_dead_at_{hyp_id}")
            outcome = self._recovery.recover()  # raises CampaignHalted on exhaustion
            if outcome.recovered:
                self._monitor.reset()
                continue  # retry the same hypothesis with fresh session

        # unreachable (loop returns or raises)

    @property
    def audit_events(self):
        return tuple(self._recovery.audit_events)
