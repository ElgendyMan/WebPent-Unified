from __future__ import annotations

import threading
import time

from .authority import authority_from_policy
from .models import ScopeDecision, ScopePolicy, ScopeStatus

# removed: unused after UM-DR-35.3 delegation -> {"http": 80, "https": 443}
# removed: unused after UM-DR-35.3 delegation -> frozenset({"DELETE", "PUT", "PATCH"})

# UM-DR-34 §2.3: ONE wildcard compiler.  Host matching (exact, IP,
# CIDR, strict leftmost-label wildcard) is compiled by the canonical
# authority compiler — the historic fnmatch-based matching is removed
# because ``fnmatch`` treats ``?`` and ``[seq]`` as metacharacters and
# lets a scope wildcard act as a general glob expression.
#
# UM-DR-35.3: ONE authorization decision engine. The enforcer no longer
# carries its own rule-matching semantics: every allow/deny decision in
# ``check_url`` is DELEGATED to the canonical authority
# (``EngagementScopeAuthority.evaluate_request``). The enforcer retains
# only operational duties — violation counters, halt threshold, rate and
# concurrency admission, and event telemetry. A canonical URL parsing
# failure is a DENIAL by construction in the authority and therefore
# here as well: invalid input can never become an allow.


class ScopeEnforcer:
    """Runtime program-scope guard layered before ScopeLaw/ToolBoundary."""

    def __init__(self, policy: ScopePolicy, *, on_event=None) -> None:
        self.policy = policy
        self._on_event = on_event
        self._lock = threading.RLock()
        self._timestamps: list[float] = []
        self._active = 0
        self._violations = 0
        self._halted = False
        # UM-DR-35.3: the ONE canonical decision authority for this policy.
        self._authority = authority_from_policy(policy)

    @property
    def violation_count(self) -> int:
        with self._lock:
            return self._violations

    @property
    def halted(self) -> bool:
        with self._lock:
            return self._halted

    @property
    def active_requests(self) -> int:
        with self._lock:
            return self._active

    def _event(self, event_type: str, **details) -> None:
        if self._on_event:
            safe = {str(k): (str(v)[:240] if isinstance(v, str) else v) for k, v in details.items()}
            self._on_event(event_type, safe)

    def _violation(self, url: str, method: str, code: str, reason: str) -> ScopeDecision:
        with self._lock:
            self._violations += 1
            if self._violations >= self.policy.limits.max_violations:
                self._halted = True
                self._event("scope.violation.threshold_halt", count=self._violations, threshold=self.policy.limits.max_violations)
        self._event("scope.violation.blocked", code=code, method=method.upper())
        return ScopeDecision(ScopeStatus.OUT_OF_SCOPE, url, method.upper(), reason, violation_code=code, request_admitted=False)

    def _violation_from_authority(self, url: str, method: str, decision: ScopeDecision) -> ScopeDecision:
        """Record the canonical authority's DENIAL through the enforcer's
        counter/halt bookkeeping while preserving the authority's violation
        code, reason and audit fields verbatim."""
        with self._lock:
            self._violations += 1
            if self._violations >= self.policy.limits.max_violations:
                self._halted = True
                self._event("scope.violation.threshold_halt", count=self._violations, threshold=self.policy.limits.max_violations)
        self._event("scope.violation.blocked", code=decision.violation_code, method=method.upper())
        return decision

    def check_url(self, url: str, *, method: str = "GET", severity: str | None = None, payload: str | None = None) -> ScopeDecision:
        method = str(method or "GET").upper()
        if self.halted:
            return self._violation(url, method, "scope_halted", "scope violation threshold reached")
        # UM-DR-35.3: DELEGATE the authorization decision to the ONE
        # canonical authority. Malformed URLs, ambiguous paths, empty
        # policies, destructive methods, blacklisted payloads, explicit
        # deny rules and unknown scope are denials INSIDE the authority —
        # the enforcer adds no matching semantics of its own.
        decision = self._authority.evaluate_request(
            url, method=method, payload=payload, severity=severity,
        )
        if not decision.allowed:
            return self._violation_from_authority(url, method, decision)
        self._event("scope.check.in_scope", method=method, rule_source=decision.rule_source)
        return decision

    def acquire(self, url: str, *, method: str = "GET", severity: str | None = None, payload: str | None = None) -> ScopeDecision:
        decision = self.check_url(url, method=method, severity=severity, payload=payload)
        if not decision.allowed:
            return decision
        with self._lock:
            now = time.monotonic()
            window = 1.0 / self.policy.limits.max_requests_per_second
            self._timestamps = [stamp for stamp in self._timestamps if now - stamp < 1.0]
            if self._timestamps and now - self._timestamps[-1] < window:
                return self._violation(url, method, "rate_limit", "operator rate limit would be exceeded")
            if self._active >= self.policy.limits.max_concurrent_requests:
                return self._violation(url, method, "concurrency_limit", "operator concurrency limit would be exceeded")
            self._timestamps.append(now)
            self._active += 1
        return decision

    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)

    def check_request(self, url: str, *, method: str = "GET", severity: str | None = None, payload: str | None = None) -> ScopeDecision:
        return self.acquire(url, method=method, severity=severity, payload=payload)


__all__ = ["ScopeEnforcer"]
