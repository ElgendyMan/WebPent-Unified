from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

from .authority import CanonicalScopeError, compile_host_matcher
from .models import ScopeDecision, ScopePolicy, ScopeRule, ScopeStatus, severity_allowed

_DEFAULT_PORTS = {"http": 80, "https": 443}
_DESTRUCTIVE = frozenset({"DELETE", "PUT", "PATCH"})

# UM-DR-34 §2.3: ONE wildcard compiler.  Host matching (exact, IP,
# CIDR, strict leftmost-label wildcard) is compiled by the canonical
# authority compiler — the historic fnmatch-based matching is removed
# because ``fnmatch`` treats ``?`` and ``[seq]`` as metacharacters and
# lets a scope wildcard act as a general glob expression.


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

    @staticmethod
    def _host_match(host: str, rule: ScopeRule) -> bool:
        """Delegate host matching to the ONE canonical strict compiler.

        Compilation failures (misplaced ``*``, glob ``?``/``[seq]``
        syntax, malformed labels/CIDR) are DENIALS, never exceptions —
        and never a silent fallback to a broader matcher.
        """
        from .authority import normalize_hostname

        normalized = normalize_hostname(host)
        if not normalized:
            return False
        try:
            matcher = compile_host_matcher(rule)
        except CanonicalScopeError:
            return False
        return matcher.matches(normalized)

    @staticmethod
    def _rule_matches(rule: ScopeRule, url: str, method: str, severity: str | None) -> bool:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            scheme = parsed.scheme.lower()
            # UM-DR-34 §2.3: EXPLICIT None handling — port 0 must never
            # be silently treated as an omitted (default) port.
            explicit_port: int | None = None
            try:
                explicit_port = parsed.port
            except ValueError:
                return False
            if explicit_port is None:
                port = _DEFAULT_PORTS.get(scheme)
                if port is None:
                    return False
            elif explicit_port == 0 or not 1 <= explicit_port <= 65535:
                return False
            else:
                port = explicit_port
            rule_parsed = urlsplit(rule.value if "://" in rule.value else f"//{rule.value}")
        except ValueError:
            return False
        if not host or not ScopeEnforcer._host_match(host, rule):
            return False
        if rule.kind == "url":
            rule_scheme = rule_parsed.scheme.lower()
            if rule_scheme and scheme != rule_scheme:
                return False
            rule_port = rule_parsed.port or _DEFAULT_PORTS.get(rule_scheme)
            if rule_port is not None and port != rule_port:
                return False
            rule_path = rule.path or (rule_parsed.path if rule_parsed.path not in {"", "/"} else None)
            if rule_path:
                request_path = parsed.path or "/"
                if not (request_path == rule_path or request_path.startswith(rule_path.rstrip("/") + "/")):
                    return False
        if rule.protocol and scheme != rule.protocol:
            return False
        if rule.port is not None:
            if isinstance(rule.port, tuple):
                if port is None or not rule.port[0] <= port <= rule.port[1]:
                    return False
            elif port != rule.port:
                return False
        if rule.path:
            path = parsed.path or "/"
            prefix = rule.path.rstrip("/") or "/"
            if not (path == prefix or path.startswith(prefix + "/")):
                return False
        if rule.allowed_methods and method.upper() not in rule.allowed_methods:
            return False
        if not severity_allowed(severity, rule.max_severity):
            return False
        return True

    def _violation(self, url: str, method: str, code: str, reason: str) -> ScopeDecision:
        with self._lock:
            self._violations += 1
            if self._violations >= self.policy.limits.max_violations:
                self._halted = True
                self._event("scope.violation.threshold_halt", count=self._violations, threshold=self.policy.limits.max_violations)
        self._event("scope.violation.blocked", code=code, method=method.upper())
        return ScopeDecision(ScopeStatus.OUT_OF_SCOPE, url, method.upper(), reason, violation_code=code, request_admitted=False)

    def check_url(self, url: str, *, method: str = "GET", severity: str | None = None, payload: str | None = None) -> ScopeDecision:
        method = str(method or "GET").upper()
        if self.halted:
            return self._violation(url, method, "scope_halted", "scope violation threshold reached")
        if method in _DESTRUCTIVE and self.policy.limits.no_destructive:
            return self._violation(url, method, "destructive_method_blocked", "destructive methods are disabled")
        if payload and any(token.lower() in payload.lower() for token in self.policy.blacklisted_payloads):
            return self._violation(url, method, "blacklisted_payload_blocked", "payload matched operator blacklist")
        rules = [r for r in self.policy.rules if self._rule_matches(r, url, method, severity)]
        deny_rules = [r for r in rules if not r.allow]
        if deny_rules:
            return self._violation(url, method, "explicit_out_of_scope", "explicit deny rule matched")
        allow_rules = [r for r in rules if r.allow]
        if not allow_rules:
            return self._violation(url, method, "unknown_scope", "no in-scope rule matched")
        # UM-DR-34 §2.2: carry the canonical audit fields on every
        # decision so boundary logs are explainable without secrets.
        from .authority import parse_request_url

        try:
            request = parse_request_url(url)
            canonical = {
                "normalized_origin": request.normalized_origin,
                "hostname": request.hostname,
                "scheme": request.scheme,
                "effective_port": request.effective_port,
                "normalized_path": request.path,
                "scope_fingerprint": self.policy.fingerprint,
            }
        except CanonicalScopeError:
            canonical = {"scope_fingerprint": self.policy.fingerprint}
        decision = ScopeDecision(
            ScopeStatus.IN_SCOPE,
            url,
            method,
            "in-scope rule matched",
            allow_rules[0].source,
            request_admitted=True,
            matched_allow_rule=f"{allow_rules[0].kind}:{allow_rules[0].value}",
            may_proceed_to_network=True,
            **canonical,
        )
        self._event("scope.check.in_scope", method=method, rule_source=allow_rules[0].source)
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
