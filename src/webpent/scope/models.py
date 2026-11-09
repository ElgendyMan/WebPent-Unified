from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class ScopeLimits:
    max_requests_per_second: float = 1.0
    max_concurrent_requests: int = 1
    max_violations: int = 5
    no_destructive: bool = True

    def __post_init__(self) -> None:
        if not math.isfinite(float(self.max_requests_per_second)) or self.max_requests_per_second <= 0:
            raise ValueError("max_requests_per_second must be positive")
        if int(self.max_concurrent_requests) != self.max_concurrent_requests or self.max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be positive")
        if int(self.max_violations) != self.max_violations or self.max_violations < 1:
            raise ValueError("max_violations must be positive")

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_requests_per_second": self.max_requests_per_second,
            "max_concurrent_requests": self.max_concurrent_requests,
            "max_violations": self.max_violations,
            "no_destructive": self.no_destructive,
        }


@dataclass(frozen=True)
class ScopeRule:
    value: str
    kind: str = "url"
    allow: bool = True
    protocol: str | None = None
    port: int | tuple[int, int] | None = None
    path: str | None = None
    source: str = "operator"
    instruction: str = ""
    max_severity: str | None = None
    allowed_methods: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        kind = self.kind.lower().strip()
        if kind not in {"url", "domain", "wildcard", "cidr"}:
            raise ValueError(f"unsupported scope rule kind: {self.kind}")
        object.__setattr__(self, "kind", kind)
        if self.protocol and self.protocol.lower() not in {"http", "https"}:
            raise ValueError("scope protocol must be http or https")
        if self.max_severity is not None and self.max_severity.lower() not in _SEVERITY_ORDER:
            raise ValueError("invalid max_severity")
        if self.path and not self.path.startswith("/"):
            raise ValueError("scope path must start with /")
        methods = frozenset(str(m).upper() for m in self.allowed_methods)
        object.__setattr__(self, "allowed_methods", methods)

    def as_dict(self) -> dict[str, Any]:
        port: Any = self.port
        if isinstance(port, tuple):
            port = list(port)
        return {
            "value": self.value,
            "kind": self.kind,
            "allow": self.allow,
            "protocol": self.protocol,
            "port": port,
            "path": self.path,
            "source": self.source,
            "instruction": self.instruction[:500],
            "max_severity": self.max_severity,
            "allowed_methods": sorted(self.allowed_methods),
        }


@dataclass(frozen=True)
class ScopeDecision:
    status: ScopeStatus
    url: str
    method: str = "GET"
    reason: str = ""
    rule_source: str | None = None
    violation_code: str | None = None
    request_admitted: bool = False

    @property
    def allowed(self) -> bool:
        return self.status is ScopeStatus.IN_SCOPE and self.request_admitted

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "url": self.url,
            "method": self.method,
            "reason": self.reason,
            "rule_source": self.rule_source,
            "violation_code": self.violation_code,
            "request_admitted": self.request_admitted,
        }


@dataclass(frozen=True)
class ScopePolicy:
    rules: tuple[ScopeRule, ...]
    limits: ScopeLimits = field(default_factory=ScopeLimits)
    blacklisted_payloads: tuple[str, ...] = ()
    source: str = "operator"
    instructions: tuple[str, ...] = ()
    fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rules": [r.as_dict() for r in self.rules],
            "limits": self.limits.as_dict(),
            "blacklisted_payloads": list(self.blacklisted_payloads),
            "instructions": list(self.instructions),
            "fingerprint": self.fingerprint,
        }


def severity_value(value: str | None) -> int:
    return _SEVERITY_ORDER.get(str(value or "info").lower(), 0)


def severity_allowed(value: str | None, maximum: str | None) -> bool:
    return maximum is None or severity_value(value) <= severity_value(maximum)


__all__ = [
    "ScopeDecision",
    "ScopeLimits",
    "ScopePolicy",
    "ScopeRule",
    "ScopeStatus",
    "severity_allowed",
    "severity_value",
]
