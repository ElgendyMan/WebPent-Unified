from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopeViolation:
    code: str
    url: str
    method: str
    count: int
    halted: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "url": self.url[:240],
            "method": self.method.upper(),
            "count": self.count,
            "halted": self.halted,
            "reason": self.reason[:240],
        }


__all__ = ["ScopeViolation"]
