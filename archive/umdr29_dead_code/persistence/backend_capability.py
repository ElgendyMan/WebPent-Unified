"""Fail-closed persistence capability reporting."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class BackendCapabilityReport:
    """Report configured backend support without attempting an unqualified migration."""

    def __init__(self, database_url: str) -> None:
        self.database_url = str(database_url or "")

    def as_dict(self) -> dict[str, Any]:
        scheme = self.database_url.split(":", 1)[0].lower() if ":" in self.database_url else ""
        if scheme == "sqlite":
            return {
                "backend": "sqlite",
                "supported": True,
                "qualified": True,
                "fail_closed": False,
                "reason": "native_database_manager",
            }
        if scheme in {"postgres", "postgresql"}:
            return {
                "backend": scheme,
                "supported": False,
                "qualified": False,
                "fail_closed": True,
                "reason": "postgresql_requires_independent_qualification",
            }
        return {
            "backend": scheme or "unknown",
            "supported": False,
            "qualified": False,
            "fail_closed": True,
            "reason": "unsupported_database_scheme",
        }

    def assert_supported(self) -> Mapping[str, Any]:
        report = self.as_dict()
        if not report["supported"]:
            raise RuntimeError(str(report["reason"]))
        return report


__all__ = ["BackendCapabilityReport"]
