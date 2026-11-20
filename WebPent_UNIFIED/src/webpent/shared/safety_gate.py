"""Central fail-closed safety controls for one engagement.

The gate is deliberately transport-agnostic. It validates action metadata before a
handler is invoked; it never performs DNS, HTTP, browser, or filesystem I/O.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import unquote, urlsplit


class SafetyStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    KILL_SWITCHED = "kill_switched"


@dataclass(frozen=True)
class SafetyDecision:
    status: SafetyStatus
    reasons: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.status == SafetyStatus.ALLOWED


class EngagementKillSwitch:
    """Monotonic, engagement-bound stop control.

    The switch has no automatic reset. A new runtime/engagement is required to
    resume execution, which prevents a stale approval or checkpoint from silently
    re-enabling actions after an operator stop.
    """

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = str(engagement_id or "").strip()[:160]
        self._lock = threading.RLock()
        self._reason = ""

    @property
    def tripped(self) -> bool:
        with self._lock:
            return bool(self._reason)

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def trip(self, reason: str) -> None:
        normalized = " ".join(str(reason or "operator_stop").split())[:300]
        with self._lock:
            if not self._reason:
                self._reason = normalized or "operator_stop"

    def check(self, engagement_id: str) -> SafetyDecision:
        if str(engagement_id or "").strip() != self.engagement_id:
            return SafetyDecision(
                SafetyStatus.BLOCKED,
                ("kill_switch:engagement_mismatch",),
            )
        with self._lock:
            if self._reason:
                return SafetyDecision(
                    SafetyStatus.KILL_SWITCHED,
                    (f"kill_switch:tripped:{self._reason}",),
                )
        return SafetyDecision(SafetyStatus.ALLOWED)


class EngagementSafetyGate:
    """Deterministic pre-handler safety gate for one engagement."""

    _SAFE_SCHEMES = frozenset({"http", "https"})
    _SENSITIVE_KEYS = frozenset(
        {
            "authorization",
            "cookie",
            "credential",
            "credentials",
            "otp",
            "password",
            "secret",
            "token",
        }
    )

    def __init__(
        self,
        *,
        engagement_id: str,
        allowed_origins: tuple[str, ...],
        kill_switch: EngagementKillSwitch | None = None,
    ) -> None:
        self.engagement_id = str(engagement_id or "").strip()[:160]
        self.allowed_origins = tuple(
            sorted(
                self._normalize_origin(origin)
                for origin in allowed_origins
                if self._normalize_origin(origin)
            )
        )
        self.kill_switch = kill_switch or EngagementKillSwitch(self.engagement_id)

    @staticmethod
    def _normalize_origin(value: str) -> str:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in EngagementSafetyGate._SAFE_SCHEMES:
            return ""
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return ""
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
        except (UnicodeError, ValueError):
            return ""
        default_port = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
            parsed.scheme.lower() == "https" and port in {None, 443}
        )
        return f"{parsed.scheme.lower()}://{host}{'' if default_port else f':{port}'}"

    @staticmethod
    def _private_network(hostname: str) -> bool:
        normalized = str(hostname or "").strip().lower().rstrip(".")
        if normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(
            ".local"
        ):
            return True
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )

    @classmethod
    def _url_reasons(cls, value: str, allowed_origins: tuple[str, ...]) -> list[str]:
        raw = str(value or "").strip()
        parsed = urlsplit(raw)
        reasons: list[str] = []
        if parsed.scheme.lower() not in cls._SAFE_SCHEMES:
            reasons.append("egress:scheme_not_allowlisted")
        if not parsed.hostname:
            reasons.append("egress:hostname_required")
        if parsed.username is not None or parsed.password is not None:
            reasons.append("egress:userinfo_forbidden")
        if "%" in parsed.path and unquote(parsed.path) != parsed.path:
            reasons.append("egress:encoded_path_ambiguous")
        origin = cls._normalize_origin(raw)
        if not origin or origin not in allowed_origins:
            reasons.append("egress:origin_not_allowlisted")
        if (
            parsed.hostname
            and cls._private_network(parsed.hostname)
            and origin not in allowed_origins
        ):
            reasons.append("egress:private_network_blocked")
        return reasons

    @classmethod
    def _contains_raw_secret(cls, value: Any, *, key: str = "") -> bool:
        normalized_key = str(key or "").lower().replace("-", "_")
        if normalized_key in cls._SENSITIVE_KEYS:
            if isinstance(value, str):
                stripped = value.strip()
                return bool(stripped) and not stripped.startswith("secretref:")
            return value is not None
        if isinstance(value, dict):
            return any(
                cls._contains_raw_secret(item, key=str(item_key))
                for item_key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(cls._contains_raw_secret(item) for item in value)
        return False

    def authorize_request(self, request: Any) -> SafetyDecision:
        reasons: list[str] = []
        engagement_id = str(getattr(request, "engagement_id", "") or "")
        kill_decision = self.kill_switch.check(engagement_id)
        if not kill_decision.allowed:
            return kill_decision
        if engagement_id != self.engagement_id:
            reasons.append("identity:engagement_mismatch")
        if not self.allowed_origins:
            reasons.append("egress:allowlist_empty")
        target_url = str(getattr(request, "target_url", "") or "")
        reasons.extend(self._url_reasons(target_url, self.allowed_origins))
        metadata = getattr(request, "metadata", {})
        if isinstance(metadata, dict):
            if self._contains_raw_secret(metadata):
                reasons.append("secrets:opaque_reference_required")
            redirects = metadata.get("redirect_chain", ())
            if isinstance(redirects, str):
                redirects = (redirects,)
            if redirects:
                for redirect in redirects:
                    reasons.extend(self._url_reasons(str(redirect), self.allowed_origins))
        if reasons:
            return SafetyDecision(SafetyStatus.BLOCKED, tuple(dict.fromkeys(reasons)))
        return SafetyDecision(SafetyStatus.ALLOWED)

    def descriptor(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "allowed_origins": list(self.allowed_origins),
            "kill_switch_tripped": self.kill_switch.tripped,
        }
