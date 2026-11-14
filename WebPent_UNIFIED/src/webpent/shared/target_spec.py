"""Strict single-target engagement contract and central scope policy.

This module is deterministic and target-I/O free.  It validates the operator's
engagement declaration before a scan starts and provides one reusable policy
object for HTTP, browser, crawler, and detector adapters.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AuthorizationRecord(BaseModel):
    """Explicit operator authorization attached to one engagement."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    authorization_id: str = Field(min_length=1, max_length=160)
    authorized_by: str = Field(min_length=1, max_length=200)
    operator: str = Field(min_length=1, max_length=200)
    permitted_test_types: list[str] = Field(min_length=1, max_length=64)
    exclusions: list[str] = Field(default_factory=list, max_length=128)
    emergency_stop_contact: str = Field(min_length=1, max_length=320)
    time_window_start: datetime
    time_window_end: datetime
    user_confirmed: bool = False

    @model_validator(mode="after")
    def validate_window(self) -> AuthorizationRecord:
        start = self.time_window_start.astimezone(UTC)
        end = self.time_window_end.astimezone(UTC)
        if end <= start:
            raise ValueError("authorization time window must end after it starts")
        self.time_window_start = start
        self.time_window_end = end
        if not self.user_confirmed:
            raise ValueError("explicit user_confirmed authorization is required")
        return self


class TargetSpec(BaseModel):
    """Bounded contract for one authorized application and one engagement."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    base_url: str = Field(min_length=1, max_length=2048)
    allowed_hosts: list[str] = Field(min_length=1, max_length=64)
    allowed_ports: list[int] = Field(min_length=1, max_length=16)
    allowed_paths: list[str] = Field(min_length=1, max_length=256)
    excluded_paths: list[str] = Field(default_factory=list, max_length=256)
    profile: Literal[
        "single_target_safe",
        "authenticated_single_target",
        "passive_only",
        "evidence_replay",
    ] = "single_target_safe"
    auth_mode: Literal[
        "unauthenticated",
        "test_credentials",
        "human_assisted",
        "imported_session",
    ] = "unauthenticated"
    allowed_schemes: list[str] = Field(default_factory=lambda: ["https"])
    max_requests: int = Field(ge=1, le=1_000_000)
    max_concurrency: int = Field(ge=1, le=64)
    requests_per_second: float = Field(gt=0, le=1000)
    timeout_seconds: int = Field(ge=1, le=86_400)
    allow_private_target: bool = False
    authorization: AuthorizationRecord

    @field_validator("allowed_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for raw in values:
            host = str(raw).strip().lower().rstrip(".")
            if not host or "://" in host or "/" in host or "@" in host:
                raise ValueError("allowed_hosts must contain bare hostnames or IPs")
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                wildcard_invalid = "*" in host and not host.startswith("*.")
                if any(ord(char) > 127 for char in host) or wildcard_invalid:
                    raise ValueError("allowed host is malformed") from exc
            if host not in result:
                result.append(host)
        return result

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(not 1 <= int(port) <= 65535 for port in values):
            raise ValueError("allowed_ports must be between 1 and 65535")
        return sorted({int(port) for port in values})

    @field_validator("allowed_schemes")
    @classmethod
    def validate_schemes(cls, values: list[str]) -> list[str]:
        normalized = [str(value).strip().lower() for value in values]
        if not normalized or any(value not in {"http", "https"} for value in normalized):
            raise ValueError("allowed_schemes may contain only http and https")
        return sorted(set(normalized))

    @field_validator("allowed_paths", "excluded_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            path = str(value).strip()
            if not path.startswith("/") or "?" in path or "#" in path:
                raise ValueError("paths must be absolute path prefixes without query/fragment")
            path = path.rstrip("/") or "/"
            if path not in normalized:
                normalized.append(path)
        return normalized

    @model_validator(mode="after")
    def validate_base(self) -> TargetSpec:
        parsed = self._parse_url(self.base_url)
        host = _normalize_host(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in self.allowed_schemes:
            raise ValueError("base_url scheme is not allowed")
        if not _host_allowed(host, self.allowed_hosts) or port not in self.allowed_ports:
            raise ValueError("base_url is outside declared host/port scope")
        path = parsed.path or "/"
        if not _path_allowed(path, self.allowed_paths, self.excluded_paths):
            raise ValueError("base_url path is outside declared path scope")
        if self.auth_mode == "unauthenticated" and self.profile == "authenticated_single_target":
            raise ValueError("authenticated profile requires an explicit authenticated mode")
        if self.allow_private_target and not self.authorization.user_confirmed:
            raise ValueError("private target requires explicit authorization")
        return self

    @staticmethod
    def _parse_url(value: str):
        parsed = urlsplit(str(value).strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError(
                "base_url must be an absolute HTTP(S) URL without credentials/fragment"
            )
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("base_url port is invalid") from exc
        return parsed

    def scope_validator(self) -> ScopeValidator:
        return ScopeValidator(self)

    def safe_dict(self) -> dict[str, object]:
        """Return a serializable declaration with no secrets or raw payloads."""
        return self.model_dump(mode="json")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason_code: str
    url_fingerprint: str


class ScopeValidator:
    """Central deterministic URL policy shared by all execution adapters."""

    def __init__(self, spec: TargetSpec):
        self.spec = spec

    def decide(self, value: str, *, method: str = "GET") -> ScopeDecision:
        del method  # Reserved for method-aware policy extensions.
        fingerprint = _fingerprint(value)
        try:
            parsed = TargetSpec._parse_url(value)
            host = _normalize_host(parsed.hostname or "")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
        except ValueError:
            return ScopeDecision(False, "invalid_url", fingerprint)
        if parsed.scheme not in self.spec.allowed_schemes:
            return ScopeDecision(False, "scheme_not_allowed", fingerprint)
        if not _host_allowed(host, self.spec.allowed_hosts):
            return ScopeDecision(False, "host_not_allowed", fingerprint)
        if port not in self.spec.allowed_ports:
            return ScopeDecision(False, "port_not_allowed", fingerprint)
        if not _path_allowed(path, self.spec.allowed_paths, self.spec.excluded_paths):
            if _path_matches(path, self.spec.excluded_paths):
                return ScopeDecision(False, "excluded_path", fingerprint)
            return ScopeDecision(False, "path_not_allowed", fingerprint)
        if _is_private_host(host) and not self.spec.allow_private_target:
            return ScopeDecision(False, "private_address_not_authorized", fingerprint)
        return ScopeDecision(True, "in_scope", fingerprint)

    def validate_redirect(self, value: str) -> ScopeDecision:
        return self.decide(value)

    def validate_resolved_addresses(self, addresses: list[str] | tuple[str, ...]) -> bool:
        """Reject private/link-local/metadata resolutions unless explicitly opted in."""
        for address in addresses:
            try:
                ip = ipaddress.ip_address(str(address).strip())
            except ValueError:
                return False
            private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            if private and not self.spec.allow_private_target:
                return False
        return True


class RequestBudget:
    """Small in-memory budget primitive for one run; no network side effects."""

    def __init__(self, spec: TargetSpec):
        self.limit = spec.max_requests
        self.used = 0
        self.stopped = False

    def consume(self, count: int = 1) -> bool:
        if self.stopped or count < 1 or self.used + count > self.limit:
            self.stopped = True
            return False
        self.used += count
        return True

    def emergency_stop(self) -> None:
        self.stopped = True

    @property
    def exhausted(self) -> bool:
        return self.stopped or self.used >= self.limit


def load_target_spec(path: str | Path) -> TargetSpec:
    """Load a local YAML/JSON TargetSpec without performing target I/O."""
    source = Path(path).expanduser()
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read target spec: {source}") from exc
    try:
        if source.suffix.lower() in {".yaml", ".yml"}:
            import yaml

            payload = yaml.safe_load(text)
        else:
            payload = json.loads(text)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("target spec must be valid JSON or YAML") from exc
    if not isinstance(payload, dict):
        raise ValueError("target spec root must be an object")
    try:
        return TargetSpec.model_validate(payload)
    except ValueError as exc:
        raise ValueError(f"invalid target spec: {exc}") from exc


def _normalize_host(value: str) -> str:
    value = str(value).strip().lower().strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        return value.encode("idna").decode("ascii").lower()


def _host_allowed(host: str, allowed: list[str]) -> bool:
    return any(
        host == item
        or (item.startswith("*.") and host.endswith(item[1:]) and host != item[2:])
        for item in allowed
    )


def _path_matches(path: str, prefixes: list[str]) -> bool:
    return any(
        prefix == "/" or path == prefix or path.startswith(prefix + "/")
        for prefix in prefixes
    )


def _path_allowed(path: str, allowed: list[str], excluded: list[str]) -> bool:
    return _path_matches(path, allowed) and not _path_matches(path, excluded)


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _fingerprint(value: str) -> str:
    parsed = urlsplit(str(value).strip())
    host = _normalize_host(parsed.hostname or "") if parsed.hostname else ""
    port = parsed.port if parsed.hostname else None
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return f"{parsed.scheme.lower()}://{host}:{effective_port}{parsed.path or '/'}"
