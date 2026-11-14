"""Canonical, target-agnostic authorization from a Target Package projection."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import unquote, urlsplit

from webpent.shared.engagement_scope import normalize_scope_host
from webpent.shared.target_package_context import TargetPackageContext


class ScopeDecisionStatus(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_CONSTRAINTS = "allow_with_constraints"
    DENY_OUT_OF_SCOPE = "deny_out_of_scope"
    DENY_POLICY = "deny_policy"
    DENY_EXPIRED = "deny_expired"
    DENY_REVOKED = "deny_revoked"
    DENY_AMBIGUOUS = "deny_ambiguous"


@dataclass(frozen=True)
class ScopeDecision:
    status: ScopeDecisionStatus
    reason: str
    matched_rule_id: str = ""
    constraints: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.status in {
            ScopeDecisionStatus.ALLOW,
            ScopeDecisionStatus.ALLOW_WITH_CONSTRAINTS,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "matched_rule_id": self.matched_rule_id,
            "constraints": list(self.constraints),
        }


@dataclass(frozen=True)
class AuthorizationContext:
    """Immutable package authorization context used by ActionAuthority."""

    package_id: str
    package_sha256: str
    scope_digest: str
    policy_digest: str
    scope_status: str
    scope_rules: tuple[dict[str, Any], ...]
    policy_constraints: dict[str, Any]
    expires_at: str
    revocation_state: str


class ScopeCompiler:
    """Compile and evaluate normalized package rules without target I/O."""

    def __init__(self, context: AuthorizationContext) -> None:
        self.context = context

    @classmethod
    def from_package_context(cls, package: TargetPackageContext) -> ScopeCompiler:
        return cls(
            AuthorizationContext(
                package_id=package.package_id,
                package_sha256=package.package_sha256,
                scope_digest=package.scope_digest,
                policy_digest=package.policy_digest,
                scope_status=package.scope_status,
                scope_rules=tuple(dict(rule) for rule in package.scope_rules),
                policy_constraints=dict(package.policy_constraints),
                expires_at=package.expires_at,
                revocation_state=package.revocation_state,
            )
        )

    @classmethod
    def from_projection(cls, projection: dict[str, Any]) -> ScopeCompiler:
        return cls(
            AuthorizationContext(
                package_id=str(
                    projection.get("package_id")
                    or projection.get("target_package_id")
                    or ""
                ),
                package_sha256=str(
                    projection.get("package_sha256")
                    or projection.get("target_package_sha256")
                    or ""
                ),
                scope_digest=str(projection.get("scope_digest") or ""),
                policy_digest=str(projection.get("policy_digest") or ""),
                scope_status=str(projection.get("scope_status") or ""),
                scope_rules=tuple(
                    dict(rule) for rule in list(projection.get("scope_rules") or [])
                    if isinstance(rule, dict)
                ),
                policy_constraints=dict(projection.get("policy_constraints") or {}),
                expires_at=str(projection.get("expires_at") or ""),
                revocation_state=str(projection.get("revocation_state") or "active"),
            )
        )

    @staticmethod
    def _effective_port(scheme: str, port: int | None) -> int | None:
        if port is not None:
            return port
        return {"http": 80, "https": 443}.get(scheme)

    @staticmethod
    def _path_matches(rule_path: Any, candidate_path: str) -> bool:
        if not rule_path or str(rule_path) == "/":
            return True
        path = str(rule_path)
        if not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/") or "/"
        return candidate_path == path or candidate_path.startswith(path + "/")

    @staticmethod
    def _methods(rule: dict[str, Any]) -> set[str]:
        values = rule.get("methods") or rule.get("allowed_methods") or []
        if isinstance(values, str):
            values = [values]
        return {str(value).upper() for value in values if str(value).strip()}

    @staticmethod
    def _actions(rule: dict[str, Any]) -> set[str]:
        values = rule.get("action_classes") or rule.get("allowed_action_classes") or []
        if isinstance(values, str):
            values = [values]
        return {str(value).strip().lower() for value in values if str(value).strip()}

    @classmethod
    def _rule_matches(
        cls,
        rule: dict[str, Any],
        *,
        scheme: str,
        host: str,
        port: int,
        path: str,
        method: str,
        action_class: str,
    ) -> bool:
        asset_type = str(rule.get("asset_type") or "").lower()
        if asset_type not in {"url", "website", "domain", "wildcard"}:
            if asset_type in {"ip", "cidr", "ip_address"}:
                try:
                    candidate = ipaddress.ip_address(host)
                    network = ipaddress.ip_network(str(rule.get("host")), strict=False)
                    if candidate not in network:
                        return False
                except ValueError:
                    return False
            else:
                return False
        rule_scheme = str(rule.get("scheme") or "").lower()
        if rule_scheme and rule_scheme != scheme:
            return False
        try:
            rule_port = rule.get("port")
            if rule_port is not None and int(rule_port) != port:
                return False
        except (TypeError, ValueError):
            return False
        rule_host = normalize_scope_host(str(rule.get("host") or ""))
        raw_host = str(rule.get("host") or "").lower().rstrip(".")
        wildcard = bool(rule.get("wildcard")) or raw_host.startswith("*.")
        if wildcard:
            suffix = raw_host[2:].rstrip(".")
            if not suffix or host == suffix or not host.endswith("." + suffix):
                return False
        elif rule_host != host:
            return False
        if not cls._path_matches(rule.get("path"), path):
            return False
        methods = cls._methods(rule)
        if methods and method not in methods:
            return False
        actions = cls._actions(rule)
        return not actions or action_class.lower() in actions

    def _candidate(self, url: str) -> tuple[str, str, int, str] | None:
        try:
            parsed = urlsplit(str(url).strip())
            if parsed.scheme.lower() not in {"http", "https"}:
                return None
            if parsed.username is not None or parsed.password is not None:
                return None
            if parsed.query or parsed.fragment:
                return None
            host = normalize_scope_host(parsed.hostname or "")
            if not host or any(ord(char) < 32 for char in str(url)):
                return None
            port = self._effective_port(parsed.scheme.lower(), parsed.port)
            if port is None:
                return None
            path = unquote(parsed.path or "/")
            if not path.startswith("/"):
                return None
            if any(ord(char) < 32 for char in path):
                return None
            if any(segment in {".", ".."} for segment in path.split("/")):
                return None
            return parsed.scheme.lower(), host, port, path
        except (TypeError, ValueError):
            return None

    def decide(
        self,
        url: str,
        *,
        method: str = "GET",
        action_class: str = "http_read",
        redirect_chain: tuple[str, ...] | list[str] = (),
        now: datetime | None = None,
    ) -> ScopeDecision:
        if self.context.revocation_state == "revoked":
            return ScopeDecision(ScopeDecisionStatus.DENY_REVOKED, "package_revoked")
        try:
            expiry = datetime.fromisoformat(
                self.context.expires_at.replace("Z", "+00:00")
            ).astimezone(UTC)
            if expiry <= (now or datetime.now(UTC)):
                return ScopeDecision(ScopeDecisionStatus.DENY_EXPIRED, "package_expired")
        except (TypeError, ValueError):
            return ScopeDecision(ScopeDecisionStatus.DENY_AMBIGUOUS, "package_expiry_invalid")
        if self.context.scope_status != "ready":
            return ScopeDecision(ScopeDecisionStatus.DENY_AMBIGUOUS, "scope_not_ready")
        prohibited = self.context.policy_constraints.get("prohibited_actions") or []
        prohibited_values = {str(item).lower() for item in prohibited}
        if str(action_class).lower() in prohibited_values or "all_actions" in prohibited_values:
            return ScopeDecision(ScopeDecisionStatus.DENY_POLICY, "action_class_prohibited")
        candidate = self._candidate(url)
        if candidate is None:
            return ScopeDecision(ScopeDecisionStatus.DENY_AMBIGUOUS, "candidate_url_ambiguous")
        scheme, host, port, path = candidate
        normalized_method = str(method or "GET").upper()
        normalized_action = str(action_class or "http_read").lower()
        exclusions = [
            rule for rule in self.context.scope_rules
            if str(rule.get("action") or "").lower() == "exclude"
            and self._rule_matches(
                rule, scheme=scheme, host=host, port=port, path=path,
                method=normalized_method, action_class=normalized_action,
            )
        ]
        if exclusions:
            return ScopeDecision(
                ScopeDecisionStatus.DENY_OUT_OF_SCOPE,
                "matched_explicit_exclusion",
                str(exclusions[0].get("rule_id") or ""),
            )
        includes = [
            rule for rule in self.context.scope_rules
            if str(rule.get("action") or "").lower() == "include"
            and self._rule_matches(
                rule, scheme=scheme, host=host, port=port, path=path,
                method=normalized_method, action_class=normalized_action,
            )
        ]
        if not includes:
            return ScopeDecision(
                ScopeDecisionStatus.DENY_OUT_OF_SCOPE,
                "no_explicit_include_matched",
            )
        constraints: list[str] = []
        if self.context.policy_constraints.get("required_headers"):
            constraints.append("required_headers")
        if self.context.policy_constraints.get("rate_limits"):
            constraints.append("rate_limits")
        for destination in tuple(redirect_chain):
            redirect_decision = self.decide(
                destination,
                method=normalized_method,
                action_class=normalized_action,
                now=now,
            )
            if not redirect_decision.allowed:
                return ScopeDecision(
                    redirect_decision.status,
                    "redirect_destination_not_authorized",
                    redirect_decision.matched_rule_id,
                    redirect_decision.constraints,
                )
        status = (
            ScopeDecisionStatus.ALLOW_WITH_CONSTRAINTS
            if constraints else ScopeDecisionStatus.ALLOW
        )
        return ScopeDecision(
            status,
            "matched_explicit_include",
            str(includes[0].get("rule_id") or ""),
            tuple(constraints),
        )


__all__ = ["AuthorizationContext", "ScopeCompiler", "ScopeDecision", "ScopeDecisionStatus"]
