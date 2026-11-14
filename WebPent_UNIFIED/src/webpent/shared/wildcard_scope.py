"""Strict wildcard scope compilation for the legacy Target contract.

The compiler is deliberately transport-free. It converts explicit operator scope
entries into anchored hostname regexes that the existing ``Target.is_in_scope``
method already consumes. Invalid or ambiguous input is rejected rather than
interpreted heuristically.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from webpent.models.targets import Target

_LABEL_RE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_WILDCARD_RE = re.compile(
    r"^\*\.(?P<root>"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$"
)


class WildcardScopeError(ValueError):
    """Raised when an operator scope entry cannot be compiled safely."""


@dataclass(frozen=True)
class CompiledScope:
    """Redaction-safe, deterministic projection of explicit scope input."""

    exact_hosts: frozenset[str]
    wildcard_root_domains: frozenset[str]
    compiled_regex: tuple[str, ...]
    raw_entries: tuple[str, ...]
    fingerprint: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON/checkpoint-safe projection without hidden input."""
        return {
            "exact_hosts": sorted(self.exact_hosts),
            "wildcard_root_domains": sorted(self.wildcard_root_domains),
            "compiled_regex": list(self.compiled_regex),
            "raw_entries": list(self.raw_entries),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class ScopeRuntimeHandle:
    """Live, immutable scope consumer backed by one compiled scope instance.

    The handle is dependency-injected through ``RuntimeContext`` only.  Its
    serializable representation is the ``CompiledScope.as_dict`` projection;
    the handle itself must never be placed in ``PentestState`` or checkpoints.
    """

    compiled: CompiledScope

    @property
    def fingerprint(self) -> str:
        return self.compiled.fingerprint

    def permits_host(self, hostname: str) -> bool:
        """Return whether a complete hostname is explicitly in compiled scope."""
        try:
            normalized = _normalize_host(hostname)
        except (TypeError, ValueError, WildcardScopeError):
            return False
        if normalized in self.compiled.exact_hosts:
            return True
        return any(
            re.fullmatch(pattern, normalized) is not None
            for pattern in self.compiled.compiled_regex
            if normalized not in self.compiled.exact_hosts
        )

    def permits_url(self, url: str) -> bool:
        """Return whether an HTTP(S) URL's hostname is in this scope."""
        parsed = urlsplit(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        return self.permits_host(parsed.hostname)

    def as_dict(self) -> dict[str, Any]:
        """Return only the checkpoint-safe projection, never the live handle."""
        return self.compiled.as_dict()


def _normalize_host(hostname: str) -> str:
    value = str(hostname or "").strip().lower().rstrip(".")
    if not value or any(ord(char) > 127 for char in value):
        raise WildcardScopeError("scope_hostname_must_be_ascii")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(_LABEL_RE, label) for label in labels):
        raise WildcardScopeError("scope_hostname_invalid")
    return value


def _parse_entry(raw_entry: str) -> tuple[str, str, bool]:
    value = str(raw_entry or "").strip()
    if not value:
        raise WildcardScopeError("scope_entry_required")
    if "\\" in value or "@" in value or "%" in value:
        raise WildcardScopeError("scope_entry_ambiguous")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise WildcardScopeError("scope_entry_requires_http_url")
    if parsed.username is not None or parsed.password is not None:
        raise WildcardScopeError("scope_entry_userinfo_denied")
    if parsed.query or parsed.fragment:
        raise WildcardScopeError("scope_entry_query_or_fragment_denied")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WildcardScopeError("scope_entry_port_invalid") from exc
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if port not in (None, default_port):
        raise WildcardScopeError("scope_entry_non_default_port_denied")
    host = parsed.hostname.lower().rstrip(".")
    wildcard_match = _WILDCARD_RE.fullmatch(host)
    if wildcard_match:
        return value.rstrip("/"), _normalize_host(wildcard_match.group("root")), True
    if "*" in host:
        raise WildcardScopeError("wildcard_must_be_leftmost_label")
    return value.rstrip("/"), _normalize_host(host), False


def _wildcard_pattern(root: str) -> str:
    # One or more complete DNS labels, anchored at both ends. The root/apex
    # itself is intentionally excluded; an explicit exact entry is required.
    return rf"^(?:{_LABEL_RE}\.)+{re.escape(root)}$"


def compile_wildcard_scope(
    raw_scope_entries: list[str] | tuple[str, ...],
) -> CompiledScope:
    """Compile explicit exact and ``*.root`` entries into safe hostname regexes."""
    exact_hosts: set[str] = set()
    wildcard_roots: set[str] = set()
    regexes: list[str] = []
    normalized_entries: list[str] = []

    for raw_entry in raw_scope_entries:
        canonical, host, is_wildcard = _parse_entry(raw_entry)
        if canonical in normalized_entries:
            continue
        normalized_entries.append(canonical)
        if is_wildcard:
            wildcard_roots.add(host)
            pattern = _wildcard_pattern(host)
        else:
            exact_hosts.add(host)
            pattern = rf"^{re.escape(host)}$"
        if pattern not in regexes:
            regexes.append(pattern)

    if not normalized_entries:
        raise WildcardScopeError("scope_entries_required")
    fingerprint_input = "\n".join(normalized_entries).encode("utf-8")
    fingerprint = f"sha256:{hashlib.sha256(fingerprint_input).hexdigest()}"
    return CompiledScope(
        exact_hosts=frozenset(exact_hosts),
        wildcard_root_domains=frozenset(wildcard_roots),
        compiled_regex=tuple(regexes),
        raw_entries=tuple(normalized_entries),
        fingerprint=fingerprint,
    )


def apply_compiled_scope(target: Target, compiled: CompiledScope) -> Target:
    """Return a target with compiled patterns appended, preserving old rules."""
    existing = list(target.in_scope_regex)
    merged = list(dict.fromkeys([*existing, *compiled.compiled_regex]))
    return target.model_copy(update={"in_scope_regex": merged})


def compile_target_scope(
    target: Target,
    raw_scope_entries: list[str] | tuple[str, ...] | None,
) -> tuple[Target, CompiledScope | None]:
    """Compile optional raw entries; absence preserves the legacy target exactly."""
    if not raw_scope_entries:
        return target, None
    compiled = compile_wildcard_scope(raw_scope_entries)
    return apply_compiled_scope(target, compiled), compiled


def wildcard_scope_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph startup node for optional wildcard scope compilation.

    Invalid operator input returns a deny-all target and a blocked status. It
    never raises into a partially-started scan and never broadens scope.
    """
    target = state.get("target")
    raw_entries = state.get("raw_scope_entries") or []
    if target is None or not raw_entries:
        return {"scope_compile_status": "not_requested"}
    try:
        updated_target, compiled = compile_target_scope(target, raw_entries)
    except (TypeError, ValueError, WildcardScopeError) as exc:
        deny_all = target.model_copy(update={"in_scope_regex": [r"(?!)"]})
        return {
            "target": deny_all,
            "scope_compile_status": "blocked",
            "scope_compile_error": str(exc),
            "compiled_scope": {"status": "blocked", "reason": str(exc)},
            "errors": [f"wildcard_scope_blocked:{exc}"],
        }
    assert compiled is not None
    return {
        "target": updated_target,
        "scope_compile_status": "compiled",
        "compiled_scope": compiled.as_dict(),
    }


def route_after_wildcard_scope(state: dict[str, Any]) -> str:
    """Route blocked compilation away from all target-facing nodes."""
    return "reporter" if state.get("scope_compile_status") == "blocked" else "planner"
