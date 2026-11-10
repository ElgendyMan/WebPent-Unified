# src/webpent/scope/authority.py
"""UM-DR-34 Phase 2 — the canonical Engagement Scope Authority.

One authoritative, deterministic, fail-closed request-level decision
contract for every network-capable execution path (UM-DR-34 §2).

Design contract
----------------

* ONE scope engine.  The existing typed ``ScopeRule`` / ``ScopePolicy``
  (:mod:`webpent.scope.models`) are the canonical rule representation;
  this module adds the ONE authoritative request-decision interface on
  top of them.  Existing public surfaces (``ScopeEnforcer``,
  ``OriginPolicy``, ``ScopeLaw``/``ToolBoundary``) remain as
  compatibility adapters that must delegate here rather than re-implement
  matching semantics.
* Deterministic.  The same ``(policy, url, method, payload)`` always
  yields the same decision, the same reason and the same matched rule.
* Deny precedence.  A matching deny rule always wins over any allow rule.
* Fail-closed.  UNKNOWN, malformed, ambiguous or missing state NEVER
  becomes an implicit allow — every parse/match failure is a denial with
  a stable reason token.
* One wildcard compiler.  Wildcard host rules use the strict
  complete-label semantics of ``shared/wildcard_scope.py`` (anchored
  ``*.root`` regexes; the apex is NOT included; misplaced ``*``,
  ``?`` and ``[seq]`` glob syntax are rejected at compile time).  The
  ``fnmatch``-based matching that used to live in
  ``ScopeEnforcer._host_match`` is gone: a wildcard must never become a
  general-purpose glob expression.

Decision record (UM-DR-34 §2.2)
-------------------------------
:func:`EngagementScopeAuthority.evaluate_request` returns a
:class:`webpent.scope.models.ScopeDecision` extended with the canonical
fields (normalized origin, hostname, scheme, effective port, normalized
path, matched allow/deny rule, exclusion reason, scope fingerprint,
authorization context id, monotonic decision sequence, and whether the
request may proceed to the network).
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from .models import ScopePolicy, ScopeRule, ScopeStatus, severity_allowed

__all__ = [
    "CanonicalScopeError",
    "ControlPlaneEgressPolicy",
    "EngagementScopeAuthority",
    "RequestURL",
    "authority_for_target_only",
    "authority_from_policy",
    "authority_from_scope_file_spec",
    "compile_host_matcher",
    "parse_request_url",
]

# ---------------------------------------------------------------------------
# Strict hostname grammar (mirrors shared/wildcard_scope.py — ONE semantics)
# ---------------------------------------------------------------------------

_LABEL_RE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_WILDCARD_ANCHOR_RE = re.compile(r"^\*\.([a-z0-9.-]+)$")
_LABEL_FULL_RE = re.compile(rf"^{_LABEL_RE}$")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
# Rule protocols are declared as http/https (models.ScopeRule contract);
# the map answers "which REQUEST schemes may satisfy this RULE scheme".
# WebSocket requests share the TLS posture of their HTTP sibling:
# an http rule admits ws requests, an https rule admits wss requests.
_SCHEME_COMPAT = {
    "http": frozenset({"http", "ws"}),
    "https": frozenset({"https", "wss"}),
    "ws": frozenset({"ws", "http"}),
    "wss": frozenset({"wss", "https"}),
}

# Encoded path characters that can change how a server interprets the
# path relative to its raw form.  A request whose raw path contains these
# is AMBIGUOUS under the supported normalization contract and is denied
# conservatively (UM-DR-34 §2.3 "Path").
_AMBIGUOUS_PATH_TOKENS = (
    "%2f",  # encoded path separator
    "%2e",  # encoded dot (dot-segments)
    "%5c",  # encoded backslash
)
_DESTRUCTIVE_METHODS = frozenset({"DELETE", "PUT", "PATCH"})


class CanonicalScopeError(ValueError):
    """Raised when scope input cannot be compiled safely (fail-closed)."""


# ---------------------------------------------------------------------------
# Request URL parsing / normalization
# ---------------------------------------------------------------------------


def normalize_hostname(value: str | None) -> str | None:
    """Canonicalize a DNS or IP-literal hostname for exact comparison.

    * IDNA/punycode encoding for unicode DNS names;
    * IPv4/IPv6 compression and lower-casing for IP literals;
    * trailing-dot removal;
    * returns ``None`` for anything malformed (fail-closed).
    """
    if not value:
        return None
    cleaned = str(value).strip().strip("[]").rstrip(".")
    if not cleaned:
        return None
    try:
        return ipaddress.ip_address(cleaned).compressed.lower()
    except ValueError:
        pass
    try:
        ascii_host = cleaned.encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, ValueError):
        return None
    if not ascii_host:
        return None
    return ascii_host


@dataclass(frozen=True)
class RequestURL:
    """A strictly parsed, normalized request target."""

    raw: str
    scheme: str
    hostname: str
    effective_port: int
    path: str
    normalized_origin: str

    @property
    def is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.hostname)
            return True
        except ValueError:
            return False


def _normalize_request_path(raw_path: str) -> str:
    path = raw_path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    # Segment-boundary normalization only — no semantic re-interpretation.
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def _path_is_ambiguous(raw_path: str, decoded_path: str) -> bool:
    """Conservative ambiguity check (UM-DR-34 §2.3)."""
    lowered = raw_path.lower()
    if any(token in lowered for token in _AMBIGUOUS_PATH_TOKENS):
        return True
    if "\\" in raw_path:
        return True
    # Double encoding: a second decode pass that changes the string means
    # the raw form was itself carrying encoded percent signs.
    if unquote(decoded_path) != decoded_path:
        return True
    return False


def parse_request_url(url: str) -> RequestURL:
    """Parse and normalize a request URL, fail-closed.

    Raises :class:`CanonicalScopeError` for: missing/unsupported scheme,
    missing host, userinfo, port 0, out-of-range ports, and any hostname
    that cannot be canonicalized.
    """
    text = str(url or "").strip()
    if not text:
        raise CanonicalScopeError("request_url_required")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise CanonicalScopeError("request_url_malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise CanonicalScopeError("request_url_scheme_unsupported")
    if parsed.username is not None or parsed.password is not None:
        raise CanonicalScopeError("request_url_userinfo_denied")
    hostname = normalize_hostname(parsed.hostname or "")
    if not hostname:
        raise CanonicalScopeError("request_url_host_required")
    # EXPLICIT ``is None`` handling — port 0 must never be treated as an
    # omitted port (UM-DR-34 §2.3).
    raw_port: int | None = None
    try:
        raw_port = parsed.port
    except ValueError as exc:
        raise CanonicalScopeError("request_url_port_invalid") from exc
    if raw_port is None:
        effective_port = _DEFAULT_PORTS[scheme]
    elif raw_port == 0:
        raise CanonicalScopeError("request_url_port_zero_denied")
    elif not 1 <= raw_port <= 65535:
        raise CanonicalScopeError("request_url_port_out_of_range")
    else:
        effective_port = raw_port
    path = _normalize_request_path(parsed.path or "/")
    host_for_origin = f"[{hostname}]" if ":" in hostname else hostname
    origin = f"{scheme}://{host_for_origin}:{effective_port}"
    return RequestURL(
        raw=text,
        scheme=scheme,
        hostname=hostname,
        effective_port=effective_port,
        path=path,
        normalized_origin=origin,
    )


# ---------------------------------------------------------------------------
# ONE strict host matcher compiler
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostMatcher:
    """Compiled, strict host matcher for one rule value."""

    kind: str  # "exact" | "ip" | "cidr" | "wildcard"
    value: str
    pattern: re.Pattern[str] | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    def matches(self, hostname: str) -> bool:
        if self.kind == "exact":
            return hostname == self.value
        if self.kind == "ip":
            return hostname == self.value
        if self.kind == "cidr":
            assert self.network is not None
            try:
                return ipaddress.ip_address(hostname) in self.network
            except ValueError:
                return False
        assert self.pattern is not None
        return self.pattern.match(hostname) is not None


def compile_host_matcher(rule: ScopeRule) -> HostMatcher:
    """Compile one rule's host constraint with strict semantics.

    Rejections (fail-closed :class:`CanonicalScopeError`):

    * a ``*`` anywhere other than a single leading ``*.`` label;
    * ``?``, ``[`` or ``]`` glob metacharacters;
    * empty or malformed labels;
    * IP literals that do not parse;
    * CIDR values that are not valid networks.
    """
    value = str(rule.value or "").strip()
    if not value:
        raise CanonicalScopeError("scope_rule_value_required")
    # Extract the host part of the rule value (URL or bare host).
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
    except ValueError as exc:
        # urlsplit fails on malformed IPv6 brackets — which is exactly
        # what glob ``[seq]`` syntax looks like.  Reject with the
        # precise token instead of a generic parse error.
        if any(char in value for char in "?[]"):
            raise CanonicalScopeError("scope_rule_glob_syntax_denied") from exc
        raise CanonicalScopeError("scope_rule_value_malformed") from exc
    # CIDR values are NETWORK DECLARATIONS, not URLs — urlsplit would
    # eat the "/prefix" as a path.  Use the raw value for them.
    if rule.kind == "cidr":
        lowered = value.lower().strip()
        if not lowered:
            raise CanonicalScopeError("scope_rule_host_required")
        if any(char in lowered for char in "?[]"):
            raise CanonicalScopeError("scope_rule_glob_syntax_denied")
        try:
            network = ipaddress.ip_network(lowered, strict=False)
        except ValueError as exc:
            raise CanonicalScopeError("scope_rule_cidr_invalid") from exc
        return HostMatcher(kind="cidr", value=lowered, network=network)
    raw_host = (parsed.hostname or value).strip("[]").rstrip(".")
    lowered = raw_host.lower()
    if not lowered:
        raise CanonicalScopeError("scope_rule_host_required")

    # Glob metacharacters are rejected on the extracted HOST — they are
    # not valid DNS label characters and must never fall through to any
    # matcher.  (Brackets in a VALID IPv6 URL never reach here: the
    # hostname is already unbracketed by urlsplit.)
    if any(char in lowered for char in "?[]"):
        raise CanonicalScopeError("scope_rule_glob_syntax_denied")

    if "*" in lowered:
        wildcard = _WILDCARD_ANCHOR_RE.match(lowered)
        if not wildcard:
            raise CanonicalScopeError(
                "scope_wildcard_must_be_leftmost_label"
            )
        root = wildcard.group(1).rstrip(".")
        labels = root.split(".")
        if len(labels) < 2 or any(not _LABEL_FULL_RE.match(label) for label in labels):
            raise CanonicalScopeError("scope_wildcard_root_invalid")
        # Anchored complete-label wildcard; the apex/root is NOT included.
        pattern = re.compile(rf"^(?:{_LABEL_RE}\.)+{re.escape(root)}$")
        return HostMatcher(kind="wildcard", value=lowered, pattern=pattern)

    normalized = normalize_hostname(lowered)
    if not normalized:
        raise CanonicalScopeError("scope_rule_host_invalid")
    try:
        ipaddress.ip_address(normalized)
        return HostMatcher(kind="ip", value=normalized)
    except ValueError:
        labels = normalized.split(".")
        if len(labels) < 2 or any(not _LABEL_FULL_RE.match(label) for label in labels):
            raise CanonicalScopeError("scope_rule_host_invalid")
    return HostMatcher(kind="exact", value=normalized)


# ---------------------------------------------------------------------------
# The canonical authority
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CompiledRule:
    rule: ScopeRule
    host: HostMatcher
    rule_scheme: str | None
    rule_port: int | tuple[int, int] | None
    rule_path: str | None


@dataclass(frozen=True)
class ControlPlaneEgressPolicy:
    """Explicit, narrow control-plane egress policy (UM-DR-34 §3.1).

    Control-plane destinations (LLM providers, Redis, OAST
    infrastructure, local first-party collectors) are declared
    explicitly.  A control-plane context can never inherit campaign
    target permissions and can never widen into a generic bypass: every
    destination is an exact (scheme, host, port) triple.
    """

    destinations: tuple[tuple[str, str, int], ...] = ()

    def allows(self, url: str) -> bool:
        try:
            request = parse_request_url(url)
        except CanonicalScopeError:
            return False
        for scheme, host, port in self.destinations:
            normalized = normalize_hostname(host)
            if (
                normalized is not None
                and request.hostname == normalized
                and request.effective_port == int(port)
                and request.scheme in _SCHEME_COMPAT.get(scheme, frozenset({scheme}))
            ):
                return True
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "destinations": [
                {"scheme": s, "host": h, "port": p}
                for s, h, p in self.destinations
            ]
        }


class EngagementScopeAuthority:
    """The one authoritative engagement scope decision engine.

    Built from a :class:`~webpent.scope.models.ScopePolicy` (already
    parsed by the unified parsers in :mod:`webpent.scope.parser` or
    converted from a :class:`~webpent.shared.scope_file.ScopeFileSpec`).
    Immutable, serializable via ``ScopePolicy.as_dict`` and fingerprinted
    by the policy fingerprint.
    """

    def __init__(
        self,
        policy: ScopePolicy,
        *,
        authorization_context_id: str | None = None,
        mode: str = "engagement",
    ) -> None:
        self.policy = policy
        self.authorization_context_id = (
            authorization_context_id or f"authctx_{policy.fingerprint[:24]}"
        )
        self.mode = mode
        self._compiled: tuple[_CompiledRule, ...] = tuple(
            self._compile_rule(rule) for rule in policy.rules
        )
        self._seq = itertools.count(1)

    # -- construction ------------------------------------------------------

    @staticmethod
    def _compile_rule(rule: ScopeRule) -> _CompiledRule:
        host = compile_host_matcher(rule)
        rule_scheme: str | None = None
        rule_port: int | tuple[int, int] | None = rule.port
        rule_path = rule.path
        value = str(rule.value or "").strip()
        if "://" in value:
            try:
                parsed = urlsplit(value)
            except ValueError as exc:
                raise CanonicalScopeError("scope_rule_value_malformed") from exc
            rule_scheme = parsed.scheme.lower() or None
            if rule.protocol:
                rule_scheme = rule.protocol.lower()
            try:
                value_port = parsed.port
            except ValueError as exc:
                raise CanonicalScopeError("scope_rule_port_invalid") from exc
            if value_port is not None:
                if value_port == 0:
                    raise CanonicalScopeError("scope_rule_port_zero_denied")
                rule_port = rule_port if rule_port is not None else value_port
            elif rule.port is None:
                rule_port = None
            value_path = parsed.path or ""
            if value_path not in {"", "/"} and rule_path is None:
                rule_path = value_path.rstrip("/") or "/"
        elif rule.protocol:
            rule_scheme = rule.protocol.lower()
        return _CompiledRule(
            rule=rule,
            host=host,
            rule_scheme=rule_scheme,
            rule_port=rule_port,
            rule_path=rule_path,
        )

    # -- the decision ------------------------------------------------------

    def evaluate_request(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: str | None = None,
        request_kind: str | None = None,
        severity: str | None = None,
        redirect_context: str | None = None,
    ) -> Any:
        """Return the authoritative :class:`ScopeDecision` for one request.

        Deterministic; deny rules take precedence; malformed input,
        ambiguous paths and unknown states are denials — never allows.
        """
        from .models import ScopeDecision  # local import: extended model

        seq = next(self._seq)
        timestamp = time.time()
        method = str(method or "GET").upper()

        def _deny(url_value: str, reason: str, code: str, matched_deny: str | None = None) -> Any:
            return ScopeDecision(
                status=ScopeStatus.OUT_OF_SCOPE,
                url=url_value,
                method=method,
                reason=reason,
                rule_source=None,
                violation_code=code,
                request_admitted=False,
                matched_deny_rule=matched_deny,
                exclusion_reason=reason,
                scope_fingerprint=self.policy.fingerprint,
                authorization_context_id=self.authorization_context_id,
                decision_seq=seq,
                decision_timestamp=timestamp,
                may_proceed_to_network=False,
                redirect_context=redirect_context,
            )

        try:
            request = parse_request_url(url)
        except CanonicalScopeError as exc:
            return _deny(str(url or ""), f"malformed request url: {exc}", "request_url_rejected")

        if not self._compiled:
            return _deny(request.raw, "no scope rules compiled", "scope_policy_empty")

        if method in _DESTRUCTIVE_METHODS and self.policy.limits.no_destructive:
            return _deny(request.raw, "destructive method disabled by policy", "destructive_method_blocked")

        if payload and any(
            token.lower() in payload.lower() for token in self.policy.blacklisted_payloads
        ):
            return _deny(request.raw, "payload matched operator blacklist", "blacklisted_payload_blocked")

        decoded_path = unquote(request.path)
        if _path_is_ambiguous(request.path, decoded_path):
            return _deny(
                request.raw,
                "request path is ambiguous under the normalization contract",
                "scope_path_ambiguous",
            )

        matched_allow: _CompiledRule | None = None
        matched_deny: _CompiledRule | None = None
        for compiled in self._compiled:
            if not self._rule_matches(compiled, request, method, severity):
                continue
            if not compiled.rule.allow:
                matched_deny = compiled
                break
            if matched_allow is None:
                matched_allow = compiled

        if matched_deny is not None:
            return _deny(
                request.raw,
                "explicit deny rule matched",
                "explicit_out_of_scope",
                matched_deny=f"{matched_deny.rule.kind}:{matched_deny.rule.value}",
            )

        if matched_allow is None:
            return _deny(request.raw, "no in-scope rule matched", "unknown_scope")

        return ScopeDecision(
            status=ScopeStatus.IN_SCOPE,
            url=request.raw,
            method=method,
            reason="in-scope rule matched",
            rule_source=matched_allow.rule.source,
            violation_code=None,
            request_admitted=True,
            normalized_origin=request.normalized_origin,
            hostname=request.hostname,
            scheme=request.scheme,
            effective_port=request.effective_port,
            normalized_path=request.path,
            matched_allow_rule=f"{matched_allow.rule.kind}:{matched_allow.rule.value}",
            matched_deny_rule=None,
            exclusion_reason="",
            scope_fingerprint=self.policy.fingerprint,
            authorization_context_id=self.authorization_context_id,
            decision_seq=seq,
            decision_timestamp=timestamp,
            may_proceed_to_network=True,
            redirect_context=redirect_context,
            request_kind=request_kind,
        )

    # -- rule matching -----------------------------------------------------

    def _rule_matches(
        self,
        compiled: _CompiledRule,
        request: RequestURL,
        method: str,
        severity: str | None,
    ) -> bool:
        rule = compiled.rule
        if not compiled.host.matches(request.hostname):
            return False
        if compiled.rule_scheme is not None:
            compatible = _SCHEME_COMPAT.get(compiled.rule_scheme, frozenset())
            if request.scheme not in compatible:
                return False
        if compiled.rule_port is not None:
            if isinstance(compiled.rule_port, tuple):
                low, high = compiled.rule_port
                if not low <= request.effective_port <= high:
                    return False
            elif request.effective_port != compiled.rule_port:
                return False
        elif request.effective_port != _DEFAULT_PORTS.get(request.scheme):
            # UM-DR-34 §2.3: a rule that declares no port (bare host,
            # wildcard, domain) matches only the SCHEME-DEFAULT ports.
            # Non-default ports require an explicit port declaration —
            # consistent with the strict wildcard compiler, which rejects
            # non-default ports outright.
            return False
        if compiled.rule_path is not None:
            prefix = compiled.rule_path.rstrip("/") or "/"
            if not (request.path == prefix or request.path.startswith(prefix + "/")):
                return False
        if rule.allowed_methods and method.upper() not in rule.allowed_methods:
            return False
        if not severity_allowed(severity, rule.max_severity):
            return False
        return True

    # -- projections -------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "authorization_context_id": self.authorization_context_id,
            "policy": self.policy.as_dict(),
        }


# ---------------------------------------------------------------------------
# Factories (parser unification entry points)
# ---------------------------------------------------------------------------


def authority_from_policy(
    policy: ScopePolicy,
    *,
    authorization_context_id: str | None = None,
) -> EngagementScopeAuthority:
    """Wrap a parsed :class:`ScopePolicy` in the canonical authority."""
    if policy is None:
        raise CanonicalScopeError("scope_policy_required")
    if not policy.fingerprint:
        raise CanonicalScopeError("scope_policy_fingerprint_required")
    return EngagementScopeAuthority(policy, authorization_context_id=authorization_context_id)


def authority_from_scope_file_spec(
    spec: Any,
    *,
    authorization_context_id: str | None = None,
) -> EngagementScopeAuthority:
    """Build the canonical authority from a ``ScopeFileSpec``.

    Unified ingestion (UM-DR-34 §2.4): scope-file entries, structured
    YAML/JSON, HackerOne/Bugcrowd-style exports all reduce to
    :class:`ScopeRule` lists through the existing strict parsers, then to
    ONE canonical authority here.  Fail-closed on any ambiguity.
    """
    from .models import ScopeLimits, ScopePolicy, ScopeRule
    from .parser import parse_scope_text

    allow_entries = list(getattr(spec, "allow_entries", ()) or ())
    excluded_hosts = list(getattr(spec, "excluded_hosts", ()) or ())
    include_paths = list(getattr(spec, "include_paths", ()) or ())
    exclude_paths = list(getattr(spec, "exclude_paths", ()) or ())
    source = getattr(spec, "source", "scope_file") or "scope_file"
    fingerprint = getattr(spec, "fingerprint", "") or ""

    if not allow_entries:
        raise CanonicalScopeError("scope_file_requires_allow_entries")

    def _host_of(entry: str) -> str:
        try:
            parsed = urlsplit(str(entry) if "://" in str(entry) else f"//{entry}")
        except ValueError as exc:
            raise CanonicalScopeError("scope_file_entry_malformed") from exc
        host = normalize_hostname(parsed.hostname or str(entry))
        if not host:
            raise CanonicalScopeError("scope_file_entry_host_required")
        return host

    rules: list[ScopeRule] = []
    for entry in allow_entries:
        text = str(entry).strip()
        kind = "wildcard" if "*" in _host_of(text) else "domain"
        scheme = urlsplit(text if "://" in text else f"//{text}").scheme.lower() or None
        rules.append(
            ScopeRule(
                value=text,
                kind=kind,
                allow=True,
                protocol=scheme if scheme in {"http", "https"} else None,
                source=source,
            )
        )
    for host in excluded_hosts:
        rules.append(
            ScopeRule(value=str(host), kind="domain", allow=False, source=source)
        )
    # Path prefixes apply as constraints on every allow rule (exclusion
    # precedence handled by deny-first evaluation).
    if include_paths or exclude_paths:
        for exclude_path in exclude_paths:
            rules.append(
                ScopeRule(
                    value=allow_entries[0],
                    kind="domain",
                    allow=False,
                    path=str(exclude_path),
                    source=f"{source}:exclude_path",
                )
            )
        if include_paths:
            constrained = []
            for rule in rules:
                if rule.allow and rule.path is None:
                    constrained.append(
                        ScopeRule(
                            value=rule.value,
                            kind=rule.kind,
                            allow=True,
                            protocol=rule.protocol,
                            port=rule.port,
                            path=include_paths[0],
                            source=rule.source,
                        )
                    )
                else:
                    constrained.append(rule)
            rules = constrained

    digest_input = json.dumps(
        {"rules": [r.as_dict() for r in rules], "spec_fingerprint": fingerprint},
        sort_keys=True,
    ).encode("utf-8")
    policy_fingerprint = f"sha256:{hashlib.sha256(digest_input).hexdigest()}"
    policy = ScopePolicy(
        rules=tuple(rules),
        limits=ScopeLimits(),
        blacklisted_payloads=(),
        source=source,
        instructions=(),
        fingerprint=policy_fingerprint,
    )
    return EngagementScopeAuthority(policy, authorization_context_id=authorization_context_id)


def authority_for_target_only(
    target_url: str,
    *,
    authorization_context_id: str | None = None,
) -> EngagementScopeAuthority:
    """Explicit, narrowly-scoped target-only compatibility authority.

    Used when a caller supplies no full scope policy (e.g. direct
    ``HunterRunner`` invocation, UM-DR-34 §4.6): the campaign is bounded
    to the EXACT declared target origin — one scheme, one host, one
    effective port, no wildcards — and the mode is reported as
    ``target_only`` so summaries never present it as a full scope.
    """
    from .models import ScopeLimits, ScopePolicy, ScopeRule

    request = parse_request_url(target_url)
    host_for_rule = f"[{request.hostname}]" if ":" in request.hostname else request.hostname
    origin_rule = ScopeRule(
        value=f"{request.scheme}://{host_for_rule}:{request.effective_port}",
        kind="url",
        allow=True,
        protocol=request.scheme if request.scheme in {"http", "https"} else None,
        source="target_only_compat",
        instruction=(
            "UM-DR-34 §4.6 target-only compatibility mode: bounded to the "
            "exact declared origin; every request is still validated at "
            "the network boundary."
        ),
    )
    digest = hashlib.sha256(
        f"target_only:{request.normalized_origin}".encode("utf-8")
    ).hexdigest()
    policy = ScopePolicy(
        rules=(origin_rule,),
        limits=ScopeLimits(),
        blacklisted_payloads=(),
        source="target_only",
        instructions=(),
        fingerprint=f"sha256:{digest}",
    )
    return EngagementScopeAuthority(
        policy,
        authorization_context_id=authorization_context_id,
        mode="target_only",
    )
