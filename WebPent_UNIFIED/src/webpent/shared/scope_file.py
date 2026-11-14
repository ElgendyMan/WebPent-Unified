"""Operator scope-file contract: explicit engagement boundaries vs URL-inferred.

SCENARIO CONTRACT (operator workflow "URL + Credentials (+ Scope sometimes)"):

* When a scope file IS supplied it is THE contractual boundary. The target URL
  must fall inside it or the engagement fails closed before the graph starts.
  Any discovery outside the allow entries is observation-only: never crawled,
  never tested, never exploited.
* When NO scope file is supplied the tool derives a cautious default scope
  from the URL alone (same exact host, no automatic subdomain expansion) and
  the report must label it ``inferred_from_url`` so reviewers know the limits
  are estimates, not contractual.

Grammar (line based, UTF-8, ``#`` comments, blank lines ignored)::

    https://app.example.com          exact allow entry (scheme required OR bare host)
    app.example.com                  bare host  -> https://app.example.com
    *.api.example.com                wildcard allow entry (leftmost label only)
    exclude: staging.example.com     excluded host (exact or wildcard)
    include-path: /api               only test URLs under this path prefix
    exclude-path: /admin             never test URLs under this prefix

Design rules (security posture preserved from engagement_scope.py):

* Path rules are literal, segment-boundary prefixes — no regex, no ReDoS.
* Host parsing/validation is delegated to the strict
  :func:`webpent.shared.wildcard_scope.compile_wildcard_scope` compiler, so
  allow entries cannot smuggle userinfo, query strings, odd ports, or
  ambiguous hostnames past this parser.
* Exclude rules win over everything. The target itself under an exclude rule
  is a hard error.
* This module is transport-free and deterministic; the same input always
  yields the same fingerprint, which the report publishes for auditability.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from webpent.shared.wildcard_scope import (
    ScopeRuntimeHandle,
    WildcardScopeError,
    compile_wildcard_scope,
)

SCOPE_SOURCE_FILE = "scope_file"
SCOPE_SOURCE_INFERRED = "inferred_from_url"


class ScopeFileError(ValueError):
    """Raised when operator scope input cannot be honoured safely.

    ``.code`` carries a stable machine-readable reason for fail-closed
    surfaces (worker logs, API errors, report limitations).
    """

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class ScopeFileSpec:
    """Redaction-safe, deterministic projection of one scope file."""

    allow_entries: tuple[str, ...]
    excluded_hosts: tuple[str, ...] = ()
    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    source: str = SCOPE_SOURCE_FILE
    fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        """JSON/checkpoint-safe projection (contains no secrets by design)."""
        return {
            "source": self.source,
            "allow_entries": list(self.allow_entries),
            "excluded_hosts": list(self.excluded_hosts),
            "include_paths": list(self.include_paths),
            "exclude_paths": list(self.exclude_paths),
            "fingerprint": self.fingerprint,
        }


def _normalize_host_entry(raw: str, *, code_prefix: str) -> str:
    """Normalize one host entry to the scheme URL the strict compiler wants."""
    value = str(raw or "").strip().rstrip("/")
    if not value:
        raise ScopeFileError(f"{code_prefix}_required")
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if "://" in value or "\\" in value or "@" in value or "%" in value:
        # Malformed scheme or ambiguous characters: pass through so the
        # strict compiler rejects it with its precise error code instead
        # of this parser guessing an interpretation.
        return value
    # Bare host / bare wildcard: anchor to https. The strict compiler
    # still validates labels, ambiguity, ports, userinfo, etc.
    return f"https://{value}"


def _normalize_path_prefix(raw: str, *, code: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise ScopeFileError(code)
    if not value.startswith("/"):
        raise ScopeFileError(f"{code}_must_start_with_slash", f"{code}: {value!r}")
    if any(char.isspace() for char in value) or any(ord(char) > 127 for char in value):
        raise ScopeFileError(f"{code}_ambiguous", f"{code}: {value!r}")
    return value.rstrip("/")


def parse_scope_file(text: str) -> ScopeFileSpec:
    """Parse scope-file text into a validated :class:`ScopeFileSpec`.

    Raises :class:`ScopeFileError` (fail-closed) on any ambiguity. Never
    guesses: an entry this parser cannot interpret strictly is an error,
    not a heuristic match.
    """
    allow_entries: list[str] = []
    excluded_hosts: list[str] = []
    include_paths: list[str] = []
    exclude_paths: list[str] = []

    for line_no, raw_line in enumerate(str(text or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("exclude:"):
            entry = _normalize_host_entry(line.split(":", 1)[1], code_prefix="scope_exclude_entry")
            excluded_hosts.append(entry)
        elif lowered.startswith("include-path:"):
            include_paths.append(
                _normalize_path_prefix(line.split(":", 1)[1], code="scope_include_path")
            )
        elif lowered.startswith("exclude-path:"):
            exclude_paths.append(
                _normalize_path_prefix(line.split(":", 1)[1], code="scope_exclude_path")
            )
        else:
            allow_entries.append(_normalize_host_entry(line, code_prefix="scope_entry"))

    if not allow_entries:
        raise ScopeFileError(
            "scope_file_no_allow_entries",
            "scope file must contain at least one allow entry (host or wildcard)",
        )
    if len(allow_entries) != len(set(allow_entries)):
        raise ScopeFileError("scope_file_duplicate_allow_entries")

    # Validate every allow entry through the strict compiler NOW so bad
    # input fails closed here instead of mid-campaign.
    try:
        compiled = compile_wildcard_scope(allow_entries)
    except (WildcardScopeError, TypeError, ValueError) as exc:
        raise ScopeFileError("scope_file_entry_invalid", str(exc)) from exc

    fingerprint_input = "\n".join(
        [
            *compiled.raw_entries,
            *[f"exclude:{entry}" for entry in excluded_hosts],
            *[f"include-path:{p}" for p in include_paths],
            *[f"exclude-path:{p}" for p in exclude_paths],
        ]
    ).encode("utf-8")
    fingerprint = f"sha256:{hashlib.sha256(fingerprint_input).hexdigest()}"

    return ScopeFileSpec(
        allow_entries=tuple(dict.fromkeys(allow_entries)),
        excluded_hosts=tuple(dict.fromkeys(excluded_hosts)),
        include_paths=tuple(dict.fromkeys(include_paths)),
        exclude_paths=tuple(dict.fromkeys(exclude_paths)),
        source=SCOPE_SOURCE_FILE,
        fingerprint=fingerprint,
    )


def parse_scope_entries(entries: list[str] | tuple[str, ...]) -> ScopeFileSpec:
    """Parse an already-split list of scope lines (API surface)."""
    return parse_scope_file("\n".join(str(entry or "") for entry in entries or []))


def _host_matches_entry(host: str, entry: str) -> bool:
    """Host-level match of ``host`` against one normalized allow entry."""
    try:
        parsed = urlsplit(entry)
        entry_host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not entry_host or not host:
        return False
    if host == entry_host:
        return True
    if entry_host.startswith("*."):
        root = entry_host[2:]
        return host.endswith(f".{root}") and host != root
    return False


def target_scope_error(spec: ScopeFileSpec, target_url: str) -> str | None:
    """Return a fail-closed error code when the target is NOT inside the file.

    Contract: with a scope file present, the target URL must be covered by an
    allow entry AND must not sit under an excluded host or excluded path.
    Returns ``None`` when the engagement may proceed.
    """
    try:
        parsed = urlsplit(str(target_url or ""))
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return "scope_file_target_url_invalid"
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return "scope_file_target_url_invalid"

    if any(_host_matches_entry(host, entry) for entry in spec.excluded_hosts):
        return "scope_file_target_url_excluded"

    path = parsed.path or "/"
    for prefix in spec.exclude_paths:
        if path == prefix or path.startswith(f"{prefix}/"):
            return "scope_file_target_url_path_excluded"

    if not any(_host_matches_entry(host, entry) for entry in spec.allow_entries):
        return "scope_file_target_url_not_in_scope"
    return None


def evaluate_path_rules(spec: ScopeFileSpec, url: str) -> str:
    """Apply include/exclude path rules to one URL.

    Returns ``"denied"`` / ``"allowed"`` / ``"not_applicable"`` (the latter
    when the spec has no path rules, so callers keep their legacy behaviour).
    Exclude rules always win over include rules.
    """
    if not spec.include_paths and not spec.exclude_paths:
        return "not_applicable"
    try:
        parsed = urlsplit(str(url or ""))
        path = parsed.path or "/"
    except ValueError:
        return "denied"
    for prefix in spec.exclude_paths:
        if path == prefix or path.startswith(f"{prefix}/"):
            return "denied"
    if not spec.include_paths:
        return "allowed"
    for prefix in spec.include_paths:
        if path == prefix or path.startswith(f"{prefix}/"):
            return "allowed"
    return "denied"


def host_excluded(spec: ScopeFileSpec, url_or_host: str) -> bool:
    """Return True when a discovered host/URL matches an excluded host entry."""
    candidate = str(url_or_host or "")
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").lower().rstrip(".") if parsed.hostname else candidate.lower().rstrip(".")
    except ValueError:
        host = candidate.lower()
    return any(_host_matches_entry(host, entry) for entry in spec.excluded_hosts)


def build_runtime_handle(spec: ScopeFileSpec) -> ScopeRuntimeHandle:
    """Compile the allow entries into the existing strict runtime handle."""
    return ScopeRuntimeHandle(compile_wildcard_scope(list(spec.allow_entries)))


def spec_from_state(declaration: dict[str, Any] | None) -> ScopeFileSpec | None:
    """Rebuild a read-only spec from the redaction-safe state projection."""
    if not declaration or declaration.get("source") != SCOPE_SOURCE_FILE:
        return None
    return ScopeFileSpec(
        allow_entries=tuple(declaration.get("allow_entries") or ()),
        excluded_hosts=tuple(declaration.get("excluded_hosts") or ()),
        include_paths=tuple(declaration.get("include_paths") or ()),
        exclude_paths=tuple(declaration.get("exclude_paths") or ()),
        source=SCOPE_SOURCE_FILE,
        fingerprint=str(declaration.get("fingerprint") or ""),
    )


def prune_endpoints_by_path_rules(
    endpoints: list[Any],
    declaration: dict[str, Any] | None,
) -> tuple[list[Any], int]:
    """Prune endpoint records/URLs outside scope-file path rules.

    ``endpoints`` may be plain URL strings or dicts with a ``url`` /
    ``endpoint`` key (the two shapes the crawler curates). Returns the kept
    list and the prune count. A declaration without path rules is a no-op so
    legacy runs keep byte-identical behaviour.
    """
    include_paths = tuple(str(p) for p in ((declaration or {}).get("include_paths") or ()))
    exclude_paths = tuple(str(p) for p in ((declaration or {}).get("exclude_paths") or ()))
    if not include_paths and not exclude_paths:
        return list(endpoints), 0

    def _url_of(item: Any) -> str:
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            return str(item.get("url") or item.get("endpoint") or "")
        return ""

    kept: list[Any] = []
    pruned = 0
    for item in endpoints:
        spec = ScopeFileSpec(
            allow_entries=(),
            include_paths=include_paths,
            exclude_paths=exclude_paths,
        )
        if evaluate_path_rules(spec, _url_of(item)) == "allowed":
            kept.append(item)
        else:
            pruned += 1
    return kept, pruned


def inferred_spec(target_url: str) -> ScopeFileSpec:
    """Cautious default scope derived from the URL alone (same exact host)."""
    try:
        parsed = urlsplit(str(target_url or ""))
    except ValueError:
        return ScopeFileSpec(allow_entries=(), source=SCOPE_SOURCE_INFERRED)
    host = (parsed.hostname or "").lower().rstrip(".")
    scheme = parsed.scheme.lower() or "https"
    entry = f"{scheme}://{host}" if host else ""
    return ScopeFileSpec(
        allow_entries=(entry,) if entry else (),
        source=SCOPE_SOURCE_INFERRED,
    )
