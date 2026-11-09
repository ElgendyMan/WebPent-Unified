"""Structure-aware, deterministic endpoint triage.

The crawler may still use an LLM as an advisory ranker, but this module keeps
coverage decisions independent from URL-only ranking.  It extracts only
passive URL signals, never sends a request, and returns redacted metadata that
can be persisted in ``crawled_data`` for later triage and reporting.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_SIGNAL_WEIGHTS: dict[str, int] = {
    "parameterized": 8,
    "api": 7,
    "auth": 7,
    "admin": 6,
    "upload": 6,
    "graphql": 7,
    "websocket": 7,
    "callback": 5,
    "redirect": 5,
    "dynamic": 4,
    "artifact": 4,
    "file_like": 3,
    "state_like": 3,
}

_GROUPS: tuple[str, ...] = (
    "parameterized",
    "api",
    "auth",
    "admin",
    "upload",
    "graphql",
    "websocket",
    "callback",
    "redirect",
    "dynamic",
    "artifact",
    "file_like",
    "state_like",
)


@dataclass(frozen=True)
class EndpointTriage:
    """Passive, redacted endpoint metadata used for deterministic selection."""

    url: str
    score: int
    signals: tuple[str, ...]
    parameter_names: tuple[str, ...]
    path_tokens: tuple[str, ...]
    discovery_index: int

    def as_dict(self) -> dict[str, Any]:
        parsed = urlparse(self.url)
        redacted_pairs = [(name, "<redacted>") for name in self.parameter_names]
        redacted_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(redacted_pairs),
                "",
            )
        )
        return {
            "url": redacted_url,
            "score": self.score,
            "signals": list(self.signals),
            "parameter_names": list(self.parameter_names),
            "path_tokens": list(self.path_tokens),
            "discovery_index": self.discovery_index,
            "evidence_refs": ["obs://recon/structure-aware-triage"],
        }


def _normalise_endpoint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return candidate.rstrip("/")


def _tokens(parsed: Any) -> tuple[str, ...]:
    raw = [token for token in parsed.path.lower().split("/") if token]
    # Do not persist arbitrary long identifiers or file names as evidence.
    return tuple(token[:80] for token in raw[-12:])


def classify_endpoint(url: str, *, discovery_index: int = 0) -> EndpointTriage | None:
    """Classify one URL using passive, URL-structure-only signals."""
    normalised = _normalise_endpoint(url)
    if not normalised:
        return None
    parsed = urlparse(normalised)
    path = parsed.path.lower()
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    parameter_names = tuple(sorted({name[:80] for name, _ in query_pairs if name})[:50])
    tokens = _tokens(parsed)
    haystack = f"{path}?{parsed.query}".lower()
    signals: set[str] = set()

    if parameter_names:
        signals.add("parameterized")
    if any(part in path for part in ("/api", "/rest", "/v1/", "/v2/", "/json", "/rpc")):
        signals.add("api")
    if any(
        part in haystack
        for part in (
            "login",
            "signin",
            "signup",
            "register",
            "logout",
            "password",
            "reset",
            "mfa",
            "oauth",
            "authorize",
            "token",
        )
    ):
        signals.add("auth")
    if any(part in path for part in ("admin", "manage", "internal", "staff", "debug", "private")):
        signals.add("admin")
    if any(part in haystack for part in ("upload", "attachment", "import", "avatar", "file")):
        signals.add("upload")
    if "graphql" in haystack or "/gql" in path:
        signals.add("graphql")
    if parsed.scheme == "ws" or parsed.scheme == "wss" or "websocket" in haystack:
        signals.add("websocket")
    if any(
        part in haystack
        for part in ("callback", "webhook", "return_url", "redirect_uri", "next=", "url=")
    ):
        signals.add("callback")
    if any(part in haystack for part in ("redirect", "redir", "forward", "continue")):
        signals.add("redirect")
    if any(
        part in haystack
        for part in (
            "create",
            "update",
            "delete",
            "checkout",
            "order",
            "transfer",
            "change",
            "submit",
            "action",
        )
    ):
        signals.add("state_like")
    if any(
        part in path
        for part in (".git", ".env", ".bak", ".old", ".zip", ".sql", "backup", "dump", "config")
    ):
        signals.add("artifact")
    if any(
        path.endswith(ext) for ext in (".php", ".asp", ".aspx", ".jsp", ".cgi", ".do", ".action")
    ):
        signals.add("dynamic")
    if any(
        path.endswith(ext) for ext in (".json", ".xml", ".yaml", ".yml", ".csv", ".txt", ".log")
    ):
        signals.add("file_like")

    score = sum(_SIGNAL_WEIGHTS.get(signal, 0) for signal in signals)
    if not signals:
        score = 1
    return EndpointTriage(
        url=normalised,
        score=score,
        signals=tuple(sorted(signals)),
        parameter_names=parameter_names,
        path_tokens=tokens,
        discovery_index=max(0, int(discovery_index)),
    )


def build_coverage_preserving_queue(
    endpoints: list[str],
    *,
    max_items: int = 25,
) -> tuple[list[str], dict[str, Any]]:
    """Return a deterministic queue that preserves signal-family coverage.

    Selection is stable: higher-scoring representatives win, and discovery
    order breaks ties.  A URL can satisfy more than one group, but it is only
    selected once.  The returned audit contains no request bodies, cookies,
    tokens, or response data.
    """
    limit = max(1, min(int(max_items), 500))
    records: list[EndpointTriage] = []
    seen: set[str] = set()
    for index, value in enumerate(endpoints):
        record = classify_endpoint(value, discovery_index=index)
        if record is None or record.url in seen:
            continue
        seen.add(record.url)
        records.append(record)

    ordered = sorted(records, key=lambda item: (-item.score, item.discovery_index, item.url))
    selected: list[EndpointTriage] = []
    selected_urls: set[str] = set()
    covered: set[str] = set()
    by_group: dict[str, list[EndpointTriage]] = defaultdict(list)
    for record in ordered:
        for group in record.signals:
            by_group[group].append(record)

    # First pass: one representative per observed signal family.
    for group in _GROUPS:
        for record in by_group.get(group, []):
            if len(selected) >= limit:
                break
            if record.url in selected_urls:
                continue
            selected.append(record)
            selected_urls.add(record.url)
            covered.update(record.signals)
            break

    # Second pass: fill remaining budget with the strongest unseen endpoints.
    for record in ordered:
        if len(selected) >= limit:
            break
        if record.url in selected_urls:
            continue
        selected.append(record)
        selected_urls.add(record.url)
        covered.update(record.signals)

    selected.sort(key=lambda item: (item.discovery_index, item.url))
    observed_groups = {group for record in records for group in record.signals}
    gaps = sorted(observed_groups - covered)
    audit = {
        "schema_version": 1,
        "mode": "structure-aware-deterministic",
        "raw_endpoint_count": len(records),
        "selected_endpoint_count": len(selected),
        "max_items": limit,
        "observed_signal_groups": sorted(observed_groups),
        "covered_signal_groups": sorted(covered),
        "coverage_gaps": gaps,
        "endpoint_observations": [record.as_dict() for record in records[:1000]],
    }
    return [record.url for record in selected], audit


__all__ = ["EndpointTriage", "build_coverage_preserving_queue", "classify_endpoint"]
