# src/webpent/graphql_testing/deep.py
"""Deep GraphQL probes (PROPOSALS_ULTIMATE_V3 §9, 2026-11-01).

Bounded, detection-only deep probes on a target's GraphQL endpoint:
API batching (one request carrying an array of operations), field
suggestion leakage ("Did you mean ...?"), depth-limit measurement,
and alias flood construction.

Honesty contracts, stated up front:
- DETECTION ONLY. Every result is evidence about the endpoint's
  configuration, never a claim of achieved harm: a batch that executed
  is a rate-limit bypass VECTOR, not a DoS; unenforced depth is a hard
  configuration gap, not an outage. The finding descriptions say so.
- NO FLOODING. Each probe issues a small, hard-capped number of
  requests: one for a batch, one per depth level (cap 8), one for a
  suggestion. Counts are asserted in tests; the module cannot emit
  more than its caps.
- Scope checking and ledger recording are MANDATORY before every send
  and fail closed (a ledger refusal means nothing is sent).
- HTTP is INJECTED (a ``send`` callable). The module owns no network
  transport; tests pass stubs.
- Flag-gated via ``enable_graphql_deep`` (default False); the batch
  and alias caps default to ``graphql_deep_max_batch`` (default 10).

Deterministic for the same stubs and settings.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

__all__ = [
    "GraphQlDeepError",
    "BatchResult",
    "SuggestionResult",
    "DepthResult",
    "build_batch_operation",
    "build_alias_flood_query",
    "build_nested_query",
    "send_batch_probe",
    "suggestion_probe",
    "depth_probe",
    "finding_payload",
    "graphql_deep_refusal",
]

_MAX_DEPTH = 8
_SLOW_SECONDS = 2.0

# ``Did you mean "email" or "emailAddress"?`` — the message span runs
# to the terminating ``?``; quoted tokens inside it are the suggestions.
_DID_YOU_MEAN = re.compile(r"Did you mean ([^?]*)\?")
_QUOTED_TOKEN = re.compile(r'"([^"\\]+)"')

BATCH_KINDS = ("batch_execution", "field_suggestion_leak", "depth_not_enforced")


class GraphQlDeepError(ValueError):
    """Raised when a probe cannot proceed within its contracts."""


@dataclass(frozen=True)
class BatchResult:
    """Outcome of one batch probe. Detection only, never harm."""

    endpoint: str
    operations: int
    responses: int
    all_executed: bool
    http_status: int = 0
    reason: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class SuggestionResult:
    """Field suggestions leaked by the server's validation errors."""

    endpoint: str
    field_guess: str
    suggestions: tuple[str, ...]
    http_status: int = 0
    reason: str = ""


@dataclass(frozen=True)
class DepthResult:
    """Outcome of the escalating depth probe."""

    endpoint: str
    depths_sent: tuple[int, ...]
    max_accepted: int
    depth_limit_enforced: bool
    slowest_seconds: float
    stopped_reason: str = ""


def graphql_deep_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_graphql_deep:
        return "graphql_deep_flag_off"
    return None


def _require_flag() -> None:
    if graphql_deep_refusal() is not None:
        raise GraphQlDeepError("graphql_deep_flag_off")


def _max_batch(cap: int | None) -> int:
    from webpent.config.settings import get_settings

    value = int(
        get_settings().graphql_deep_max_batch if cap is None else cap
    )
    if value < 1:
        raise GraphQlDeepError("graphql_deep_bad_cap")
    return value


def _gql_query(source: str) -> dict:
    return {"query": source}


def build_batch_operation(
    queries: Sequence[str], *, max_batch: int | None = None
) -> str:
    """JSON array body carrying every operation in ONE request.

    Detection vector for missing batch rejection (rate-limit bypass
    potential). Capped hard: more than ``graphql_deep_max_batch``
    (default 10) operations is refused, never truncated.
    """
    cap = _max_batch(max_batch)
    if len(queries) > cap:
        raise GraphQlDeepError("graphql_deep_batch_cap_exceeded")
    if not queries:
        raise GraphQlDeepError("graphql_deep_empty_batch")
    return json.dumps([_gql_query(q) for q in queries], separators=(",", ":"))


def build_alias_flood_query(
    field_name: str, count: int, *, max_batch: int | None = None
) -> str:
    """One operation aliasing the same field ``count`` times.

    Same detection vector as batching via aliases. Capped hard by the
    same setting.
    """
    cap = _max_batch(max_batch)
    if count > cap:
        raise GraphQlDeepError("graphql_deep_batch_cap_exceeded")
    if count < 1:
        raise GraphQlDeepError("graphql_deep_empty_batch")
    if not field_name.strip():
        raise GraphQlDeepError("graphql_deep_bad_field")
    aliases = " ".join(f"a{i}: {field_name}" for i in range(count))
    return "{" + f" {aliases} " + "}"


def build_nested_query(depth: int) -> str:
    """A nested ``__typename`` query of exactly ``depth`` levels.

    ``__typename`` is valid on every GraphQL schema, so the probe
    needs no knowledge of the target's fields and requests nothing
    sensitive.
    """
    if depth < 1 or depth > _MAX_DEPTH:
        raise GraphQlDeepError("graphql_deep_bad_depth")
    return "{" * depth + "__typename" + "}" * depth


def _checked_send(
    endpoint: str,
    body: str,
    *,
    send: Callable[[str, str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
) -> tuple[int, str]:
    """Scope-check, ledger-record, then send — each gate fail-closed."""
    if not endpoint or not endpoint.strip():
        raise GraphQlDeepError("graphql_deep_bad_endpoint")
    if scope_checker is None:
        raise GraphQlDeepError("graphql_deep_scope_checker_required")
    if ledger is None:
        raise GraphQlDeepError("graphql_deep_ledger_required")
    if not scope_checker(endpoint):
        raise GraphQlDeepError("graphql_deep_out_of_scope")
    recorded = ledger.record("POST", endpoint, flags="graphql_deep")
    if not recorded:
        raise GraphQlDeepError("graphql_deep_ledger_refused")
    return send(endpoint, body)


def send_batch_probe(
    endpoint: str,
    queries: Sequence[str],
    *,
    send: Callable[[str, str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
    max_batch: int | None = None,
) -> BatchResult:
    """ONE request carrying all operations; does the server run them all?

    A JSON-array response with one entry per operation means the batch
    executed; anything else (a single error object, a batch-rejection
    message) is an honest ``all_executed=False``.
    """
    _require_flag()
    body = build_batch_operation(queries, max_batch=max_batch)
    status, text = _checked_send(
        endpoint, body, send=send, scope_checker=scope_checker, ledger=ledger
    )
    responses = -1
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            responses = len(parsed)
    except (ValueError, TypeError):
        pass
    all_executed = responses == len(queries)
    reason = "graphql_deep_batch_executed" if all_executed else (
        "graphql_deep_batch_rejected" if responses < 0
        else "graphql_deep_batch_partial"
    )
    return BatchResult(
        endpoint=endpoint,
        operations=len(queries),
        responses=responses,
        all_executed=all_executed,
        http_status=status,
        reason=reason,
        evidence={
            "note": (
                "Detection only: one request executed the whole batch, "
                "a rate-limit bypass VECTOR. No flooding was performed "
                "and no rate limit was actually bypassed in anger."
            ),
            "body_preview": text[:200],
        },
    )


def suggestion_probe(
    endpoint: str,
    field_guess: str,
    *,
    send: Callable[[str, str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
) -> SuggestionResult:
    """Send one misspelled field; read the server's 'Did you mean' leaks.

    Validation-suggestion leakage can reveal real (including hidden or
    sensitive) field names. One request, honest empty result when the
    server leaks nothing.
    """
    _require_flag()
    if not field_guess.strip():
        raise GraphQlDeepError("graphql_deep_bad_field")
    body = "{ " + field_guess + " }"
    status, text = _checked_send(
        endpoint, body, send=send, scope_checker=scope_checker, ledger=ledger
    )
    suggestions: list[str] = []
    # JSON escapes the quotes inside error messages; unescape just
    # those before reading the suggestion tokens.
    clean = text.replace('\\"', '"')
    for span in _DID_YOU_MEAN.findall(clean):
        suggestions.extend(
            s.strip() for s in _QUOTED_TOKEN.findall(span) if s.strip()
        )
    return SuggestionResult(
        endpoint=endpoint,
        field_guess=field_guess,
        suggestions=tuple(suggestions),
        http_status=status,
        reason=(
            "graphql_deep_suggestions_leaked" if suggestions
            else "graphql_deep_no_suggestions"
        ),
    )


def depth_probe(
    endpoint: str,
    *,
    send: Callable[[str, str], tuple[int, str]],
    scope_checker: Callable[[str], bool] | None,
    ledger,
    max_depth: int | None = None,
) -> DepthResult:
    """Escalating nested queries; does the server enforce a depth limit?

    At most ``max_depth`` (default 8, hard cap 8) requests. Stops
    early on a depth-rejection error, a timeout, or a notably slow
    reply (over 2.0s) — the probe measures configuration, it never
    pushes a struggling server.
    """
    _require_flag()
    cap = _MAX_DEPTH if max_depth is None else int(max_depth)
    if cap < 1 or cap > _MAX_DEPTH:
        raise GraphQlDeepError("graphql_deep_bad_depth")

    depths: list[int] = []
    max_accepted = 0
    slowest = 0.0
    stopped = ""
    enforced = False
    for depth in range(1, cap + 1):
        body = build_nested_query(depth)
        start = time.perf_counter()
        try:
            status, text = _checked_send(
                endpoint, body, send=send,
                scope_checker=scope_checker, ledger=ledger,
            )
        except TimeoutError:
            depths.append(depth)
            stopped = "graphql_deep_stopped_timeout"
            break
        elapsed = time.perf_counter() - start
        slowest = max(slowest, elapsed)
        depths.append(depth)
        if status != 200 or "depth" in text.lower():
            enforced = True
            stopped = "graphql_deep_depth_rejected"
            break
        max_accepted = depth
        if elapsed > _SLOW_SECONDS:
            stopped = "graphql_deep_stopped_slow"
            break
    if not stopped and max_accepted == cap:
        stopped = "graphql_deep_cap_reached"
    return DepthResult(
        endpoint=endpoint,
        depths_sent=tuple(depths),
        max_accepted=max_accepted,
        depth_limit_enforced=enforced,
        slowest_seconds=slowest,
        stopped_reason=stopped,
    )


def finding_payload(kind: str, *, endpoint: str, detail: str) -> dict:
    """Report-ready finding dict. Honest severity, honest description."""
    if kind not in BATCH_KINDS:
        raise GraphQlDeepError("graphql_deep_unknown_finding_kind")
    severity = {
        "batch_execution": "medium",
        "field_suggestion_leak": "medium",
        "depth_not_enforced": "low",
    }[kind]
    vuln_class = {
        "batch_execution": "rate_limit_bypass",
        "field_suggestion_leak": "info_disclosure",
        "depth_not_enforced": "dos",
    }[kind]
    return {
        "title": kind.replace("_", " ").title(),
        "severity": severity,
        "vuln_class": vuln_class,
        "tool_name": "graphql_deep",
        "endpoint": endpoint,
        "description": detail,
        "evidence_note": (
            "Detection only: configuration evidence from a capped, "
            "ledgered probe. No flooding, no rate-limit bypass in "
            "practice, and no denial of service was performed."
        ),
    }
