# src/webpent/models/taint.py
"""webpent.models.taint

Project Zero-tier item 1 — Taint tracking across sessions.

"Track any user input from its entry point to the sink across
multiple requests and different sessions, not just within the same
request. Catches second-order SQLi and stored XSS."

The key architectural move here, following the same "record a hash,
never the value" discipline already used by ``evidence.py``'s
``evidence_refs``/``sha256_text``: a taint value is identified by a
stable fingerprint (`value_fingerprint`, a salted SHA-256 digest of
the value — salted so the fingerprint itself can't be rainbow-tabled
back to short/common injected payloads), never stored or logged in
the clear. This is what makes it safe for this to be a durable,
cross-session, cross-engagement store: nothing in it is itself
sensitive target data.

A single "flow" is the lifecycle of one tainted value:

  1. introduced at a SOURCE (a parameter name on an endpoint, at a
     point in time, in a given session),
  2. observed again, unchanged or derived, at zero or more SINKS
     (potentially much later, in a DIFFERENT session — e.g. a stored
     XSS payload submitted in session A and rendered back out to
     session B's admin viewing a dashboard).

Distinct from, and deliberately not duplicating:

  * :mod:`webpent.shared.surface_influence_graph` (item 2) — maps
    which PARAMETER NAMES recur across endpoints, as a structural,
    name-only, pre-exploitation signal. This module tracks a specific
    VALUE's propagation (by fingerprint) once it has actually been
    introduced, which is a runtime/temporal concern this engagement
    observed, not a static crawl-time structural one. The two are
    complementary: a shared parameter name from item 2 is a strong
    prior for where to look for a taint flow in item 1.
  * :mod:`webpent.memory.decision_log` / :mod:`webpent.memory.postmortem`
    — append-only audit trails of decisions/mistakes. Taint flows are
    also append-only, but they are a disposition-aggregating index
    (did this fingerprint reappear anywhere?), not a decision record.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class TaintPointKind(str, Enum):
    """Whether a taint-flow observation is where a value entered
    (SOURCE) or where it reappeared (SINK).
    """

    SOURCE = "source"
    SINK = "sink"


class TaintSinkContext(str, Enum):
    """Closed vocabulary for the context a tainted value reappeared
    in at a sink, when known. Mirrors the kind of context distinctions
    ``PostmortemCategory.CONTEXT_MISREAD`` cares about — this is what
    lets a caller tell a second-order SQLi sink from a stored-XSS sink
    without free-text parsing.
    """

    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    JSON_RESPONSE = "json_response"
    SQL_ERROR_OR_BEHAVIOR = "sql_error_or_behavior"
    HTTP_HEADER = "http_header"
    LOG_OR_ADMIN_VIEW = "log_or_admin_view"
    UNKNOWN = "unknown"


class TaintFlowPoint(BaseModel):
    """One observation of a tainted value: either its introduction
    (SOURCE) or a later reappearance (SINK).

    Attributes:
        id: Stable UUID for this observation.
        timestamp: UTC timestamp of the observation.
        kind: SOURCE or SINK.
        value_fingerprint: Salted SHA-256 hex digest of the value that
            was observed. Never the raw value itself.
        endpoint_label: A value-free endpoint label (e.g.
            ``"POST /comments"``), matching
            ``surface_influence_graph``'s ``_safe_endpoint_label``
            convention — never a full URL with a live query string.
        parameter_name: The parameter/field name the value was carried
            in, when known. Name only, never the value.
        session_id: An opaque session identifier (already-redacted by
            the caller — this model does not redact it itself, the
            same posture ``Finding.campaign_id`` takes with its own
            caller-redacted identifiers).
        sink_context: For SINK points only, the context the value
            reappeared in, when determinable.
        thread_id: Optional engagement/thread identifier.
        evidence_refs: Bounded list of evidence references (hashes),
            never raw secrets or full HTTP bodies.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    kind: TaintPointKind
    value_fingerprint: str = Field(..., min_length=8, max_length=128)
    endpoint_label: str = Field(default="", max_length=900)
    parameter_name: str | None = Field(default=None, max_length=120)
    session_id: str | None = Field(default=None, max_length=160)
    sink_context: TaintSinkContext | None = Field(default=None)
    thread_id: str | None = Field(default=None, max_length=160)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

    def to_dict_for_state(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = [
    "TaintFlowPoint",
    "TaintPointKind",
    "TaintSinkContext",
]
