"""webpent.shared.surface_influence_graph — attack surface dependency graph.

Project Zero-tier item 2: "a full dependency/data-flow graph for the
whole application instead of plain crawling — which parameter affects
which other endpoint, and what state transitions are possible."

Distinct from, and built ON TOP OF (not duplicating):

  * :mod:`webpent.shared.surface_evidence_graph` /
    :mod:`webpent.models.surface_graph` — the existing *passive
    observation* graph. It already models endpoints, forms, XHR
    targets, GraphQL operations etc. as nodes, but treats each as an
    opaque unit: it answers "what surface have we seen?", never
    "which PARAMETER on surface A can influence surface B?". This
    module's input is the same ``crawled_data`` shape that feeds
    :func:`build_surface_evidence_graph`, and its output is meant to
    be read alongside that graph, not instead of it.
  * :mod:`webpent.shared.attack_graph` / :mod:`webpent.attack_graph` —
    project *already-collected evidence* (confirmed findings, chained
    exploits) into a reasoning graph for exploit-chain planning. Those
    graphs answer "given what we've PROVEN, what's exploitable next?".
    This module answers an earlier question — "given what we've
    CRAWLED (no proof needed), which parameters could possibly be
    load-bearing across more than one endpoint, before we've tested
    any of them?" — the attack-surface-mapping step that should
    happen before (and feed) exploit-chain reasoning, not after it.

Deterministic, pure, no network calls, no LLM. Parameter **names**
only are ever recorded — never values — matching this codebase's
existing redaction posture (``surface_evidence_graph.py``'s
``_safe_url`` replaces every query value with ``[REDACTED]`` before a
URL is stored; this module goes one step further for its own nodes
and never stores the value side of a parameter at all, by construction
rather than by redaction-after-the-fact).

The headline capability this closes: the same parameter name observed
on two or more distinct endpoints is a candidate for cross-endpoint
influence (shared session/account state, an ID reused across a
workflow, a feature flag threaded through multiple routes) — exactly
the shape of thing that turns an isolated IDOR or stored-XSS into a
chained, second-order finding. This module surfaces those candidates
as ranked, auditable evidence; it does not itself confirm influence
(no payload is ever sent) — that confirmation is the exploit
chainer's/validator's job, downstream of this module.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

# Parameter names this common across an application (session/CSRF
# plumbing, pagination) are structurally expected to recur and carry
# near-zero signal as "interesting shared state" on their own. Kept as
# a small, explicit denylist rather than a confidence penalty so the
# ranking for everything else stays simple and auditable.
_LOW_SIGNAL_PARAM_NAMES = frozenset(
    {
        "csrf", "csrfmiddlewaretoken", "_csrf", "_token", "authenticity_token",
        "page", "limit", "offset", "per_page", "sort", "order", "lang", "locale",
        "_", "callback", "jsonp", "utm_source", "utm_medium", "utm_campaign",
    }
)

_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_\[\]\.\-]{1,120}$")


def _safe_endpoint_label(url: str, method: str) -> str:
    """Return a stable, value-free endpoint label: ``METHOD path``.

    Query string is dropped entirely (not even redacted-in-place) —
    the parameter NAMES are recorded separately as their own nodes, so
    nothing is lost, and the endpoint label itself can never leak a
    value no matter how the caller's redaction elsewhere behaves.
    """
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        path = parts.path or "/"
    except ValueError:
        path = raw.split("?", 1)[0]
    return f"{method.upper()[:12]} {path[:800]}"


def _extract_param_names(item: Mapping[str, Any]) -> set[str]:
    """Extract parameter NAMES only from one crawled-endpoint record.

    Looks at (in order): an explicit ``params``/``parameters`` list or
    dict, a ``body_params``/``form_fields`` list, and the endpoint's
    own URL query string (names only — ``parse_qsl`` on a URL that may
    carry a value is used here only to split name=value and the value
    half is discarded immediately, never stored, never hashed, never
    logged).
    """
    names: set[str] = set()

    def _add(candidate: Any) -> None:
        name = str(candidate).strip()
        if name and _PARAM_NAME_RE.match(name):
            names.add(name[:120])

    for key in ("params", "parameters", "body_params", "form_fields", "fields"):
        value = item.get(key)
        if isinstance(value, Mapping):
            for name in value:
                _add(name)
        elif isinstance(value, (list, tuple)):
            for entry in value:
                if isinstance(entry, Mapping):
                    candidate = entry.get("name") or entry.get("key")
                    if candidate:
                        _add(candidate)
                elif isinstance(entry, str):
                    _add(entry)

    url = str(item.get("url") or item.get("endpoint") or item.get("target") or "")
    if url and "?" in url:
        try:
            query = urlsplit(url).query
            for name, _value in parse_qsl(query, keep_blank_values=True):
                _add(name)
        except ValueError:
            pass

    return names


def _endpoint_identity(item: Any) -> tuple[str, str]:
    if isinstance(item, str):
        return item, "GET"
    if isinstance(item, Mapping):
        url = str(
            next(
                (item.get(k) for k in ("url", "endpoint", "route", "target") if item.get(k)),
                "",
            )
        )
        method = str(item.get("method") or "GET").upper()[:12]
        return url, method
    return "", "GET"


def _param_node_id(name: str) -> str:
    return f"param:{hashlib.sha256(name.encode('utf-8', 'ignore')).hexdigest()[:16]}"


def _endpoint_node_id(label: str) -> str:
    return f"endpoint:{hashlib.sha256(label.encode('utf-8', 'ignore')).hexdigest()[:16]}"


@dataclass
class ParameterNode:
    """One distinct parameter name, and every endpoint it was observed on."""

    param_id: str
    name: str
    endpoint_labels: list[str] = field(default_factory=list)
    low_signal: bool = False

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoint_labels)

    def as_dict(self) -> dict[str, Any]:
        return {
            "param_id": self.param_id,
            "name": self.name,
            "endpoint_count": self.endpoint_count,
            "endpoint_labels": self.endpoint_labels[:50],
            "low_signal": self.low_signal,
        }


@dataclass
class InfluenceEdge:
    """A candidate cross-endpoint influence: the same parameter name
    observed on two distinct endpoints. Never a confirmed data flow —
    confirmation requires an active validator/exploit chainer to
    actually trace the value, which this module never does.
    """

    param_name: str
    source_endpoint: str
    target_endpoint: str
    confidence: float
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "param_name": self.param_name,
            "source_endpoint": self.source_endpoint,
            "target_endpoint": self.target_endpoint,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
        }


@dataclass
class SurfaceInfluenceGraph:
    """Result of mapping parameter names to the endpoints they appear on."""

    schema_version: str = "surface-influence-graph-v1"
    endpoint_labels: list[str] = field(default_factory=list)
    parameters: list[ParameterNode] = field(default_factory=list)
    influence_edges: list[InfluenceEdge] = field(default_factory=list)

    @property
    def shared_parameters(self) -> list[ParameterNode]:
        """Parameters observed on more than one endpoint, excluding
        low-signal boilerplate names — the actual candidates for
        second-order/chained findings.
        """
        return [
            p for p in self.parameters
            if p.endpoint_count > 1 and not p.low_signal
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "endpoint_count": len(self.endpoint_labels),
            "parameter_count": len(self.parameters),
            "shared_parameter_count": len(self.shared_parameters),
            "parameters": [p.as_dict() for p in self.parameters],
            "influence_edges": [e.as_dict() for e in self.influence_edges],
        }


def build_surface_influence_graph(
    crawled_data: Mapping[str, Any] | None,
    *,
    max_endpoints: int = 500,
    max_edges: int = 1000,
) -> SurfaceInfluenceGraph:
    """Build a parameter-name-level influence graph from crawled data.

    Args:
        crawled_data: Same shape consumed by
            :func:`webpent.shared.surface_evidence_graph.build_surface_evidence_graph`
            — a mapping with an ``endpoints`` list (and the same
            ``surface_records``/``autopentestx_surface_records``/
            ``nettacker_surface_records`` keys). Note this is
            deliberately NARROWER than some other ``crawled_data``
            consumers in this codebase (e.g.
            ``agents/target_understanding/agent.py``'s
            ``_endpoint_values()``, which additionally accepts
            ``urls``/``links``/``pages``/``resources`` as alternate
            endpoint-list keys): this function matches
            ``build_surface_evidence_graph``'s key set exactly, by
            design, since it is meant to run alongside that function
            on the same input. A caller whose ``crawled_data`` only
            populates one of those broader alternate keys will see an
            empty graph here (not a crash) — normalise to
            ``endpoints`` first if so.
        max_endpoints: Bound on how many endpoint records are examined.
        max_edges: Bound on how many influence edges are returned
            (highest-confidence first).

    Returns:
        A :class:`SurfaceInfluenceGraph`. Every parameter observed on
        more than one endpoint (excluding boilerplate names like
        ``page``/``csrf_token``) produces one :class:`InfluenceEdge`
        per additional endpoint it appears on, confidence-ranked by
        how unusual/specific the parameter name is (a short, generic
        looking name like ``id`` is weaker evidence of real shared
        state than a long, specific name like
        ``pending_invoice_reference``).
    """
    data = crawled_data if isinstance(crawled_data, Mapping) else {}

    raw_endpoints: list[Any] = list(data.get("endpoints") or [])
    for key in (
        "surface_records",
        "autopentestx_surface_records",
        "nettacker_surface_records",
    ):
        value = data.get(key)
        if isinstance(value, list):
            raw_endpoints.extend(item for item in value if isinstance(item, Mapping))
        elif isinstance(value, Mapping):
            raw_endpoints.append(value)

    raw_endpoints = raw_endpoints[: max(0, max_endpoints)]

    endpoint_labels: list[str] = []
    param_to_endpoints: dict[str, list[str]] = defaultdict(list)
    seen_endpoint_ids: set[str] = set()

    for item in raw_endpoints:
        url, method = _endpoint_identity(item)
        label = _safe_endpoint_label(url, method)
        if not label:
            continue
        endpoint_id = _endpoint_node_id(label)
        if endpoint_id not in seen_endpoint_ids:
            seen_endpoint_ids.add(endpoint_id)
            endpoint_labels.append(label)

        if not isinstance(item, Mapping):
            continue
        for name in _extract_param_names(item):
            if label not in param_to_endpoints[name]:
                param_to_endpoints[name].append(label)

    parameters: list[ParameterNode] = []
    for name, labels in param_to_endpoints.items():
        parameters.append(
            ParameterNode(
                param_id=_param_node_id(name),
                name=name,
                endpoint_labels=sorted(labels),
                low_signal=name.lower() in _LOW_SIGNAL_PARAM_NAMES,
            )
        )
    parameters.sort(key=lambda p: (-p.endpoint_count, p.name))

    influence_edges: list[InfluenceEdge] = []
    for param in parameters:
        if param.low_signal or param.endpoint_count < 2:
            continue
        # Confidence signal: longer / more specific parameter names are
        # less likely to be coincidental reuse (two unrelated features
        # both happening to use a field called "id") than long,
        # application-specific names.
        specificity = min(1.0, len(param.name) / 24.0)
        base_confidence = 0.3 + (0.5 * specificity)
        labels = param.endpoint_labels
        for i in range(len(labels)):
            for j in range(i + 1, len(labels)):
                influence_edges.append(
                    InfluenceEdge(
                        param_name=param.name,
                        source_endpoint=labels[i],
                        target_endpoint=labels[j],
                        confidence=round(min(1.0, base_confidence), 2),
                        reason=(
                            f"Parameter '{param.name}' observed on both endpoints; "
                            "candidate for shared state/second-order influence "
                            "(unconfirmed — no payload sent)."
                        ),
                    )
                )

    influence_edges.sort(key=lambda e: -e.confidence)
    influence_edges = influence_edges[: max(0, max_edges)]

    return SurfaceInfluenceGraph(
        endpoint_labels=endpoint_labels,
        parameters=parameters,
        influence_edges=influence_edges,
    )


__all__ = [
    "InfluenceEdge",
    "ParameterNode",
    "SurfaceInfluenceGraph",
    "build_surface_influence_graph",
]
