# src/webpent/agents/graphql_testing/agent.py
"""GraphQL vulnerability testing node (2026-10-25 capability batch).

Closes the loop the schema-ingestion layer opened: the project already
knows a target speaks GraphQL (``crawled_data["graphql_operations"]``
from ``shared/schema_ingestion.parse_graphql_introspection``) but no
node probed the GraphQL-specific finding families. This node runs
FOUR bounded, deterministic probes and emits TENTATIVE findings whose
evidence is shaped exactly for the canonical validators in
``production/graphql_validator.py`` (baseline / candidate /
negative_control).

Hard bounds (the testing itself must never harm the target):

  * ``_MAX_TOTAL_PROBES = 12`` requests per engagement, enforced by a
    counter every request path must pass;
  * depth probe nesting <= 8 levels, its over-limit control <= 16;
  * batch size <= 5 operations;
  * per-request timeout 8s through ``make_safe_httpx_client`` (the
    SSRF-guarded client every other agent uses) and a probe-local
    ``RequestRateGovernor`` for pacing (the engagement-level governor
    is not reachable from a flag-gated probe node yet — documented
    limitation, see the 2026-10-25 proposals file).

Gating (zero side effects by construction):

  * flag ``enable_graphql_testing`` (default False) — off means the
    node returns the state untouched without constructing a client;
  * no GraphQL evidence in ``crawled_data`` (no operations AND no
    graphql_urls) means the node is a no-op even with the flag on, so
    REST-only targets are never probed.

Findings stay TENTATIVE until a canonical validator confirms them;
nothing here routes into EXPLOITABLE_CLASSES.
"""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

from langchain_core.messages import AIMessage

from webpent.state.state import PentestState
from webpent.config.settings import get_settings
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.rate_governor import RequestRateGovernor

logger = __import__("logging").getLogger(__name__)

NODE_NAME = "graphql_testing"

_MAX_TOTAL_PROBES = 12
_MAX_BATCH_OPERATIONS = 5
_MAX_DEPTH_LEVELS = 8
_MAX_CONTROL_DEPTH_LEVELS = 16
_REQUEST_TIMEOUT_S = 8
_MAX_BODY_SNAPSHOT = 4096

_INTROSPECTION_QUERY = "{ __schema { types { name } } }"
_TYPENAME_QUERY = "{ __typename }"


def _probe_budget() -> list[int]:
    return [_MAX_TOTAL_PROBES]


def _bounded_body(text: str) -> str:
    return (text or "")[:_MAX_BODY_SNAPSHOT]


def _evidence(resp: Any, elapsed_ms: int) -> dict[str, Any]:
    return {
        "status_code": getattr(resp, "status_code", 0),
        "response_body": _bounded_body(getattr(resp, "text", "") or ""),
        "headers": dict(getattr(resp, "headers", {}) or {}),
        "elapsed_ms": elapsed_ms,
        "url": str(getattr(resp, "url", "")),
    }


def _fail_soft(probe_name: str, exc: Exception) -> None:
    logger.warning("GraphQL probe %s failed (skipped): %s", probe_name, exc)


def _derive_graphql_endpoint(state: PentestState) -> str | None:
    """Derive the GraphQL endpoint from ingested evidence, never guessed.

    Only origins already crawled by the engagement are considered. The
    endpoint itself must have been recorded by discovery
    (graphql_urls) or have ingested operations — a bare origin + guess
    is NOT enough, so REST-only targets cannot be probed by accident.
    """
    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, dict):
        return None
    ops = crawled.get("graphql_operations")
    urls = crawled.get("graphql_urls")
    has_ops = isinstance(ops, list) and bool(ops)
    if isinstance(urls, list):
        for url in urls:
            if isinstance(url, str) and url.startswith("http"):
                return url
    if has_ops:
        target = state.get("target")
        base = getattr(target, "url", "") or ""
        if base:
            parts = urlsplit(base)
            return f"{parts.scheme}://{parts.netloc}/graphql"
    return None


def _ingested_field_names(state: PentestState) -> list[str]:
    crawled = state.get("crawled_data") or {}
    ops = crawled.get("graphql_operations") if isinstance(crawled, dict) else None
    names: list[str] = []
    if isinstance(ops, list):
        for op in ops[:100]:
            if isinstance(op, dict) and isinstance(op.get("name"), str):
                names.append(op["name"])
    return names[:50]


def _near_miss(name: str) -> str:
    """Deterministic near-miss of an ingested field name (prefix x/y)."""
    if not name:
        return "xqueryxprobe"
    return f"{'x' if name[0] != 'x' else 'y'}{name}"


def _introspection_control_url(endpoint: str) -> str:
    """Non-GraphQL control path on the same origin.

    FIX (2026-10-25 critique): naive ``{endpoint}-nonexistent-probe``
    concatenation broke on endpoints with a query string, a fragment,
    or a trailing slash — the control then hit a DIFFERENT (404) route
    shape than intended.
    """
    parts = urlsplit(endpoint)
    clean_path = (parts.path or "/").rstrip("/")
    return f"{parts.scheme}://{parts.netloc}{clean_path}-nonexistent-probe"


def _nested_query(field: str, levels: int) -> str:
    inner = field
    for _ in range(max(1, levels) - 1):
        inner = f"{field} {{ {inner} }}"
    return f"{{ {inner} }}"


def _self_referential_type(state: PentestState) -> str | None:
    """First ingested field usable for nesting; None when nothing is ingested.

    FIX (2026-10-25 critique): the old ``__typename`` fallback produced
    ``{ __typename { __typename { ... } } }`` — syntactically INVALID
    GraphQL (scalars take no selection sets), so both the deep probe and
    its control were rejected for syntax, not depth, and the emitted
    "unbounded depth acceptance" evidence measured nothing. With no
    ingested field there is no honest nesting probe, so probe 4 is
    skipped entirely.
    """
    names = _ingested_field_names(state)
    for name in names:
        if name and not name.startswith("__"):
            return name
    return None


def _post(client: Any, endpoint: str, payload: Any,
          budget: list[int], governor: RequestRateGovernor,
          host: str) -> dict[str, Any] | None:
    if budget[0] <= 0:
        logger.warning("GraphQL probe budget exhausted — remaining probes skipped")
        return None
    budget[0] -= 1
    with governor.acquire(host) as permit:
        if permit.aborted:
            logger.warning("GraphQL probe aborted by governor: %s", permit.reason)
            return None
        start = time.monotonic()
        try:
            resp = client.post(endpoint, json=payload)
        except Exception as exc:  # noqa: BLE001 — network probe, fail-soft
            _fail_soft("post", exc)
            return None
        governor.record_response(host, getattr(resp, "status_code", 0))
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return _evidence(resp, elapsed_ms)


def _make_finding(
    vuln_class: VulnClass,
    title: str,
    url: str,
    evidence: dict[str, Any],
    description: str,
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.MEDIUM,
        description=description,
        tool_name=NODE_NAME,
        url=url,
        vuln_class=vuln_class,
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        evidence=evidence,
    )


def _probe_refutation_suppressed(state: PentestState, vuln_class: str) -> bool:
    """Proposal 1 (2026-10-25): delay-not-delete gate for one probe set.

    True only when ``enable_refutation_learning`` is ON and the
    refutation ledger has accumulated >= the suppression threshold of
    refuted outcomes for this (vuln class, target) pair. Fail-open by
    contract: any error means "run the probe" — suppression is a
    budget optimization and must never block detection.
    """
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_refutation_learning:
            return False
        target = state.get("target")
        url = getattr(target, "url", "") or ""
        if not url:
            return False
        from webpent.learning.refutation_ledger import (
            get_ledger,
            target_fingerprint_from_url,
        )

        return get_ledger().should_suppress(
            vuln_class=vuln_class, target_fingerprint=target_fingerprint_from_url(url)
        )
    except Exception:  # noqa: BLE001 — fail-open
        return False


def graphql_testing_node(state: PentestState) -> dict:
    """LangGraph node: bounded GraphQL vulnerability probes.

    No-op unless ``enable_graphql_testing`` is on AND discovery recorded
    GraphQL evidence for the target. Every probe is capped and
    fail-soft; findings are TENTATIVE pending canonical validation.
    """
    if not get_settings().enable_graphql_testing:
        return {
            "messages": [
                AIMessage(
                    content="GraphQL Testing: disabled (enable_graphql_testing=False) — no probes sent."
                )
            ],
            "current_phase": NODE_NAME,
        }
    endpoint = _derive_graphql_endpoint(state)
    if not endpoint:
        return {
            "messages": [
                AIMessage(
                    content="GraphQL Testing: no ingested GraphQL evidence for this target — REST-only target, zero probes sent."
                )
            ],
            "current_phase": NODE_NAME,
        }

    target = state.get("target")
    base_url = getattr(target, "url", "") or ""
    crawled = state.get("crawled_data") or {}
    public_fields = _ingested_field_names(state)
    findings: list[Finding] = list(state.get("findings") or [])
    probes_log: list[str] = []
    budget = _probe_budget()
    governor = RequestRateGovernor()
    host = urlsplit(base_url or endpoint).netloc

    try:
        with make_safe_httpx_client(timeout=_REQUEST_TIMEOUT_S) as client:
            # Probe 1 — introspection exposure (3 requests).
            # The typename baseline is SHARED by probes 1-4, so it is
            # always fetched; the Proposal 1 delay gate skips only the
            # introspection-specific requests (candidate + control).
            baseline = _post(client, endpoint, {"query": _TYPENAME_QUERY}, budget, governor, host)
            if _probe_refutation_suppressed(
                state, VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE.value
            ):
                probes_log.append("introspection:suppressed")
            else:
                candidate = _post(client, endpoint, {"query": _INTROSPECTION_QUERY}, budget, governor, host)
                negative_control = _post(
                    client, _introspection_control_url(endpoint),
                    {"query": _INTROSPECTION_QUERY}, budget, governor, host)
                if baseline and candidate and negative_control:
                    findings.append(_make_finding(
                        VulnClass.GRAPHQL_INTROSPECTION_EXPOSURE,
                        "GraphQL introspection exposure (probe)",
                        endpoint,
                        {"baseline": baseline, "candidate": candidate,
                         "negative_control": negative_control},
                        "Full GraphQL schema returned by introspection query "
                        "on a production endpoint; awaiting canonical validation.",
                    ))
                    probes_log.append("introspection")

            # Probe 2 — field-suggestion leak (3 requests).
            if public_fields:
                near_miss = _near_miss(public_fields[0])
                sug_cand = _post(
                    client, endpoint,
                    {"query": f"{{ {near_miss} }}"}, budget, governor, host)
                sug_neg = _post(
                    client, endpoint,
                    {"query": "{ zzqqxxnothingfield }"}, budget, governor, host)
                if baseline and sug_cand and sug_neg:
                    findings.append(_make_finding(
                        VulnClass.GRAPHQL_FIELD_SUGGESTION_LEAK,
                        "GraphQL field-suggestion leak (probe)",
                        endpoint,
                        {"baseline": baseline, "candidate": sug_cand,
                         "negative_control": sug_neg,
                         "public_schema_fields": public_fields},
                        "Error responses appear to suggest field names; "
                        "comparing against the ingested public schema for "
                        "undocumented leakage.",
                    ))
                    probes_log.append("field_suggestion")

            # Probe 3 — batching / rate-limit differential
            # (1 batch + 3 sequential singles = 4 requests).
            batch_payload = [
                {"query": _TYPENAME_QUERY}
                for _ in range(min(3, _MAX_BATCH_OPERATIONS))
            ]
            batch_resp = _post(client, endpoint, batch_payload, budget, governor, host)
            singles = [
                _post(client, endpoint, {"query": _TYPENAME_QUERY},
                      budget, governor, host)
                for _ in range(3)
            ]
            single_throttled = next(
                (s for s in singles if s and s.get("status_code") == 429), None)
            # FIX (2026-10-25 critique): the old "baseline or singles[0]"
            # fallback could inject a None baseline when the request
            # budget ran out — evidence the validator then failed closed
            # on, making the finding unvalidatable garbage.
            probe_baseline = baseline or next((s for s in singles if s), None)
            if batch_resp and single_throttled and probe_baseline:
                findings.append(_make_finding(
                    VulnClass.GRAPHQL_BATCHING_ABUSE,
                    "GraphQL batching bypasses rate limiting (probe)",
                    endpoint,
                    {"baseline": probe_baseline,
                     "candidate": batch_resp,
                     "negative_control": single_throttled},
                    "A batched array request executed multiple operations "
                    "while sequential individual requests were throttled; "
                    "awaiting canonical validation.",
                ))
                probes_log.append("batching")

            # Probe 4 — bounded depth differential (2 requests).
            # Skipped entirely without an ingested nestable field (see
            # _self_referential_type): an invalid-syntax probe would be
            # rejected for the wrong reason and produce meaningless
            # evidence.
            nesting_field = _self_referential_type(state)
            if nesting_field:
                deep_query = _nested_query(nesting_field, _MAX_DEPTH_LEVELS)
                control_query = _nested_query(nesting_field, _MAX_CONTROL_DEPTH_LEVELS)
                deep_resp = _post(client, endpoint, {"query": deep_query}, budget, governor, host)
                control_resp = _post(client, endpoint, {"query": control_query}, budget, governor, host)
                if baseline and deep_resp and control_resp:
                    findings.append(_make_finding(
                        VulnClass.GRAPHQL_DEPTH_COMPLEXITY_DOS,
                        "GraphQL unbounded depth acceptance (probe)",
                        endpoint,
                        {"baseline": baseline, "candidate": deep_resp,
                         "negative_control": control_resp},
                        f"A depth-{_MAX_DEPTH_LEVELS} nested query executed "
                        "while a depth-16 control was rejected; timing "
                        "differential decides confirmation.",
                    ))
                    probes_log.append("depth")
    except Exception as exc:  # noqa: BLE001 — probe session, fail-soft
        _fail_soft("session", exc)

    summary = (
        f"GraphQL Testing: {len(probes_log)} probe set(s) run "
        f"({', '.join(probes_log) or 'none'}) in ≤{_MAX_TOTAL_PROBES} requests, "
        f"{len(findings)} tentative finding(s) queued for canonical validation."
    )
    logger.info(summary)
    return {
        "messages": [AIMessage(content=summary)],
        "current_phase": NODE_NAME,
        "findings": findings,
    }


__all__ = ["graphql_testing_node", "NODE_NAME"]
