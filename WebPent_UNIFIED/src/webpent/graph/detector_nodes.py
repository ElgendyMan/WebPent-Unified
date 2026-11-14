# src/webpent/graph/detector_nodes.py
"""Graph nodes wrapping the Ultimate-plan deterministic detectors.

Ultimate plan 2026-10-27, proposal 7 (new vulnerability classes):

Four thin nodes that bridge the graph to the new pure detector modules
(created by this window, all deterministic — no network, no LLM):

* ``graphql_testing_node``      -> validators/graphql_validator.py
  (introspection exposure / batching abuse / field-suggestion leak /
  depth-complexity DoS analysis)
* ``cache_poisoning_node``      -> shared/cache_poisoning_detector.py
  (unkeyed-header reflection on cacheable responses + web-cache
  deception path analysis)
* ``prototype_pollution_node``  -> shared/prototype_pollution_detector.py
  (client-side merge gadgets + server-side pollution validation)
* ``oauth_misconfig_node``      -> validators/oauth_misconfig_validator.py
  (redirect_uri manipulation + state parameter validation)

Wiring contract (matches how the V7 deep-probe agents behave):

* Each node is a PASS-THROUGH when its feature flag is off or the
  target carries no relevant surface — it returns ``{}`` and the chain
  continues. Zero side effects, zero requests: the plan's "صفر أثر
  جانبي على أهداف لا تحتوي الخاصية" requirement.
* Nodes never promote findings by themselves. Their ValidationResults
  land in ``state["detector_results"]`` as JSON-safe advisory dicts
  (outcome + evidence quality + bounded signals); promotion to Finding
  stays with the existing validator/strategist authority chain, exactly
  like every other deep-probe agent.
* Evidence comes from what the campaign already captured
  (``crawled_data`` probe responses, graphql_operations, auth flow
  records). The nodes do not issue requests.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger(__name__)

__all__ = [
    "graphql_testing_node",
    "cache_poisoning_node",
    "prototype_pollution_node",
    "oauth_misconfig_node",
]

#: Belt-and-braces cap on how many detector dicts one node may append.
_MAX_RESULTS_PER_NODE = 64


def _validation_result_to_dict(result: Any) -> dict[str, Any]:
    """Project a ValidationResult into a JSON-safe advisory dict."""
    return {
        "vulnerability_class": getattr(result, "vulnerability_class", "unknown"),
        "outcome": str(getattr(getattr(result, "outcome", None), "value", "INCONCLUSIVE")),
        "evidence_quality": int(
            getattr(getattr(result, "evidence_quality", None), "value", 0)
        ),
        "discriminating_signal": str(getattr(result, "discriminating_signal", ""))[:512],
        "details": {
            key: value
            for key, value in (getattr(result, "details", None) or {}).items()
            if isinstance(value, (str, int, float, bool, type(None)))
        },
        "advisory_only": True,
        "source": "ultimate_plan_20261027",
    }


def _probe_responses_from_state(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect already-captured probe responses from crawled_data.

    Looks under the documented response-capture keys. Anything absent
    yields an empty list — the detectors then honestly return
    INCONCLUSIVE/no-signal without inventing evidence.
    """
    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        return []
    out: list[dict[str, Any]] = []
    for key in ("probe_responses", "captured_responses", "response_samples"):
        records = crawled.get(key) or []
        if isinstance(records, list):
            out.extend(r for r in records[:200] if isinstance(r, Mapping))
    return out


def graphql_testing_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Run the deterministic GraphQL validators when a GraphQL surface exists.

    Activation contract: the node is a no-op unless the campaign's
    schema ingestion reported non-empty ``graphql_operations`` — a REST
    target never pays a single cycle here (plan requirement), and no
    GraphQL probe requests are issued by this node.
    """
    try:
        from webpent.config.settings import get_settings

        if not bool(get_settings().enable_graphql_testing):
            return {}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return {}
    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        return {}
    operations = crawled.get("graphql_operations") or []
    introspection = crawled.get("graphql_introspection_payload")
    if not operations and not introspection:
        # No GraphQL surface detected — zero side effects (the plan's
        # "لا تتفعل خالص على أهداف لا تحتوي الخاصية" contract).
        return {}
    try:
        from webpent.validators.graphql_validator import analyze_graphql_surface
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("GraphQL validator unavailable: %s", exc)
        return {}

    evidence: dict[str, Any] = {}
    if isinstance(introspection, Mapping):
        evidence["introspection_payload"] = introspection
    batch_records = crawled.get("graphql_batch_records") or []
    if isinstance(batch_records, list):
        evidence["batch_records"] = batch_records[:50]
    error_responses = [
        r for r in _probe_responses_from_state(state)
        if r.get("body") and int(r.get("status") or 0) >= 400
    ]
    if error_responses:
        evidence["error_responses"] = error_responses[:50]
    depth_probe = crawled.get("graphql_depth_probe")
    if isinstance(depth_probe, Mapping):
        evidence["depth_probe"] = depth_probe

    results: list[dict[str, Any]] = []
    try:
        for validation in analyze_graphql_surface(
            operations=operations[:100] if isinstance(operations, list) else [],
            evidence=evidence,
        ):
            results.append(_validation_result_to_dict(validation))
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("GraphQL surface analysis failed (node is advisory): %s", exc)
        return {}
    if not results:
        return {}
    logger.info("GraphQL testing: %d advisory validator results", len(results))
    return {"detector_results": results[:_MAX_RESULTS_PER_NODE]}


def cache_poisoning_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic cache-poisoning / web-cache-deception analysis.

    Analyzes already-captured probe responses (no new requests — the
    detector module is pure). Reflected unkeyed headers on cacheable
    responses become CONFIRMED-grade advisory results; the deception
    path analysis appends bounded advisory observations.
    """
    try:
        from webpent.shared.cache_poisoning_detector import (
            analyze_cache_behavior,
            cache_poisoning_detection_enabled,
            detect_web_cache_deception,
        )

        if not cache_poisoning_detection_enabled():
            return {}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return {}

    responses = _probe_responses_from_state(state)
    if not responses:
        return {}
    baseline = None
    if responses:
        first = responses[0]
        baseline = {
            "status": first.get("status"),
            "headers": first.get("headers") or {},
            "body": str(first.get("body") or "")[:4096],
        }
    results: list[dict[str, Any]] = []
    try:
        analysis = analyze_cache_behavior(responses, baseline_response=baseline)
        verdict = getattr(analysis, "verdict", None)
        if verdict is not None:
            results.append(_validation_result_to_dict(verdict))
        for observation in detect_web_cache_deception(responses)[:_MAX_RESULTS_PER_NODE]:
            results.append(
                {
                    "vulnerability_class": str(observation.get("class", "web_cache_deception")),
                    "outcome": "INCONCLUSIVE",
                    "evidence_quality": 1,
                    "discriminating_signal": str(observation.get("signal", ""))[:512],
                    "details": {
                        key: value
                        for key, value in observation.items()
                        if isinstance(value, (str, int, float, bool, type(None)))
                    },
                    "advisory_only": True,
                    "source": "ultimate_plan_20261027",
                }
            )
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Cache-poisoning analysis failed (node is advisory): %s", exc)
        return {}
    if not results:
        return {}
    logger.info("Cache poisoning: %d advisory results", len(results))
    return {"detector_results": results[:_MAX_RESULTS_PER_NODE]}


def prototype_pollution_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Prototype-pollution pattern analysis over captured surfaces."""
    try:
        from webpent.shared.prototype_pollution_detector import (
            analyze_client_merge_gadgets,
            prototype_pollution_detection_enabled,
            validate_server_side_pollution,
        )

        if not prototype_pollution_detection_enabled():
            return {}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return {}

    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        return {}
    results: list[dict[str, Any]] = []
    try:
        js_samples = crawled.get("javascript_sources") or crawled.get("js_assets") or []
        if isinstance(js_samples, list):
            for observation in analyze_client_merge_gadgets(
                [s for s in js_samples[:100] if isinstance(s, Mapping)]
            )[:_MAX_RESULTS_PER_NODE]:
                results.append(
                    {
                        "vulnerability_class": "prototype_pollution",
                        "outcome": "INCONCLUSIVE",
                        "evidence_quality": 1,
                        "discriminating_signal": str(observation.get("pattern", ""))[:512],
                        "details": {
                            key: value
                            for key, value in observation.items()
                            if isinstance(value, (str, int, float, bool, type(None)))
                        },
                        "advisory_only": True,
                        "source": "ultimate_plan_20261027",
                    }
                )
        json_responses = crawled.get("json_merge_probes") or []
        if isinstance(json_responses, list) and json_responses:
            validation = validate_server_side_pollution(
                [r for r in json_responses[:50] if isinstance(r, Mapping)]
            )
            results.append(_validation_result_to_dict(validation))
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Prototype-pollution analysis failed (node is advisory): %s", exc)
        return {}
    if not results:
        return {}
    logger.info("Prototype pollution: %d advisory results", len(results))
    return {"detector_results": results[:_MAX_RESULTS_PER_NODE]}


def oauth_misconfig_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic OAuth/SSO misconfiguration checks over captured flows."""
    try:
        from webpent.validators.oauth_misconfig_validator import analyze_oauth_flow

        try:
            from webpent.config.settings import get_settings

            if not bool(get_settings().enable_oauth_misconfig_detection):
                return {}
        except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
            return {}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return {}

    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        return {}
    redirect_records = crawled.get("oauth_redirect_records") or []
    state_records = crawled.get("oauth_state_records") or []
    if not isinstance(redirect_records, list) and not isinstance(state_records, list):
        return {}
    if not redirect_records and not state_records:
        return {}
    evidence: dict[str, Any] = {}
    if isinstance(redirect_records, list):
        evidence["redirect_records"] = [
            r for r in redirect_records[:50] if isinstance(r, Mapping)
        ]
    if isinstance(state_records, list):
        evidence["state_records"] = [
            r for r in state_records[:50] if isinstance(r, Mapping)
        ]
    results: list[dict[str, Any]] = []
    try:
        for validation in analyze_oauth_flow(evidence):
            results.append(_validation_result_to_dict(validation))
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("OAuth misconfiguration analysis failed (node is advisory): %s", exc)
        return {}
    if not results:
        return {}
    logger.info("OAuth misconfiguration: %d advisory results", len(results))
    return {"detector_results": results[:_MAX_RESULTS_PER_NODE]}
