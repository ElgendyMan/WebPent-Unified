# src/webpent/graph/surface_sizing.py
"""Surface-sizing node: measure the target, derive the step budget.

Ultimate plan 2026-10-27, proposal 2 (Dynamic step budget):

``settings.max_graph_steps`` was a flat 50 no matter the target — a
5-endpoint site and a 500-endpoint app got the same ceiling, which is
exactly what produced the historical ``terminated_recursion_limit``
evidence (see budget_governor's docstring). The fix is NOT to raise the
number blindly: it is to MEASURE the surface right after crawling and
derive the budget from the measurement, always clamped by
``settings.dynamic_step_budget_cap`` and the cost ceiling.

This node runs between the WAF detector and the hypothesis generator —
after crawling/scope (the surface is known) and before the exploratory
tail (the budget's consumers).

Outputs (all advisory bookkeeping — no finding authority here):

* ``state["surface_metrics"]`` — {"endpoints", "forms", "parameters",
  "graphql_operations", "surface_size"} bounded counts.
* ``state["dynamic_step_budget"]`` — the derived per-run step budget,
  computed by :func:`webpent.graph.budget_governor.compute_step_budget`
  (single source of truth for the math, unit-tested there). When the
  dynamic-budget flag is off the node writes nothing and the flat
  ceiling applies — the legacy path is byte-identical.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger(__name__)

__all__ = ["surface_sizing_node", "measure_surface"]

#: Hard caps on what we count — sizing must be cheaper than the scan
#: itself, and counts beyond these change no budget decision.
_MAX_ENDPOINTS_COUNTED = 5000
_MAX_FORMS_COUNTED = 2000
_MAX_PARAMETERS_COUNTED = 10000


def _count_parameters(endpoints: Any, forms: Any) -> int:
    total = 0
    if isinstance(endpoints, list):
        for ep in endpoints[:_MAX_ENDPOINTS_COUNTED]:
            if isinstance(ep, Mapping):
                params = ep.get("parameters") or ep.get("params") or []
                if isinstance(params, Mapping):
                    total += len(params)
                elif isinstance(params, list):
                    total += len(params)
    if isinstance(forms, list):
        for form in forms[:_MAX_FORMS_COUNTED]:
            if isinstance(form, Mapping):
                fields = form.get("fields") or form.get("inputs") or []
                if isinstance(fields, Mapping):
                    total += len(fields)
                elif isinstance(fields, list):
                    total += len(fields)
    return min(total, _MAX_PARAMETERS_COUNTED)


def measure_surface(state: Mapping[str, Any]) -> dict[str, int]:
    """Pure surface measurement from crawled_data (no I/O, bounded)."""
    crawled = state.get("crawled_data") or {}
    if not isinstance(crawled, Mapping):
        crawled = {}
    endpoints = crawled.get("curated_endpoints") or crawled.get("endpoints") or []
    endpoint_count = len(endpoints) if isinstance(endpoints, list) else 0
    endpoint_count = min(endpoint_count, _MAX_ENDPOINTS_COUNTED)
    forms = crawled.get("discovered_forms") or crawled.get("forms") or []
    form_count = len(forms) if isinstance(forms, list) else 0
    form_count = min(form_count, _MAX_FORMS_COUNTED)
    graphql_ops = crawled.get("graphql_operations") or []
    graphql_count = len(graphql_ops) if isinstance(graphql_ops, list) else 0
    parameter_count = _count_parameters(endpoints, forms)
    surface_size = endpoint_count + form_count + parameter_count
    return {
        "endpoints": endpoint_count,
        "forms": form_count,
        "parameters": parameter_count,
        "graphql_operations": graphql_count,
        "surface_size": surface_size,
    }


def surface_sizing_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Measure the surface and derive the dynamic step budget.

    Sits between waf_detector and hypothesis. Fail-open: any error in
    the (pure) math logs a warning and returns an empty dict — the run
    then continues under the flat max_graph_steps ceiling, exactly the
    pre-plan behavior.
    """
    try:
        from webpent.config.settings import get_settings

        if not bool(get_settings().enable_dynamic_step_budget):
            return {}
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return {}

    metrics = measure_surface(state)
    llm_budget = state.get("llm_budget_usd") or state.get("max_cost_usd")
    try:
        from webpent.graph.budget_governor import compute_step_budget

        budget = compute_step_budget(
            surface_size=metrics["surface_size"],
            cost_ceiling_usd=float(llm_budget) if isinstance(llm_budget, (int, float)) else None,
        )
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Dynamic step budget unavailable (flat ceiling applies): %s", exc)
        return {"surface_metrics": {**metrics, "budget_source": "flat_fallback"}}

    logger.info(
        "Surface sizing: %d endpoints + %d forms + %d parameters "
        "(surface=%d) -> dynamic step budget %d",
        metrics["endpoints"], metrics["forms"], metrics["parameters"],
        metrics["surface_size"], budget,
    )
    return {
        "surface_metrics": {**metrics, "budget_source": "dynamic"},
        "dynamic_step_budget": budget,
    }
