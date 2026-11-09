"""Bounded three-agent Planner -> Exploiter -> Validator hunter graph.

The graph owns advisory coordination only. Effectful execution and promotion are
injected callbacks that must delegate to WebPent's existing authorities.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, replace
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from webpent.agents.hunter_contracts import (
    BudgetState,
    ExploitationResult,
    HunterState,
    HunterStatus,
    PlannerHypothesis,
    ValidationVerdict,
    Verdict,
    digest,
    sanitize_mapping,
    sanitize_text,
)

LLMCallable = Callable[[list[dict[str, str]]], Any]
ExploitCallable = Callable[[PlannerHypothesis, dict[str, Any]], ExploitationResult]
ValidateCallable = Callable[[PlannerHypothesis, ExploitationResult, dict[str, Any]], ValidationVerdict]
_ADVISORY_CREDENTIAL_ASSIGNMENT = re.compile(
    r'"(?:authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key|access[-_]?key|session)[^" ]*"\s*:\s*(?:"[^"\\]*(?:\\.[^"\\]*)*"|[^,}\]]+)',
    re.IGNORECASE,
)


class HunterGraphState(TypedDict, total=False):
    hunter: HunterState
    current_hypothesis: dict[str, Any]
    last_exploitation: dict[str, Any]
    last_validation: dict[str, Any]
    transition: str
    error: str
    replan_feedback: dict[str, Any]


def _message_content(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "".join(str(part.get("text", part)) if isinstance(part, dict) else str(part) for part in content)
    return str(content or "")


def _advisory_json(value: Any, *, limit: int) -> str:
    """Serialize structural advisory context without credential assignments.

    Concrete request specifications stay in the deterministic candidate catalog
    and are restored only after an advisory selects that catalog item.  This
    defensive scrub also covers target-derived query/body representations that
    may survive earlier structural projections.
    """
    text = json.dumps(value, sort_keys=True, default=str)
    return _ADVISORY_CREDENTIAL_ASSIGNMENT.sub('"credential_material_omitted": true', text)[:limit]


def _json_object(response: Any) -> dict[str, Any]:
    text = _message_content(response).strip()
    start = text.find("{")
    if start < 0:
        raise ValueError("llm_output_missing_json_object")
    decoder = json.JSONDecoder()
    value, _end = decoder.raw_decode(text[start:])
    if not isinstance(value, dict):
        raise ValueError("llm_output_not_object")
    return value


def _hypothesis_from_dict(value: dict[str, Any], *, persona: str, index: int) -> PlannerHypothesis:
    required = ("hypothesis", "target_endpoint", "attack_type", "priority", "reasoning", "expected_behavior")
    if any(not str(value.get(key, "")).strip() for key in required):
        raise ValueError("planner_hypothesis_missing_required_field")
    endpoint = str(value["target_endpoint"]).strip()
    if endpoint.upper().split(" ", 1)[0] in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} and " " in endpoint:
        endpoint = endpoint.split(" ", 1)[1].strip()
    if not endpoint.startswith(("/", "http://", "https://")):
        raise ValueError("planner_endpoint_out_of_shape")
    priority = max(0, min(100, int(value["priority"])))
    raw_requests = value.get("requests") if isinstance(value.get("requests"), dict) else {}
    requests = {
        str(role): dict(spec)
        for role, spec in list(raw_requests.items())[:3]
        if str(role) in {"baseline", "candidate", "negative_control"} and isinstance(spec, dict)
    }
    return PlannerHypothesis(
        hypothesis_id=str(value.get("hypothesis_id") or f"hunter_h_{index:03d}_{digest(value)[:12]}"),
        hypothesis=str(value["hypothesis"]),
        target_endpoint=endpoint,
        attack_type=str(value["attack_type"]).upper(),
        priority=priority,
        reasoning=str(value["reasoning"]),
        expected_behavior=str(value["expected_behavior"]),
        persona=persona,
        wstg_reference=str(value.get("wstg_reference"))[:64] if value.get("wstg_reference") else None,
        payload_id=str(value.get("payload_id"))[:80] if value.get("payload_id") else None,
        attempt=int(value.get("attempt", 0) or 0),
        method=str(value.get("method") or "GET").upper()[:12],
        parameter_to_change=str(value.get("parameter_to_change"))[:128] if value.get("parameter_to_change") else None,
        owner_value=str(value.get("owner_value"))[:160] if value.get("owner_value") is not None else None,
        foreign_value=str(value.get("foreign_value"))[:160] if value.get("foreign_value") is not None else None,
        expected_success=str(value.get("expected_success") or value.get("expected_behavior") or "")[:300],
        requests=requests,
    )


def _catalog_fallback_hypotheses(hunter: HunterState, *, limit: int) -> list[dict[str, Any]]:
    """Project existing governed candidates when advisory JSON is unusable.

    This is not a second discovery or execution path: every fallback item must
    already be present in the bounded catalog produced by the recon layer.
    """
    catalog = hunter.surface_data.get("candidate_catalog", []) if isinstance(hunter.surface_data, dict) else []
    result: list[dict[str, Any]] = []
    family_order = {"IDOR": 0, "BOLA": 0, "AUTH_BYPASS": 1, "INFO_DISCLOSURE": 2}
    ordered_catalog = sorted(
        [item for item in list(catalog or [])[:64] if isinstance(item, dict)],
        key=lambda item: (family_order.get(str(item.get("vulnerability_class") or "").upper(), 3), -float(item.get("priority") or 0), str(item.get("hypothesis_id") or "")),
    )
    for item in ordered_catalog:
        if not isinstance(item, dict) or not item.get("executable"):
            continue
        route = str(item.get("route") or "").strip()
        attack_type = str(item.get("vulnerability_class") or "").strip().upper()
        if not route or not attack_type:
            continue
        try:
            priority = int(float(item.get("priority", 0) or 0))
        except (TypeError, ValueError):
            priority = 0
        result.append({
            "hypothesis_id": item.get("hypothesis_id"),
            "hypothesis": f"Governed {attack_type} candidate on the observed route.",
            "target_endpoint": route,
            "attack_type": attack_type,
            "priority": priority,
            "reasoning": "Deterministic projection of an existing recon candidate; no new route or payload was invented.",
            "expected_behavior": "Validator determines whether the governed candidate produces a causal security signal.",
            "wstg_reference": item.get("wstg_reference"),
            "payload_id": item.get("payload_id"),
            "method": item.get("method", "GET"),
            "parameter_to_change": item.get("parameter"),
            "owner_value": item.get("owner_value"),
            "foreign_value": item.get("foreign_value"),
            "expected_success": item.get("expected_success") or "Validator compares owner baseline, foreign candidate, and an independent negative control.",
            "requests": item.get("requests") if isinstance(item.get("requests"), dict) else {},
        })
        if len(result) >= limit:
            break
    return result


def _is_identity_candidate(value: Any) -> bool:
    if isinstance(value, dict):
        if bool(value.get("identity_template_candidate")):
            return True
        if "{id}" in str(value.get("resource_template") or ""):
            return True
        requests = value.get("requests") if isinstance(value.get("requests"), dict) else {}
    else:
        requests = getattr(value, "requests", {}) if isinstance(getattr(value, "requests", {}), dict) else {}
    return any("{id}" in str(spec.get("target_resource") or "") for spec in requests.values() if isinstance(spec, dict))


def _planner_prompt(hunter: HunterState) -> list[dict[str, str]]:
    routes = hunter.surface_data.get("routes", []) if isinstance(hunter.surface_data, dict) else []
    browser = hunter.surface_data.get("browser_intelligence", {}) if isinstance(hunter.surface_data, dict) else {}
    route_shapes = []
    for route in list(routes)[:40]:
        if isinstance(route, dict):
            route_shapes.append({
                "route": route.get("route"), "method": route.get("method"),
                "status_code": route.get("status_code"), "content_type": route.get("content_type"),
                "parameters": [item.get("name") for item in list(route.get("parameters", []))[:12] if isinstance(item, dict)],
            })
    structural = {
        "surface_data": {
            "target_host": hunter.surface_data.get("target_host") if isinstance(hunter.surface_data, dict) else "",
            "scope_fingerprint": hunter.surface_data.get("scope_fingerprint") if isinstance(hunter.surface_data, dict) else "",
            "route_shapes": route_shapes,
            "candidate_catalog": list(hunter.surface_data.get("candidate_catalog", []))[:32] if isinstance(hunter.surface_data, dict) else [],
            "principal_availability": hunter.surface_data.get("principal_availability", {}) if isinstance(hunter.surface_data, dict) else {},
            "authentication": hunter.surface_data.get("authentication", {}) if isinstance(hunter.surface_data, dict) else {},
            "persona_profile": hunter.surface_data.get("persona_profile", {}) if isinstance(hunter.surface_data, dict) else {},
        },
        "browser_intelligence": {"state_graph_stats": dict(browser.get("state_graph_stats", {})) if isinstance(browser, dict) else {}, "api_endpoints": list(browser.get("api_endpoints", []))[:100] if isinstance(browser, dict) else [], "js_endpoints": list(browser.get("js_endpoints", []))[:100] if isinstance(browser, dict) else [], "hidden_routes": list(browser.get("hidden_routes", []))[:50] if isinstance(browser, dict) else [], "tech_stack": list(browser.get("tech_stack", []))[:30] if isinstance(browser, dict) else [], "traffic_stats": dict(browser.get("traffic_stats", {})) if isinstance(browser, dict) else {}},
        "tech_stack": hunter.tech_stack,
        "curiosity_flags": [flag.to_dict() for flag in hunter.curiosity_flags[:32]],
        "notes": hunter.notes[-20:],
        "persona": hunter.persona,
        "budget": hunter.budget.to_dict(),
        "previous_verdicts": [item.to_dict() for item in hunter.validation_verdicts[-20:]],
    }
    system = (
        "You are the Planner agent in a bounded authorized web-security hunt. "
        "Use only structural data below. Never request secrets, raw bodies, cookies, headers, or scope expansion. "
        "Return JSON only with exactly one top-level key hypotheses. The value is an array of at most 5 objects. "
        "Each object must contain hypothesis, target_endpoint, attack_type, priority, reasoning, expected_behavior, method, "
        "parameter_to_change, owner_value, foreign_value, expected_success, and requests. The requests object must contain "
        "baseline, candidate, and negative_control concrete method/path specs copied from the candidate catalog; for IDOR/BOLA "
        "baseline uses owner, candidate uses foreign on the owner resource, and negative_control uses an invalid resource. "
        "Optional keys are hypothesis_id,wstg_reference,payload_id. Keep every string under 240 characters. "
        "Choose only from the candidate catalog routes/families. Follow the selected persona's focus and preferred families when ranking candidates, but never bypass the existing governed M4/AVI path."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": _advisory_json(structural, limit=14000)}]


def _replan_prompt(hypothesis: PlannerHypothesis, feedback: dict[str, Any], hunter: HunterState) -> list[dict[str, str]]:
    """Create a feedback-only prompt for a bounded, catalog-constrained replan."""
    verdict_value = str(feedback.get("verdict") or "inconclusive")
    payload = {
        "hypothesis_id": hypothesis.hypothesis_id,
        "attempt": hypothesis.attempt,
        "verdict": verdict_value,
        "reason": sanitize_text(str(feedback.get("reason") or ""), 300) or "inconclusive",
        "status_category": str(feedback.get("status_category") or verdict_value),
        "candidate_catalog": list(hunter.surface_data.get("candidate_catalog", []))[:32] if isinstance(hunter.surface_data, dict) else [],
    }
    return [
        {"role": "system", "content": "You are a bounded replan advisor. Use only the existing governed candidate catalog. Return JSON with optional hypothesis_id, target_endpoint, attack_type, reasoning, expected_behavior. Never invent routes, payloads, identities, secrets, raw responses, or scope expansion."},
        {"role": "user", "content": _advisory_json(payload, limit=7000)},
    ]


def _record_event(hunter: HunterState, node: str, detail: Any) -> None:
    hunter.graph_events.append({
        "node": node,
        "at_monotonic": round(time.monotonic(), 6),
        "detail_digest": digest(detail),
        "status": hunter.status.value,
    })
    del hunter.graph_events[:-200]


def build_hunter_graph(
    *,
    llm: LLMCallable | None = None,
    planner_llm: LLMCallable | None = None,
    exploiter_llm: LLMCallable | None = None,
    validator_llm: LLMCallable | None = None,
    exploiter: ExploitCallable | None = None,
    validator: ValidateCallable | None = None,
    max_hypotheses_per_plan: int = 5,
):
    """Compile the bounded graph; callbacks are the only effectful seams."""
    planner_llm = planner_llm or llm
    exploiter_llm = exploiter_llm or llm
    validator_llm = validator_llm or llm
    if int(max_hypotheses_per_plan) < 1:
        raise ValueError("max_hypotheses_per_plan must be positive")

    def planner_node(state: HunterGraphState) -> dict[str, Any]:
        hunter = state["hunter"]
        if hunter.budget.halted or not hunter.budget.can_continue():
            hunter.status = HunterStatus.HALTED
            _record_event(hunter, "planner", {"reason": "budget_or_halt"})
            return {"hunter": hunter, "transition": "halt"}
        if planner_llm is None:
            raw = state.get("candidate_hypotheses") or hunter.surface_data.get("candidate_hypotheses") or []
            suggestions = {"hypotheses": list(raw)[:max_hypotheses_per_plan]}
        else:
            try:
                response = planner_llm(_planner_prompt(hunter))
                suggestions = _json_object(response)
            except Exception as exc:
                # Advisory failure is not an execution authority failure. Use
                # only the already-built bounded catalog; never invent a route
                # or bypass M4/AVI because a provider response was unusable.
                suggestions = {"hypotheses": []}
                _record_event(hunter, "planner_advisory_failed", {"error_class": type(exc).__name__, "fallback": "existing_candidate_catalog"})
        values = suggestions.get("hypotheses")
        if not isinstance(values, list):
            values = []
            _record_event(hunter, "planner_output_invalid", {"fallback": "existing_candidate_catalog"})
        generated: list[PlannerHypothesis] = []
        rejected = 0
        for index, item in enumerate(values[:max_hypotheses_per_plan]):
            if isinstance(item, dict):
                try:
                    generated.append(_hypothesis_from_dict(item, persona=hunter.persona, index=index))
                except (TypeError, ValueError, KeyError):
                    rejected += 1
        if not generated:
            fallback = _catalog_fallback_hypotheses(hunter, limit=max_hypotheses_per_plan)
            for index, item in enumerate(fallback):
                try:
                    generated.append(_hypothesis_from_dict(item, persona=hunter.persona, index=index))
                except (TypeError, ValueError, KeyError):
                    rejected += 1
            if generated:
                _record_event(hunter, "planner_fallback", {"count": len(generated), "source": "existing_candidate_catalog"})
        principal_availability = hunter.surface_data.get("principal_availability", {}) if isinstance(hunter.surface_data, dict) else {}
        if int(principal_availability.get("successful_count", 0) or 0) >= 2:
            identity_catalog = [
                item for item in list(hunter.surface_data.get("candidate_catalog", []) or [])
                if isinstance(item, dict) and item.get("executable") and _is_identity_candidate(item)
            ]
            existing_ids = {item.hypothesis_id for item in generated}
            added_identity = 0
            for item in identity_catalog[:2]:
                item_id = str(item.get("hypothesis_id") or "")
                if not item_id or item_id in existing_ids:
                    continue
                try:
                    generated.append(_hypothesis_from_dict(_catalog_fallback_hypotheses(HunterState(surface_data={"candidate_catalog": [item]}), limit=1)[0], persona=hunter.persona, index=len(generated)))
                    existing_ids.add(item_id)
                    added_identity += 1
                except (TypeError, ValueError, KeyError, IndexError):
                    rejected += 1
            if added_identity:
                _record_event(hunter, "planner_identity_catalog_guard", {"count": added_identity, "reason": "real_identity_id_candidate_present"})
            access_families = {"IDOR", "BOLA"}
            if not any(item.attack_type.upper() in access_families for item in generated):
                for index, item in enumerate(_catalog_fallback_hypotheses(hunter, limit=max_hypotheses_per_plan)):
                    if str(item.get("attack_type", "")).upper() not in access_families:
                        continue
                    try:
                        generated.append(_hypothesis_from_dict(item, persona=hunter.persona, index=index + len(generated)))
                    except (TypeError, ValueError, KeyError):
                        rejected += 1
                    if any(candidate.attack_type.upper() in access_families for candidate in generated):
                        break
                if any(item.attack_type.upper() in access_families for item in generated):
                    _record_event(hunter, "planner_catalog_guard", {"reason": "two_principal_access_control_candidate_present"})
        persona_profile = hunter.surface_data.get("persona_profile", {}) if isinstance(hunter.surface_data, dict) else {}
        preferred = {
            str(value).upper().replace("-", "_")
            for value in (persona_profile.get("preferred_families", []) if isinstance(persona_profile, dict) else [])
        }
        generated.sort(key=lambda item: (
            0 if item.attack_type.upper().replace("-", "_") in preferred else 1,
            0 if _is_identity_candidate(item) else 1,
            0 if item.attack_type.upper() in {"IDOR", "BOLA"} else 1,
            -item.priority,
            item.hypothesis_id,
        ))
        hunter.hypotheses.extend(generated)
        hunter.current_hypothesis_index = 0
        hunter.status = HunterStatus.PLANNED
        _record_event(hunter, "planner", {"hypotheses": [item.hypothesis_id for item in generated], "rejected_schema_items": rejected})
        if not generated:
            hunter.status = HunterStatus.COMPLETED
            return {"hunter": hunter, "transition": "complete"}
        return {"hunter": hunter, "current_hypothesis": generated[0].to_dict(), "transition": "exploit"}

    def exploiter_node(state: HunterGraphState) -> dict[str, Any]:
        hunter = state["hunter"]
        current = state.get("current_hypothesis")
        if not current:
            hunter.status = HunterStatus.COMPLETED
            return {"hunter": hunter, "transition": "complete"}
        hypothesis = _hypothesis_from_dict(current, persona=hunter.persona, index=hunter.current_hypothesis_index)
        hunter.status = HunterStatus.EXPLOITING
        _record_event(hunter, "exploiter", {"hypothesis_id": hypothesis.hypothesis_id})
        advisory_ok = True
        if exploiter_llm is not None:
            try:
                advisory = _json_object(exploiter_llm([
                    {"role": "system", "content": "You are the Exploiter advisory agent. Return JSON only with execute:boolean, request_intent:string, control_plan:string. Never request secrets or scope expansion. Actual execution is delegated to a governed callback."},
                    {"role": "user", "content": _advisory_json({"hypothesis": hypothesis.to_dict(), "surface": hunter.surface_data, "validator_feedback": state.get("replan_feedback", {})}, limit=12000)},
                ]))
                advisory_ok = bool(advisory.get("execute")) and bool(str(advisory.get("request_intent", "")).strip())
                _record_event(hunter, "exploiter_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "accepted": advisory_ok, "plan_digest": digest(advisory)})
            except Exception as exc:
                advisory_ok = False
                hunter.budget = replace(hunter.budget, halted=True)
                _record_event(hunter, "exploiter_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "accepted": False, "reason": type(exc).__name__})
        if exploiter is None or not advisory_ok:
            result = ExploitationResult(
                hypothesis_id=hypothesis.hypothesis_id, status=HunterStatus.HALTED,
                request_executed=False, response_received=False,
                error="no_governed_exploiter_callback" if exploiter is None else "exploiter_advisory_rejected",
            )
        else:
            result = exploiter(hypothesis, hunter.to_dict())
        hunter.exploitation_results.append(result)
        hunter.status = HunterStatus.VALIDATING
        _record_event(hunter, "exploiter_complete", result.to_dict())
        return {"hunter": hunter, "last_exploitation": result.to_dict(), "transition": "validate"}

    def validator_node(state: HunterGraphState) -> dict[str, Any]:
        hunter = state["hunter"]
        current = state.get("current_hypothesis") or {}
        hypothesis = _hypothesis_from_dict(current, persona=hunter.persona, index=hunter.current_hypothesis_index)
        exploitation = hunter.exploitation_results[-1] if hunter.exploitation_results else ExploitationResult(
            hypothesis_id=hypothesis.hypothesis_id, status=HunterStatus.HALTED,
            request_executed=False, response_received=False, error="missing_exploitation_result",
        )
        if validator_llm is not None and exploitation.status is not HunterStatus.HALTED:
            try:
                reflection = _json_object(validator_llm([
                    {"role": "system", "content": "You are the Validator advisory agent. Return JSON only with concern:string and requested_checks:list. Do not set the final verdict; deterministic validators and replay are authoritative."},
                    {"role": "user", "content": _advisory_json({"hypothesis": hypothesis.to_dict(), "exploitation": exploitation.to_dict()}, limit=10000)},
                ]))
                _record_event(hunter, "validator_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "reflection_digest": digest(reflection)})
            except Exception as exc:
                hunter.budget = replace(hunter.budget, halted=True)
                _record_event(hunter, "validator_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "reason": type(exc).__name__})
        if validator is None:
            verdict = ValidationVerdict(
                hypothesis_id=hypothesis.hypothesis_id, verdict=Verdict.INCONCLUSIVE,
                confidence=0.0, reason="no_deterministic_validator_callback",
            )
        else:
            verdict = validator(hypothesis, exploitation, hunter.to_dict())
        hunter.validation_verdicts.append(verdict)
        hunter.status = {
            Verdict.CONFIRMED: HunterStatus.CONFIRMED,
            Verdict.REFUTED: HunterStatus.REFUTED,
            Verdict.BLOCKED: HunterStatus.BLOCKED,
            Verdict.INCONCLUSIVE: HunterStatus.INCONCLUSIVE,
        }[verdict.verdict]
        if verdict.verdict is Verdict.CONFIRMED and verdict.proof_bundle_ref:
            hunter.confirmed_findings.append({"hypothesis_id": hypothesis.hypothesis_id, "proof_bundle_ref": verdict.proof_bundle_ref, "replay_verified": verdict.replay_verified})
        _record_event(hunter, "validator", verdict.to_dict())
        if hunter.budget.halted:
            hunter.status = HunterStatus.HALTED
            _record_event(hunter, "validator", {"reason": "budget_halted", "hypothesis_id": hypothesis.hypothesis_id})
            return {"hunter": hunter, "last_validation": verdict.to_dict(), "transition": "halt"}
        if verdict.verdict is Verdict.INCONCLUSIVE and hypothesis.attempt < hunter.budget.max_replans_per_hypothesis and hunter.budget.can_continue():
            return {
                "hunter": hunter,
                "current_hypothesis": asdict(hypothesis),
                "last_validation": verdict.to_dict(),
                "replan_feedback": {
                    "verdict": verdict.verdict.value,
                    "reason": sanitize_text(verdict.reason, 300),
                    "status_category": "inconclusive",
                    "attempt": hypothesis.attempt,
                },
                "transition": "replan",
            }
        # r6c (Gap 3): a FIRST-attempt REFUTED routes to the replan node once
        # (the graph event projects the production-trace stage); a refuted
        # hypothesis that already consumed its swap (attempt >= 1) advances
        # and never loops back.
        if verdict.verdict is Verdict.REFUTED and hypothesis.attempt < 1 and hunter.budget.can_continue():
            return {
                "hunter": hunter,
                "current_hypothesis": asdict(hypothesis),
                "last_validation": verdict.to_dict(),
                "replan_feedback": {
                    "verdict": verdict.verdict.value,
                    "reason": sanitize_text(verdict.reason, 300),
                    "status_category": "refuted",
                    "attempt": hypothesis.attempt,
                },
                "transition": "replan",
            }
        hunter.current_hypothesis_index += 1
        if hunter.current_hypothesis_index < len(hunter.hypotheses) and hunter.budget.can_continue():
            next_hypothesis = hunter.hypotheses[hunter.current_hypothesis_index]
            return {"hunter": hunter, "current_hypothesis": next_hypothesis.to_dict(), "last_validation": verdict.to_dict(), "transition": "exploit"}
        hunter.status = HunterStatus.COMPLETED
        return {"hunter": hunter, "last_validation": verdict.to_dict(), "transition": "complete"}

    def replan_node(state: HunterGraphState) -> dict[str, Any]:
        hunter = state["hunter"]
        current = state.get("current_hypothesis") or {}
        hypothesis = _hypothesis_from_dict(current, persona=hunter.persona, index=hunter.current_hypothesis_index)
        feedback = dict(state.get("replan_feedback") or {})
        next_hypothesis = asdict(hypothesis)
        next_hypothesis["attempt"] = hypothesis.attempt + 1
        accepted_advisory = False
        swapped = False
        if planner_llm is not None and hunter.budget.can_continue():
            try:
                advisory = _json_object(planner_llm(_replan_prompt(hypothesis, feedback, hunter)))
                catalog = list(hunter.surface_data.get("candidate_catalog", [])) if isinstance(hunter.surface_data, dict) else []
                proposed_id = str(advisory.get("hypothesis_id") or "")
                proposed = (str(advisory.get("target_endpoint") or hypothesis.target_endpoint), str(advisory.get("attack_type") or hypothesis.attack_type).upper())
                selected_catalog = next((item for item in catalog
                                         if isinstance(item, dict) and proposed_id
                                         and str(item.get("hypothesis_id")) == proposed_id), None)
                if selected_catalog is None:
                    selected_catalog = next((item for item in catalog
                                             if isinstance(item, dict)
                                             and (str(item.get("route")), str(item.get("vulnerability_class", "")).upper()) == proposed), None)
                if selected_catalog is not None and selected_catalog.get("executable"):
                    selected_id = str(selected_catalog.get("hypothesis_id") or "")
                    selected_route = str(selected_catalog.get("route") or "")
                    selected_family = str(selected_catalog.get("vulnerability_class") or "").upper()
                    # r6c same-item guard: an advisory that re-selects the
                    # JUST-REFUTED item (by id, or by its degenerate own
                    # route+family) is a NO-OP — the refuted hypothesis is
                    # retired, never re-exploited.
                    same_item = (
                        (selected_id and selected_id == hypothesis.hypothesis_id)
                        or (selected_route == hypothesis.target_endpoint
                            and selected_family == str(hypothesis.attack_type).upper())
                    )
                    if not same_item:
                        next_hypothesis.update({
                            "hypothesis_id": selected_id or hypothesis.hypothesis_id,
                            "target_endpoint": selected_route or proposed[0],
                            "attack_type": selected_family or proposed[1],
                            "method": str(selected_catalog.get("method") or hypothesis.method).upper(),
                            "parameter_to_change": selected_catalog.get("parameter") or hypothesis.parameter_to_change,
                            "owner_value": (selected_catalog.get("metadata") or {}).get("owner_value") or hypothesis.owner_value,
                            "foreign_value": (selected_catalog.get("metadata") or {}).get("foreign_value") or hypothesis.foreign_value,
                            "expected_success": (selected_catalog.get("metadata") or {}).get("expected_success") or hypothesis.expected_success,
                            "requests": dict(selected_catalog.get("requests") or {}),
                            "reasoning": sanitize_text(advisory.get("reasoning") or hypothesis.reasoning),
                            "expected_behavior": sanitize_text(advisory.get("expected_behavior") or hypothesis.expected_behavior),
                            "attempt": hypothesis.attempt + 1,
                        })
                        accepted_advisory = True
                        swapped = True
                _record_event(hunter, "replan_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "accepted": accepted_advisory, "proposal_digest": digest(advisory)})
            except Exception as exc:
                _record_event(hunter, "replan_advisory", {"hypothesis_id": hypothesis.hypothesis_id, "accepted": False, "reason": type(exc).__name__})
        if swapped:
            # The swap consumed this ladder slot: the swapped item occupies
            # the next position, so the post-refutation advance must move
            # PAST it — otherwise the ladder re-exploits the same item.
            hunter.current_hypothesis_index += 1
            _record_event(hunter, "replan", {
                "hypothesis_id": hypothesis.hypothesis_id,
                "attempt": next_hypothesis["attempt"],
                "feedback": feedback,
                "adjustment": "existing_catalog_only",
                "advisory_accepted": True,
            })
            return {"hunter": hunter, "current_hypothesis": next_hypothesis, "replan_feedback": feedback, "transition": "exploit"}
        if str(feedback.get("verdict") or "").lower() == "refuted":
            # r6c no-op replan: retire-and-advance — the refuted hypothesis is
            # NOT re-exploited; the ladder moves to the next catalog hypothesis.
            _record_event(hunter, "replan", {
                "hypothesis_id": hypothesis.hypothesis_id,
                "attempt": hypothesis.attempt,
                "feedback": feedback,
                "adjustment": "retire_and_advance",
                "advisory_accepted": False,
            })
            hunter.current_hypothesis_index += 1
            if hunter.current_hypothesis_index < len(hunter.hypotheses) and hunter.budget.can_continue():
                advance_hypothesis = hunter.hypotheses[hunter.current_hypothesis_index]
                return {"hunter": hunter, "current_hypothesis": advance_hypothesis.to_dict(), "replan_feedback": feedback, "transition": "exploit"}
            hunter.status = HunterStatus.COMPLETED
            return {"hunter": hunter, "replan_feedback": feedback, "transition": "complete"}
        # Inconclusive retry (legacy semantics byte-unchanged): re-exploit the
        # SAME hypothesis at attempt+1.
        _record_event(hunter, "replan", {
            "hypothesis_id": hypothesis.hypothesis_id,
            "attempt": next_hypothesis["attempt"],
            "feedback": feedback,
            "adjustment": "existing_catalog_only",
            "advisory_accepted": False,
        })
        return {"hunter": hunter, "current_hypothesis": next_hypothesis, "replan_feedback": feedback, "transition": "exploit"}

    def route_after_planner(state: HunterGraphState) -> str:
        return state.get("transition", "halt")

    def route_after_exploiter(state: HunterGraphState) -> str:
        return state.get("transition", "validate")

    def route_after_validator(state: HunterGraphState) -> str:
        return state.get("transition", "complete")

    graph = StateGraph(HunterGraphState)
    graph.add_node("planner", planner_node)
    graph.add_node("exploiter", exploiter_node)
    graph.add_node("validator", validator_node)
    graph.add_node("replan", replan_node)
    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", route_after_planner, {"exploit": "exploiter", "complete": END, "halt": END})
    graph.add_conditional_edges("exploiter", route_after_exploiter, {"validate": "validator", "complete": END, "halt": END})
    graph.add_conditional_edges("validator", route_after_validator, {"retry": "replan", "replan": "replan", "exploit": "exploiter", "complete": END, "halt": END})
    graph.add_conditional_edges("replan", lambda state: state.get("transition", "exploit"), {"exploit": "exploiter", "halt": END, "complete": END})
    return graph.compile()


def run_hunter_graph(
    *,
    hunter: HunterState,
    llm: LLMCallable | None = None,
    planner_llm: LLMCallable | None = None,
    exploiter_llm: LLMCallable | None = None,
    validator_llm: LLMCallable | None = None,
    exploiter: ExploitCallable | None = None,
    validator: ValidateCallable | None = None,
) -> HunterState:
    """Invoke the graph and return its sanitized mutable state."""
    compiled = build_hunter_graph(
        llm=llm, planner_llm=planner_llm, exploiter_llm=exploiter_llm,
        validator_llm=validator_llm, exploiter=exploiter, validator=validator,
    )
    result = compiled.invoke({"hunter": hunter})
    return result["hunter"]


__all__ = ["HunterGraphState", "build_hunter_graph", "run_hunter_graph"]
