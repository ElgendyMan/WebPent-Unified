"""Offline failure-injection matrix for VIP safety contracts.

The matrix exercises state transitions and evidence contracts only. It never
starts a tool, opens a socket, or creates a Finding. A ``reviewable`` result is
still not a confirmed vulnerability; live validators and ProofBundle gates
remain authoritative.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from webpent.benchmark.waptlab_offline_validator_fixtures import (
    evaluate_waptlab_offline_fixture,
)
from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_contracts import ActiveResearchLoop


def _fixture_bundle(status: str) -> dict[str, Any]:
    base: dict[str, Any] = {
        "campaign_key": "xslt_injection",
        "probe_id": "offline:probe",
        "control_ref": "offline:control",
        "variant_ref": "offline:variant",
        "cleanup": {"status": "completed"},
        "oracle": {
            "negative_control_observed": True,
            "causal_signal": True,
            "evidence_complete": True,
        },
    }
    if status == "missing":
        base.pop("oracle")
    elif status == "blocked":
        base["cleanup"] = {"status": "blocked"}
    elif status == "inconclusive":
        base["oracle"]["negative_control_observed"] = False
    return base


def _candidate() -> CandidateAction:
    return CandidateAction(
        action_id="failure-matrix:action",
        action_class="read_only_observation",
        objective="exercise local failure boundary",
        target_ref="offline://fixture",
        capability="offline_fixture",
        required_capabilities=["offline_fixture"],
        cost=1.0,
    )


def _research_case(kind: str) -> dict[str, Any]:
    context = ResearchContext(
        session_id="failure-matrix:session",
        engagement_id="failure-matrix:engagement",
        client_id="failure-matrix:client",
        target_ref="offline://fixture",
        budget_remaining=5.0,
    )
    loop = ActiveResearchLoop(max_steps=2)
    handler: Callable[[CandidateAction], dict[str, Any]] | None
    if kind == "handler_failure":
        def handler(_: CandidateAction) -> dict[str, Any]:
            raise RuntimeError("injected-handler-failure")
    else:
        def handler(action: CandidateAction) -> dict[str, Any]:
            return {
                "observation_id": f"observation:{action.action_id}",
                "action_id": action.action_id,
                "action_fingerprint": action.fingerprint(),
                "status": "negative",
                "reason": "offline matrix observation",
            }
    result = loop.step(
        context,
        [_candidate()],
        handler=handler,
        available_capabilities={"offline_fixture"},
        target_allowed=kind != "scope_denied",
    )
    return {
        "case": kind,
        "status": result.observation.status,
        "reason": result.observation.reason,
        "scope_safe": result.observation.status == "blocked" if kind == "scope_denied" else True,
        "network_used": False,
    }


def run_failure_matrix() -> dict[str, Any]:
    """Return deterministic local failure classifications and invariants."""
    validator_cases = {
        status: evaluate_waptlab_offline_fixture(_fixture_bundle(status))
        for status in ("reviewable", "missing", "blocked", "inconclusive")
    }
    research_cases = {
        kind: _research_case(kind)
        for kind in ("scope_denied", "handler_failure", "success")
    }
    all_results = [*validator_cases.values(), *research_cases.values()]
    return {
        "mode": "offline_failure_injection",
        "network_used": any(item.get("network_used") is True for item in all_results),
        "finding_created": any(item.get("finding_created") is True for item in all_results),
        "validator_cases": validator_cases,
        "research_cases": research_cases,
        "invariants": {
            "no_network": not any(item.get("network_used") is True for item in all_results),
            "no_finding_promotion": not any(
                item.get("finding_created") is True for item in all_results
            ),
            "scope_denial_is_blocked": research_cases["scope_denied"]["status"] == "blocked",
            "handler_failure_is_infrastructure_failure": research_cases["handler_failure"]["status"]
            == "infrastructure_failure",
            "missing_evidence_is_not_confirmed": validator_cases["missing"]["disposition"]
            != "confirmed",
        },
    }


__all__ = ["run_failure_matrix"]
