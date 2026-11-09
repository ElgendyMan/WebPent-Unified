"""webpent.stateful_api.bola — M5 (Part 4 §7): BOLA/IDOR testing plans
with two authorized identities and negative controls.

Acceptance: "BOLA/IDOR with two authorized identities and negative
controls" and "causal evidence bundle for sequences".

* :func:`build_bola_plans` — for every operation that consumes an
  object identifier, emits a differential plan across TWO
  operator-supplied identities: identity A creates and accesses its own
  object (the allowed baseline), identity B attempts the cross-tenant
  access (the differential), and a NEGATIVE CONTROL pins the
  enforcement baseline (B requests a randomized non-existent id — the
  404/403 that proves an access check exists at all).
* Every plan carries the causal evidence bundle SPEC (the M6
  vocabulary: precondition / action / effect / baseline / control /
  repeatability) — the deterministic validator fills the evidence; this
  planner never fabricates responses.
* Fewer than two authorized identities ⇒ NO plans (an honest refusal,
  not a single-identity guess): the differential IS the test.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from webpent.stateful_api.contracts import ApiOperation

__all__ = ["BolaPlan", "bola_hypotheses", "build_bola_plans"]

_MAX_PLANS = 32


class BolaPlan(BaseModel):
    """One BOLA/IDOR differential plan across two authorized identities."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(min_length=3, max_length=120)
    operation_id: str
    method: str
    path: str
    object_param: str
    identity_a: str
    identity_b: str
    differential_actions: list[dict[str, Any]] = Field(default_factory=list, max_length=8)
    negative_control: dict[str, Any] = Field(default_factory=dict)
    causal_evidence_spec: dict[str, Any] = Field(default_factory=dict)
    bounded_requests: int = Field(default=0, ge=0, le=16)
    provenance: str = "stateful_api:bola_differential"

    def replay_spec(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "operation_id": self.operation_id,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
            "actions": list(self.differential_actions),
            "negative_control": dict(self.negative_control),
            "bounded_requests": self.bounded_requests,
        }


def _authorized_identities(state: Mapping[str, Any] | Any) -> list[str]:
    """Distinct operator-supplied identity roles (order-stable)."""
    profiles = (
        state.get("identity_profiles")
        if isinstance(state, Mapping)
        else getattr(state, "identity_profiles", None)
    )
    roles: list[str] = []
    if isinstance(profiles, Mapping):
        for label, profile in profiles.items():
            if not isinstance(profile, Mapping):
                continue
            role = str(profile.get("role") or label or "").strip()
            if role and role not in roles:
                roles.append(role)
    return roles


def build_bola_plans(
    operations: Iterable[ApiOperation],
    *,
    identities: Iterable[str],
    max_plans: int = _MAX_PLANS,
) -> list[BolaPlan]:
    """Build the two-identity BOLA/IDOR differential plans.

    ``identities`` must carry at least two DISTINCT operator-authorized
    roles; anything less returns [] (the differential is the test — a
    single identity cannot differential-test object-level access).
    """
    identity_list = [str(role) for role in identities if str(role).strip()]
    distinct = list(dict.fromkeys(identity_list))
    if len(distinct) < 2:
        return []

    identity_a, identity_b = distinct[0], distinct[1]
    plans: list[BolaPlan] = []
    for operation in operations:
        if not operation.path_params or len(plans) >= max_plans:
            continue
        object_param = operation.path_params[0]
        plan_id = "bola-" + hashlib.sha256(
            f"{operation.operation_id}|{identity_a}|{identity_b}".encode("utf-8")
        ).hexdigest()[:16]

        differential_actions = [
            {
                "actor": identity_a,
                "action": f"{operation.method} {operation.path} with {object_param}=<A-owned id>",
                "expectation": "allowed (A accesses its own object — the baseline)",
            },
            {
                "actor": identity_b,
                "action": f"{operation.method} {operation.path} with {object_param}=<A-owned id>",
                "expectation": "denied iff object-level authorization holds (the differential)",
            },
        ]
        negative_control = {
            "actor": identity_b,
            "action": f"{operation.method} {operation.path} with {object_param}=<randomized non-existent id>",
            "expectation": "404/403 baseline — proves an access check exists at all; "
            "a 2xx here refutes the control and the plan",
        }
        plans.append(
            BolaPlan(
                plan_id=plan_id,
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                object_param=object_param,
                identity_a=identity_a,
                identity_b=identity_b,
                differential_actions=differential_actions,
                negative_control=negative_control,
                causal_evidence_spec={
                    "precondition": f"identity A created an object; both identities authorized by the operator",
                    "action": f"identity B issues {operation.method} on A's object",
                    "effect": "response body/status differential between A-own and B-cross",
                    "baseline": "A-own access response",
                    "control": "B on randomized non-existent id (404/403)",
                    "repeatability": "replay_spec() carries the full request/identity contract",
                },
                bounded_requests=3,
            )
        )
    return plans


def bola_hypotheses(
    plans: Iterable[BolaPlan],
    *,
    target_url: str,
) -> list[Any]:
    """Project plans as advisory hypotheses (M3 research-contract fields)."""
    import uuid

    from webpent.models.hypothesis import Hypothesis, HypothesisStatus

    out: list[Any] = []
    for plan in plans:
        out.append(
            Hypothesis(
                id=uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"webpent:stateful_api:bola:{plan.plan_id}",
                ),
                target_url=target_url,
                statement=(
                    f"{plan.identity_b} may access {plan.identity_a}'s object "
                    f"via {plan.operation_id} (BOLA differential)"
                )[:500],
                status=HypothesisStatus.UNEXPLORED,
                origin_detail=f"stateful_api_bola:{plan.plan_id}",
                preconditions=[
                    f"identity:{plan.identity_a} and identity:{plan.identity_b} (operator-supplied, authorized)",
                    f"{plan.identity_a} owns an object addressable via {plan.object_param}",
                ],
                expected_behavior=(
                    f"{plan.identity_b} is DENIED {plan.method} on {plan.identity_a}'s object"
                )[:500],
                negative_control=str(plan.negative_control.get("expectation") or "")[:500],
            )
        )
    return out
