"""EGAIE controlled local fixture: deterministic offline observations.

Emits observation triples that satisfy the exact cqa_v2.causal_guard
observation contract (status_code + semantic_digest + X-* authorization
and resource headers, no _placeholder). No network: everything is
in-process and deterministic.

Positive simple case  -> candidate bypasses authorization, control enforces
                         it  => CausalGuard CONFIRMED.
Negative case         -> candidate is properly denied like its control
                         => CausalGuard CLEAN.
Multi-step positive   -> stage1 probe is intentionally inconclusive
                         (granted but no resource-owner context); only a
                         stage2 follow-up confirms.
Incomplete candidate  => BLOCKED (fail-closed, guard's own rule).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webpent.egaie.schemas import ProposedExperiment

ACTOR = "user-a"
ACTOR_ROLE = "user"
TENANT = "tenant-1"
OTHER_OWNER = "user-b"


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    family: str
    positive: bool
    multi_step: bool = False


@dataclass
class ControlledFixtureTarget:
    cases: list[FixtureCase] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_id = {case.case_id: case for case in self.cases}

    def observation_triple(
        self, case_id: str, family: str, stage: str = "stage1"
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        case = self._by_id[case_id]
        baseline = self._baseline_observation(family)
        control = self._control_observation(family)
        if case.positive:
            if case.multi_step and stage == "stage1":
                candidate = self._inconclusive_candidate(family)
            else:
                candidate = self._bypass_candidate(family)
        else:
            candidate = self._denied_candidate(family)
        return baseline, candidate, control

    def _baseline_observation(
        self, family: str
    ) -> dict[str, Any]:
        resource_type = family.lower()
        return {
            "request": {
                "method": "GET",
                "path": f"/api/{resource_type}/res-1001",
            },
            "status_code": 200,
            "semantic_digest": f"{resource_type}-res-1001-owner-view",
            "body_length": 1200,
            "headers": {
                "X-Actor-Echo": ACTOR,
                "X-Actor-Role": ACTOR_ROLE,
                "X-Actor-Tenant": TENANT,
                "X-Resource-Type": resource_type,
                "X-Resource-Id": "res-1001",
                "X-Resource-Owner": ACTOR,
                "X-Resource-Tenant": TENANT,
                "X-Privilege-Required": "owner_or_admin",
            },
        }

    def _bypass_candidate(self, family: str) -> dict[str, Any]:
        resource_type = family.lower()
        headers = {
            "X-Actor-Echo": ACTOR,
            "X-Actor-Role": ACTOR_ROLE,
            "X-Actor-Tenant": TENANT,
            "X-Resource-Type": resource_type,
            "X-Resource-Id": "res-2002",
            "X-Resource-Owner": OTHER_OWNER,
            "X-Resource-Tenant": TENANT,
            "X-Privilege-Required": "owner_or_admin",
            "X-Authorization-Outcome": "granted_full",
        }
        return {
            "request": {
                "method": "GET",
                "path": f"/api/{resource_type}/res-2002",
            },
            "status_code": 200,
            "semantic_digest": f"{resource_type}-res-2002-full-record",
            "body_length": 1800,
            "headers": headers,
        }

    def _inconclusive_candidate(self, family: str) -> dict[str, Any]:
        # Granted, but missing resource-owner/tenant context: the guard
        # cannot establish an authorization mismatch => INCONCLUSIVE.
        resource_type = family.lower()
        headers = {
            "X-Actor-Echo": ACTOR,
            "X-Actor-Role": ACTOR_ROLE,
            "X-Actor-Tenant": TENANT,
            "X-Resource-Type": resource_type,
            "X-Resource-Id": "res-2002",
            "X-Authorization-Outcome": "granted_full",
        }
        return {
            "request": {
                "method": "GET",
                "path": f"/api/{resource_type}/res-2002",
            },
            "status_code": 200,
            "semantic_digest": f"{resource_type}-res-2002-partial",
            "body_length": 900,
            "headers": headers,
        }

    def _denied_candidate(self, family: str) -> dict[str, Any]:
        resource_type = family.lower()
        headers = {
            "X-Actor-Echo": ACTOR,
            "X-Actor-Role": ACTOR_ROLE,
            "X-Actor-Tenant": TENANT,
            "X-Resource-Type": resource_type,
            "X-Resource-Id": "res-2002",
            "X-Resource-Owner": OTHER_OWNER,
            "X-Resource-Tenant": TENANT,
            "X-Privilege-Required": "owner_or_admin",
            "X-Authorization-Outcome": "denied",
        }
        return {
            "request": {
                "method": "GET",
                "path": f"/api/{resource_type}/res-2002",
            },
            "status_code": 403,
            "semantic_digest": f"{resource_type}-res-2002-denied",
            "body_length": 90,
            "headers": headers,
        }

    def _control_observation(self, family: str) -> dict[str, Any]:
        resource_type = family.lower()
        headers = {
            "X-Actor-Echo": ACTOR,
            "X-Actor-Role": ACTOR_ROLE,
            "X-Actor-Tenant": TENANT,
            "X-Resource-Type": resource_type,
            "X-Resource-Id": "res-2002",
            "X-Resource-Owner": OTHER_OWNER,
            "X-Resource-Tenant": TENANT,
            "X-Privilege-Required": "owner_or_admin",
            "X-Authorization-Outcome": "denied",
        }
        return {
            "request": {
                "method": "GET",
                "path": f"/control/api/{resource_type}/res-2002",
            },
            "status_code": 403,
            "semantic_digest": f"{resource_type}-res-2002-denied",
            "body_length": 90,
            "headers": headers,
        }


class FixtureExperimentPort:
    """Executes experiments against the controlled fixture, in process."""

    def __init__(
        self, target: ControlledFixtureTarget, scope_allowed: bool = True
    ) -> None:
        self.target = target
        self.scope_allowed = scope_allowed

    def execute(
        self, experiment: ProposedExperiment
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        case_id, stage = self._case_and_stage(experiment)
        return self.target.observation_triple(
            case_id, experiment.family, stage=stage
        )

    def _case_and_stage(
        self, experiment: ProposedExperiment
    ) -> tuple[str, str]:
        signature = experiment.signature
        if signature.endswith(":stage2"):
            stage = "stage2"
            signature = signature[: -len(":stage2")]
        else:
            stage = "stage1"
        if "/" in signature:
            signature = signature.rsplit("/", 1)[0]
        return signature, stage
