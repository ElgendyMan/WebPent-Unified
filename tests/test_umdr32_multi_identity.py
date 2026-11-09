"""UM-DR-32 §6 — Multi-Identity Authorization Reasoning tests.

Covers the §9.1 fixture requirements:
  * owner vs foreign user; owner vs anonymous; lower vs higher
    privilege; same-tenant vs cross-tenant boundary;
  * safe, legitimately shared object (negative control);
  * session-isolation negative control;

plus §6.5 — the privilege_differential validator route closure (the
UM-DR-31.1 missing-validator gap) and §6.6 session-contamination
prevention.
"""
from __future__ import annotations

import pytest

from webpent.production.multi_identity import (
    AuthenticationState,
    DifferentialQuestion,
    PrincipalContext,
    PrincipalObjectOperationMatrix,
    PrincipalRole,
    SessionBindingError,
    build_privilege_differential_input,
    matrix_from_observations,
    principals_from_state,
)


def _principal(ref: str, role: PrincipalRole, *, tenant: str = "t1",
               session: str | None = None) -> PrincipalContext:
    return PrincipalContext(
        principal_ref=ref, role=role, tenant=tenant,
        session_ref=session or f"session:{ref}",
        authentication_state=AuthenticationState.AUTHENTICATED,
    )


class TestPrincipalModel:
    def test_principal_context_is_pseudonymous_and_credential_free(self) -> None:
        principal = _principal("user-abc", PrincipalRole.OWNER)
        public = principal.public_dict()
        # no credential-shaped field can exist by construction, but the
        # projection is checked explicitly
        text = str(public).lower()
        for forbidden in ("password", "cookie", "token", "bearer", "api_key"):
            assert forbidden not in text
        assert public["principal_ref"] == "user-abc"
        assert public["role"] == "owner"

    def test_binding_key_is_principal_plus_session(self) -> None:
        principal = _principal("u1", PrincipalRole.OWNER, session="sess-1")
        assert principal.binding_key() == ("u1", "sess-1")

    def test_principals_from_state_identity_profiles(self) -> None:
        state = {
            "identity_profiles": {
                "User_A": {"role": "owner", "tenant": "t1"},
                "User_B": {"role": "foreign", "tenant": "t1"},
            },
        }
        principals = principals_from_state(state)
        by_ref = {p.principal_ref: p for p in principals}
        assert by_ref["User_A"].role is PrincipalRole.OWNER
        assert by_ref["User_B"].role is PrincipalRole.FOREIGN_SAME_TENANT
        # anonymous is representable without credentials
        assert any(
            p.role is PrincipalRole.ANONYMOUS for p in principals
        )
        # session refs are opaque references, distinct per principal
        assert len({p.session_ref for p in principals}) == len(principals)

    def test_principals_bounded(self) -> None:
        profiles = {f"u{i}": {"role": "foreign"} for i in range(50)}
        principals = principals_from_state(
            {"identity_profiles": profiles}, max_principals=16,
        )
        assert len(principals) <= 16


class TestPrincipalObjectOperationMatrix:
    def _matrix(self) -> PrincipalObjectOperationMatrix:
        principals = [
            _principal("owner-1", PrincipalRole.OWNER),
            _principal("foreign-1", PrincipalRole.FOREIGN_SAME_TENANT),
        ]
        observations = [
            # owner reads own object: allowed
            {"principal_ref": "owner-1", "tenant": "t1",
             "object_ref": "orders:501", "operation": "read",
             "outcome": "allowed", "evidence_refs": ["ev1"]},
            # foreign was DENIED on a blanket-restricted object (control)
            {"principal_ref": "foreign-1", "tenant": "t1",
             "object_ref": "vaults:900", "operation": "read",
             "outcome": "denied", "evidence_refs": ["ev2"]},
        ]
        return matrix_from_observations(principals, observations)

    def test_coverage_reports_principals_and_cells(self) -> None:
        matrix = self._matrix()
        coverage = matrix.coverage()
        assert coverage["principals"] == 2  # + anonymous implicit? no: matrix registers only passed principals
        assert coverage["cells"] == 2
        assert "owner_vs_foreign_same_tenant" in coverage["available_comparisons"]

    def test_unknown_principal_observations_rejected(self) -> None:
        principals = [_principal("owner-1", PrincipalRole.OWNER)]
        observations = [
            {"principal_ref": "ghost", "object_ref": "orders:1",
             "operation": "read", "outcome": "allowed"},
        ]
        matrix = matrix_from_observations(principals, observations)
        assert matrix.cells() == []  # unknown principal -> no assumptions

    def test_missing_identity_stays_unknown(self) -> None:
        matrix = self._matrix()
        cell = matrix.cells()[0]
        assert cell.object_state == "unknown"  # never fabricated

    def test_differential_question_generated_with_control(self) -> None:
        matrix = self._matrix()
        questions = matrix.differential_questions()
        assert questions, "owner-allowed read + foreign with denied control must yield a question"
        question = questions[0]
        assert question.kind == "privilege_differential"
        assert question.owner_principal == "owner-1"
        assert question.foreign_principal == "foreign-1"
        assert question.control_object_ref == "vaults:900"
        assert len(question.required_probes) == 3  # owner, foreign, control
        assert question.question_id  # deterministic uuid5

    def test_no_question_without_negative_control(self) -> None:
        # foreign principal has NO denied object: no control, abstain
        principals = [
            _principal("owner-1", PrincipalRole.OWNER),
            _principal("foreign-1", PrincipalRole.FOREIGN_SAME_TENANT),
        ]
        observations = [
            {"principal_ref": "owner-1", "object_ref": "orders:501",
             "operation": "read", "outcome": "allowed"},
            # foreign was ALLOWED on something else — not a control
            {"principal_ref": "foreign-1", "object_ref": "shared:1",
             "operation": "read", "outcome": "allowed"},
        ]
        matrix = matrix_from_observations(principals, observations)
        assert matrix.differential_questions() == []

    def test_questions_deterministic_and_deduplicated(self) -> None:
        matrix = self._matrix()
        q1 = matrix.differential_questions()
        q2 = matrix.differential_questions()
        assert [q.question_id for q in q1] == [q.question_id for q in q2]

    def test_questions_bounded(self) -> None:
        principals = [_principal("owner-1", PrincipalRole.OWNER)] + [
            _principal(f"foreign-{i}", PrincipalRole.FOREIGN_SAME_TENANT)
            for i in range(10)
        ]
        observations = [
            {"principal_ref": "owner-1", "object_ref": f"orders:{i}",
             "operation": "read", "outcome": "allowed"}
            for i in range(30)
        ] + [
            {"principal_ref": f"foreign-{i}", "object_ref": "vaults:900",
             "operation": "read", "outcome": "denied"}
            for i in range(10)
        ]
        matrix = matrix_from_observations(principals, observations)
        assert len(matrix.differential_questions(max_questions=12)) <= 12


class TestPrivilegeDifferentialValidatorRoute:
    """§6.5 — the actual route closure: the validator exists, is
    registered in BOTH registries, and the strategist no longer records
    privilege_differential as missing-validator."""

    def test_capability_registry_routes_privilege_differential(self) -> None:
        from webpent.agents.validator.registry import (
            capability_for,
            validator_id_for,
        )

        assert validator_id_for("privilege_differential") == (
            "privilege_differential"
        )
        capability = capability_for("privilege_differential")
        assert capability.status != "missing-validator"

    def test_production_validators_dispatch_reaches_the_validator(self) -> None:
        from webpent.production.validators import VALIDATORS, run_validator

        assert "PRIVILEGE_DIFFERENTIAL" in VALIDATORS
        # a real differential triple through the real dispatch
        result = run_validator(
            "PRIVILEGE_DIFFERENTIAL",
            baseline={  # owner on restricted resource R: allowed
                "status_code": 200,
                "response_body": '{"id": "501", "data": "owner-view"}',
                "headers": {},
            },
            candidate={  # lower-privilege on R: ALSO allowed -> violation
                "status_code": 200,
                "response_body": '{"id": "501", "data": "foreign-view"}',
                "headers": {},
            },
            negative_control={  # lower-privilege on C: denied
                "status_code": 403,
                "response_body": '{"error": "forbidden"}',
                "headers": {},
            },
        )
        assert result.outcome == "CONFIRMED", (
            "the registered validator must confirm the differential triple"
        )

    def test_experiment_registry_has_privilege_differential(self) -> None:
        from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY

        entry = EXPERIMENT_REGISTRY["PRIVILEGE_DIFFERENTIAL"]
        assert entry["validator"] == "PRIVILEGE_DIFFERENTIAL"
        assert entry["replay_required"] is True
        assert entry["execution_bounds"]["max_requests"] == 3

    def test_strategist_validator_route_no_longer_missing(self) -> None:
        # the exact import path the strategist's hypothesis classifier
        # uses (agents/validator/agent.py does this local import)
        from webpent.agents.validator.registry import validator_id_for

        assert validator_id_for("privilege_differential") is not None


class TestValidatorInputConstruction:
    def _question(self) -> DifferentialQuestion:
        return DifferentialQuestion(
            question_id="q-1",
            kind="privilege_differential",
            description="can foreign read owner object?",
            target_object_ref="orders:501",
            target_representation="/api/orders/501",
            owner_principal="owner-1",
            foreign_principal="foreign-1",
            control_object_ref="vaults:900",
            required_probes=("owner:read:R", "foreign:read:R", "foreign:read:C"),
            evidence_refs=["ev1"],
        )

    def test_typed_input_maps_the_triple(self) -> None:
        principals = {
            "owner-1": _principal("owner-1", PrincipalRole.OWNER),
            "foreign-1": _principal("foreign-1", PrincipalRole.FOREIGN_SAME_TENANT),
        }
        payload = build_privilege_differential_input(
            self._question(),
            owner_observation={"status_code": 200, "response_body": "owner"},
            foreign_observation={"status_code": 200, "response_body": "foreign"},
            control_observation={"status_code": 403, "response_body": "denied"},
            principal_contexts=principals,
        )
        assert payload["vulnerability_class"] == "PRIVILEGE_DIFFERENTIAL"
        assert payload["baseline"]["status_code"] == 200
        assert payload["candidate"]["status_code"] == 200
        assert payload["negative_control"]["status_code"] == 403
        # principal + tenant context preserved end-to-end
        assert payload["principal_context"]["owner"]["role"] == "owner"
        assert payload["principal_context"]["foreign"]["tenant"] == "t1"
        assert payload["object_context"]["target_object_ref"] == "orders:501"
        assert payload["object_context"]["control_object_ref"] == "vaults:900"

    def test_session_contamination_fails_safely(self) -> None:
        # owner and foreign share ONE session reference: the differential
        # would test nothing — SessionBindingError BEFORE any request
        contaminated = {
            "owner-1": _principal(
                "owner-1", PrincipalRole.OWNER, session="shared-session"),
            "foreign-1": _principal(
                "foreign-1", PrincipalRole.FOREIGN_SAME_TENANT,
                session="shared-session"),
        }
        with pytest.raises(SessionBindingError):
            build_privilege_differential_input(
                self._question(),
                owner_observation={"status_code": 200},
                foreign_observation={"status_code": 200},
                control_observation={"status_code": 403},
                principal_contexts=contaminated,
            )

    def test_no_credentials_in_payload(self) -> None:
        principals = {
            "owner-1": _principal("owner-1", PrincipalRole.OWNER),
            "foreign-1": _principal("foreign-1", PrincipalRole.FOREIGN_SAME_TENANT),
        }
        payload = build_privilege_differential_input(
            self._question(),
            owner_observation={"status_code": 200},
            foreign_observation={"status_code": 200},
            control_observation={"status_code": 403},
            principal_contexts=principals,
        )
        text = str(payload).lower()
        for forbidden in ("password", "set-cookie", "authorization:", "bearer "):
            assert forbidden not in text
