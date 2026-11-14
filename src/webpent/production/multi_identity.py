"""UM-DR-32 §6 — Multi-Identity Authorization Reasoning.

Single-session reasoning is insufficient for IDOR/BOLA/BFLA and
business-logic vulnerabilities (§6.1). This module supplies:

  * an explicit, pseudonymous principal model (§6.1) — PrincipalContext
    carries identity, tenant, role, authorization level, session
    REFERENCE and authentication STATE, never raw passwords, cookies,
    API tokens or bearer credentials;
  * a controlled identity matrix over the principals the authorized
    campaign actually has (§6.2) — never assuming roles the target does
    not provide, never creating accounts or acquiring credentials;
  * an evidence-backed principal × tenant × object × operation × state
    matrix (§6.3) — unknown stays unknown;
  * controlled differential questions (§6.4) that compare actual object
    identity and state, not just status codes;
  * the typed validator-input construction for the privilege differential
    route (§6.5) — the (owner-on-R, foreign-on-R, foreign-on-C) triple
    the existing ``validate_privilege_differential`` validator consumes,
    plus the CausalGuard observation mapping;
  * session isolation contracts (§6.6) — every probe binds principal to
    its own session reference; a mismatch fails safely.

Nothing here confirms anything: results flow through the existing
validator registry and CausalGuard (cqa_v2.guarded_causal_evaluate),
the sole confirmation authority.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

__all__ = [
    "PRINCIPAL_NAMESPACE",
    "AuthenticationState",
    "DifferentialQuestion",
    "MatrixCell",
    "PrincipalContext",
    "PrincipalObjectOperationMatrix",
    "PrincipalRole",
    "SessionBindingError",
    "build_privilege_differential_input",
    "matrix_from_observations",
    "principals_from_state",
]

PRINCIPAL_NAMESPACE = uuid.UUID("7c2d1e9a-3b4f-4d5e-8f90-a1b2c3d4e5f6")


class PrincipalRole(str, Enum):
    """The controlled role vocabulary (§6.2) — only roles the campaign
    actually has principals for ever appear in the matrix."""

    OWNER = "owner"
    FOREIGN_SAME_TENANT = "foreign_same_tenant"
    FOREIGN_OTHER_TENANT = "foreign_other_tenant"
    ANONYMOUS = "anonymous"
    LOWER_PRIVILEGE = "lower_privilege"
    HIGHER_PRIVILEGE = "higher_privilege"
    OPERATOR_TEST = "operator_test"
    UNKNOWN = "unknown"


class AuthenticationState(str, Enum):
    AUTHENTICATED = "authenticated"
    ANONYMOUS = "anonymous"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class SessionBindingError(RuntimeError):
    """Raised when a probe would use the wrong principal's session —
    a session mismatch ALWAYS fails safely (§6.6)."""


@dataclass(frozen=True)
class PrincipalContext:
    """A pseudonymous principal (§6.1).

    Raw credentials never enter this record or anything derived from
    it: ``session_ref`` is an opaque REFERENCE (a key into the
    credential-isolated session store owned by the executor layer),
    never the credential itself.
    """

    principal_ref: str            # pseudonymous, stable, non-secret
    role: PrincipalRole = PrincipalRole.UNKNOWN
    tenant: str = ""              # observed tenant context, "" unknown
    authorization_level: str = "" # observed/declared level, "" unknown
    session_ref: str = ""         # opaque session store key (never a secret)
    authentication_state: AuthenticationState = AuthenticationState.UNKNOWN
    allowed_operation_context: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        """Report-safe projection — no credentials by construction."""
        return {
            "principal_ref": self.principal_ref,
            "role": self.role.value,
            "tenant": self.tenant,
            "authorization_level": self.authorization_level,
            "session_ref": self.session_ref,
            "authentication_state": self.authentication_state.value,
            "allowed_operation_context": list(self.allowed_operation_context),
            "evidence_refs": list(self.evidence_refs)[:20],
        }

    def binding_key(self) -> tuple[str, str]:
        """(principal_ref, session_ref) — the isolation invariant."""
        return (self.principal_ref, self.session_ref)


@dataclass
class MatrixCell:
    """One evidence-backed cell: principal × tenant × object × op × state."""

    principal_ref: str
    tenant: str
    object_identity_ref: str      # registry identity_id or observed ref
    operation: str                # e.g. "read", "update", "transition:submit"
    object_state: str = "unknown"
    outcome: str = "unknown"      # allowed | denied | error | unknown
    evidence_refs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal_ref": self.principal_ref,
            "tenant": self.tenant,
            "object": self.object_identity_ref,
            "operation": self.operation,
            "state": self.object_state,
            "outcome": self.outcome,
            "evidence_refs": list(self.evidence_refs)[:20],
        }


@dataclass
class DifferentialQuestion:
    """A controlled, repeatable differential comparison (§6.4).

    A question is a SIGNAL, never proof: it becomes a hypothesis that a
    validator evaluates under CausalGuard with positive and negative
    controls.
    """

    question_id: str
    kind: str                     # "privilege_differential" | "idor" | ...
    description: str
    target_object_ref: str
    target_representation: str
    owner_principal: str
    foreign_principal: str
    control_object_ref: str       # the blanket-restricted negative control
    required_probes: tuple[str, ...] = ()  # ordered probe design
    evidence_refs: list[str] = field(default_factory=list)
    baseline_object_ref: str = ""  # cross-tenant: the own-tenant positive

    def as_dict(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "kind": self.kind,
            "description": self.description,
            "target_object_ref": self.target_object_ref,
            "target_representation": self.target_representation,
            "owner_principal": self.owner_principal,
            "foreign_principal": self.foreign_principal,
            "control_object_ref": self.control_object_ref,
            "required_probes": list(self.required_probes),
            "evidence_refs": list(self.evidence_refs)[:20],
            "baseline_object_ref": self.baseline_object_ref,
        }


class PrincipalObjectOperationMatrix:
    """§6.3 — the evidence-backed principal×tenant×object×operation×state
    matrix. Missing identity information stays unknown."""

    def __init__(self, *, max_cells: int = 5000) -> None:
        self.max_cells = max_cells
        self._cells: dict[tuple, MatrixCell] = {}
        self._principals: dict[str, PrincipalContext] = {}

    def register_principal(self, principal: PrincipalContext) -> None:
        self._principals[principal.principal_ref] = principal

    def principals(self) -> list[PrincipalContext]:
        return [self._principals[k] for k in sorted(self._principals)]

    def principal(self, ref: str) -> PrincipalContext | None:
        return self._principals.get(ref)

    def record(self, cell: MatrixCell) -> None:
        key = (
            cell.principal_ref, cell.tenant, cell.object_identity_ref,
            cell.operation, cell.object_state,
        )
        if key not in self._cells and len(self._cells) >= self.max_cells:
            return
        self._cells[key] = cell

    def cells(self) -> list[MatrixCell]:
        return [self._cells[k] for k in sorted(self._cells)]

    def coverage(self) -> dict[str, Any]:
        by_principal: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for cell in self._cells.values():
            by_principal[cell.principal_ref] = (
                by_principal.get(cell.principal_ref, 0) + 1)
            by_outcome[cell.outcome] = by_outcome.get(cell.outcome, 0) + 1
        return {
            "principals": len(self._principals),
            "cells": len(self._cells),
            "cells_by_principal": dict(sorted(by_principal.items())),
            "cells_by_outcome": dict(sorted(by_outcome.items())),
            "available_comparisons": self._available_comparisons(),
        }

    def _available_comparisons(self) -> list[str]:
        """Which identity comparisons the campaign can actually run
        (§6.2: report availability honestly; never assume roles)."""
        roles = {p.role for p in self._principals.values()}
        out = []
        if PrincipalRole.OWNER in roles:
            if PrincipalRole.FOREIGN_SAME_TENANT in roles:
                out.append("owner_vs_foreign_same_tenant")
            if PrincipalRole.FOREIGN_OTHER_TENANT in roles:
                out.append("owner_vs_foreign_other_tenant")
            if PrincipalRole.ANONYMOUS in roles:
                out.append("owner_vs_anonymous")
            if PrincipalRole.LOWER_PRIVILEGE in roles:
                out.append("owner_vs_lower_privilege")
            if PrincipalRole.HIGHER_PRIVILEGE in roles:
                out.append("lower_vs_higher_privilege")
        if PrincipalRole.OPERATOR_TEST in roles:
            out.append("operator_test_pairs")
        return sorted(out)

    # -- differential question generation (§6.4/§6.5) ----------------------

    def differential_questions(
        self, *, max_questions: int = 24,
    ) -> list[DifferentialQuestion]:
        """Generate typed privilege-differential questions from evidence.

        Only from OBSERVED cells: a question exists when the matrix has
        an owner-allowed operation on an object AND a principal whose
        role makes the same operation security-relevant to compare, AND
        a usable negative-control object (an object the comparing
        principal was denied on, or a blanket-restricted object).
        """
        questions: list[DifferentialQuestion] = []
        seen: set[str] = set()
        owner_refs = {
            p.principal_ref for p in self._principals.values()
            if p.role is PrincipalRole.OWNER
        }
        if not owner_refs:
            return questions
        # index denied cells per principal (candidate negative controls)
        denied_objects: dict[str, set[str]] = {}
        for cell in self._cells.values():
            if cell.outcome == "denied":
                denied_objects.setdefault(cell.principal_ref, set()).add(
                    cell.object_identity_ref)

        # RULE A — tenant boundary (§6.4: "Is the tenant boundary
        # enforced consistently?"): a principal ALLOWED on an object
        # whose observed tenant differs from the principal's tenant is a
        # cross-tenant question. The baseline is the principal's OWN
        # tenant object of the same resource; the negative control is
        # the principal's denied object.
        for cell in sorted(
            self._cells.values(),
            key=lambda c: (c.principal_ref, c.object_identity_ref, c.operation),
        ):
            if len(questions) >= max_questions:
                break
            if cell.outcome != "allowed":
                continue
            principal = self._principals.get(cell.principal_ref)
            if principal is None:
                continue
            # the object's tenant context comes from the cell
            # (a resource-scoped ref like "t2-orders:501" also carries it)
            if not (principal.tenant and cell.tenant
                    and principal.tenant != cell.tenant):
                continue
            control = sorted(
                denied_objects.get(principal.principal_ref, set())
                - {cell.object_identity_ref}
            )
            if not control:
                continue
            qid = str(uuid.uuid5(
                PRINCIPAL_NAMESPACE,
                f"xtenant|{principal.principal_ref}|{cell.object_identity_ref}",
            ))
            if qid in seen:
                continue
            seen.add(qid)
            questions.append(DifferentialQuestion(
                question_id=qid,
                kind="privilege_differential",
                description=(
                    f"Principal {principal.principal_ref} (tenant "
                    f"{principal.tenant}) is allowed on object "
                    f"{cell.object_identity_ref} (tenant {cell.tenant}) — "
                    "is the tenant boundary enforced?"
                ),
                target_object_ref=cell.object_identity_ref,
                target_representation="",
                owner_principal=principal.principal_ref,
                foreign_principal=principal.principal_ref,
                control_object_ref=control[0],
                required_probes=(
                    f"principal:read:{cell.object_identity_ref}",
                    f"principal:read:{control[0]}",
                ),
                evidence_refs=list(cell.evidence_refs),
                baseline_object_ref=cell.object_identity_ref,
            ))

        # RULE B — privilege differential: an owner-allowed operation
        # probed under a lower-privilege principal with a denied control.
        for cell in sorted(
            self._cells.values(),
            key=lambda c: (c.principal_ref, c.object_identity_ref, c.operation),
        ):
            if len(questions) >= max_questions:
                break
            if cell.principal_ref not in owner_refs or cell.outcome != "allowed":
                continue
            obj = cell.object_identity_ref
            for principal in self._principals.values():
                if len(questions) >= max_questions:
                    break
                if principal.principal_ref == cell.principal_ref:
                    continue
                if principal.role not in (
                    PrincipalRole.FOREIGN_SAME_TENANT,
                    PrincipalRole.FOREIGN_OTHER_TENANT,
                    PrincipalRole.LOWER_PRIVILEGE,
                    PrincipalRole.ANONYMOUS,
                ):
                    continue
                # negative control: an object this principal was DENIED on
                control = sorted(
                    denied_objects.get(principal.principal_ref, set())
                    - {obj}
                )
                if not control:
                    continue  # no negative control available — abstain
                qid = str(uuid.uuid5(
                    PRINCIPAL_NAMESPACE,
                    f"{principal.principal_ref}|{obj}|{cell.operation}",
                ))
                if qid in seen:
                    continue
                seen.add(qid)
                questions.append(DifferentialQuestion(
                    question_id=qid,
                    kind="privilege_differential",
                    description=(
                        f"Can {principal.role.value} principal "
                        f"{principal.principal_ref} perform "
                        f"'{cell.operation}' on object {obj} that "
                        f"{cell.principal_ref} (owner) is allowed to?"
                    ),
                    target_object_ref=obj,
                    target_representation="",
                    owner_principal=cell.principal_ref,
                    foreign_principal=principal.principal_ref,
                    control_object_ref=control[0],
                    required_probes=(
                        f"owner:read:{obj}",
                        f"foreign:{cell.operation.split(':')[0]}:{obj}",
                        f"foreign:read:{control[0]}",
                    ),
                    evidence_refs=list(cell.evidence_refs),
                ))
        return questions

    def as_dict(self) -> dict[str, Any]:
        return {
            "principals": [p.public_dict() for p in self.principals()],
            "cells": [c.as_dict() for c in self.cells()],
            "coverage": self.coverage(),
        }


# ---------------------------------------------------------------------------
# State adapters and the validator-input construction (§6.5)
# ---------------------------------------------------------------------------

_ROLE_MAP = {
    "owner": PrincipalRole.OWNER,
    "user_a": PrincipalRole.OWNER,          # idor_lab vocabulary: A owns
    "foreign": PrincipalRole.FOREIGN_SAME_TENANT,
    "user_b": PrincipalRole.FOREIGN_SAME_TENANT,
    "foreign_user": PrincipalRole.FOREIGN_SAME_TENANT,
    "cross_tenant": PrincipalRole.FOREIGN_OTHER_TENANT,
    "anonymous": PrincipalRole.ANONYMOUS,
    "guest": PrincipalRole.ANONYMOUS,
    "low_privilege": PrincipalRole.LOWER_PRIVILEGE,
    "lower_privilege": PrincipalRole.LOWER_PRIVILEGE,
    "viewer": PrincipalRole.LOWER_PRIVILEGE,
    "admin": PrincipalRole.HIGHER_PRIVILEGE,
    "operator_test": PrincipalRole.OPERATOR_TEST,
}


def principals_from_state(
    state: Mapping[str, Any], *, max_principals: int = 16,
) -> list[PrincipalContext]:
    """Build principal contexts from REAL state channels (§6.1).

    Sources: ``identity_profiles`` / ``bac_identities`` (the
    bac_identity_tester vocabulary) and ``role_matrix`` sessions. Only
    pseudonymous references are kept — cookies/tokens stay in the
    executor's isolated session store, never in these records.
    """
    get = state.get if hasattr(state, "get") else (lambda k, d=None: d)
    principals: dict[str, PrincipalContext] = {}

    def _register(ref: str, role_hint: str, tenant: str, session_ref: str,
                  auth: str, evidence: str) -> None:
        if len(principals) >= max_principals or not ref:
            return
        role = _ROLE_MAP.get(str(role_hint).lower(), PrincipalRole.UNKNOWN)
        auth_state = {
            "authenticated": AuthenticationState.AUTHENTICATED,
            "anonymous": AuthenticationState.ANONYMOUS,
            "expired": AuthenticationState.EXPIRED,
        }.get(str(auth).lower(), AuthenticationState.UNKNOWN)
        principals.setdefault(ref, PrincipalContext(
            principal_ref=ref, role=role, tenant=tenant or "",
            session_ref=session_ref or f"session:{ref}",
            authentication_state=auth_state,
            evidence_refs=(evidence,) if evidence else (),
        ))

    for source in ("identity_profiles", "bac_identities", "identities"):
        raw = get(source)
        if not isinstance(raw, Mapping):
            continue
        for name, profile in raw.items():
            if not isinstance(profile, Mapping):
                continue
            _register(
                str(name),
                str(profile.get("role") or ""),
                str(profile.get("tenant") or ""),
                str(profile.get("session_ref") or f"session:{name}"),
                str(profile.get("auth_state") or "authenticated"),
                str(profile.get("evidence_ref") or source),
            )
    # anonymous is always representable (no credential needed)
    if not any(
        p.role is PrincipalRole.ANONYMOUS for p in principals.values()
    ):
        _register("anonymous", "anonymous", "", "session:anonymous",
                  "anonymous", "implicit")
    return [principals[k] for k in sorted(principals)]


def build_privilege_differential_input(
    question: DifferentialQuestion,
    *,
    owner_observation: Mapping[str, Any],
    foreign_observation: Mapping[str, Any],
    control_observation: Mapping[str, Any],
    principal_contexts: Mapping[str, PrincipalContext] | None = None,
) -> dict[str, Any]:
    """§6.5 — the typed validator input for the privilege differential.

    Maps observed authorization evidence onto the exact triple the
    registered ``validate_privilege_differential`` validator consumes:
    baseline = privileged principal on the restricted resource;
    candidate = lower-privilege principal on the SAME resource;
    negative_control = the lower-privilege principal on a
    blanket-restricted resource. Principal identity, tenant context and
    object identity are preserved end-to-end.
    """
    contexts = dict(principal_contexts or {})
    owner = contexts.get(question.owner_principal)
    foreign = contexts.get(question.foreign_principal)
    # session isolation invariant (§6.6): the foreign probe MUST carry
    # the foreign principal's session reference, never the owner's
    if owner and foreign and owner.session_ref == foreign.session_ref \
            and owner.principal_ref != foreign.principal_ref:
        raise SessionBindingError(
            "principal/session contamination: owner and foreign principals "
            "share one session reference — the differential would test "
            "nothing; failing safely"
        )
    return {
        "vulnerability_class": "PRIVILEGE_DIFFERENTIAL",
        "question_id": question.question_id,
        "baseline": dict(owner_observation),      # owner on R
        "candidate": dict(foreign_observation),   # foreign on R
        "negative_control": dict(control_observation),  # foreign on C
        "principal_context": {
            "owner": owner.public_dict() if owner else None,
            "foreign": foreign.public_dict() if foreign else None,
        },
        "object_context": {
            "target_object_ref": question.target_object_ref,
            "control_object_ref": question.control_object_ref,
            "target_representation": question.target_representation,
        },
        "evidence_refs": list(question.evidence_refs)[:20],
    }


def matrix_from_observations(
    principals: Iterable[PrincipalContext],
    observations: Iterable[Mapping[str, Any]],
    *,
    max_cells: int = 5000,
) -> PrincipalObjectOperationMatrix:
    """Build the matrix from principal list + authorization observations.

    Observation vocabulary (all optional): principal_ref, tenant,
    object_ref, operation, object_state, outcome, evidence_refs.
    """
    matrix = PrincipalObjectOperationMatrix(max_cells=max_cells)
    for principal in principals:
        matrix.register_principal(principal)
    for obs in observations:
        if not isinstance(obs, Mapping):
            continue
        ref = str(obs.get("principal_ref") or "")
        if not ref or matrix.principal(ref) is None:
            continue  # unknown principal stays out (no assumptions)
        matrix.record(MatrixCell(
            principal_ref=ref,
            tenant=str(obs.get("tenant") or ""),
            object_identity_ref=str(obs.get("object_ref") or ""),
            operation=str(obs.get("operation") or "read"),
            object_state=str(obs.get("object_state") or "unknown"),
            outcome=str(obs.get("outcome") or "unknown"),
            evidence_refs=[str(e) for e in (obs.get("evidence_refs") or [])][:20],
        ))
    return matrix
