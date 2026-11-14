"""Randomized discovery surface over the controlled HTTP target.

The Logic Breaker benchmark (http-v3) exposes fixed case ids, so a
detector can score against known endpoints. Genuine discovery must
not depend on memorized names. DiscoveryTarget mounts the SAME
controlled backend under a randomized alias surface:

- every endpoint segment name is randomized per deployment seed;
- every resource id, order id and receipt reference is randomized;
- every account identity is randomized (owner values in bodies are
  the external account ids, not the canonical ones);
- a small stateful workflow family (draft -> submitted -> approved)
  is served locally by this class, with a documented enforcement
  matrix: some workflow instances enforce owner-only, in-order
  transitions, and defective instances accept cross-owner and
  out-of-order transitions;
- a read-only index document lists links without revealing which
  operation belongs to which resource type: the detector must infer
  the relationships from allowed observations.

Everything else (ownership model, enforcement matrix, idempotency,
actor roles, budgets) is the existing controlled target, unchanged.
The benchmark declares ground truth over the EXTERNAL ids in
discovery_ground_truth.py; this module exports no defect labels.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from webpent.egaie.http_target import (
    _ACTOR_ROLES,
    ACTOR_A,
    ACTOR_ADMIN,
    ACTOR_B,
    ControlledInvestigationTarget,
)

# Canonical actors the synthetic accounts map onto.
_CANONICAL_ACTORS = (ACTOR_A, ACTOR_B, ACTOR_ADMIN)

# Canonical resource ids (stable backend pool).
_CANONICAL_RESOURCES = (
    "inv-1", "inv-2", "inv-3",
    "doc-1", "doc-2",
    "rec-1", "rec-2",
    "file-1",
)

# Canonical GET segments by resource type / special view.
_CANONICAL_GET_SEGMENTS = {
    "invoice": "invoices",
    "document": "documents",
    "record": "records",
    "file": "files",
    "order": "orders",
    "archive_note": "archive",
}

# Canonical state-changing POST segments (operation surface).
_CANONICAL_POST_SEGMENTS = (
    "payments", "wire", "charges", "checkout", "till", "coupons",
)

WORKFLOW_STATES = ("draft", "submitted", "approved")

# Published promotion codes (public marketing surface, listed in the
# index document). These are NOT secret: discovering the cross-owner
# coupon scenario must not depend on guessing secrets.
_PUBLISHED_COUPON_CODES = ("SAFE10",)

_WORKFLOW_TARGET_STATE = {"submit": "submitted", "approve": "approved"}
# The state a workflow must be in BEFORE the action is legitimate.
_WORKFLOW_REQUIRED_STATE = {"submit": "draft", "approve": "submitted"}


def _next_state(action: str) -> str:
    return _WORKFLOW_TARGET_STATE[action]


@dataclass
class WorkflowInstance:
    """A stateful workflow resource served by the discovery surface.

    enforce_identity: only the owner (or the admin) may transition
    the workflow. enforce_order: submit only from draft, approve only
    from submitted. Instances that disable either check are the
    defective population declared by the benchmark; the responses
    below never expose which check is disabled.
    """

    workflow_id: str
    owner: str
    state: str = "draft"
    last_action: str = "none"
    last_actor: str = ""
    transition_count: int = 0
    enforce_identity: bool = True
    enforce_order: bool = True


@dataclass
class DiscoveryDeployment:
    """The randomized external surface for one benchmark deployment."""

    seed: int
    actor_of: dict[str, str] = field(default_factory=dict)   # canon -> ext
    canonical_actor_of: dict[str, str] = field(default_factory=dict)
    segment_of: dict[str, str] = field(default_factory=dict)  # canon -> ext
    canonical_segment_of: dict[str, str] = field(default_factory=dict)
    resource_of: dict[str, str] = field(default_factory=dict)  # canon -> ext
    canonical_resource_of: dict[str, str] = field(default_factory=dict)
    workflows: dict[str, WorkflowInstance] = field(default_factory=dict)
    # Once-per-token workflow mutation identities (idempotency).
    applied_tokens: set[str] = field(default_factory=set)

    def workflow_segment(self) -> str:
        return self.segment_of["workflows"]


def build_deployment(seed: int) -> DiscoveryDeployment:
    tag = f"{seed:04x}"

    deployment = DiscoveryDeployment(seed=seed)
    # Accounts (deterministic role assignment: first two are the two
    # synthetic regular users, third is the admin).
    deployment.actor_of[ACTOR_A] = f"acct-{tag}a"
    deployment.actor_of[ACTOR_B] = f"acct-{tag}b"
    deployment.actor_of[ACTOR_ADMIN] = f"acct-{tag}x"
    deployment.canonical_actor_of = {
        v: k for k, v in deployment.actor_of.items()}
    # Endpoint segments.
    names = {
        "invoices": f"docs-{tag}",
        "documents": f"files-{tag}",
        "records": f"regs-{tag}",
        "files": f"blobs-{tag}",
        "orders": f"ords-{tag}",
        "archive": f"arc-{tag}",
        "payments": f"pay-{tag}",
        "wire": f"trf-{tag}",
        "charges": f"chg-{tag}",
        "checkout": f"chk-{tag}",
        "till": f"reg-{tag}",
        "coupons": f"cpn-{tag}",
        "workflows": f"wf-{tag}",
    }
    deployment.segment_of = names
    deployment.canonical_segment_of = {v: k for k, v in names.items()}
    # Resource aliases (1:1 with the canonical pool).
    for i, canonical in enumerate(_CANONICAL_RESOURCES):
        external = f"r-{tag}{i:02x}"
        deployment.resource_of[canonical] = external
        deployment.canonical_resource_of[external] = canonical
    # Orders and receipts are derived per canonical id.
    # Workflow population: six instances, deterministic defective /
    # enforced layout (three enforced, three defective), owners split
    # across the two synthetic accounts.
    layouts = (
        (True, True, ACTOR_A), (True, True, ACTOR_B),
        (True, True, ACTOR_ADMIN), (False, True, ACTOR_A),
        (False, False, ACTOR_B), (True, False, ACTOR_A),
    )
    for i, (enforce_identity, enforce_order, owner) in enumerate(layouts):
        external = f"w-{tag}{i:02x}"
        deployment.workflows[external] = WorkflowInstance(
            workflow_id=external,
            owner=deployment.actor_of[owner],
            enforce_identity=enforce_identity,
            enforce_order=enforce_order,
        )
    return deployment


_ID_RE = re.compile(r"[A-Za-z0-9-]+")


class DiscoveryTarget(ControlledInvestigationTarget):
    """The controlled target under a randomized external surface."""

    def __init__(self, *, seed: int = 0) -> None:
        super().__init__()
        self._deployment = build_deployment(seed)

    # -- deployment introspection (benchmark-only, no defect labels) --
    @property
    def deployment(self) -> DiscoveryDeployment:
        return self._deployment

    # -- externalization ------------------------------------------
    def _canonicalize_path(self, path: str) -> str:
        ext = self._deployment
        parts = path.strip("/").split("/")
        if len(parts) == 2:
            seg, resource = parts
            canonical_seg = ext.canonical_segment_of.get(seg)
            if canonical_seg == "workflows":
                return path  # handled locally
            canonical_resource = ext.canonical_resource_of.get(resource)
            if canonical_seg == "orders":
                bare = resource[len("ord-"):] if resource.startswith(
                    "ord-") else resource
                canonical_resource = ext.canonical_resource_of.get(bare)
                if canonical_resource:
                    canonical_resource = f"ord-{canonical_resource}"
            if canonical_seg and canonical_resource:
                return f"/api/{canonical_seg}/{canonical_resource}"
        return path

    def _canonicalize_params(
        self, params: dict[str, str],
    ) -> dict[str, str]:
        ext = self._deployment
        canonical = dict(params)
        actor = canonical.get("actor")
        if actor in ext.canonical_actor_of:
            canonical["actor"] = ext.canonical_actor_of[actor]
        return canonical

    def _externalize_text(self, text: str) -> str:
        ext = self._deployment
        # Order references first (ord-inv-2 -> external order id).
        for canonical in sorted(ext.resource_of, key=len, reverse=True):
            text = text.replace(
                f"ord-{canonical}",
                f"ord-{ext.resource_of[canonical]}")
            text = text.replace(
                f"rcpt-{canonical}",
                f"rcpt-{ext.resource_of[canonical]}")
        # Canonical path prefixes -> external segments.
        for canonical_seg, external_seg in ext.segment_of.items():
            text = text.replace(
                f"/api/{canonical_seg}/", f"/{external_seg}/")
        # Bare canonical resource ids -> external ids.
        for canonical in sorted(ext.resource_of, key=len, reverse=True):
            text = re.sub(
                rf"(?<![A-Za-z0-9-]){canonical}(?![A-Za-z0-9-])",
                ext.resource_of[canonical], text)
        # Canonical actor values -> external account ids.
        for canonical_actor, external_actor in ext.actor_of.items():
            text = re.sub(
                rf"(?<![A-Za-z0-9-]){canonical_actor}(?![A-Za-z0-9-])",
                external_actor, text)
        return text

    def _externalize_response(
        self, response: tuple[int, dict[str, str], str],
    ) -> tuple[int, dict[str, str], str]:
        status, headers, body = response
        body = self._externalize_text(body)
        headers = {
            key: self._externalize_text(value)
            for key, value in headers.items()
        }
        return status, headers, body

    # -- request entry points --------------------------------------
    def handle_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        if path == "/":
            body = json.dumps(self._index_document())
            return 200, {"Content-Type": "application/json"}, body
        if self._is_workflow_path(path):
            return self._workflow_get(path, params)
        return self._externalize_response(super().handle_get(
            self._canonicalize_path(path),
            self._canonicalize_params(params)))

    def handle_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        if self._is_workflow_path(path):
            return self._workflow_post(path, params)
        return self._externalize_response(super().handle_post(
            self._canonicalize_path(path),
            self._canonicalize_params(params)))

    # -- index (allowed observation, no labels) --------------------
    def _index_document(self) -> dict[str, Any]:
        ext = self._deployment
        return {
            "service": "billing-portal",
            "promotions": sorted(_PUBLISHED_COUPON_CODES),
            "api": {
                "documents": sorted(
                    f"/{ext.segment_of['invoices']}/"
                    f"{ext.resource_of[c]}"
                    for c in ("inv-1", "inv-2", "inv-3")),
                "records": sorted(
                    f"/{ext.segment_of['records']}/"
                    f"{ext.resource_of[c]}"
                    for c in ("rec-1", "rec-2")),
                "files": sorted(
                    f"/{ext.segment_of['files']}/{ext.resource_of[c]}"
                    for c in ("file-1",)),
                "operations": sorted(
                    f"/{ext.segment_of[s]}"
                    for s in _CANONICAL_POST_SEGMENTS),
                "workflows": sorted(
                    f"/{ext.workflow_segment()}/{wf_id}"
                    for wf_id in ext.workflows),
            },
        }

    # -- local workflow family --------------------------------------
    def _is_workflow_path(self, path: str) -> bool:
        prefix = f"/{self._deployment.workflow_segment()}/"
        return path.startswith(prefix)

    def _workflow_of_path(self, path: str) -> WorkflowInstance | None:
        resource = path.strip("/").split("/")[1]
        return self._deployment.workflows.get(resource)

    def _workflow_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        instance = self._workflow_of_path(path)
        if instance is None:
            return 404, {}, json.dumps({"error": "not_found"})
        actor = self._canonicalize_params(params).get("actor", "")
        if self._actor_role(actor) == "none":
            body = json.dumps({"error": "forbidden"})
            return 403, {}, body
        body = json.dumps({
            "workflow_id": instance.workflow_id,
            "owner": instance.owner,
            "state": instance.state,
            "last_action": instance.last_action,
            "last_actor": instance.last_actor,
            "transition_count": instance.transition_count,
        })
        return 200, {"Content-Type": "application/json"}, body

    def _workflow_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        instance = self._workflow_of_path(path)
        if instance is None:
            return 404, {}, json.dumps({"error": "not_found"})
        canonical_params = self._canonicalize_params(params)
        actor = canonical_params.get("actor", "anonymous")
        action = params.get("action", "")
        if action not in ("submit", "approve"):
            body = json.dumps({
                "error": "invalid_action", "requested": action})
            return 400, {}, body
        # Application-level idempotency, mirroring the canonical
        # target's once-per-token semantics: a repeated token is a
        # no-op that reports the current state.
        idem = canonical_params.get("idem", "")
        if idem and idem in self._deployment.applied_tokens:
            body = json.dumps({
                "workflow_id": instance.workflow_id,
                "owner": instance.owner,
                "requested_action": action,
                "applied": False,
                "state": instance.state,
                "transitioned_by": instance.last_actor,
                "duplicate": True,
            })
            return 200, {"Content-Type": "application/json"}, body
        role = self._actor_role(actor)
        if role not in ("user", "admin"):
            body = json.dumps({"error": "forbidden"})
            return 403, {}, body
        external_actor = self._deployment.actor_of.get(actor, actor)
        if (instance.enforce_identity
                and external_actor != instance.owner
                and role != "admin"):
            body = json.dumps({
                "error": "forbidden",
                "required": "owner",
                "state": instance.state,
            })
            return 403, {}, body
        required_state = _WORKFLOW_REQUIRED_STATE[action]
        if (instance.enforce_order
                and instance.state != required_state):
            body = json.dumps({
                "error": "invalid_transition",
                "state": instance.state,
                "requested_action": action,
            })
            return 409, {}, body
        target_state = _next_state(action)
        if instance.state == target_state:
            # Same-state transition is a no-op for both layouts.
            applied = False
        else:
            applied = True
            instance.state = target_state
            instance.last_action = action
            instance.last_actor = (
                self._deployment.actor_of.get(actor, actor))
            instance.transition_count += 1
        if applied and idem:
            self._deployment.applied_tokens.add(idem)
        body = json.dumps({
            "workflow_id": instance.workflow_id,
            "owner": instance.owner,
            "requested_action": action,
            "applied": applied,
            "state": instance.state,
            "transitioned_by": self._deployment.actor_of.get(actor, actor),
        })
        return 200, {"Content-Type": "application/json"}, body

    def _actor_role(self, actor: str) -> str:
        return _ACTOR_ROLES.get(actor, "none")

    def reset(self) -> None:
        super().reset()
        seed = self._deployment.seed
        self._deployment = build_deployment(seed)
