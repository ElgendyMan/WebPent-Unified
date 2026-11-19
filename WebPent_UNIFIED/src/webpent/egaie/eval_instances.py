"""L6 evaluation instances: independently generated application deployments.

The generator is deliberately separate from the development fixtures in
http_target.py / discovery_target.py. Nothing here imports them, and the
discovery engine never sees this module's ground truth (eval_evaluator.py).

Each InstanceSpec is a complete description of one application instance:
surface vocabulary, resource pool, workflow state machines, enforcement
styles, and a defect profile. InstanceTarget serves the spec on loopback
with a deterministic reset.

Observation contract (the surface the engine may rely on):
- the index (GET /) returns an api block of path groups, a kinds map
  (path -> read|mutate|workflow), and a schema block that maps semantic
  ROLES to this instance's field/param/action/header names. The schema
  is the app's public API documentation: it names the vocabulary, never
  the enforcement matrix;
- enforcement outcomes are marked by the outcome header, independent of
  the chosen denial status code (401/403/404 vary by instance);
- every GET body carries the instance's own field names, and the owner
  of a resource is exposed both in the body (schema role "owner") and
  in the instance's owner header.

Everything else is randomized per instance and must be inferred from
behavior: routes, resource and identity ids, action and state names,
state-machine shapes, counts, and which implementations are enforced.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

from webpent.egaie.http_target import (
    ACTOR_A,
    ACTOR_ADMIN,
    ACTOR_B,
    ControlledInvestigationTarget,
)

OUTCOME_HEADER = "x-authorization-outcome"
OUTCOME_GRANTED = "granted_full"
OUTCOME_DENIED = "denied"

# Denial status styles an instance may choose for its enforcement points.
DENIAL_STYLES = ("403", "404", "401")

_WORDLIST = [
    "kite", "orchard", "mural", "quartz", "harbor", "lantern", "cedar",
    "basil", "pebble", "signal", "ember", "thistle", "compass", "willow",
    "cobalt", "juniper", "marble", "ripple", "saffron", "tidepool",
]

_ROLE_NAMES = {
    "resource": "rsc", "order": "ord", "workflow": "wrk",
    "document": "doc", "account": "acc",
}

# Semantic roles the schema document maps onto per-instance names.
_FIELD_ROLES = [
    "resource_id", "order_id", "account_id", "workflow_id",
    "owner", "kind", "state", "total", "charged",
    "authoritative_total", "discount_applied_by", "transitioned_by",
    "applied", "available", "paid", "order_path", "note_path",
]
_PARAM_ROLES = ["actor", "resource", "account", "amount", "action", "idem"]
_ACTION_ROLES = ["submit", "approve", "release", "finalize"]

# Defect-profile layouts. Each tuple entry is one profile; True marks a
# family implemented WITHOUT its enforcement check (the vulnerable
# population). Every profile guarantees each defective family has at
# least one enforced sibling operation in the same instance, so a
# confirmed finding is always backed by a distinguishing denial.
_PROFILE_LAYOUTS: tuple[dict[str, bool], ...] = (
    {
        "identity_read": True, "identity_mutation": False,
        "workflow_identity": True, "order": False,
        "price": True, "coupon": True, "balance": False,
    },
    {
        "identity_read": False, "identity_mutation": True,
        "workflow_identity": True, "order": True,
        "price": False, "coupon": True, "balance": True,
    },
    {
        "identity_read": True, "identity_mutation": False,
        "workflow_identity": False, "order": True,
        "price": True, "coupon": False, "balance": True,
    },
    {
        "identity_read": False, "identity_mutation": False,
        "workflow_identity": True, "order": True,
        "price": True, "coupon": True, "balance": False,
    },
    {
        "identity_read": True, "identity_mutation": True,
        "workflow_identity": False, "order": True,
        "price": True, "coupon": False, "balance": True,
    },
    {
        "identity_read": False, "identity_mutation": True,
        "workflow_identity": False, "order": False,
        "price": True, "coupon": True, "balance": True,
    },
)

_PROFILE_KEYS = (
    "identity_read", "identity_mutation", "workflow_identity",
    "order", "price", "coupon", "balance",
)


@dataclass
class InstanceSpec:
    """One independently generated application instance."""

    instance_id: str
    origin: str
    seed: int
    blind: bool

    # surface vocabulary
    app_name: str
    read_segment: str
    order_segment: str
    workflow_segment: str
    pay_segment: str
    coupon_segment: str
    withdraw_segment: str
    resource_prefix: str
    workflow_prefix: str
    account_prefix: str
    actor_ids: dict[str, str]                 # role -> external id
    field_names: dict[str, str]               # role -> external field name
    param_names: dict[str, str]               # role -> external param name
    action_names: dict[str, str]              # role -> external action value
    owner_header: str
    group_names: dict[str, str]               # role -> index group name

    # content
    resources: list[dict[str, Any]]
    workflows: list[dict[str, Any]]
    accounts: list[dict[str, Any]]
    state_chains: dict[str, list[str]]         # per workflow id
    action_targets: dict[str, dict[str, str]]  # per workflow id
    workflow_bases: dict[str, str]             # wf id -> wf base

    # enforcement and defects (True flag = family enforced/safe)
    denial_status: int
    identity_read_enforced: bool
    identity_mutation_enforced: bool
    workflow_identity_enforced: dict[str, bool]  # per workflow id
    order_enforced: dict[str, bool]              # per workflow id
    price_authoritative: bool
    coupon_owner_enforced: bool
    balance_enforced: bool

    def schema(self) -> dict[str, Any]:
        """The public response-schema document served with the index."""
        return {
            "fields": dict(self.field_names),
            "params": dict(self.param_names),
            "actions": dict(self.action_names),
            "state_chains": {
                wf_id: list(states)
                for wf_id, states in self.state_chains.items()
            },
            "action_targets": {
                wf_id: dict(targets)
                for wf_id, targets in self.action_targets.items()
            },
            "owner_header": self.owner_header,
            "outcome_header": OUTCOME_HEADER,
        }


def _words(rng: random.Random, count: int) -> list[str]:
    picked = rng.sample(_WORDLIST, count)
    return [f"{word}-{rng.randrange(100, 999)}" for word in picked]


def _deny(spec: InstanceSpec) -> tuple[int, dict[str, str]]:
    return spec.denial_status, {
        OUTCOME_HEADER: OUTCOME_DENIED,
        "Content-Type": "application/json",
    }


def generate_instance(
    seed: int,
    *,
    instance_id: str = "",
    blind: bool = False,
    profile: dict[str, bool] | None = None,
) -> InstanceSpec:
    """Build one application instance from an independent RNG.

    profile sets the defect layout (True = defective in that family);
    when omitted, a deterministic mixed layout is derived from the seed.
    Secured lookalikes pass an all-False profile.
    """
    rng = random.Random(91000 + seed * 977)
    words = _words(rng, 6)
    (
        read_segment, order_segment, workflow_segment, pay_segment,
        coupon_segment, withdraw_segment,
    ) = words
    actor_ids = {
        "a": f"usr-{rng.randrange(10000, 99999)}",
        "b": f"usr-{rng.randrange(10000, 99999)}",
        "admin": f"usr-{rng.randrange(10000, 99999)}",
    }
    field_names = {
        role: f"f{rng.randrange(100, 999)}{role[:2]}"
        for role in _FIELD_ROLES
    }
    param_names = {
        role: f"p{rng.randrange(100, 999)}{role[:2]}"
        for role in _PARAM_ROLES
    }
    action_names = {
        role: f"op-{role[:3]}-{rng.randrange(10, 99)}"
        for role in _ACTION_ROLES
    }
    owner_header = f"x-{rng.randrange(100, 999)}-principal"
    group_names = {
        "resources": f"g{rng.randrange(100, 999)}",
        "operations": f"g{rng.randrange(100, 999)}",
        "workflows": f"g{rng.randrange(100, 999)}",
    }

    # content: 6 resources, 4 accounts, 3 workflows with different
    # state-machine shapes; owners split across the two identities so
    # every family has an enforced contrast within the instance.
    actors = [actor_ids["a"], actor_ids["b"]]
    resources = [
        {
            "resource_id":
                f"{_ROLE_NAMES['resource']}-{rng.randrange(100000, 999999)}",
            "kind": _ROLE_NAMES["document"],
            "owner": actors[index % 2],
            "total": 50 + 10 * index,
        }
        for index in range(6)
    ]
    accounts = [
        {
            "account_id":
                f"{_ROLE_NAMES['account']}-{rng.randrange(100000, 999999)}",
            "owner": actors[index % 2],
            "available": 80 + 10 * index,
        }
        for index in range(4)
    ]

    if profile is None:
        profile = dict(_PROFILE_LAYOUTS[seed % len(_PROFILE_LAYOUTS)])
    missing = set(_PROFILE_KEYS) - set(profile)
    if missing:
        raise ValueError(f"profile missing keys: {sorted(missing)}")

    # Workflow population and enforcement placement:
    #   wf0 owner a  - order family target (skips the order check only
    #                  when the order family is defective), identity
    #                  always enforced;
    #   wf1 owner b  - identity control (both checks always enforced);
    #   wf2 owner b  - identity family target (skips the identity check
    #                  only when the workflow-identity family is
    #                  defective), order always enforced.
    workflows: list[dict[str, Any]] = []
    state_chains: dict[str, list[str]] = {}
    action_targets: dict[str, dict[str, str]] = {}
    workflow_bases: dict[str, str] = {}
    for wf_index in range(3):
        base = f"{_ROLE_NAMES['workflow']}-{rng.randrange(100000, 999999)}"
        chain = [
            f"st-{rng.randrange(10, 99)}{state}"
            for state in ("a", "b", "c")
        ]
        if wf_index == 1:
            chain.append(f"st-{rng.randrange(10, 99)}d")
        workflow_id = f"{base}-{rng.randrange(100, 999)}"
        workflows.append({
            "workflow_id": workflow_id,
            "owner": actors[0] if wf_index == 0 else actors[1],
            "resource_id": resources[wf_index]["resource_id"],
        })
        workflow_bases[workflow_id] = base
        state_chains[workflow_id] = chain
        # one action per edge; the first action drives the initial
        # transition, later actions follow in chain order
        action_order = ["submit", "approve", "release", "finalize"]
        action_targets[workflow_id] = {
            action_names[action_order[edge]]: chain[edge + 1]
            for edge in range(len(chain) - 1)
        }

    workflow_identity_enforced = {
        wf_id: (wf_id != workflows[2]["workflow_id"])
        or not profile["workflow_identity"]
        for wf_id in state_chains
    }
    order_enforced = {
        wf_id: (wf_id != workflows[0]["workflow_id"])
        or not profile["order"]
        for wf_id in state_chains
    }

    return InstanceSpec(
        instance_id=instance_id or f"instance-{seed}",
        origin=f"http://127.0.0.1:0/{rng.randrange(100000, 999999)}",
        seed=seed,
        blind=blind,
        app_name=f"app-{rng.randrange(1000, 9999)}",
        read_segment=read_segment,
        order_segment=order_segment,
        workflow_segment=workflow_segment,
        pay_segment=pay_segment,
        coupon_segment=coupon_segment,
        withdraw_segment=withdraw_segment,
        resource_prefix=_ROLE_NAMES["resource"],
        workflow_prefix=_ROLE_NAMES["workflow"],
        account_prefix=_ROLE_NAMES["account"],
        actor_ids=actor_ids,
        field_names=field_names,
        param_names=param_names,
        action_names=action_names,
        owner_header=owner_header,
        group_names=group_names,
        resources=resources,
        workflows=workflows,
        accounts=accounts,
        state_chains=state_chains,
        action_targets=action_targets,
        workflow_bases=workflow_bases,
        denial_status=int(rng.choice(DENIAL_STYLES)),
        identity_read_enforced=not profile["identity_read"],
        identity_mutation_enforced=not profile["identity_mutation"],
        workflow_identity_enforced=workflow_identity_enforced,
        order_enforced=order_enforced,
        price_authoritative=not profile["price"],
        coupon_owner_enforced=not profile["coupon"],
        balance_enforced=not profile["balance"],
    )


class InstanceTarget(ControlledInvestigationTarget):
    """A loopback deployment serving one generated InstanceSpec.

    Self-contained: it shares the lifecycle and HTTP plumbing of the
    controlled target but serves none of the canonical fixtures. Every
    route, id, field and action name comes from the spec. Mutations are
    applied at most once per (family, key, idempotency token), so a
    resumed investigation never re-applies a completed mutation.
    """

    def __init__(self, spec: InstanceSpec) -> None:
        super().__init__()
        self.spec = spec
        self.reset()

    # --------------------------------------------------------------- reset
    def reset(self) -> None:
        spec = self.spec
        with self._lock:
            self._request_count = 0
            self._resources = {
                item["resource_id"]: dict(item) for item in spec.resources
            }
            self._accounts = {
                item["account_id"]: dict(item) for item in spec.accounts
            }
            self._workflows = {
                item["workflow_id"]: dict(item) for item in spec.workflows
            }
            self._wf_state = {
                wf_id: spec.state_chains[wf_id][0]
                for wf_id in self._workflows
            }
            self._orders: dict[str, dict[str, Any]] = {}
            self._paid: dict[str, str] = {}
            self._applied_codes: set[str] = set()
            self._applied_mutations: set[tuple[str, str, str]] = set()
            self._authorized_actors: set[str] = {
                spec.actor_ids["a"], spec.actor_ids["b"],
                spec.actor_ids["admin"],
            }

    # ------------------------------------------------------------- helpers
    def _actor_of(self, params: dict[str, str]) -> str:
        """Map the caller's credential onto this instance's external
        identity space at request time (the same contract the canonical
        fixture target follows: probe credentials are the caller's own
        synthetic accounts; the deployment resolves who they are)."""
        external = {
            ACTOR_A: self.spec.actor_ids["a"],
            ACTOR_B: self.spec.actor_ids["b"],
            ACTOR_ADMIN: self.spec.actor_ids["admin"],
        }
        credential = params.get(self.spec.param_names["actor"], "")
        return external.get(credential, credential or "anonymous")

    def _emit(self, roles: dict[str, Any]) -> dict[str, Any]:
        names = self.spec.field_names
        return {names.get(key, key): value for key, value in roles.items()}

    def _grant_headers(self, owner: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            OUTCOME_HEADER: OUTCOME_GRANTED,
        }
        if owner:
            headers[self.spec.owner_header] = owner
        return headers

    def _json(
        self, status: int, body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], str]:
        merged = {"Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        return status, merged, json.dumps(body)

    def _deny_response(self, body: dict[str, Any]) -> tuple[
        int, dict[str, str], str,
    ]:
        status, headers = _deny(self.spec)
        return status, headers, json.dumps(body)

    # ---------------------------------------------------------------- gets
    def handle_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        spec = self.spec
        actor = self._actor_of(params)
        if path in ("/", "/index"):
            return self._json(200, self._index_body())
        if path.startswith(f"/{spec.workflow_segment}/"):
            return self._get_workflow(path, actor)
        if path.startswith(f"/{spec.order_segment}/"):
            return self._get_order(path, actor)
        if path in self._read_paths():
            return self._get_read(path, actor)
        return self._json(404, {"error": "unknown"})

    def _get_workflow(
        self, path: str, actor: str,
    ) -> tuple[int, dict[str, str], str]:
        wf_id = path.rsplit("/", 1)[1]
        wf = self._workflows.get(wf_id)
        if wf is None:
            return self._json(404, {"error": "unknown"})
        if actor not in self._authorized_actors:
            return self._deny_response({"error": "forbidden"})
        body = dict(wf)
        body["state"] = self._wf_state[wf_id]
        return self._json(
            200, self._emit(body), self._grant_headers(wf["owner"]))

    def _get_order(
        self, path: str, actor: str,
    ) -> tuple[int, dict[str, str], str]:
        order_id = path.rsplit("/", 1)[1]
        order = self._orders.get(order_id)
        if order is None:
            return self._json(404, {"error": "unknown"})
        if actor not in self._authorized_actors:
            return self._deny_response({"error": "forbidden"})
        return self._json(
            200, self._emit(dict(order)),
            self._grant_headers(order["owner"]))

    def _read_paths(self) -> set[str]:
        spec = self.spec
        return {
            f"/{spec.read_segment}/{item['resource_id']}"
            for item in spec.resources
        } | {
            f"/{spec.read_segment}/{item['account_id']}"
            for item in spec.accounts
        }

    def _get_read(
        self, path: str, actor: str,
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        if actor not in self._authorized_actors:
            return self._deny_response({"error": "forbidden"})
        key = path.rsplit("/", 1)[1]
        item = self._resources.get(key) or self._accounts.get(key)
        if item is None:
            return self._json(404, {"error": "unknown"})
        owner = item["owner"]
        if (spec.identity_read_enforced and owner != actor
                and actor != spec.actor_ids["admin"]):
            return self._deny_response({"error": "forbidden"})
        return self._json(200, self._emit(dict(item)), self._grant_headers(owner))

    # ---------------------------------------------------------------- posts
    def handle_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        spec = self.spec
        actor = self._actor_of(params)
        if actor not in self._authorized_actors:
            return self._deny_response({"error": "forbidden"})
        if path == f"/{spec.order_segment}":
            return self._post_order(actor, params)
        if path == f"/{spec.pay_segment}":
            return self._post_pay(actor, params)
        if path == f"/{spec.coupon_segment}":
            return self._post_coupon(actor, params)
        if path == f"/{spec.withdraw_segment}":
            return self._post_withdraw(actor, params)
        if path.startswith(f"/{spec.workflow_segment}/"):
            return self._post_workflow(
                path.rsplit("/", 1)[1], actor, params)
        return self._json(404, {"error": "unknown"})

    def _fresh_token(self, family: str, key: str, idem: str) -> bool:
        token = idem or f"{family}:{key}:auto"
        mutation = (family, key, token)
        if mutation in self._applied_mutations:
            return False
        self._applied_mutations.add(mutation)
        return True

    def _post_order(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        resource_id = params.get(spec.param_names["resource"], "")
        resource = self._resources.get(resource_id)
        if resource is None:
            return self._json(404, {"error": "unknown"})
        total = resource["total"]
        if spec.price_authoritative:
            charged = total
        else:
            raw = params.get(spec.param_names["amount"], "")
            charged = int(raw) if raw.isdigit() else total
        self._fresh_token("order", resource_id,
                          params.get(spec.param_names["idem"], ""))
        order_id = f"ord-{len(self._orders) + 1:06d}"
        order = {
            "order_id": order_id,
            "owner": resource["owner"],
            "resource_id": resource_id,
            "charged": charged,
            "authoritative_total": total,
            "applied": True,
        }
        self._orders[order_id] = order
        return self._json(
            200, self._emit(dict(order)),
            self._grant_headers(order["owner"]))

    def _post_pay(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        resource_id = params.get(spec.param_names["resource"], "")
        resource = self._resources.get(resource_id)
        if resource is None:
            return self._json(404, {"error": "unknown"})
        if spec.identity_mutation_enforced and resource["owner"] != actor:
            return self._deny_response({"error": "forbidden"})
        self._fresh_token("pay", resource_id,
                          params.get(spec.param_names["idem"], ""))
        self._paid[resource_id] = actor
        return self._json(200, self._emit({
            "resource_id": resource_id,
            "owner": resource["owner"],
            "paid": True,
        }), self._grant_headers(resource["owner"]))

    def _post_coupon(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        resource_id = params.get(spec.param_names["resource"], "")
        resource = self._resources.get(resource_id)
        if resource is None:
            return self._json(404, {"error": "unknown"})
        if spec.coupon_owner_enforced and resource["owner"] != actor:
            return self._deny_response({"error": "forbidden"})
        applied = self._fresh_token(
            "coupon", resource_id, params.get(spec.param_names["idem"], ""))
        self._applied_codes.add(resource_id)
        total = resource["total"]
        order_id = f"cpn-{len(self._orders) + 1:06d}"
        order = {
            "order_id": order_id,
            "owner": resource["owner"],
            "resource_id": resource_id,
            "charged": total - 5,
            "authoritative_total": total,
            "discount_applied_by": actor,
            "applied": applied,
            "order_path": f"/{spec.order_segment}/{order_id}",
            "note_path": f"/{spec.read_segment}/{resource_id}",
        }
        self._orders[order_id] = order
        return self._json(
            200, self._emit(dict(order)),
            self._grant_headers(order["owner"]))

    def _post_withdraw(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        account_id = params.get(spec.param_names["account"], "")
        account = self._accounts.get(account_id)
        if account is None:
            return self._json(404, {"error": "unknown"})
        if account["owner"] != actor:
            # ownership of accounts is always enforced; the boundary
            # family under test is the balance limit
            return self._deny_response({"error": "forbidden"})
        raw = params.get(spec.param_names["amount"], "")
        if not raw.isdigit():
            return self._json(400, {"error": "invalid"})
        amount = int(raw)
        if spec.balance_enforced and amount > account["available"]:
            return self._json(400, {"error": "insufficient"})
        self._fresh_token("withdraw", account_id,
                          params.get(spec.param_names["idem"], ""))
        account["available"] -= amount
        return self._json(200, self._emit({
            "account_id": account_id,
            "owner": account["owner"],
            "charged": amount,
            "available": account["available"],
        }), self._grant_headers(account["owner"]))

    def _post_workflow(
        self, wf_id: str, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        wf = self._workflows.get(wf_id)
        if wf is None:
            return self._json(404, {"error": "unknown"})
        action = params.get(spec.param_names["action"], "")
        targets = spec.action_targets[wf_id]
        if action not in targets:
            body = {"error": "unknown_action",
                    "state": self._wf_state[wf_id]}
            # an error response never claims a granted outcome: the
            # outcome header must agree with the status code
            return self._json(400, body)
        if (spec.workflow_identity_enforced[wf_id]
                and wf["owner"] != actor
                and actor != spec.actor_ids["admin"]):
            return self._deny_response({"error": "forbidden"})
        if spec.order_enforced[wf_id]:
            chain = spec.state_chains[wf_id]
            required = chain[chain.index(targets[action]) - 1]
            if self._wf_state[wf_id] != required:
                body = {"error": "invalid_transition",
                        "state": self._wf_state[wf_id]}
                return self._json(
                    409, self._emit(body), self._grant_headers(wf["owner"]))
        self._fresh_token("workflow", wf_id,
                          params.get(spec.param_names["idem"], ""))
        self._wf_state[wf_id] = targets[action]
        body = dict(wf)
        body["state"] = self._wf_state[wf_id]
        body["transitioned_by"] = actor
        body["applied"] = True
        return self._json(200, self._emit(body), self._grant_headers(wf["owner"]))

    # ---------------------------------------------------------------- index
    def _index_body(self) -> dict[str, Any]:
        spec = self.spec
        names = spec.field_names
        resources = [
            {
                "path": f"/{spec.read_segment}/{item['resource_id']}",
                names["kind"]: item["kind"],
            }
            for item in spec.resources
        ]
        accounts = [
            {
                "path": f"/{spec.read_segment}/{item['account_id']}",
                names["available"]: item["available"],
            }
            for item in spec.accounts
        ]
        workflows = [
            {"path": f"/{spec.workflow_segment}/{item['workflow_id']}"}
            for item in spec.workflows
        ]
        operations = [
            {"path": f"/{spec.order_segment}",
             "role": "order",
             spec.param_names["resource"]: "rid",
             spec.param_names["amount"]: "n"},
            {"path": f"/{spec.pay_segment}",
             "role": "pay",
             spec.param_names["resource"]: "rid"},
            {"path": f"/{spec.coupon_segment}",
             "role": "coupon",
             spec.param_names["resource"]: "rid"},
            {"path": f"/{spec.withdraw_segment}",
             "role": "withdraw",
             spec.param_names["account"]: "aid",
             spec.param_names["amount"]: "n"},
        ]
        kinds: dict[str, str] = {}
        for item in resources + accounts:
            kinds[item["path"]] = "read"
        for item in workflows:
            kinds[item["path"]] = "workflow"
        for item in operations:
            kinds[item["path"]] = "mutate"
        return {
            "app": spec.app_name,
            "api": {
                spec.group_names["resources"]: resources + accounts,
                spec.group_names["operations"]: operations,
                spec.group_names["workflows"]: workflows,
            },
            "kinds": kinds,
            "schema": spec.schema(),
        }
