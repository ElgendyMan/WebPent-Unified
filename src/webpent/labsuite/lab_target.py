"""L7 lab deployment: an independently implemented loopback application.

No code is shared with the L6 fixture generation. The deployment below
is written from the engine's documented observation contract alone
(index + kinds + schema roles, outcome header, probe-credential
protocol) and implements five invariant families, each with MULTIPLE
mechanically distinct implementations of the same security invariant:

- records ownership: who may read and mutate a record. Implemented by
  direct owner comparison OR by access-control-list membership.
- checkout totals: what the deployment charges. Implemented by client-
  supplied total, server-authoritative total, or authoritative charge
  with a mirrored display total (a secured lookalike).
- approval chains: which transitions are legal and who may perform
  them. Order implemented by chain-position checking OR by transition-
  history checking; approver identity by owner comparison OR approver
  ACL.
- spend caps: how much may be withdrawn. Implemented with no cap, a
  per-request cap only (cumulative invariant defective), or a
  cumulative ledger (secured).
- grant tokens (held-out family, never used to tune the L6 engine): a
  single-use consumable authorization. Implemented as replayable,
  consumed-on-first-use, or a documented two-use grant (ambiguous by
  design).

Everything an engine could memorize from another corpus is randomized
per deployment: route segments, resource and identity ids, field and
param names, action names, state names, ownership assignment, denial
status codes. Ground truth for a deployment lives ONLY in
labsuite.evaluator and is derived from the defect profile the corpus
declares, never published on the wire.
"""
from __future__ import annotations

import json
import random
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client

# Probe-credential protocol (documented observation contract; the
# literals are the contract's own wire values, not an import from the
# fixture module).
PROBE_CREDENTIALS = ("actor-a", "actor-b", "actor-admin")

OUTCOME_GRANTED = "granted_full"
OUTCOME_DENIED = "denied"

DENIAL_STYLES = (401, 403, 404)

_WORDLIST = [
    "atlas", "bramble", "cinder", "dovetail", "esparto", "flint",
    "garnet", "hollow", "ibex", "jetty", "kiln", "lumen", "mesa",
    "nutmeg", "onyx", "pilaster", "quiver", "roan", "sable", "tundra",
    "umbel", "vestry", "wicket", "yarrow", "zephyr",
]

# Implementation variants per family. The corpus rotates these by seed
# so both DEV and held-out blocks contain every variant.
OWNERSHIP_IMPLS = ("owner-compare", "acl-set")
CHECKOUT_IMPLS = ("client-total", "authoritative", "mirror-total")
APPROVER_IMPLS = ("owner-compare", "approver-acl")
ORDER_IMPLS = ("chain-position", "history-sequence")
SPEND_IMPLS = ("no-cap", "per-request", "cumulative")
GRANT_IMPLS = ("replayable", "consumed", "two-use")


@dataclass
class LabSpec:
    """One independent lab deployment."""

    instance_id: str
    seed: int
    blind: bool

    # vocabulary
    app_name: str
    record_segment: str
    mutate_segment: str
    checkout_segment: str
    approval_segment: str
    spend_segment: str
    grant_segment: str
    consume_segment: str
    record_prefix: str
    workflow_prefix: str
    account_prefix: str
    actor_ids: dict[str, str]
    field_names: dict[str, str]
    param_names: dict[str, str]
    action_names: dict[str, str]
    owner_header: str
    outcome_header: str
    group_names: dict[str, str]

    # content
    records: list[dict[str, Any]]
    accounts: list[dict[str, Any]]
    workflows: list[dict[str, Any]]
    state_chains: dict[str, list[str]]
    action_targets: dict[str, dict[str, str]]

    # implementations and defects
    denial_status: int
    ownership_impl: str
    identity_read_enforced: bool
    identity_mutation_enforced: bool
    checkout_impl: str
    approver_impl: str
    order_impl: str
    workflow_identity_enforced: dict[str, bool]
    order_enforced: dict[str, bool]
    spend_impl: str
    spend_limit: int
    grant_impl: str
    grant_uses_allowed: int

    def schema(self) -> dict[str, Any]:
        """The deployment's own published response-schema document."""
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
            "outcome_header": self.outcome_header,
        }


def generate_lab_instance(
    seed: int,
    *,
    instance_id: str = "",
    blind: bool = False,
    profile: dict[str, Any] | None = None,
) -> LabSpec:
    """Build one lab deployment from its own RNG.

    profile overrides individual implementation choices (used by the
    corpus to place variants deterministically and by the negative
    block to secure everything); keys not supplied rotate by seed.
    """
    rng = random.Random(77000 + seed * 733)
    words = rng.sample(_WORDLIST, 7)
    (
        record_segment, mutate_segment, checkout_segment,
        approval_segment, spend_segment, grant_segment,
        consume_segment,
    ) = [f"{word}-{rng.randrange(100, 999)}" for word in words]
    actor_ids = {
        "a": f"prs-{rng.randrange(10000, 99999)}",
        "b": f"prs-{rng.randrange(10000, 99999)}",
        "admin": f"prs-{rng.randrange(10000, 99999)}",
    }
    field_roles = [
        "resource_id", "record_id", "account_id", "workflow_id",
        "owner", "acl", "kind", "state", "total", "charged",
        "authoritative_total", "available", "paid", "transitioned_by",
        "applied", "subject", "token", "uses_allowed", "uses_left",
        "spent", "display_total", "transition_history",
    ]
    field_names = {
        role: f"f{rng.randrange(100, 999)}{role[:3]}"
        for role in field_roles
    }
    param_roles = [
        "actor", "resource", "account", "amount", "action", "idem",
        "subject", "token",
    ]
    param_names = {
        role: f"q{rng.randrange(100, 999)}{role[:3]}"
        for role in param_roles
    }
    action_names = {
        role: f"mv-{role[:3]}-{rng.randrange(10, 99)}"
        for role in ("submit", "approve", "release", "finalize")
    }
    owner_header = f"x-{rng.randrange(100, 999)}-holder"
    outcome_header = f"x-{rng.randrange(100, 999)}-verdict"
    group_names = {
        "holdings": f"h{rng.randrange(100, 999)}",
        "operations": f"o{rng.randrange(100, 999)}",
        "approvals": f"a{rng.randrange(100, 999)}",
    }

    actors = [actor_ids["a"], actor_ids["b"]]
    records = [
        {
            "record_id":
                f"{_pfx('rcd', rng)}-{rng.randrange(100000, 999999)}",
            "kind": "ledger-entry",
            "owner": actors[index % 2],
            "acl": {actors[index % 2], actor_ids["admin"]},
            "total": 60 + 10 * index,
        }
        for index in range(6)
    ]
    accounts = [
        {
            "account_id":
                f"{_pfx('bal', rng)}-{rng.randrange(100000, 999999)}",
            "owner": actors[index % 2],
            "acl": {actors[index % 2], actor_ids["admin"]},
            "available": 90 + 15 * index,
        }
        for index in range(4)
    ]

    workflows: list[dict[str, Any]] = []
    state_chains: dict[str, list[str]] = {}
    action_targets: dict[str, dict[str, str]] = {}
    order = ["submit", "approve", "release", "finalize"]
    for wf_index in range(3):
        wf_id = (
            f"{_pfx('apv', rng)}-{rng.randrange(100000, 999999)}"
            f"-{rng.randrange(100, 999)}")
        chain = [f"ph-{rng.randrange(10, 99)}{s}" for s in "abc"]
        if wf_index == 1:
            chain.append(f"ph-{rng.randrange(10, 99)}d")
        workflows.append({
            "workflow_id": wf_id,
            "owner": actors[0] if wf_index == 0 else actors[1],
            "acl": {actors[0] if wf_index == 0 else actors[1],
                    actor_ids["admin"]},
            "resource_id": records[wf_index]["record_id"],
        })
        state_chains[wf_id] = chain
        action_targets[wf_id] = {
            action_names[order[edge]]: chain[edge + 1]
            for edge in range(len(chain) - 1)
        }

    # Implementation and defect profile: explicit keys win, the rest
    # rotate deterministically by seed.
    defaults: dict[str, Any] = {
        "denial_status": int(rng.choice(DENIAL_STYLES)),
        "ownership_impl": OWNERSHIP_IMPLS[seed % len(OWNERSHIP_IMPLS)],
        "identity_read_enforced": bool(seed % 2),
        "identity_mutation_enforced": not bool(seed % 3),
        "checkout_impl": CHECKOUT_IMPLS[seed % len(CHECKOUT_IMPLS)],
        "approver_impl": APPROVER_IMPLS[seed % len(APPROVER_IMPLS)],
        "order_impl": ORDER_IMPLS[seed % len(ORDER_IMPLS)],
        "workflow_identity_enforced": {},
        "order_enforced": {},
        "spend_impl": SPEND_IMPLS[seed % len(SPEND_IMPLS)],
        "spend_limit": 150,
        "grant_impl": GRANT_IMPLS[seed % len(GRANT_IMPLS)],
        "grant_uses_allowed": 1,
    }
    if (grant_impl := profile_over(profile, "grant_impl")) is not None:
        defaults["grant_impl"] = grant_impl
    if defaults["grant_impl"] == "two-use":
        defaults["grant_uses_allowed"] = 2
    for key in ("identity_read_enforced", "identity_mutation_enforced",
                "checkout_impl", "spend_impl", "ownership_impl",
                "approver_impl", "order_impl"):
        if (value := profile_over(profile, key)) is not None:
            defaults[key] = value
    # Workflows: wf0 carries the order family target, wf2 the identity
    # family target (mirroring the corpus convention that every family
    # has an enforced sibling in the same deployment).
    defaults["workflow_identity_enforced"] = {
        wf["workflow_id"]: (wf is not workflows[2])
        for wf in workflows
    }
    defaults["order_enforced"] = {
        wf["workflow_id"]: (wf is not workflows[0])
        for wf in workflows
    }
    # Workflow enforcement is profile-overridable too: a True value
    # secures every workflow (the fully-secured negative profile), a
    # dict merges per-workflow flags over the rotation.
    for key in ("workflow_identity_enforced", "order_enforced"):
        value = profile_over(profile, key)
        if value is True:
            defaults[key] = {wf["workflow_id"]: True for wf in workflows}
        elif isinstance(value, dict):
            defaults[key] = {**defaults[key], **value}

    return LabSpec(
        instance_id=instance_id or f"lab-{seed}",
        seed=seed,
        blind=blind,
        app_name=f"lab-{rng.randrange(1000, 9999)}",
        record_segment=record_segment,
        mutate_segment=mutate_segment,
        checkout_segment=checkout_segment,
        approval_segment=approval_segment,
        spend_segment=spend_segment,
        grant_segment=grant_segment,
        consume_segment=consume_segment,
        record_prefix="rcd",
        workflow_prefix="apv",
        account_prefix="bal",
        actor_ids=actor_ids,
        field_names=field_names,
        param_names=param_names,
        action_names=action_names,
        owner_header=owner_header,
        outcome_header=outcome_header,
        group_names=group_names,
        records=records,
        accounts=accounts,
        workflows=workflows,
        state_chains=state_chains,
        action_targets=action_targets,
        **defaults,
    )


def profile_over(profile: dict[str, Any] | None, key: str) -> Any:
    if not isinstance(profile, dict):
        return None
    return profile.get(key)


def _pfx(prefix: str, rng: random.Random) -> str:
    return f"{prefix}{rng.randrange(10, 99)}"


class LabTarget:
    """A loopback deployment serving one LabSpec.

    The HTTP lifecycle is this module's own implementation (its own
    handler class and server wiring), not a subclass of any fixture
    target. Mutations are applied at most once per (family, key,
    idempotency token) so a resumed investigation never re-applies one.
    """

    def __init__(self, spec: LabSpec) -> None:
        self.spec = spec
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.reset()

    # --------------------------------------------------------------- lifecycle
    def start(self) -> LabTarget:
        self.reset()
        handler = _LabRequestHandler
        handler.target = self  # type: ignore[attr-defined]
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> LabTarget:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def reset(self) -> None:
        spec = self.spec
        with self._lock:
            self._request_count = 0
            self._records = {
                item["record_id"]: {**item, "acl": set(item["acl"])}
                for item in spec.records
            }
            self._accounts = {
                item["account_id"]: {**item, "acl": set(item["acl"])}
                for item in spec.accounts
            }
            self._workflows = {
                item["workflow_id"]: {**item, "acl": set(item["acl"])}
                for item in spec.workflows
            }
            self._wf_state = {
                wf_id: spec.state_chains[wf_id][0]
                for wf_id in self._workflows
            }
            self._wf_history: dict[str, list[str]] = {
                wf_id: [] for wf_id in self._workflows
            }
            self._receipts: dict[str, dict[str, Any]] = {}
            self._grants: dict[str, dict[str, Any]] = {}
            self._grant_seq = 0
            self._applied_mutations: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------ introspection
    @property
    def target_origin(self) -> str:
        if self._server is None:
            raise RuntimeError("lab target not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    def get(
        self, path: str, params: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        return self._http("GET", path, params)

    def post(
        self, path: str, params: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        return self._http("POST", path, params)

    def _http(
        self, method: str, path: str, params: dict[str, str] | None,
    ) -> tuple[int, dict[str, str], Any]:
        query = ""
        if params:
            query = "?" + "&".join(
                f"{key}={value}"
                for key, value in sorted(params.items()))
        target_token = set_engagement_target_hosts(self.target_origin)
        try:
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False,
            ) as client:
                if method.upper() == "GET":
                    response = client.get(
                        self.target_origin + path + query)
                else:
                    response = client.post(
                        self.target_origin + path + query)
        finally:
            clear_engagement_target_hosts(target_token)
        headers = {
            key.lower(): value for key, value in response.headers.items()
        }
        try:
            body: Any = json.loads(response.text)
        except ValueError:
            body = response.text
        return response.status_code, headers, body

    # ---------------------------------------------------------------- helpers
    def _actor_of(self, params: dict[str, str]) -> str:
        """Resolve the caller's credential onto this deployment's
        identity space (probe-credential protocol)."""
        external = {
            "actor-a": self.spec.actor_ids["a"],
            "actor-b": self.spec.actor_ids["b"],
            "actor-admin": self.spec.actor_ids["admin"],
        }
        credential = params.get(self.spec.param_names["actor"], "")
        return external.get(credential, credential or "anonymous")

    def _emit(self, roles: dict[str, Any]) -> dict[str, Any]:
        names = self.spec.field_names
        return {
            names.get(key, key): (
                sorted(value) if isinstance(value, set) else value)
            for key, value in roles.items()
        }

    def _headers(self, owner: str, outcome: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            self.spec.outcome_header: outcome,
        }
        if owner and outcome == OUTCOME_GRANTED:
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

    def _denied(self, body: dict[str, Any]) -> tuple[
        int, dict[str, str], str,
    ]:
        return self._json(
            self.spec.denial_status, body,
            self._headers("", OUTCOME_DENIED))

    def _allowed(
        self, item: dict[str, Any], actor: str,
    ) -> bool:
        """The records-ownership invariant, in either implementation.

        Both implementations express the SAME invariant (access
        requires ownership) by different mechanisms: direct comparison
        against the owner, or membership in the item's ACL.
        """
        if actor == self.spec.actor_ids["admin"]:
            return True
        if self.spec.ownership_impl == "acl-set":
            return actor in item["acl"]
        return actor == item["owner"]

    def _approver_allowed(
        self, wf: dict[str, Any], actor: str,
    ) -> bool:
        """The approver-identity invariant, in either implementation."""
        if actor == self.spec.actor_ids["admin"]:
            return True
        if self.spec.approver_impl == "approver-acl":
            return actor in wf["acl"]
        return actor == wf["owner"]

    def _order_ok(self, wf_id: str, action: str) -> bool:
        """The approval-order invariant, in either implementation."""
        if not self.spec.order_enforced[wf_id]:
            return True
        targets = self.spec.action_targets[wf_id]
        chain = self.spec.state_chains[wf_id]
        target_state = targets[action]
        required = chain[chain.index(target_state) - 1]
        if self.spec.order_impl == "history-sequence":
            history = self._wf_history[wf_id]
            if not history:
                return required == chain[0]
            return history[-1] == required
        return self._wf_state[wf_id] == required

    def _fresh_token(self, family: str, key: str, idem: str) -> bool:
        token = idem or f"{family}:{key}:auto"
        mutation = (family, key, token)
        if mutation in self._applied_mutations:
            return False
        self._applied_mutations.add(mutation)
        return True

    # ------------------------------------------------------------------ GETs
    def handle_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        spec = self.spec
        actor = self._actor_of(params)
        if path in ("/", "/index"):
            return self._json(200, self._index_body())
        if path.startswith(f"/{spec.approval_segment}/"):
            return self._get_workflow(path.rsplit("/", 1)[1], actor)
        if path in self._read_paths():
            return self._get_holding(path.rsplit("/", 1)[1], actor)
        return self._json(404, {"error": "unknown"})

    def _read_paths(self) -> set[str]:
        spec = self.spec
        return {
            f"/{spec.record_segment}/{item_id}"
            for item_id in list(self._records) + list(self._accounts)
        }

    def _get_holding(
        self, item_id: str, actor: str,
    ) -> tuple[int, dict[str, str], str]:
        item = self._records.get(item_id) or self._accounts.get(item_id)
        if item is None:
            return self._json(404, {"error": "unknown"})
        if (self.spec.identity_read_enforced
                and not self._allowed(item, actor)):
            return self._denied({"error": "forbidden"})
        body = {key: value for key, value in item.items()
                if key != "acl"}
        return self._json(
            200, self._emit(body),
            self._headers(item["owner"], OUTCOME_GRANTED))

    def _get_workflow(
        self, wf_id: str, actor: str,
    ) -> tuple[int, dict[str, str], str]:
        wf = self._workflows.get(wf_id)
        if wf is None:
            return self._json(404, {"error": "unknown"})
        # Reading a workflow requires authentication, not ownership:
        # transition authority is the invariant under test, so read
        # visibility is deliberately separate from it.
        if actor == "anonymous":
            return self._denied({"error": "forbidden"})
        body = dict(wf)
        body.pop("acl", None)
        body["state"] = self._wf_state[wf_id]
        body["transition_history"] = list(self._wf_history[wf_id])
        return self._json(
            200, self._emit(body),
            self._headers(wf["owner"], OUTCOME_GRANTED))

    # ----------------------------------------------------------------- POSTs
    def handle_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        spec = self.spec
        actor = self._actor_of(params)
        if actor == "anonymous":
            return self._denied({"error": "forbidden"})
        if path == f"/{spec.checkout_segment}":
            return self._post_checkout(actor, params)
        if path == f"/{spec.mutate_segment}":
            return self._post_mutate(actor, params)
        if path == f"/{spec.spend_segment}":
            return self._post_spend(actor, params)
        if path == f"/{spec.grant_segment}":
            return self._post_grant(actor, params)
        if path == f"/{spec.consume_segment}":
            return self._post_consume(actor, params)
        if path.startswith(f"/{spec.approval_segment}/"):
            return self._post_workflow(
                path.rsplit("/", 1)[1], actor, params)
        return self._json(404, {"error": "unknown"})

    def _post_checkout(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        record_id = params.get(spec.param_names["resource"], "")
        record = self._records.get(record_id)
        if record is None:
            return self._json(404, {"error": "unknown"})
        if not self._allowed(record, actor):
            return self._denied({"error": "forbidden"})
        authoritative = record["total"]
        raw = params.get(spec.param_names["amount"], "")
        client_total = int(raw) if raw.isdigit() else authoritative
        impl = spec.checkout_impl
        if impl == "client-total":
            charged = client_total
        else:
            charged = authoritative
        self._fresh_token(
            "checkout", record_id, params.get(spec.param_names["idem"], ""))
        receipt_id = f"ord-{len(self._receipts) + 1:06d}"
        receipt: dict[str, Any] = {
            "record_id": record_id,
            "owner": record["owner"],
            "charged": charged,
            "authoritative_total": authoritative,
            "applied": True,
        }
        if impl == "mirror-total":
            # A display field that echoes the client's number: the
            # charge is authoritative, the surface is a lookalike.
            receipt["display_total"] = client_total
        self._receipts[receipt_id] = receipt
        return self._json(
            200, self._emit(dict(receipt)),
            self._headers(record["owner"], OUTCOME_GRANTED))

    def _post_mutate(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        record_id = params.get(spec.param_names["resource"], "")
        record = self._records.get(record_id)
        if record is None:
            return self._json(404, {"error": "unknown"})
        if (spec.identity_mutation_enforced
                and not self._allowed(record, actor)):
            return self._denied({"error": "forbidden"})
        self._fresh_token(
            "mutate", record_id, params.get(spec.param_names["idem"], ""))
        return self._json(200, self._emit({
            "record_id": record_id,
            "owner": record["owner"],
            "paid": True,
        }), self._headers(record["owner"], OUTCOME_GRANTED))

    def _post_spend(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        account_id = params.get(spec.param_names["account"], "")
        account = self._accounts.get(account_id)
        if account is None:
            return self._json(404, {"error": "unknown"})
        # Account ownership is always enforced here: the family under
        # test is the spend cap, not ownership.
        if not self._allowed(account, actor):
            return self._denied({"error": "forbidden"})
        raw = params.get(spec.param_names["amount"], "")
        if not raw.isdigit():
            return self._json(400, {"error": "invalid"})
        amount = int(raw)
        impl = spec.spend_impl
        if impl == "per-request" and amount > spec.spend_limit:
            # A fixed per-request ceiling above every account balance:
            # single over-balance withdrawals sail through, so the
            # cumulative spend-cap invariant is defective.
            return self._json(400, {"error": "over_limit"})
        if impl == "cumulative" and amount > account["available"]:
            # The balance itself is the cap and it is tracked across
            # requests: the cumulative spend-cap invariant holds.
            return self._json(400, {"error": "over_limit"})
        self._fresh_token(
            "spend", account_id, params.get(spec.param_names["idem"], ""))
        account["available"] -= amount
        return self._json(200, self._emit({
            "account_id": account_id,
            "owner": account["owner"],
            "spent": amount,
            "available": account["available"],
        }), self._headers(account["owner"], OUTCOME_GRANTED))

    def _post_grant(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        subject = params.get(spec.param_names["subject"], "")
        action = params.get(spec.param_names["action"], "")
        if not subject or not action:
            return self._json(400, {"error": "invalid"})
        self._grant_seq += 1
        token = (
            f"tkn-{self._grant_seq:04d}-"
            f"{spec.seed * 31 + self._grant_seq:08x}")
        self._grants[token] = {
            "subject": subject,
            "action": action,
            "uses_allowed": spec.grant_uses_allowed,
            "uses_left": spec.grant_uses_allowed,
        }
        return self._json(200, self._emit({
            "subject": subject,
            "token": token,
            "uses_allowed": spec.grant_uses_allowed,
            "uses_left": spec.grant_uses_allowed,
            "applied": True,
        }), self._headers("", OUTCOME_GRANTED))

    def _post_consume(
        self, actor: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        token = params.get(spec.param_names["token"], "")
        grant = self._grants.get(token)
        if grant is None:
            return self._denied({"error": "unknown_token"})
        if grant["uses_left"] <= 0:
            return self._denied({"error": "token_exhausted"})
        if spec.grant_impl != "replayable":
            grant["uses_left"] -= 1
        return self._json(200, self._emit({
            "subject": grant["subject"],
            "token": token,
            "uses_allowed": grant["uses_allowed"],
            "uses_left": grant["uses_left"],
            "applied": True,
        }), self._headers("", OUTCOME_GRANTED))

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
            return self._json(
                400, self._emit({
                    "error": "unknown_action",
                    "state": self._wf_state[wf_id]}))
        if (spec.workflow_identity_enforced[wf_id]
                and not self._approver_allowed(wf, actor)):
            return self._denied({"error": "forbidden"})
        if not self._order_ok(wf_id, action):
            return self._json(
                409, self._emit({
                    "error": "invalid_transition",
                    "state": self._wf_state[wf_id]}),
                self._headers(wf["owner"], OUTCOME_GRANTED))
        self._fresh_token(
            "approval", wf_id, params.get(spec.param_names["idem"], ""))
        self._wf_state[wf_id] = targets[action]
        self._wf_history[wf_id].append(action)
        body = dict(wf)
        body.pop("acl", None)
        body["state"] = self._wf_state[wf_id]
        body["transition_history"] = list(self._wf_history[wf_id])
        body["transitioned_by"] = actor
        body["applied"] = True
        return self._json(
            200, self._emit(body),
            self._headers(wf["owner"], OUTCOME_GRANTED))

    # ----------------------------------------------------------------- index
    def _index_body(self) -> dict[str, Any]:
        spec = self.spec
        names = spec.field_names
        holdings = [
            {
                "path": f"/{spec.record_segment}/{item['record_id']}",
                names["kind"]: item["kind"],
            }
            for item in spec.records
        ] + [
            {
                "path": f"/{spec.record_segment}/{item['account_id']}",
                names["available"]: item["available"],
            }
            for item in spec.accounts
        ]
        operations = [
            {
                "path": f"/{spec.checkout_segment}",
                "role": "checkout",
                spec.param_names["resource"]: "rid",
                spec.param_names["amount"]: "n",
                spec.param_names["idem"]: "idem",
            },
            {
                "path": f"/{spec.mutate_segment}",
                "role": "pay",
                spec.param_names["resource"]: "rid",
                spec.param_names["idem"]: "idem",
            },
            {
                "path": f"/{spec.spend_segment}",
                "role": "spend",
                spec.param_names["account"]: "aid",
                spec.param_names["amount"]: "n",
                spec.param_names["idem"]: "idem",
            },
            {
                "path": f"/{spec.grant_segment}",
                "role": "grant",
                spec.param_names["subject"]: "sub",
                spec.param_names["action"]: "act",
            },
            {
                "path": f"/{spec.consume_segment}",
                "role": "consume",
                spec.param_names["token"]: "tkn",
            },
        ]
        workflows = [
            {"path": f"/{spec.approval_segment}/{item['workflow_id']}"}
            for item in spec.workflows
        ]
        kinds: dict[str, str] = {}
        for item in holdings:
            kinds[item["path"]] = "read"
        for item in workflows:
            kinds[item["path"]] = "workflow"
        for item in operations:
            kinds[item["path"]] = "mutate"
        return {
            "app": spec.app_name,
            "api": {
                spec.group_names["holdings"]: holdings,
                spec.group_names["operations"]: operations,
                spec.group_names["approvals"]: workflows,
            },
            "kinds": kinds,
            "schema": spec.schema(),
        }


class _LabRequestHandler(BaseHTTPRequestHandler):
    """Minimal GET/POST handler; all logic delegates to the target."""

    target: LabTarget

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
        }
        status, headers, body = self.target.handle_get(
            parsed.path, params)
        self._respond(status, headers, body)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        params = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
        }
        status, headers, body = self.target.handle_post(
            parsed.path, params)
        self._respond(status, headers, body)

    def _respond(
        self, status: int, headers: dict[str, str], body: str,
    ) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *_args: Any) -> None:
        pass
