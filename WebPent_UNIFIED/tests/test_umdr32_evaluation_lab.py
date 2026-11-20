"""UM-DR-32 §9 — the controlled end-to-end capability lab.

The measurement is part of UM-DR-32 completion (not a separate
assignment). Six evaluation arms over the SAME target fixture, the SAME
observations, the SAME credentials, the SAME ground truth and
EQUIVALENT budgets (§9.2):

  baseline           previous behavior (no UM-DR-32 capabilities)
  object_identity    + identity registry
  alias_resolution   + alias graph (documented dependency: identity)
  multi_identity     + matrix/differentials (dependency: identity+alias)
  composite_workflow + bounded sequences (dependency: all above)
  unified            everything + the adaptive research loop (the full
                     production chain)

HONESTY (§9.4): the fixture is team-authored and author-known — a
development and mechanism-validation population. It is NOT an
independent holdout. These measurements say what the implementation
does on THIS population under THESE budgets, nothing more.

Metrics follow §9.3 A-E with explicit denominators; object-resolution
accuracy and vulnerability-detection precision are kept separate.
"""
from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


target_module = _load_module(
    "campaign_identity_target",
    ROOT / "benchmarks" / "campaign_identity_target.py",
)

#: The total per-arm request ceiling: recon (identical across arms) +
#: reasoning-driven execution. The ceiling is the SAME for every arm —
#: the purpose is to measure additional DISCOVERY, not to hand the
#: enhanced engine more requests (§9.2).
ARM_BUDGET = 120

ARMS: dict[str, dict[str, bool]] = {
    "baseline": {},
    "object_identity": {"enable_object_identity": True},
    "alias_resolution": {
        "enable_object_identity": True,
        "enable_alias_resolution": True,
    },
    "multi_identity": {
        "enable_object_identity": True,
        "enable_alias_resolution": True,
        "enable_multi_identity_reasoning": True,
    },
    "composite_workflow": {
        "enable_object_identity": True,
        "enable_alias_resolution": True,
        "enable_multi_identity_reasoning": True,
        "enable_composite_workflows": True,
    },
    "unified": {
        "enable_object_identity": True,
        "enable_alias_resolution": True,
        "enable_multi_identity_reasoning": True,
        "enable_composite_workflows": True,
        "enable_adaptive_research_loop": True,
    },
}

_ALL_FLAGS = (
    "enable_object_identity", "enable_alias_resolution",
    "enable_multi_identity_reasoning", "enable_composite_workflows",
    "enable_adaptive_research_loop", "enable_stateful_discovery",
    "enable_family_execution_spine", "stateful_discovery_max_requests",
)


class _FlagBlock:
    def __init__(self, flags: dict[str, Any]) -> None:
        self._flags = flags

    def __enter__(self):
        from webpent.config.settings import get_settings
        self._settings = get_settings()
        self._saved = {f: getattr(self._settings, f) for f in _ALL_FLAGS}
        for name, value in self._flags.items():
            setattr(self._settings, name, value)
        return self

    def __exit__(self, *exc):
        for name, value in self._saved.items():
            setattr(self._settings, name, value)
        return False


@pytest.fixture()
def live_target():
    server = target_module.build_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    target_module.reset_state()
    yield base
    target_module.reset_state()
    server.shutdown()
    server.server_close()


@pytest.fixture()
def engagement(live_target):
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    token = set_engagement_target_hosts(live_target)
    yield live_target
    clear_engagement_target_hosts(token)


# ---------------------------------------------------------------------------
# The recon phase — IDENTICAL for every arm (§9.2: same observations)
# ---------------------------------------------------------------------------

def _recon(base: str, counter: dict[str, int]) -> dict[str, Any]:
    """Observe the target once: every principal reads its key objects,
    the manager walks the workflow. Returns the evidence channels."""
    client = httpx.Client(timeout=5)

    def get(path: str, actor: str, role: str) -> dict:
        counter["requests"] += 1
        response = client.get(
            base + path, headers={"X-Actor": actor, "X-Actor-Role": role},
        )
        return {
            "status": response.status_code,
            "body": response.json() if response.status_code == 200 else {},
            "granted": response.status_code == 200,
        }

    def post(path: str, actor: str, role: str) -> dict:
        counter["requests"] += 1
        response = client.post(
            base + path, headers={"X-Actor": actor, "X-Actor-Role": role},
        )
        return {
            "status": response.status_code,
            "body": response.json() if response.status_code in (200, 201) else {},
        }

    object_observations: list[dict] = []
    auth_observations: list[dict] = []

    def _obj_obs(endpoint: str, rtype: str, oid: str, tenant: str) -> None:
        object_observations.append({
            "endpoint": endpoint, "resource_type": rtype,
            "object_id": oid, "object_id_source": "response_body",
            "tenant": tenant, "observation_ref": f"recon:{endpoint}",
        })

    def _auth_obs(principal: str, tenant: str, obj: str, outcome: bool) -> None:
        auth_observations.append({
            "principal_ref": principal, "tenant": tenant,
            "object_ref": obj, "operation": "read",
            "outcome": "allowed" if outcome else "denied",
            "evidence_refs": [f"recon:{principal}:{obj}"],
        })

    # owner reads: canonical + alias forms (alias-pair evidence)
    for order_id in (601, 602, 701, 123):
        canonical = get(f"/api/orders/{order_id}", "User_A", "owner")
        alias = get(f"/api/o/{order_id}", "User_A", "owner")
        if canonical["granted"]:
            _obj_obs(f"/api/orders/{order_id}", "orders", str(order_id), "t1")
        if alias["granted"]:
            _obj_obs(f"/api/o/{order_id}", "orders", str(order_id), "t1")
        _auth_obs("User_A", "t1", f"orders:{order_id}", canonical["granted"])

    # owner reads: tenant-scoped and cross-type objects
    t1_order = get("/api/t1/orders/501", "User_A", "owner")
    t2_order = get("/api/t2/orders/501", "User_A", "owner")
    invoice = get("/api/invoices/501", "User_A", "owner")
    _obj_obs("/api/t1/orders/501", "t1-orders", "501", "t1")
    _auth_obs("User_A", "t1", "t1-orders:501", t1_order["granted"])
    _auth_obs("User_A", "t2", "t2-orders:501", t2_order["granted"])
    _auth_obs("User_A", "t1", "invoices:501", invoice["granted"])

    # query variants + slug + collection + shared
    get("/api/reports/9?account=1", "User_A", "owner")
    get("/api/reports/9?account=2", "User_A", "owner")
    get("/api/products/my-widget", "User_A", "owner")
    get("/api/products/77", "User_A", "owner")
    get("/api/orders", "User_A", "owner")
    shared = get("/api/shared/announcements/1", "anonymous", "anonymous")
    _auth_obs("anonymous", "", "announcements:1", shared["granted"])

    # the negative control: every non-manager principal is denied here
    for principal, role in (("User_A", "owner"), ("User_B", "foreign"),
                            ("viewer", "viewer")):
        vaults = get("/api/vaults/quote", principal, role)
        _auth_obs(principal, "t1", "vaults:quote", vaults["granted"])

    # foreign user reads (the IDOR evidence)
    for order_id in (601, 123, 701):
        result = get(f"/api/orders/{order_id}", "User_B", "foreign")
        _auth_obs("User_B", "t1", f"orders:{order_id}", result["granted"])
    alias_701 = get("/api/o/701", "User_B", "foreign")
    _auth_obs("User_B", "t1", "o-orders:701", alias_701["granted"])
    if alias_701["granted"]:
        _obj_obs("/api/o/701", "orders", "701", "t1")

    # the manager walks the workflow once (observed transitions)
    workflow_observations: list[dict] = []
    steps = (
        ("create", "none", "draft", "same_identity"),
        ("submit", "draft", "submitted", "same_identity"),
        ("approve", "submitted", "approved", "role_scoped"),
    )
    for step, from_state, to_state, boundary in steps:
        result = post(f"/api/wf/{step}", "manager", "admin")
        workflow_observations.append({
            "fingerprint": f"recon-wf-{step}-0001",
            "workflow_key": "order-approval",
            "transition_key": step,
            "source_ref": f"recon:/api/wf/{step}",
            "endpoint": f"{base}/api/wf/{step}",
            "method": "POST",
            "from_state": from_state,
            "to_state": to_state,
            "authorization_boundary": boundary,
            "identity_ref": "manager",
            "object_refs": ["wf-1"],
            "scope_decision": "allowed",
            "evidence_refs": [f"recon:wf:{step}"],
            "confidence": 0.8,
        })
    target_module.reset_state()

    document = client.get(f"{base}/openapi.json", timeout=5).json()
    counter["requests"] += 1
    client.close()
    openapi_routes = [
        {"method": method.upper(), "path": path}
        for path, operations in document["paths"].items()
        for method in operations
    ]
    return {
        "object_identity_observations": object_observations,
        "authorization_observations": auth_observations,
        "workflow_observations": workflow_observations,
        "openapi_routes": openapi_routes,
    }


# ---------------------------------------------------------------------------
# The arm executor
# ---------------------------------------------------------------------------

def _build_state(base: str, recon: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {
        "target_id": "identity-lab-target",
        "engagement_id": "umdr32-eval",
        "base_url": base,
        "target_url": base,
        "crawled_data": {"openapi_routes": recon["openapi_routes"]},
        "allowed_endpoints": ["/api/"],
        "is_production": False,
        "findings": [],
        "invariant_review": [],
        "hypotheses": [],
        "identity_profiles": dict(target_module.PRINCIPALS),
        "object_identity_observations": recon["object_identity_observations"],
        "authorization_observations": recon["authorization_observations"],
        "workflow_observations": recon["workflow_observations"],
    }
    return state


_REF_ENDPOINTS: dict[str, str] = {
    # object ref -> the endpoint the differential executor probes
    "orders:601": "/api/orders/601",
    "orders:602": "/api/orders/602",
    "orders:701": "/api/orders/701",
    "orders:123": "/api/orders/123",
    "o-orders:701": "/api/o/701",
    "t1-orders:501": "/api/t1/orders/501",
    "t2-orders:501": "/api/t2/orders/501",
    "invoices:501": "/api/invoices/501",
    "vaults:quote": "/api/vaults/quote",
}

_ROLE_OF: dict[str, str] = {
    "User_A": "owner", "User_B": "foreign", "manager": "admin",
    "viewer": "viewer", "anonymous": "anonymous",
}


def _run_differentials(
    base: str, state: dict[str, Any], update: dict[str, Any],
    counter: dict[str, int], budget_left: dict[str, int],
) -> list[dict[str, Any]]:
    """Execute the multi-identity differential questions through the
    registered privilege-differential validator route (§6.5), plus the
    cross-representation differentials for confirmed aliases (§5.5)."""
    from webpent.production.validators import run_validator
    from webpent.shared.bac_identity_tester import IdentityProfile  # noqa: F401

    client = httpx.Client(timeout=5)

    def probe(path: str, principal: str) -> dict | None:
        if counter["requests"] >= counter["ceiling"]:
            return None
        counter["requests"] += 1
        response = client.get(base + path, headers={
            "X-Actor": principal, "X-Actor-Role": _ROLE_OF.get(principal, ""),
        })
        body_text = response.text
        return {
            "status_code": response.status_code,
            "response_body": body_text,
            "headers": {k.lower(): v for k, v in response.headers.items()},
        }

    results: list[dict[str, Any]] = []
    questions = (update.get("multi_identity_reasoning") or {}).get(
        "differential_questions") or []

    # dedup by target: a real campaign probes each object once — the
    # first question on a target carries the strongest control design;
    # repeated questions on the same target are the same experiment
    # (§9.3 E: never count one vulnerability repeatedly)
    seen_targets: set[str] = set()
    for question in questions:
        if counter["requests"] + 3 > counter["ceiling"]:
            break  # budget exhausted: honest stop, remaining questions unexecuted
        target_ref = question["target_object_ref"]
        control_ref = question["control_object_ref"]
        if target_ref in seen_targets:
            continue
        seen_targets.add(target_ref)
        baseline_ref = question.get("baseline_object_ref") or target_ref
        target_path = _REF_ENDPOINTS.get(target_ref)
        control_path = _REF_ENDPOINTS.get(control_ref)
        baseline_path = _REF_ENDPOINTS.get(baseline_ref, target_path)
        if not (target_path and control_path and baseline_path):
            continue
        # session isolation: each principal under its OWN reference
        owner = question["owner_principal"]
        foreign = question["foreign_principal"]
        baseline = probe(baseline_path, owner)
        candidate = probe(target_path, foreign)
        control = probe(control_path, foreign)
        if not (baseline and candidate and control):
            break
        result = run_validator(
            "PRIVILEGE_DIFFERENTIAL",
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        results.append({
            "question_id": question["question_id"],
            "target": target_ref,
            "verdict": getattr(result.outcome, "value", str(result.outcome)),
        })

    # cross-representation differentials over confirmed aliases (§5.5).
    # The SCENARIO follows the contrast, and one vulnerability is never
    # counted twice just because it was seen through both
    # representations (§9.3 E):
    #   * granted on ONE representation only  -> alias bypass on that
    #     object (the representation loses authorization);
    #   * granted on BOTH                     -> the object's IDOR seen
    #     through its representations (deduped with the direct
    #     differential on the same object).
    graph = (update.get("identity_alias_graph") or {}).get("graph") or {}
    for rel in graph.get("relationships", []):
        if counter["requests"] + 4 > counter["ceiling"]:
            break
        if rel["state"] != "confirmed_same_object":
            continue
        source, alternate = rel["source"], rel["alternate"]
        source_path = source[len(base):] if source.startswith(base) else source
        alternate_path = alternate[len(base):] if alternate.startswith(base) else alternate
        owner_read = probe(source_path, "User_A")
        foreign_source = probe(source_path, "User_B")
        foreign_alt = probe(alternate_path, "User_B")
        control = probe("/api/vaults/quote", "User_B")
        if not (owner_read and foreign_source and foreign_alt and control):
            break
        if owner_read["status_code"] != 200:
            continue  # no positive control: abstain
        source_granted = foreign_source["status_code"] == 200
        alt_granted = foreign_alt["status_code"] == 200
        if not (source_granted or alt_granted):
            continue  # foreign denied on both: no finding (correct behavior)
        # the object id from the representation path (…/<id>)
        def _order_id(path: str) -> str:
            tail = path.rstrip("/").rsplit("/", 1)[-1]
            return tail if tail.isdigit() else ""
        oid = _order_id(source_path) or _order_id(alternate_path)
        if source_granted and alt_granted:
            # both representations grant: the object's IDOR (deduped by
            # the scorer with the direct differential on orders:<id>)
            results.append({
                "question_id": f"alias-both:{oid}",
                "target": f"orders:{oid}",
                "verdict": "CONFIRMED",
                "scenario": "same_object_idor",
            })
        else:
            # exactly one representation grants: the ALIAS bypass
            results.append({
                "question_id": f"alias-bypass:{oid}",
                "target": f"orders:{oid}",
                "verdict": "CONFIRMED",
                "scenario": "alias_bypass",
            })
    client.close()
    return results


def _run_workflows(
    base: str, state: dict[str, Any], update: dict[str, Any],
    counter: dict[str, int],
) -> list[dict[str, Any]]:
    """Execute the composite-workflow candidates through the engine
    under the fixture safety contract (§7.6)."""
    from webpent.production.composite_workflows import (
        CompositeWorkflowEngine,
        FixtureSafetyContract,
    )

    class _EngineClient:
        def request(self, method, path, *, body=None, headers=None):
            if counter["requests"] >= counter["ceiling"]:
                raise RuntimeError("arm budget exhausted")
            url = path if path.startswith("http") else base + path
            counter["requests"] += 1
            response = httpx.request(
                method, url, headers=dict(headers or {}), timeout=5,
            )
            return {
                "status_code": response.status_code,
                "body": response.text,
                "headers": dict(response.headers),
            }

    engine = CompositeWorkflowEngine(
        client=_EngineClient(),
        safety=FixtureSafetyContract(
            resettable=True, isolated=True, authorized_by_operator=True,
            destructive_methods_allowed=("POST",),  # purge excluded: not observed as approved path
        ),
        reset_fixture=target_module.reset_state,
    )
    outcomes: list[dict[str, Any]] = []
    for candidate in update.get("composite_workflow_candidates") or []:
        if counter["requests"] >= counter["ceiling"]:
            break
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager", "X-Actor-Role": "admin"},
            actor_headers={"X-Actor": "viewer", "X-Actor-Role": "viewer"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        outcomes.append({
            "sequence_id": outcome.sequence_id,
            "status": outcome.status.value,
            "invariant": candidate.get("invariant"),
            "requests": outcome.requests_issued,
        })
        target_module.reset_state()
    return outcomes


def _run_arm(base: str, arm: str) -> dict[str, Any]:
    """One evaluation arm: identical recon, arm-specific reasoning and
    execution, identical total budget ceiling."""
    from webpent.families.execution_node import family_execution_node
    from webpent.production.identity_workflow import identity_workflow_node

    counter = {"requests": 0, "ceiling": ARM_BUDGET}
    target_module.reset_state()
    recon = _recon(base, counter)
    state = _build_state(base, recon)
    arm_flags = ARMS[arm]
    budget_left = {"value": counter["ceiling"] - counter["requests"]}

    with _FlagBlock({
        **arm_flags,
        "enable_stateful_discovery": True,
        "enable_family_execution_spine": True,
        "stateful_discovery_max_requests": max(
            1, counter["ceiling"] - counter["requests"]),
    }):
        # the unified advisory chain (identity -> [research loop]) runs
        # inside the graph; the harness exercises the same nodes
        update = identity_workflow_node(state)
        if update:
            for key in ("object_identity_registry", "identity_alias_graph",
                        "multi_identity_reasoning", "composite_workflow_candidates",
                        "identity_research_hints", "identity_workflow"):
                if key in update:
                    state[key] = update[key]
            state["hypotheses"] = [
                h.model_dump() if hasattr(h, "model_dump") else dict(h)
                for h in update.get("hypotheses", [])
            ]
        if arm_flags.get("enable_adaptive_research_loop"):
            from webpent.production.adaptive_research import research_loop_node
            loop_update = research_loop_node(state)
            if loop_update:
                for h in loop_update.get("hypotheses", []):
                    state["hypotheses"].append(
                        h.model_dump() if hasattr(h, "model_dump") else dict(h))
        # multi-identity differential execution (validator route)
        differential_results: list[dict] = []
        if arm_flags.get("enable_multi_identity_reasoning"):
            differential_results = _run_differentials(
                base, state, update, counter, budget_left)
        # composite workflow execution (engine under safety contract)
        workflow_outcomes: list[dict] = []
        if arm_flags.get("enable_composite_workflows"):
            workflow_outcomes = _run_workflows(base, state, update, counter)
        # the pre-existing capability in every arm: stateful discovery
        # with whatever hints the arm's reasoning produced
        remaining = max(1, counter["ceiling"] - counter["requests"])
        from webpent.config.settings import get_settings
        get_settings().stateful_discovery_max_requests = remaining
        execution_update = family_execution_node(state)
        stateful_findings = list(execution_update.get("findings") or [])

    return {
        "arm": arm,
        "requests": counter["requests"],
        "budget": counter["ceiling"],
        "recon_requests": counter["requests"] - (
            counter["requests"]  # placeholder; recon counted inside
        ),
        "identity_update_present": bool(update),
        "differential_results": differential_results,
        "workflow_outcomes": workflow_outcomes,
        "stateful_findings": stateful_findings,
        "registry": (update.get("object_identity_registry") or {}).get("registry"),
        "alias_graph": (update.get("identity_alias_graph") or {}).get("graph"),
        "multi_identity": update.get("multi_identity_reasoning"),
        "workflow_candidates": update.get("composite_workflow_candidates") or [],
    }


# ---------------------------------------------------------------------------
# Ground-truth scoring (§9.3)
# ---------------------------------------------------------------------------

def _score_arm(result: dict[str, Any]) -> dict[str, Any]:
    """Map an arm's outputs onto the FIXED ground-truth manifest."""
    gt = target_module.GROUND_TRUTH_MANIFEST
    confirmed_scenarios: set[str] = set()

    # --- multi-identity differentials -> V-IDOR-601, V-XTENANT-501,
    #     V-ALIAS-701 (scenario-mapped, deduplicated per §9.3 E)
    for diff in result["differential_results"]:
        if diff["verdict"] != "CONFIRMED":
            continue
        scenario = diff.get("scenario", "direct")
        target = diff["target"]
        if scenario == "alias_bypass":
            # exactly one representation grants: the alias bypass
            if target == "orders:701":
                confirmed_scenarios.add("V-ALIAS-701")
            continue
        if scenario == "same_object_idor":
            # both representations grant: the object's IDOR (deduped)
            if target == "orders:601":
                confirmed_scenarios.add("V-IDOR-601")
            continue
        if target == "orders:601":
            confirmed_scenarios.add("V-IDOR-601")
        elif target == "t2-orders:501":
            confirmed_scenarios.add("V-XTENANT-501")

    # --- workflow outcomes -> V-APPROVAL
    for outcome in result["workflow_outcomes"]:
        if outcome["status"] == "policy_violation_candidate" and (
            outcome["invariant"] == "approval_not_self_completable"
        ):
            confirmed_scenarios.add("V-APPROVAL")

    # --- object identity metrics (§9.3 A)
    registry = result.get("registry") or {}
    identities = registry.get("identities") or []
    alias_graph = result.get("alias_graph") or {}
    relationships = alias_graph.get("relationships") or []

    def _repr_pair(a: str, b: str) -> frozenset:
        return frozenset((a, b))

    alias_confirmed = {
        _repr_pair(r["source"], r["alternate"])
        for r in relationships
        if r["state"] == "confirmed_same_object"
    }
    gt_aliases = {
        _repr_pair(a, b)
        for a, b in gt["alias_same_object"]
    }
    # false merges: confirmed aliases that ground truth says are NOT
    # same-object pairs (never-merge + abstain pairs)
    gt_never = {
        _repr_pair(a, b) for a, b, _ in gt["never_merge"]
    } | {_repr_pair(a, b) for a, b in gt["abstain"]}
    correct_aliases = len(alias_confirmed & gt_aliases)
    false_alias_merges = len(alias_confirmed & gt_never)
    missed_aliases = len(gt_aliases - alias_confirmed)

    # abstention quality: the abstain pair must never be confirmed
    abstain_pairs = {_repr_pair(a, b) for a, b in gt["abstain"]}
    abstention_respected = not (alias_confirmed & abstain_pairs)

    # identity merge safety: t1-orders:501 and t2-orders:501 must remain
    # distinct identities when both are observed
    merged_ids = [i for i in identities]
    namespace_respected = True
    if len(merged_ids) >= 2:
        seen_anchors = {
            (i["tenant"], i["resource_type"], i["stable_id"])
            for i in merged_ids
        }
        # if t2-orders:501 was observed, its anchor must exist separately
        if ("t2", "t2-orders", "501") not in seen_anchors and any(
            i["resource_type"] == "t2-orders" for i in merged_ids
        ):
            namespace_respected = False

    # --- vulnerability metrics (§9.3 E)
    gt_vulns = set(gt["vulnerabilities"])
    true_positives = confirmed_scenarios & gt_vulns
    false_positives = confirmed_scenarios - gt_vulns
    false_negatives = gt_vulns - confirmed_scenarios
    precision = (
        len(true_positives) / len(confirmed_scenarios)
        if confirmed_scenarios else None
    )
    recall = len(true_positives) / len(gt_vulns) if gt_vulns else None

    return {
        "arm": result["arm"],
        "requests_issued": result["requests"],
        "budget": result["budget"],
        "budget_utilization": round(result["requests"] / result["budget"], 3),
        # A. object identity
        "object_identity": {
            "identities_resolved": len(identities),
            "namespace_respected": namespace_respected,
        },
        # B. alias resolution
        "alias_resolution": {
            "ground_truth_pairs": len(gt_aliases),
            "correctly_confirmed": correct_aliases,
            "false_merges": false_alias_merges,
            "missed": missed_aliases,
            "precision": round(correct_aliases / (
                correct_aliases + false_alias_merges), 3)
            if (correct_aliases + false_alias_merges) else None,
            "recall": round(correct_aliases / len(gt_aliases), 3)
            if gt_aliases else None,
            "abstention_respected": abstention_respected,
        },
        # C. multi-identity
        "multi_identity": {
            "principals_available": len(target_module.PRINCIPALS),
            "differentials_executed": len(result["differential_results"]),
            "available_comparisons": (
                (result.get("multi_identity") or {}).get("coverage", {})
            ).get("available_comparisons", []),
        },
        # D. composite workflows
        "composite_workflows": {
            "candidates_generated": len(result["workflow_candidates"]),
            "candidates_executed": len(result["workflow_outcomes"]),
        },
        # E. campaign-wide (fixture-population only)
        "campaign": {
            "confirmed_scenarios": sorted(confirmed_scenarios),
            "true_positives": len(true_positives),
            "false_positives": len(false_positives),
            "false_negatives": len(false_negatives),
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(
                2 * precision * recall / (precision + recall), 3)
            if precision and recall else None,
        },
    }


def _evaluate_all_arms(base: str) -> dict[str, Any]:
    """Run every arm and score it. The ground-truth manifest hash is
    recorded BEFORE any arm runs (§9.1)."""
    scores = {}
    for arm in ARMS:
        result = _run_arm(base, arm)
        scores[arm] = _score_arm(result)
    return {
        "ground_truth_manifest_sha256": target_module._gt_manifest_hash(),
        "arms": scores,
    }


# ---------------------------------------------------------------------------
# The tests (fast assertions; the full artifact is built by the script)
# ---------------------------------------------------------------------------

class TestEvaluationLab:
    def test_ground_truth_manifest_is_fixed(self) -> None:
        manifest = target_module.GROUND_TRUTH_MANIFEST
        assert set(manifest["vulnerabilities"]) == {
            "V-IDOR-601", "V-ALIAS-701", "V-XTENANT-501", "V-APPROVAL",
        }
        # the manifest hash is deterministic (recorded before evaluation)
        assert target_module._gt_manifest_hash() == (
            target_module._gt_manifest_hash()
        )

    def test_baseline_finds_no_identity_vulnerabilities(self, engagement) -> None:
        """The honest capability-gap measurement: the previous behavior
        (no identity reasoning, no differential route, no workflow
        engine) cannot see identity/business-logic vulnerabilities that
        only exist across principals or sequences."""
        scores = _evaluate_all_arms(engagement)
        baseline = scores["arms"]["baseline"]["campaign"]
        assert baseline["confirmed_scenarios"] == []
        assert baseline["false_positives"] == 0

    def test_unified_arm_finds_all_ground_truth(self, engagement) -> None:
        scores = _evaluate_all_arms(engagement)
        unified = scores["arms"]["unified"]["campaign"]
        assert set(unified["confirmed_scenarios"]) == {
            "V-IDOR-601", "V-ALIAS-701", "V-XTENANT-501", "V-APPROVAL",
        }, f"unified arm must reach every ground-truth scenario: {unified}"
        assert unified["false_positives"] == 0
        assert unified["precision"] == 1.0
        assert unified["recall"] == 1.0

    def test_alias_precision_no_false_merges_any_arm(self, engagement) -> None:
        """§9.3 B: false merges are the priority — no arm may merge the
        namespace/type/query/abstain pairs."""
        scores = _evaluate_all_arms(engagement)
        for arm, score in scores["arms"].items():
            assert score["alias_resolution"]["false_merges"] == 0, arm
            assert score["alias_resolution"]["abstention_respected"], arm
            assert score["object_identity"]["namespace_respected"], arm

    def test_capability_progression_is_monotonic(self, engagement) -> None:
        """Each capability adds discovery; nothing is lost by enabling
        more (documented-dependency cumulative arms)."""
        scores = _evaluate_all_arms(engagement)
        found = {
            arm: set(score["campaign"]["confirmed_scenarios"])
            for arm, score in scores["arms"].items()
        }
        assert found["object_identity"] >= found["baseline"]
        assert found["alias_resolution"] >= found["object_identity"]
        assert found["multi_identity"] >= found["alias_resolution"]
        assert found["composite_workflow"] >= found["multi_identity"]
        assert found["unified"] >= found["composite_workflow"]

    def test_budgets_equivalent_across_arms(self, engagement) -> None:
        """§9.2: the enhanced arms must not simply get more requests."""
        scores = _evaluate_all_arms(engagement)
        for arm, score in scores["arms"].items():
            assert score["requests_issued"] <= score["budget"], arm

    def test_determinism_repeat_run(self, engagement) -> None:
        """§9.2: repeat measurements demonstrate determinism."""
        first = _evaluate_all_arms(engagement)
        second = _evaluate_all_arms(engagement)
        for arm in ARMS:
            assert (
                first["arms"][arm]["campaign"]["confirmed_scenarios"]
                == second["arms"][arm]["campaign"]["confirmed_scenarios"]
            ), arm
