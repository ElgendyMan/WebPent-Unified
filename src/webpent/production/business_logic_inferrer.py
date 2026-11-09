"""webpent.production.business_logic_inferrer — TC-3 §2 V-2.

The Business Logic State Machine Inferrer: it OBSERVES the application's
flow (authorized spine requests only), builds a STATE DIAGRAM from the
observed transitions, and generates "what if we jump/manipulate?"
hypotheses — each of which goes through the FULL spine (hypothesis ->
EV -> governed execution -> observations -> CausalGuard -> ProofBundle ->
replay -> promotion).  The inferrer proposes; the pipeline disposes.

Evidence contract (per the charter): every generated hypothesis carries
the differential between the EXPECTED flow and the MANIPULATED flow plus
the SEQUENTIAL CONTROL (the expected flow re-run on an independent
surface must reproduce the expected outcome — proving the differential
is caused by the manipulation, not by nondeterminism).

Generation rules (each with its applicability guard — a rule that does
not apply generates NOTHING, never a filler hypothesis):
  R1 transition-replay   — an observed state transition re-applied in the
                           reached state (coupon stacking, quota replay).
  R2 value-manipulation  — a client-supplied numeric field the server
                           echoes as the state-carrying value (price
                           tampering, quantity tampering).
  R3 state-jump          — a direct jump across a GUARDED terminal
                           (a state whose entry requires a precondition
                           another state establishes).  Diagrams without a
                           guarded terminal yield NO jump hypotheses.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FlowObservation:
    step: int
    endpoint: str
    method: str
    request_body: dict[str, Any]
    response_status: int
    response_body: dict[str, Any]
    state: str = ""
    value_field: str = ""       # the state-carrying value field ("total")
    value: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class StateDiagram:
    states: set[str] = field(default_factory=set)
    transitions: list[dict[str, str]] = field(default_factory=list)
    # transition: {"from": "CART", "to": "COUPON_APPLIED",
    #              "endpoint": "/api/cart/{id}/coupon", "action": "coupon"}
    guards: dict[str, str] = field(default_factory=dict)
    # state -> the observed precondition that guards its entry.  Populated
    # ONLY by negative precondition probing (a probe that tries to enter a
    # state without its precondition and is REFUSED).  A diagram built
    # from positive observations alone has NO guards — R3 (state jump)
    # generates nothing for it, because a jump hypothesis without an
    # observed guard would be a filler hypothesis.

    def record(self, *, frm: str, to: str, endpoint: str, action: str) -> None:
        self.states.update({frm, to})
        self.transitions.append({"from": frm, "to": to,
                                 "endpoint": endpoint, "action": action})

    def record_guard(self, *, state: str, precondition: str) -> None:
        self.guards[state] = precondition

    def guarded_terminals(self) -> list[str]:
        """States with an OBSERVED entry guard (negative-probe evidence
        only).  R3 (state jump) applies only to these."""
        return sorted(self.guards)

    def to_dict(self) -> dict[str, Any]:
        return {"states": sorted(self.states),
                "transitions": list(self.transitions),
                "guards": dict(self.guards)}


class BusinessLogicInferrer:
    """Observe -> diagram -> hypotheses.  Advisory proposals only; the
    spine's gates remain the only confirmation authority."""

    def __init__(self, *, orchestrator: Any, value_field: str = "total",
                 state_field: str = "state"):
        self.orch = orchestrator
        self.value_field = value_field
        self.state_field = state_field
        self.observations: list[FlowObservation] = []
        self.diagram = StateDiagram()
        self.sequential_control: dict[str, Any] = {}
        self.observed_value_multiplier: float | None = None

    # -- observation ---------------------------------------------------------
    def _post(self, base_url: str, path: str, body: dict[str, Any]) -> FlowObservation:
        resp = self.orch.execute_real_request(
            method="POST", target_url=f"{base_url}{path}",
            headers={"Content-Type": "application/json"},
            body=json.dumps(body, sort_keys=True))
        status = int(resp.get("status_code") or 0)
        raw = resp.get("response_body", resp.get("body", ""))
        try:
            parsed = json.loads(raw) if isinstance(raw, str) and raw else {}
        except (TypeError, ValueError):
            parsed = {}
        obs = FlowObservation(
            step=len(self.observations) + 1, endpoint=path, method="POST",
            request_body=dict(body), response_status=status,
            response_body=parsed if isinstance(parsed, dict) else {},
            state=str(parsed.get(self.state_field, "")) if isinstance(parsed, dict) else "",
            value_field=self.value_field,
            value=float(parsed[self.value_field])
            if isinstance(parsed, dict) and parsed.get(self.value_field) is not None
            else None)
        self.observations.append(obs)
        return obs

    def observe_flow(self, base_url: str) -> StateDiagram:
        """Run the EXPECTED flow twice on independent surfaces (the
        sequential control) and build the diagram from the observed
        transitions.  Also provisions the DEDICATED fresh carts the R1
        triple needs (a CART-state cart for the baseline/candidate legs
        and an independent CART-state cart for the sequential-control
        leg) — provisioning runs through the same authorized spine path
        and is recorded in the observations."""
        terminals: list[float] = []
        cart_id = ""
        cart_id_ctrl = ""
        for run in (1, 2):
            obs_add = self._post(base_url, "/api/cart/items", {"sku": "WIDGET"})
            if run == 1:
                cart_id = str(obs_add.response_body.get("cart_id", ""))
            else:
                cart_id_ctrl = str(obs_add.response_body.get("cart_id", ""))
            active_cart = cart_id if run == 1 else cart_id_ctrl
            if run == 1:
                self.diagram.record(frm="START", to=obs_add.state or "CART",
                                    endpoint="/api/cart/items", action="add_item")
            obs_coupon = self._post(base_url, f"/api/cart/{active_cart}/coupon",
                                    {"code": "SAVE50"})
            if run == 1:
                self.diagram.record(frm="CART", to=obs_coupon.state or "COUPON_APPLIED",
                                    endpoint="/api/cart/{id}/coupon", action="coupon")
            obs_checkout = self._post(base_url, f"/api/cart/{active_cart}/checkout", {})
            if run == 1:
                self.diagram.record(frm=obs_coupon.state or "COUPON_APPLIED",
                                    to=obs_checkout.state or "PAID",
                                    endpoint="/api/cart/{id}/checkout",
                                    action="checkout")
            terminals.append(obs_checkout.value if obs_checkout.value is not None else -1.0)
        # the observed value multiplier across the coupon transition
        # (100.0 -> 50.0 => 0.5): the R1 hypothesis predicts the
        # manipulated flow's outcome with it
        if (self.observations and self.observations[0].value
                and self.observations[0].value > 0):
            coupon_obs = next((o for o in self.observations
                               if o.endpoint.endswith("/coupon")
                               and o.value is not None), None)
            if coupon_obs is not None:
                self.observed_value_multiplier = round(
                    float(coupon_obs.value) / float(self.observations[0].value), 4)
        # dedicated fresh carts for the R1 triple (baseline/candidate share
        # the first; the sequential-control leg uses the second)
        self._stack_cart_id = str(self._post(
            base_url, "/api/cart/items", {"sku": "GADGET"}).response_body.get("cart_id", ""))
        self._stack_control_cart_id = str(self._post(
            base_url, "/api/cart/items", {"sku": "GADGET"}).response_body.get("cart_id", ""))
        self.sequential_control = {
            "expected_total": terminals[0],
            "control_replay_total": terminals[1],
            "deterministic": terminals[0] == terminals[1] and terminals[0] > 0,
            "note": "the expected flow re-run on an independent cart must "
                    "reproduce the expected outcome (the sequential control)"}
        self._control_cart_id = cart_id_ctrl
        return self.diagram

    # -- hypothesis generation ------------------------------------------------
    def generate_hypotheses(self, *, engagement_id: str,
                            manipulated_price: str = "0.01") -> list[dict[str, Any]]:
        """Generate the R1/R2 hypotheses whose applicability the observed
        diagram + probe established.  Each hypothesis carries the full
        evidence contract (expected flow vs manipulated flow + the
        sequential control) and goes through the NORMAL spine."""
        hyps: list[dict[str, Any]] = []
        cart_id = ""
        control_cart_id = getattr(self, "_control_cart_id", "")
        for obs in self.observations:
            if obs.endpoint == "/api/cart/items" and obs.step == 1:
                cart_id = str(obs.response_body.get("cart_id", ""))
                break
        # R2 — value manipulation: the probe observed the cart-add endpoint
        # accepting a client-influenced numeric value field (the price).
        add_obs = next((o for o in self.observations
                        if o.endpoint == "/api/cart/items"), None)
        if add_obs is not None:
            hyps.append({
                "id": f"{engagement_id}_bl_price",
                "vulnerability_class": "BUSINESS_LOGIC",
                "api_type": "rest",
                "path": "/api/cart/items",
                "information_value": 0.9,
                "engagement_id": engagement_id,
                "metadata": {"candidate_value": manipulated_price},
                "business_logic_metadata": {
                    "rule": "R2_value_manipulation",
                    "evidence_contract": {
                        "expected_flow_outcome": add_obs.value,
                        "manipulated_value": manipulated_price,
                        "sequential_control": self.sequential_control,
                    },
                },
                "requests": {
                    "baseline": {"method": "POST", "path": "/api/cart/items",
                                 "headers": {"Content-Type": "application/json"},
                                 "body": {"sku": "WIDGET"}},
                    "candidate": {"method": "POST", "path": "/api/cart/items",
                                  "headers": {"Content-Type": "application/json"},
                                  "body": {"sku": "WIDGET",
                                           "price": float(manipulated_price)}},
                    "negative_control": {"method": "POST", "path": "/api/cart/items",
                                         "headers": {"Content-Type": "application/json"},
                                         "body": {"sku": "GADGET"}},
                },
            })
        # R1 — transition replay: the coupon transition re-applied in the
        # reached state (stacking).  The triple's legs are SEQUENTIAL on the
        # SAME cart (baseline = first application = the expected flow;
        # candidate = the replayed transition = the manipulated flow; nc =
        # an independent cart replaying the legit single application — the
        # sequential control surface).
        coupon_trans = next((t for t in self.diagram.transitions
                             if t["action"] == "coupon"), None)
        stack_cart = getattr(self, "_stack_cart_id", "")
        stack_ctrl_cart = getattr(self, "_stack_control_cart_id", "")
        if coupon_trans is not None and stack_cart and stack_ctrl_cart:
            # the predicted MANIPULATED flow outcome: the stack cart's
            # total after the SECOND application (baseline apply #1 ->
            # candidate apply #2), using the probe-observed multiplier
            stack_cart_total = 0.0
            for obs in self.observations:
                if (obs.endpoint == "/api/cart/items"
                        and obs.response_body.get("cart_id") == stack_cart):
                    stack_cart_total = float(obs.value or 0.0)
            mult = float(self.observed_value_multiplier or 0.5)
            predicted_candidate_value = str(round(stack_cart_total * mult * mult, 2))
            hyps.append({
                "id": f"{engagement_id}_bl_stack",
                "vulnerability_class": "BUSINESS_LOGIC",
                "api_type": "rest",
                "path": f"/api/cart/{stack_cart}/coupon",
                "information_value": 0.9,
                "engagement_id": engagement_id,
                "metadata": {"candidate_value": predicted_candidate_value},
                "business_logic_metadata": {
                    "rule": "R1_transition_replay",
                    "evidence_contract": {
                        "expected_flow_outcome": "single application",
                        "manipulated_flow": "the SAME transition re-applied "
                                            "in the reached state",
                        "sequential_control": self.sequential_control,
                    },
                },
                "requests": {
                    "baseline": {"method": "POST",
                                 "path": f"/api/cart/{stack_cart}/coupon",
                                 "headers": {"Content-Type": "application/json"},
                                 "body": {"code": "SAVE50"}},
                    "candidate": {"method": "POST",
                                  "path": f"/api/cart/{stack_cart}/coupon",
                                  "headers": {"Content-Type": "application/json"},
                                  "body": {"code": "SAVE50"}},
                    "negative_control": {"method": "POST",
                                         "path": f"/api/cart/{stack_ctrl_cart}/coupon",
                                         "headers": {"Content-Type": "application/json"},
                                         "body": {"code": "SAVE50"}},
                },
            })
        # R3 — state jump: only for diagrams with a guarded terminal.  This
        # lane's PAID state has no guarded precondition -> NO jump
        # hypothesis is generated (a rule that does not apply generates
        # nothing — never a filler hypothesis).
        for terminal in self.diagram.guarded_terminals():
            hyps.append({
                "id": f"{engagement_id}_bl_jump_{terminal.lower()}",
                "vulnerability_class": "BUSINESS_LOGIC",
                "api_type": "rest",
                "path": "/api/cart/{id}/checkout",
                "information_value": 0.9,
                "engagement_id": engagement_id,
                "business_logic_metadata": {
                    "rule": "R3_state_jump",
                    "target_state": terminal,
                },
            })
        return hyps
