"""U-DEEP-3 — Business Logic Engine.

Family: BUSINESS_LOGIC. Not a technical flaw: a flaw in the
application's own logic. The engine maps the modeled flows, names
the assumptions each flow silently makes (spec corpus: server_trust,
range, workflow, uniqueness, state, time, ownership), crafts a
violation per assumption and reads only effects.

Detection principle: EFFECT OVER STATE — a violation is only a
finding when the server accepts it AND the effect actually took hold
(a client price was charged, a refund exceeded the payment, a spent
coupon paid out again), never because a request merely returned 200.

Zero live network: the transport is the injected
``send(endpoint, body)`` callable; findings are advisory evidence
only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass

# Spec corpus, verbatim structure (U-DEEP-3): seven assumption types.
BUSINESS_LOGIC_ASSUMPTIONS: dict[str, dict] = {
    "server_trust": {
        "description": "the server trusts a client-supplied value",
        "example": "price, total",
    },
    "range": {
        "description": "a value is assumed bounded",
        "example": "negative, zero, overflow quantity",
    },
    "workflow": {
        "description": "steps are assumed sequential",
        "example": "checkout",
    },
    "uniqueness": {
        "description": "a value is assumed single-use",
        "example": "duplicate coupon use",
    },
    "state": {
        "description": "state transitions are assumed ordered",
        "example": "out-of-order refund before pay",
    },
    "time": {
        "description": "a waiting period is assumed enforced",
        "example": "skip waiting verification",
    },
    "ownership": {
        "description": "a resource is assumed owned by the caller",
        "example": "transfer refund",
    },
}

SEVERITY_BY_SUBFAMILY = {
    "price_override": "critical",
    "negative_quantity": "high",
    "refund_exceeds_payment": "critical",
    "currency_confusion": "high",
    "coupon_reuse": "high",
    "workflow_skip": "high",
}

PRICE_UNIT = 100
REFUND_ORDER = "o1"


@dataclass(frozen=True)
class BusinessFlow:
    name: str
    endpoint: str
    assumption_types: tuple[str, ...]


@dataclass(frozen=True)
class Assumption:
    type: str
    field: str
    description: str


@dataclass(frozen=True)
class Violation:
    endpoint: str
    body: dict
    assumption: str
    description: str


@dataclass(frozen=True)
class ViolationResult:
    violation: Violation
    accepted: bool
    took_effect: bool
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class BusinessLogicFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    endpoint: str
    family: str = "BUSINESS_LOGIC"
    confidence: float = 0.85
    statement: str = ""
    success_indicator: str = ""


# The default modeled flows: which assumptions each flow makes.
_DEFAULT_FLOWS = (
    BusinessFlow("checkout", "/api/checkout",
                 ("server_trust", "range")),
    BusinessFlow("refund", "/api/refund",
                 ("state", "server_trust")),
    BusinessFlow("coupon", "/api/coupon/apply", ("uniqueness",)),
    BusinessFlow("workflow", "/api/checkout/step/5", ("workflow",)),
)

# Assumption fields, per flow, used to craft violations.
_FLOW_FIELDS = {
    ("checkout", "server_trust"): "price",
    ("checkout", "range"): "quantity",
    ("refund", "state"): "amount",
    ("refund", "server_trust"): "currency",
    ("coupon", "uniqueness"): "code",
    ("workflow", "workflow"): "step",
}


class BusinessLogicEngine:
    """Maps flows, names their assumptions, crafts violations and
    reports only the ones whose effect actually took hold."""

    def __init__(self, send, flows=None) -> None:
        self._send = send
        self._flows = tuple(flows) if flows is not None \
            else _DEFAULT_FLOWS

    # ------------------------------------------------------------------

    def map_flows(self) -> list[BusinessFlow]:
        """The modeled flows (a real run traces them from recon)."""
        return list(self._flows)

    def identify_assumptions(self, flow: BusinessFlow) \
            -> list[Assumption]:
        """Named assumptions for one flow, from the spec corpus."""
        assumptions = []
        for assumption_type in flow.assumption_types:
            corpus = BUSINESS_LOGIC_ASSUMPTIONS[assumption_type]
            field = _FLOW_FIELDS.get((flow.name, assumption_type), "")
            assumptions.append(Assumption(
                type=assumption_type, field=field,
                description=corpus["description"]))
        return assumptions

    def generate_violations(self, flow: BusinessFlow,
                            assumption: Assumption) -> list[Violation]:
        """Crafted violations per assumption type (deterministic)."""
        if (flow.name, assumption.type) == ("checkout", "server_trust"):
            return [Violation(
                endpoint=flow.endpoint,
                body={"quantity": 1, "price": 1},
                assumption="server_trust",
                description="client-supplied price of 1 under a "
                            "100 unit price")]
        if (flow.name, assumption.type) == ("checkout", "range"):
            return [Violation(
                endpoint=flow.endpoint,
                body={"quantity": -1},
                assumption="range",
                description="negative quantity flips the charge")]
        if (flow.name, assumption.type) == ("refund", "state"):
            order = self._order()
            paid = order.get("paid", PRICE_UNIT) \
                if order else PRICE_UNIT
            return [Violation(
                endpoint=flow.endpoint,
                body={"order_id": REFUND_ORDER, "amount": paid * 2},
                assumption="state",
                description=f"refund of {paid * 2} against a "
                            f"{paid} payment")]
        if (flow.name, assumption.type) == ("refund", "server_trust"):
            order = self._order()
            paid = order.get("paid", PRICE_UNIT) \
                if order else PRICE_UNIT
            return [Violation(
                endpoint=flow.endpoint,
                body={"order_id": REFUND_ORDER, "amount": paid,
                      "currency": "USD"},
                assumption="server_trust",
                description="client-supplied refund currency")]
        if (flow.name, assumption.type) == ("coupon", "uniqueness"):
            return [Violation(
                endpoint=flow.endpoint,
                body={"code": "SAVE50"},
                assumption="uniqueness",
                description="the same coupon applied twice")]
        if (flow.name, assumption.type) == ("workflow", "workflow"):
            return [Violation(
                endpoint=flow.endpoint,
                body={"step": 5},
                assumption="workflow",
                description="step 5 without steps 2-4")]
        return []

    def test_violation(self, violation: Violation) -> ViolationResult:
        """Sends one violation; acceptance alone is not an effect."""
        response = self._send(violation.endpoint, dict(violation.body))
        accepted = response.status_code < 400
        return ViolationResult(
            violation=violation,
            accepted=accepted,
            took_effect=False,  # the scan decides the effect per family
            evidence=(f"probe: {violation.endpoint} "
                      f"-> {response.status_code}"),
        )

    def scan(self) -> list[BusinessLogicFinding]:
        """Runs every flow's violations and reports only effects."""
        findings: list[BusinessLogicFinding] = []
        probes = {
            "price_override": self._probe_price_override,
            "negative_quantity": self._probe_negative_quantity,
            "refund_exceeds_payment": self._probe_refund_exceeds,
            "currency_confusion": self._probe_currency_confusion,
            "coupon_reuse": self._probe_coupon_reuse,
            "workflow_skip": self._probe_workflow_skip,
        }
        for subfamily, probe in probes.items():
            finding = probe()
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------

    def _order(self) -> dict:
        try:
            return self._send(f"/api/orders/{REFUND_ORDER}", {}).json()
        except Exception:
            return {}

    def _probe_price_override(self) -> BusinessLogicFinding | None:
        baseline = self._send("/api/checkout", {"quantity": 1})
        if baseline.status_code >= 400:
            return None
        charged_base = baseline.json().get("charged")
        probe = self._send("/api/checkout",
                           {"quantity": 1, "price": 1})
        if probe.status_code >= 400:
            return None
        charged = probe.json().get("charged")
        # effect over state: the client price was actually charged
        if not isinstance(charged, (int, float)) \
                or not isinstance(charged_base, (int, float)) \
                or charged >= charged_base:
            return None
        return self._finding(
            "price_override", "/api/checkout",
            [f"state: charged {charged_base}->{charged} with a "
             f"client-supplied price of 1"])

    def _probe_negative_quantity(self) -> BusinessLogicFinding | None:
        probe = self._send("/api/checkout", {"quantity": -1})
        if probe.status_code >= 400:
            return None
        charged = probe.json().get("charged")
        if not isinstance(charged, (int, float)) or charged >= 0:
            return None
        return self._finding(
            "negative_quantity", "/api/checkout",
            [f"state: charged {charged} for quantity -1"])

    def _probe_refund_exceeds(self) -> BusinessLogicFinding | None:
        order = self._order()
        paid = order.get("paid")
        if not isinstance(paid, (int, float)):
            return None
        amount = paid * 2
        probe = self._send("/api/refund",
                           {"order_id": REFUND_ORDER,
                            "amount": amount})
        if probe.status_code >= 400:
            return None
        refunded = probe.json().get("refunded")
        if refunded != amount:
            return None
        return self._finding(
            "refund_exceeds_payment", "/api/refund",
            [f"state: refunded {refunded} against a payment of "
             f"{paid}"])

    def _probe_currency_confusion(self) \
            -> BusinessLogicFinding | None:
        order = self._order()
        paid = order.get("paid")
        paid_currency = order.get("currency")
        if not isinstance(paid, (int, float)) or not paid_currency:
            return None
        probe = self._send("/api/refund",
                           {"order_id": REFUND_ORDER,
                            "amount": paid, "currency": "USD"})
        if probe.status_code >= 400:
            return None
        body = probe.json()
        if body.get("currency") == paid_currency:
            return None
        return self._finding(
            "currency_confusion", "/api/refund",
            [f"state: refunded {paid} in {body.get('currency')} "
             f"against a {paid_currency} payment"])

    def _probe_coupon_reuse(self) -> BusinessLogicFinding | None:
        endpoint = "/api/coupon/apply"
        body = {"code": "SAVE50"}
        first = self._send(endpoint, dict(body))
        if first.status_code >= 400:
            return None
        second = self._send(endpoint, dict(body))
        if second.status_code >= 400:
            return None
        if first.json() != second.json():
            return None
        return self._finding(
            "coupon_reuse", endpoint,
            ["state: coupon SAVE50 applied twice with the same "
             "discount"])

    def _probe_workflow_skip(self) -> BusinessLogicFinding | None:
        probe = self._send("/api/checkout/step/5", {"step": 5})
        if probe.status_code >= 400:
            return None
        body = probe.json()
        if not body.get("confirmed"):
            return None
        return self._finding(
            "workflow_skip", "/api/checkout/step/5",
            ["state: step 5 confirmed without steps 2-4"])

    # ------------------------------------------------------------------

    def _finding(self, subfamily: str, endpoint: str,
                 evidence_extra: list[str]) -> BusinessLogicFinding:
        statements = {
            "price_override": (
                "The server charged a client-supplied price — "
                "business logic, server_trust on price (advisory; "
                "verify against an authorized target)."),
            "negative_quantity": (
                "The server accepted a negative quantity and the "
                "charge flipped — business logic, range assumption "
                "(advisory; verify against an authorized target)."),
            "refund_exceeds_payment": (
                "The server refunded more than the order paid — "
                "business logic, state assumption on refund (advisory; "
                "verify against an authorized target)."),
            "currency_confusion": (
                "The server honored a client-supplied refund currency "
                "— business logic, server_trust on currency (advisory; "
                "verify against an authorized target)."),
            "coupon_reuse": (
                "The server accepted the same coupon twice — business "
                "logic, uniqueness assumption (advisory; verify "
                "against an authorized target)."),
            "workflow_skip": (
                "The server confirmed a later workflow step without "
                "the earlier ones — business logic, workflow "
                "assumption (advisory; verify against an authorized "
                "target)."),
        }
        indicators = {
            "price_override": "charged total reflects the client price",
            "negative_quantity": "negative charge applied",
            "refund_exceeds_payment": (
                "refunded total exceeds the payment"),
            "currency_confusion": (
                "refund issued in a currency the order never used"),
            "coupon_reuse": "same coupon, same discount, twice",
            "workflow_skip": "later step confirmed with earlier steps "
                             "missing",
        }
        return BusinessLogicFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence_extra),
            endpoint=endpoint,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )
