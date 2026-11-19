"""Business-logic flaw probes: price, coupon, workflow, and quantity abuse.

PURE LOGIC ONLY. No I/O. This module builds the concrete request triples that
AVI executes through the governed boundary, and it defines the value-shape
catalog the planner uses to recognise manipulable fields.

Four patterns from the sprint brief:

A. Price manipulation      — negative/zero/fractional/oversized price values
B. Coupon reuse            — the same coupon applied more than once
C. Workflow bypass         — reaching a later step without an earlier one
D. Quantity manipulation   — negative/zero/oversized quantity values

The canonical validator ``validate_business_logic`` lives in
``webpent.production.validators``. It confirms only when the manipulated value
is accepted where baseline and negative control use a legitimate value, i.e. the
server-side business invariant was actually broken — never from a mere 200.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BUSINESS_LOGIC_EXPERIMENT_ID = "exp_business_logic_v1"
BUSINESS_LOGIC_FAMILY = "BUSINESS_LOGIC"

# Value shapes the planner recognises as business-logic-manipulable. Keys are
# the recognized field-name classes; values are the candidate probe values.
BUSINESS_LOGIC_FIELD_SHAPES: dict[str, dict[str, Any]] = {
    "price": {
        "name_tokens": ("price", "amount", "cost", "total", "unit_price", "price_total"),
        "candidate_values": ("-1", "0", "0.01"),
        "legitimate_value": "100",
    },
    "quantity": {
        "name_tokens": ("quantity", "qty", "count", "amount", "units"),
        "candidate_values": ("-1", "0", "999999"),
        "legitimate_value": "1",
    },
    "coupon": {
        "name_tokens": ("coupon", "discount", "promo", "voucher", "code"),
        "candidate_values": ("REUSE_PROBE", "REUSE_PROBE"),
        "legitimate_value": "NONE_PROBE",
    },
}

# Business-logic patterns supported by the module.
BUSINESS_LOGIC_PATTERNS = ("price", "coupon_reuse", "workflow_bypass", "quantity")

# Structured-field keys the validator reads from the candidate observation.
ACCEPTED_VALUE_KEY = "_business_value_accepted"
INVARIANT_SIGNAL_KEY = "_business_invariant_violated"

# Body keys whose names match a manipulable shape.
def _body_key_for_shape(body_keys: tuple[str, ...], shape: str) -> str | None:
    shape_spec = BUSINESS_LOGIC_FIELD_SHAPES.get(shape)
    if not shape_spec:
        return None
    tokens = tuple(str(item).lower() for item in shape_spec["name_tokens"])
    for key in body_keys:
        lowered = str(key).lower()
        if any(token in lowered for token in tokens):
            return str(key)
    return None


def matches_business_logic_shape(field_name: str) -> str | None:
    """Return the business-logic shape a field name belongs to, if any."""
    lowered = str(field_name or "").lower()
    for shape, spec in BUSINESS_LOGIC_FIELD_SHAPES.items():
        if any(str(token) in lowered for token in spec["name_tokens"]):
            return shape
    return None


@dataclass(frozen=True)
class BusinessLogicProbe:
    """One business-logic manipulation probe (baseline/candidate/control)."""

    pattern: str
    endpoint_path: str
    method: str
    field_name: str
    candidate_value: str
    legitimate_value: str
    body_template: dict[str, Any] = field(default_factory=dict)
    content_type: str = "application/json"
    control_path: str | None = None
    replay_path: str | None = None

    def as_hypothesis(self, *, target_url: str, hypothesis_id: str) -> dict[str, Any]:
        """Project to the AVI hypothesis shape (advisory input, no credentials)."""
        def _body(value: str | None) -> dict[str, Any]:
            body = dict(self.body_template)
            body[self.field_name] = value if value is not None else self.legitimate_value
            return body

        requests: dict[str, dict[str, Any]] = {
            "baseline": {
                "method": str(self.method).upper(),
                "path": self.endpoint_path,
                "content_type": self.content_type,
                "body": _body(self.legitimate_value),
            },
            "candidate": {
                "method": str(self.method).upper(),
                "path": self.endpoint_path,
                "content_type": self.content_type,
                "body": _body(self.candidate_value),
            },
            "negative_control": {
                "method": str(self.method).upper(),
                "path": self.control_path or self.endpoint_path,
                "content_type": self.content_type,
                "body": _body(_control_value(self.pattern, self.legitimate_value)),
            },
        }
        return {
            "id": hypothesis_id,
            "hypothesis_id": hypothesis_id,
            "vulnerability_class": BUSINESS_LOGIC_FAMILY,
            "api_type": "rest",
            "path": self.endpoint_path,
            "method": str(self.method).upper(),
            "information_value": 0.85,
            "requests": requests,
            "family_contract_version": "v1",
        "executable": True,
            "hypothesis_template": (
                "a business workflow endpoint may accept a manipulated "
                f"{self.field_name} value that breaks a server-side invariant"
            ),
            "expected_evidence": [
                "candidate_manipulated_value_accepted",
                "baseline_legitimate_value_accepted",
                "control_rejected_or_unchanged",
            ],
            "target_url": str(target_url),
            "metadata": {
                "experiment_id": BUSINESS_LOGIC_EXPERIMENT_ID,
                "pattern": self.pattern,
                "field_name": self.field_name,
                "candidate_value": self.candidate_value,
                "legitimate_value": self.legitimate_value,
                "replay_path": self.replay_path,
            },
        }


def _control_value(pattern: str, legitimate_value: str) -> str:
    """Return a benign control value that must NOT break the invariant."""
    if pattern == "coupon_reuse":
        return "INVALID_PROBE_CONTROL"
    return legitimate_value


def build_business_logic_probes(
    *,
    endpoint_path: str,
    method: str = "POST",
    field_name: str = "price",
    body_template: dict[str, Any] | None = None,
    candidate_values: tuple[str, ...] | None = None,
    legitimate_value: str | None = None,
    pattern: str = "price",
    content_type: str = "application/json",
    control_path: str | None = None,
    replay_path: str | None = None,
) -> list[BusinessLogicProbe]:
    """Build one probe per candidate value for a business-logic pattern."""
    shape = matches_business_logic_shape(field_name)
    spec = BUSINESS_LOGIC_FIELD_SHAPES.get(shape or "", {})
    values = tuple(candidate_values) if candidate_values else tuple(spec.get("candidate_values", ("-1", "0")))
    legit = legitimate_value or str(spec.get("legitimate_value", "100"))
    return [
        BusinessLogicProbe(
            pattern=str(pattern),
            endpoint_path=str(endpoint_path),
            method=str(method or "POST").upper(),
            field_name=str(field_name),
            candidate_value=str(value),
            legitimate_value=legit,
            body_template=dict(body_template or {}),
            content_type=str(content_type or "application/json"),
            control_path=str(control_path) if control_path else None,
            replay_path=str(replay_path) if replay_path else None,
        )
        for value in values
    ]


def analyze_business_logic_response(evidence: dict[str, Any], *, field_name: str,
                                    candidate_value: str) -> dict[str, Any]:
    """Extract validator-readable signals from ONE redacted observation.

    Returns only structural booleans/aggregates; the raw body is never copied.
    """
    status = _status_code(evidence)
    body = str(evidence.get("response_body", evidence.get("body", "")))
    lowered = body.lower()
    accepted = 200 <= status < 300
    # The manipulated value is "reflected/accepted" when the response carries it
    # (any spelling) OR echoes the field name with an error-free 2xx.
    value_echo = str(candidate_value).lower() in lowered
    field_echo = str(field_name).lower() in lowered
    negative_seen = any(marker in lowered for marker in ("invalid", "must be positive", "not allowed", "rejected"))
    return {
        ACCEPTED_VALUE_KEY: bool(accepted and (value_echo or field_echo)),
        "_business_status": status,
        "_business_value_echo": value_echo,
        "_business_rejection_marker": negative_seen,
    }


def _status_code(evidence: dict[str, Any]) -> int:
    raw = evidence.get("status_code", evidence.get("status", 0))
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


__all__ = [
    "BUSINESS_LOGIC_EXPERIMENT_ID",
    "BUSINESS_LOGIC_FAMILY",
    "BUSINESS_LOGIC_FIELD_SHAPES",
    "BUSINESS_LOGIC_PATTERNS",
    "ACCEPTED_VALUE_KEY",
    "INVARIANT_SIGNAL_KEY",
    "BusinessLogicProbe",
    "analyze_business_logic_response",
    "build_business_logic_probes",
    "matches_business_logic_shape",
]
