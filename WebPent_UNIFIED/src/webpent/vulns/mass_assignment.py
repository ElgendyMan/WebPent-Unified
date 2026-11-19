"""Mass-assignment probes: injecting non-user-controllable fields.

PURE LOGIC ONLY. No I/O. This module builds the create/update request triples
that AVI executes through the governed boundary.

Pattern: send a request with extra privileged fields that should not be
user-controllable; if the server persists them, mass assignment is present.

Field variants from the sprint brief (boolean, string, and numeric spellings):

    role=admin, isAdmin=true, verified=true, is_admin=true, admin=true,
    privilege=admin, isAdmin=1

The canonical validator ``validate_mass_assignment`` already lives in
``webpent.production.validators`` and remains the single authority for this
family; this module only constructs the probes it consumes. The validator
confirms only when the protected field changed for the candidate while baseline
and negative control stayed clean — never from a 2xx alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MASS_ASSIGNMENT_EXPERIMENT_ID = "exp_massassign_v1"
MASS_ASSIGNMENT_FAMILY = "MASS_ASSIGNMENT"

# The exact field variants from the brief. Each is a (field_name, value) pair so
# numeric and boolean spellings are both covered.
MASS_ASSIGNMENT_FIELD_VARIANTS: tuple[tuple[str, Any], ...] = (
    ("role", "admin"),
    ("isAdmin", True),
    ("verified", True),
    ("is_admin", True),
    ("admin", True),
    ("privilege", "admin"),
    ("isAdmin", 1),
)

# Privileged values the canonical validator looks for in the candidate response.
PROTECTED_FIELD_MARKERS: tuple[str, ...] = (
    "admin", "root", "superuser", "is_admin=true", "role=admin",
)


def matches_protected_field(field_name: str) -> bool:
    """Return whether a field name is a known privileged/privilege-shaped field."""
    lowered = str(field_name or "").lower().replace("_", "")
    return any(
        token in lowered
        for token in ("role", "admin", "privilege", "verified", "superuser", "iselevated")
    )


@dataclass(frozen=True)
class MassAssignmentProbe:
    """One mass-assignment probe (benign baseline / injected / control)."""

    endpoint_path: str
    method: str
    injected_field: str
    injected_value: Any
    legitimate_body: dict[str, Any] = field(default_factory=dict)
    content_type: str = "application/json"

    def as_hypothesis(self, *, target_url: str, hypothesis_id: str,
                      privileged_field_name: str = "role") -> dict[str, Any]:
        """Project to the AVI hypothesis shape (advisory input, no credentials)."""
        legitimate = dict(self.legitimate_body)
        injected = dict(self.legitimate_body)
        injected[self.injected_field] = self.injected_value
        # Negative control: the same endpoint with only a safe, non-privileged
        # extra field, so a change caused purely by "an extra key" is not
        # mistaken for privilege escalation.
        control = dict(self.legitimate_body)
        control["display_name"] = "control_value"
        return {
            "id": hypothesis_id,
            "hypothesis_id": hypothesis_id,
            "vulnerability_class": MASS_ASSIGNMENT_FAMILY,
            "api_type": "rest",
            "path": self.endpoint_path,
            "method": str(self.method).upper(),
            "information_value": 0.9,
            "requests": {
                "baseline": {
                    "method": str(self.method).upper(),
                    "path": self.endpoint_path,
                    "content_type": self.content_type,
                    "body": legitimate,
                },
                "candidate": {
                    "method": str(self.method).upper(),
                    "path": self.endpoint_path,
                    "content_type": self.content_type,
                    "body": injected,
                },
                "negative_control": {
                    "method": str(self.method).upper(),
                    "path": self.endpoint_path,
                    "content_type": self.content_type,
                    "body": control,
                },
            },
            "family_contract_version": "v1",
        "executable": True,
            "hypothesis_template": (
                "a create/update endpoint may persist a non-user-controllable "
                f"privileged field ({self.injected_field}) supplied by the client"
            ),
            "expected_evidence": [
                "candidate_protected_field_reflected",
                "baseline_control_clean",
            ],
            "target_url": str(target_url),
            "metadata": {
                "experiment_id": MASS_ASSIGNMENT_EXPERIMENT_ID,
                "injected_field": self.injected_field,
                "injected_value": self.injected_value,
                "protected_field": privileged_field_name,
            },
        }


def build_mass_assignment_probes(
    *,
    endpoint_path: str,
    method: str = "POST",
    legitimate_body: dict[str, Any] | None = None,
    variants: tuple[tuple[str, Any], ...] | None = None,
    content_type: str = "application/json",
) -> list[MassAssignmentProbe]:
    """Build one probe per protected-field variant."""
    chosen = tuple(variants) if variants else MASS_ASSIGNMENT_FIELD_VARIANTS
    return [
        MassAssignmentProbe(
            endpoint_path=str(endpoint_path),
            method=str(method or "POST").upper(),
            injected_field=str(name),
            injected_value=value,
            legitimate_body=dict(legitimate_body or {"name": "webpent_probe", "email": "probe@example.invalid"}),
            content_type=str(content_type or "application/json"),
        )
        for name, value in chosen
    ]


def analyze_mass_assignment_response(evidence: dict[str, Any], *,
                                     injected_field: str, injected_value: Any) -> dict[str, Any]:
    """Extract validator-readable signals from one redacted observation."""
    status = _status_code(evidence)
    body = str(evidence.get("response_body", evidence.get("body", "")))
    lowered = body.lower()
    reflected = any(marker in lowered for marker in PROTECTED_FIELD_MARKERS)
    # The injected field name itself echoed back with an elevated value is a
    # stronger, more specific signal than a bare "admin" substring.
    field_and_value = (
        str(injected_field).lower() in lowered
        and str(injected_value).lower() in lowered
    )
    return {
        "_mass_assignment_status": status,
        "_mass_assignment_reflected": bool(reflected),
        "_mass_assignment_field_and_value": bool(field_and_value),
        "_mass_assignment_accepted": 200 <= status < 300,
    }


def _status_code(evidence: dict[str, Any]) -> int:
    raw = evidence.get("status_code", evidence.get("status", 0))
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


__all__ = [
    "MASS_ASSIGNMENT_EXPERIMENT_ID",
    "MASS_ASSIGNMENT_FAMILY",
    "MASS_ASSIGNMENT_FIELD_VARIANTS",
    "PROTECTED_FIELD_MARKERS",
    "MassAssignmentProbe",
    "analyze_mass_assignment_response",
    "build_mass_assignment_probes",
    "matches_protected_field",
]
