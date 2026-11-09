"""Bounded experiment planning and evidence lifecycle metadata.

The experiment manager is deliberately proposal-only.  It does not construct
requests, invoke transports, or promote findings.  It records only redacted,
bounded metadata that can be correlated with the existing proof-bundle path.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from webpent.models.evidence import redact_sensitive, sha256_text

_TEMPLATE_SPECS: dict[str, dict[str, Any]] = {
    "idor": {
        "required_inputs": ("actor_refs", "object_ref"),
        "max_steps": 6,
        "stop_condition": "stop_on_scope_block_or_differential_or_inconclusive",
    },
    "privilege_escalation": {
        "required_inputs": ("identity_refs", "protected_action_ref"),
        "max_steps": 6,
        "stop_condition": "stop_on_scope_block_or_authorization_differential",
    },
    "session_confusion": {
        "required_inputs": ("identity_refs", "session_transition_ref"),
        "max_steps": 7,
        "stop_condition": "stop_on_scope_block_or_session_differential",
    },
    "workflow_abuse": {
        "required_inputs": ("workflow_ref", "transition_refs"),
        "max_steps": 8,
        "stop_condition": "stop_on_scope_block_or_invalid_transition_signal",
    },
}

_STAGES = ("input", "action", "observation", "validator", "evidence")
_ALLOWED_CLEANUP = frozenset({"complete", "not_applicable", "pending", "failed", "not_recorded"})


def _bounded_text(value: Any, limit: int = 160) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return clean.strip()[:limit]


def _safe_refs(value: Any, limit: int = 50) -> list[str]:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (list, tuple, set)):
        return []
    refs: list[str] = []
    for item in value:
        ref = _bounded_text(item, 240)
        if ref:
            refs.append(ref)
    return list(dict.fromkeys(refs))[:limit]


def _input_summary(value: Any) -> dict[str, Any]:
    """Summarize an input without retaining identifiers, payloads, or secrets."""
    if isinstance(value, Mapping):
        clean, _ = redact_sensitive(dict(value))
        serialized = clean if isinstance(clean, Mapping) else {}
        return {
            "provided": True,
            "field_count": min(len(serialized), 32),
            "fingerprint": f"sha256:{sha256_text(serialized)}",
        }
    if isinstance(value, (list, tuple, set)):
        return {"provided": bool(value), "item_count": min(len(value), 50)}
    return {"provided": value is not None}


class ExperimentManager:
    """Create bounded experiment proposals and redacted lifecycle records."""

    MAX_RECORDS = 200

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []

    def plan(
        self,
        *,
        hypothesis_id: str,
        engagement_id: str,
        template: str,
        inputs: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return a proposal-only template plan; never materialize an action."""
        template_id = _bounded_text(template, 80).lower()
        spec = _TEMPLATE_SPECS.get(template_id)
        if spec is None:
            return {
                "status": "blocked",
                "reason": "unsupported_experiment_template",
                "hypothesis_id": _bounded_text(hypothesis_id),
                "engagement_id": _bounded_text(engagement_id),
                "template_id": template_id,
                "approval_required": True,
                "action_authority_required": True,
                "execution_mode": "proposal_only",
            }
        supplied = inputs if isinstance(inputs, Mapping) else {}
        missing_inputs = [key for key in spec["required_inputs"] if not supplied.get(key)]
        if missing_inputs:
            return {
                "status": "blocked",
                "reason": "required_experiment_inputs_missing",
                "hypothesis_id": _bounded_text(hypothesis_id),
                "engagement_id": _bounded_text(engagement_id),
                "template_id": template_id,
                "missing_inputs": list(missing_inputs),
                "approval_required": True,
                "action_authority_required": True,
                "execution_mode": "proposal_only",
            }
        return {
            "status": "proposed",
            "hypothesis_id": _bounded_text(hypothesis_id),
            "engagement_id": _bounded_text(engagement_id),
            "template_id": template_id,
            "stages": list(_STAGES),
            "required_inputs": list(spec["required_inputs"]),
            "inputs": {key: _input_summary(supplied.get(key)) for key in spec["required_inputs"]},
            "max_steps": int(spec["max_steps"]),
            "stop_condition": spec["stop_condition"],
            "approval_required": True,
            "action_authority_required": True,
            "execution_mode": "proposal_only",
            "requires_negative_control": True,
            "requires_replayable_evidence": True,
        }

    def record(self, hypothesis_id: str, observation: Mapping[str, Any]) -> dict[str, Any]:
        """Store bounded evidence metadata; never store raw requests or payloads."""
        data = observation if isinstance(observation, Mapping) else {}
        safe_refs = _safe_refs(data.get("evidence_refs"))
        evidence_roles = [
            role
            for role in ("baseline", "candidate", "negative_control")
            if role in data and data.get(role) is not None
        ]
        cleanup = _bounded_text(data.get("cleanup_status") or "not_recorded", 40)
        if cleanup not in _ALLOWED_CLEANUP:
            cleanup = "not_recorded"
        replay_metadata = data.get("replay_metadata")
        replayable = data.get("replayable") is True or (
            isinstance(replay_metadata, Mapping) and replay_metadata.get("replayable") is True
        )
        record = {
            "hypothesis_id": _bounded_text(hypothesis_id, 120),
            "engagement_id": _bounded_text(data.get("engagement_id"), 160),
            "template_id": _bounded_text(data.get("template_id"), 80).lower(),
            "outcome": _bounded_text(data.get("outcome") or "inconclusive", 40),
            "causal_signal": data.get("causal_signal") is True,
            "negative_control_complete": data.get("negative_control_complete") is True,
            "negative_control_independent": data.get("negative_control_independent") is True,
            "target_backed": data.get("target_backed") is True,
            "evidence_roles": evidence_roles,
            "evidence_refs": safe_refs,
            "proof_bundle_id": _bounded_text(data.get("proof_bundle_id"), 160) or None,
            "proof_bundle_sealed": data.get("proof_bundle_sealed") is True,
            "replayable": replayable,
            "validator_id": _bounded_text(data.get("validator_id"), 120) or None,
            "validator_version": _bounded_text(data.get("validator_version"), 80) or None,
            "cleanup_status": cleanup,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._records.append(record)
        del self._records[: -self.MAX_RECORDS]
        return dict(record)

    def records(self) -> list[dict[str, Any]]:
        """Return a defensive copy suitable for state or reporting."""
        return [dict(record) for record in self._records]


__all__ = ["ExperimentManager"]
