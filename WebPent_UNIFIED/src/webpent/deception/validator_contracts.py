"""webpent.deception.validator_contracts — M6 (Part 4 §8): declared
evidence contracts per vulnerability class.

Registry scope: "validator contracts declared (required evidence,
negative controls, limitations, replay)".

Each contract names, per vuln class:

* ``required_evidence`` — the fields an evidence bundle MUST carry
  before a validator may even evaluate it;
* ``negative_control_required`` — whether a randomized/control
  response is mandatory for this class (it is for every
  response-differential class);
* ``limitations`` — the declared blind spots (what this contract does
  NOT prove);
* ``replay_required`` — whether the evidence must carry a replayable
  request spec.

``validate_evidence_bundle`` enforces the declared contract and
returns the missing pieces — fail-closed, per class, with the contract
version recorded so a bundle's provenance is auditable.
"""

from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CONTRACT_VERSION",
    "EvidenceContract",
    "EVIDENCE_CONTRACTS",
    "validate_evidence_bundle",
]

CONTRACT_VERSION = "webpent-evidence-contracts-v1"


class EvidenceContract(BaseModel):
    """The declared evidence contract for one vulnerability class."""

    model_config = ConfigDict(extra="forbid")

    vuln_class: str = Field(min_length=3, max_length=60)
    required_evidence: list[str] = Field(min_length=1, max_length=20)
    negative_control_required: bool = True
    limitations: list[str] = Field(default_factory=list, max_length=20)
    replay_required: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "vuln_class": self.vuln_class,
            "required_evidence": list(self.required_evidence),
            "negative_control_required": self.negative_control_required,
            "limitations": list(self.limitations),
            "replay_required": self.replay_required,
        }


_BASE_EVIDENCE = [
    "precondition",
    "action",
    "effect",
    "baseline_digest",
    "candidate_digest",
]

EVIDENCE_CONTRACTS: dict[str, EvidenceContract] = {
    contract.vuln_class: contract
    for contract in (
        EvidenceContract(
            vuln_class="xss",
            required_evidence=_BASE_EVIDENCE + ["interpreted_context", "control_digest"],
            limitations=[
                "reflection alone proves nothing: the context must interpret the payload",
                "DOM sinks require a dataflow trace, not a response differential",
            ],
        ),
        EvidenceContract(
            vuln_class="sqli",
            required_evidence=_BASE_EVIDENCE + ["control_digest", "differential_extracted_from_pair"],
            limitations=[
                "a tool's 'vulnerable' banner in one run proves nothing: the "
                "baseline run must NOT carry the marker (differential)",
                "time-based classes require repeatability against delay-only deception",
            ],
        ),
        EvidenceContract(
            vuln_class="idor_bola",
            required_evidence=_BASE_EVIDENCE
            + ["identity_a", "identity_b", "object_id", "control_digest"],
            limitations=[
                "a single identity cannot differential-test object-level access",
                "the negative control (randomized id) must produce the enforcement baseline",
            ],
        ),
        EvidenceContract(
            vuln_class="ssrf",
            required_evidence=_BASE_EVIDENCE + ["oob_interaction_digest", "control_digest"],
            limitations=[
                "in-band responses prove nothing without the out-of-band callback",
                "callbacks must be nonce-bound to the hypothesis (forgery resistance)",
            ],
        ),
        EvidenceContract(
            vuln_class="cache_poisoning",
            required_evidence=_BASE_EVIDENCE + ["uncached_baseline_digest", "control_digest"],
            limitations=[
                "a poisoned edge cache must be shown to differ from the origin response",
                "same-ETag responses are cache-frozen deception, not poisoning",
            ],
        ),
        EvidenceContract(
            vuln_class="tenant_isolation",
            required_evidence=_BASE_EVIDENCE
            + ["identity_a", "identity_b", "foreign_data_present", "control_digest"],
            limitations=[
                "identical cross-tenant bodies require content-level differential, not status codes",
            ],
        ),
    )
}


def validate_evidence_bundle(
    vuln_class: str,
    evidence: Mapping[str, Any] | None,
) -> tuple[bool, list[str], EvidenceContract | None]:
    """Enforce the declared contract for one bundle.

    Returns ``(ok, missing, contract)`` — fail-closed per class: an
    unknown class refuses with ``unknown_vuln_class_contract`` (never a
    silent default-allow).
    """
    contract = EVIDENCE_CONTRACTS.get(str(vuln_class).lower())
    if contract is None:
        return False, [f"unknown_vuln_class_contract:{vuln_class}"], None
    bundle = evidence if isinstance(evidence, Mapping) else {}
    missing: list[str] = [
        field for field in contract.required_evidence if not bundle.get(field)
    ]
    if contract.negative_control_required and not bundle.get("control_digest"):
        if "control_digest" not in missing:
            missing.append("control_digest")
    if contract.replay_required and not bundle.get("replay_spec"):
        missing.append("replay_spec")
    return (not missing), missing, contract
