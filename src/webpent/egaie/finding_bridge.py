"""EGAIE finding bridge: promote only reportable logic results.

The bridge maps investigation results to reportable Finding objects
and is deliberately rejecting:

- Only results with a replay-valid sealed proof bundle are promoted.
  A bundle record whose replay, seal, verdict or digest check failed
  is never reportable.
- Only cases whose hypothesis actually reached CONFIRMED are
  promoted: candidate-only, inconclusive and blocked results are
  never reportable.
- The promoted vulnerability class is VulnClass.UNKNOWN. A
  pricing-invariant violation is business logic, not an authorization
  bypass: the invariant oracle verifies pricing predicates only and
  gathers no authorization-boundary evidence, so relabelling the
  result as auth_bypass would claim evidence that was never
  verified. The repository's VulnClass taxonomy has no price-
  integrity member and findings.py is never modified, so no class is
  fabricated; the explicit business-logic typing is preserved in the
  finding's title, description and reasoning.

A logic verdict says the pricing invariant was violated under the
controlled probe. It is not an authorization verdict and not a
claim about any live production system: the url points at the
controlled investigation target the evidence was gathered against.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie.schemas import (
    HypothesisStatus,
    InvestigationState,
)
from webpent.models.findings import (
    Confidence,
    Finding,
    Severity,
    VulnClass,
)

_LOGIC_TOOL_NAME = "webpent-egaie-logic-breaker"


def _case_id_of(signature: str) -> str:
    return signature.split("/", 1)[0]


def _reportable_bundle_records(
    state: InvestigationState,
) -> list[dict[str, Any]]:
    """Bundle records that passed every verification gate."""
    reportable: list[dict[str, Any]] = []
    for record in state.proof_bundles_verified:
        if record.get("replay_valid") is not True:
            continue
        if record.get("seal_valid") is not True:
            continue
        if record.get("verdict_match") is not True:
            continue
        if record.get("digest_match") is not True:
            continue
        reportable.append(record)
    return reportable


def _confirmed_origins(
    state: InvestigationState,
) -> set[str]:
    return {
        hypothesis.origin
        for hypothesis in state.hypotheses
        if hypothesis.status is HypothesisStatus.CONFIRMED
        and hypothesis.origin
    }


def logic_findings_from_state(
    state: InvestigationState,
    target_origin: str,
) -> list[Finding]:
    """Promote replay-valid confirmed logic results to Findings.

    Everything else (candidate-only, inconclusive, blocked, invalid
    bundle, invalid replay, mismatched identity) is rejected here.
    """
    confirmed = _confirmed_origins(state)
    promoted: dict[str, Finding] = {}
    for record in _reportable_bundle_records(state):
        case_id = _case_id_of(record.get("signature", ""))
        if not case_id or case_id not in confirmed:
            continue
        if case_id in promoted:
            continue
        promoted[case_id] = _finding_for_case(state, record, target_origin)
    return [promoted[case_id] for case_id in sorted(promoted)]


def _finding_for_case(
    state: InvestigationState,
    record: dict[str, Any],
    target_origin: str,
) -> Finding:
    case_id = _case_id_of(record.get("signature", ""))
    evidence = _bundle_evidence(state, record)
    return Finding(
        title=f"Price integrity violation: {case_id}",
        severity=Severity.HIGH,
        description=(
            f"Case {case_id}: the server accepted a state-changing "
            f"request that violates a pricing invariant (the amount "
            f"accepted must match the authoritative amount, and any "
            f"discount must be applied by the order's own owner). "
            f"Confirmed only through an independent invariant oracle "
            f"on a sealed, replay-valid proof bundle gathered against "
            f"the controlled investigation target {target_origin}."
        ),
        tool_name=_LOGIC_TOOL_NAME,
        url=target_origin,
        campaign_id=record.get("experiment_id"),
        confidence=Confidence.CONFIRMED,
        evidence=evidence,
        references=[
            "https://owasp.org/www-project-top-ten/",
        ],
        # Business logic, not an authorization bypass: the oracle
        # verified pricing invariants only, and the VulnClass taxonomy
        # has no price-integrity member (no fabricated class).
        vuln_class=VulnClass.UNKNOWN,
        confidence_level="Tool-Confirmed",
        reasoning=(
            "Price-integrity logic verdict from the invariant oracle"
            " (amount_mismatch / unauthorized_discount), sealed and"
            " replay-verified on the recorded observations. Not an"
            " authorization-boundary finding: no authorization"
            " evidence was gathered or verified."
        ),
    )


def _bundle_evidence(
    state: InvestigationState,
    record: dict[str, Any],
) -> dict[str, Any]:
    experiment_id = record.get("experiment_id", "")
    observations = [
        obs for obs in state.observations
        if obs.get("experiment_id") == experiment_id
    ]
    return {
        "experiment_id": experiment_id,
        "signature": record.get("signature", ""),
        "replay_valid": record.get("replay_valid"),
        "seal_valid": record.get("seal_valid"),
        "verdict_match": record.get("verdict_match"),
        "digest_match": record.get("digest_match"),
        "runtime_provenance": record.get("runtime_provenance"),
        # M1-B (E-1): explicit writer provenance for the model-level
        # Tool-Confirmed proof requirement (models/findings.py). The
        # invariant-oracle verdict above (seal/replay/digest/verdict all
        # valid) is the deterministic gate this key names.
        "tool_confirmed_by": "egaie.invariant_oracle_bridge",
        "observations": observations,
    }
