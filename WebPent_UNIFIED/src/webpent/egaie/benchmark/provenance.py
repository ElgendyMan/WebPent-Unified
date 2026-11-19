"""L7 Step 5: machine-readable provenance per confirmed finding.

Mission section 5 requires that every reported finding carries a
machine-readable record of how it was established: which initial
observations seeded the hypothesis, which evidence and experiments
confirmed it, what the model contributed (ranking only, never a
verdict), which sealed proof bundle and replay verification back it,
and which ground-truth classification was attached to it.

Two integrity rules are enforced by construction, not by convention:

- provenance is built ONLY for hypotheses whose status is CONFIRMED,
  and ONLY from the finished investigation state; the record carries
  the terminal reason and round as witnesses that the run ended;
- the ground-truth ``classification`` field is None at build time and
  can be attached only through :func:`attach_classification`, which
  stamps the record as classified after investigation. Scoring during
  the run is structurally impossible: nothing here accepts a scorer.

The module imports only schemas and (optionally) json/hashlib: it
runs in a fresh interpreter with no fixture, lab or target code
loaded, which the subprocess test pins.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from webpent.egaie.schemas import (
    HypothesisStatus,
    InvestigationState,
)

PROVENANCE_VERSION = "l7-provenance-1"

# Every strategy's advisory origin namespace. An LLM output may
# propose or rank hypotheses but must never independently establish a
# finding: provenance records the origin so an auditor can check that
# the confirming weight sits on executed experiments and sealed
# bundles, never on the model port.
ADVISORY_ORIGINS = (
    "differential:recon:",
    "independent:recon:",
    "baseline:rule:",
)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"),
                   default=str).encode("utf-8")).hexdigest()


def build_finding_provenance(
    state: InvestigationState, hypothesis_id: str
) -> dict[str, Any]:
    """Assemble the provenance record for one confirmed finding.

    Raises KeyError for an unknown hypothesis and ValueError for a
    hypothesis that is not CONFIRMED: provenance exists only for
    findings established by a finished investigation.
    """
    record = next(
        (h for h in state.hypotheses
         if h.hypothesis_id == hypothesis_id), None)
    if record is None:
        raise KeyError(hypothesis_id)
    if record.status is not HypothesisStatus.CONFIRMED:
        raise ValueError(
            "provenance requires a CONFIRMED finding; "
            f"{hypothesis_id} is {record.status.value}")

    experiments = [
        e for e in state.experiments
        if e.hypothesis_id == hypothesis_id
    ]
    experiment_ids = {e.experiment_id for e in experiments}
    evidence = [
        item.to_dict() for item in state.evidence
        if item.ref in experiment_ids
    ]
    decisions = [
        d.to_dict() for d in state.decisions
        if d.selected_experiment_id in experiment_ids
        or d.selected_experiment_id == ""
    ]
    bundles = [
        dict(bundle) for bundle in state.proof_bundles_verified
        if bundle.get("experiment_id") in experiment_ids
    ]
    # The initial-observation inventory the proposer built the
    # hypothesis from: ids and digests only, so the record stays
    # small and the observations themselves remain in the state.
    observation_digests = [
        _digest(obs) for obs in state.observations
    ]
    proposals = [
        dict(entry) for entry in state.proposal_log
        if experiment_ids & set(entry.get("experiment_ids", []))
    ]

    provenance: dict[str, Any] = {
        "provenance_version": PROVENANCE_VERSION,
        "finding": {
            "hypothesis_id": record.hypothesis_id,
            "family": record.family,
            "statement": record.statement,
            "source": record.source,
            "origin": record.origin,
            "origin_is_advisory": record.origin.startswith(
                ADVISORY_ORIGINS),
        },
        "investigation": {
            "engagement_id": state.engagement_id,
            "target_url": state.target_url,
            "rounds_used": state.round,
            "terminal_reason": state.terminal_reason,
            "initial_observations": {
                "count": len(state.observations),
                "digests_sha256": observation_digests,
            },
        },
        "confirmation": {
            "experiments": [
                {
                    "experiment_id": e.experiment_id,
                    "signature": e.signature,
                    "family": e.family,
                    "hypothesis_id": e.hypothesis_id,
                    "outcome": state.experiment_outcome(
                        e.experiment_id),
                }
                for e in experiments
            ],
            "evidence": evidence,
            "selection_decisions": decisions,
            "proposal_log_entries": proposals,
        },
        "model_contribution": {
            # The model port may propose and rank only. Every finding
            # rests on executed differential experiments and a sealed
            # bundle; if any bundle is missing or replay-invalid the
            # seal summary below shows it, and the record is invalid.
            "advisory_only": True,
            "established_finding": False,
        },
        "seal_summary": {
            "bundles": bundles,
            "all_replay_valid": all(
                bundle.get("replay_valid") is True
                for bundle in bundles) if bundles else False,
            "bundle_count": len(bundles),
        },
        # Ground truth scores AFTER investigation only; the field is
        # attached by attach_classification and is None until then.
        "classification": None,
        "classified_after_investigation": False,
    }
    provenance["provenance_digest"] = _digest(
        {k: v for k, v in provenance.items()
         if k != "provenance_digest"})
    return provenance


def attach_classification(
    provenance: dict[str, Any], classification: dict[str, Any]
) -> dict[str, Any]:
    """Attach the ground-truth classification AFTER investigation.

    Returns a new record: the input is never mutated, so the
    pre-classification digest stays checkable against the copy's
    provenance_digest. The stamp records that scoring happened after
    the run ended, which is the only permitted order.
    """
    if not classification:
        raise ValueError("classification must be non-empty")
    record = json.loads(json.dumps(provenance))
    pre_digest = record.get("provenance_digest")
    record.pop("provenance_digest")
    computed = _digest(record)
    if pre_digest is not None and pre_digest != computed:
        raise ValueError(
            "provenance record was modified before classification")
    record["classification"] = dict(classification)
    record["classified_after_investigation"] = True
    record["provenance_digest"] = _digest({
        k: v for k, v in record.items() if k != "provenance_digest"
    })
    return record


def findings_provenance(
    state: InvestigationState,
) -> list[dict[str, Any]]:
    """Provenance records for every confirmed finding in a run."""
    return [
        build_finding_provenance(state, h.hypothesis_id)
        for h in state.hypotheses
        if h.status is HypothesisStatus.CONFIRMED
    ]
