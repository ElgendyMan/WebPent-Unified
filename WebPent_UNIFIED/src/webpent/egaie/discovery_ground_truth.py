"""Benchmark ground truth for the differential discovery engine (L5).

Scenario labels over the randomized EXTERNAL surface of one
deployment seed, declared INDEPENDENTLY of the detector. This module
is the only source of truth for what counts as a true defect on the
discovery surface, and the detector (differential.py) never imports
it: nothing here can leak into observations, hypotheses or verdicts.

Label independence: each case's justification states the target's
documented enforcement behavior in benchmark terms. The labels are
derived from the target's own enforcement matrix (the layouts the
discovery surface builds per seed), not from the detector's
observations; a label would stay correct if the detector were
replaced entirely.

Case families mirror the detector's OUTPUT families (identity,
price, workflow identity, workflow order) so per-family precision,
recall and F1 are measurable, but the labels themselves carry no
verdict semantics: they say what the TARGET does, not what a run
found. Positive cases include identity-boundary reads (cross-owner
document reads), a state-transition defect (out-of-order workflow
transitions), a state-changing authorization defect (cross-owner
workflow transitions), and a multi-step scenario (cross-owner
discount application whose effect is visible only in a follow-up
read). Negative controls cover both legitimate identity differences
(owner-authorized actions on enforcing resources) and benign errors
(malformed requests that the target rejects for reasons unrelated to
authorization).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.egaie.differential import (
    FAMILY_IDENTITY_BOUNDARY,
    FAMILY_PRICE_INTEGRITY,
    FAMILY_WORKFLOW_IDENTITY,
    FAMILY_WORKFLOW_ORDER,
)
from webpent.egaie.discovery_target import build_deployment

DISCOVERY_GROUND_TRUTH_VERSION = "discovery-v2"

# Seeds the benchmark declares results for. Any other seed is a
# configuration error, mirroring the http-v3 version discipline.
_DECLARED_SEEDS: tuple[int, ...] = (1, 2, 3)


@dataclass(frozen=True)
class DiscoveryCase:
    """One labeled scenario on the external discovery surface."""

    case_id: str
    family: str
    positive: bool
    path: str
    justification: str
    multi_step: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "family": self.family,
            "positive": self.positive,
            "path": self.path,
            "justification": self.justification,
            "multi_step": self.multi_step,
        }


def discovery_ground_truth_version() -> str:
    return DISCOVERY_GROUND_TRUTH_VERSION


def declared_seeds() -> tuple[int, ...]:
    return _DECLARED_SEEDS


def discovery_ground_truth(seed: int) -> tuple[DiscoveryCase, ...]:
    """Declare the scenario labels for one deployment seed.

    Paths are the randomized external ids of THIS seed's deployment
    (segment names, resource ids, workflow ids all differ per seed);
    case ids are stable across seeds so runs are comparable.
    """
    if seed not in _DECLARED_SEEDS:
        raise ValueError(f"undeclared discovery seed: {seed}")
    deployment = build_deployment(seed)
    segment = deployment.segment_of
    resource = deployment.resource_of

    def rpath(canonical_resource: str, canonical_segment: str) -> str:
        return f"/{segment[canonical_segment]}/{resource[canonical_resource]}"

    def wpath(index: int) -> str:
        return (
            f"/{deployment.workflow_segment()}/"
            f"{sorted(deployment.workflows)[index]}")

    cases: list[DiscoveryCase] = []

    # -- identity boundary: cross-owner document reads -------------
    for i, canonical in enumerate(("inv-1", "inv-2", "inv-3")):
        cases.append(DiscoveryCase(
            case_id=f"identity-read-{i + 1}",
            family=FAMILY_IDENTITY_BOUNDARY,
            positive=True,
            path=rpath(canonical, "invoices"),
            justification=(
                "the target's enforcement matrix marks these document "
                "reads as missing an owner check: a second synthetic "
                "account is served the owner's document content, while "
                "the control twin denies the same read"),
        ))
    cases.append(DiscoveryCase(
        case_id="identity-read-file-1",
        family=FAMILY_IDENTITY_BOUNDARY,
        positive=False,
        path=rpath("file-1", "files"),
        justification=(
            "the target's enforcement matrix enforces owner-only reads "
            "on this resource: a second account's read is denied, so a "
            "confirmed cross-owner read here would be a false positive"),
    ))
    for canonical in ("rec-1", "rec-2"):
        cases.append(DiscoveryCase(
            case_id=f"identity-read-{canonical.replace('-', '')}",
            family=FAMILY_IDENTITY_BOUNDARY,
            positive=False,
            path=rpath(canonical, "records"),
            justification=(
                "the target's enforcement matrix enforces owner-only "
                "reads on this resource; a legitimate-difference "
                "control: the owner CAN read it, so a grant/deny "
                "differential must not be mistaken for a defect"),
        ))

    # -- price integrity -------------------------------------------
    # The checkout defect is OPERATION-scoped: the enforcement matrix
    # accepts a client price on every priced invoice, so each invoice
    # under the defective checkout is declared (the identity family
    # follows the same per-resource convention). discovery-v2 corrects
    # the v1 under-declaration, which counted genuine confirmations of
    # the same real defect on sibling invoices as false positives.
    for i, canonical in enumerate(("inv-1", "inv-2", "inv-3")):
        suffix = "" if i == 0 else f"-{i + 1}"
        cases.append(DiscoveryCase(
            case_id=f"price-override-checkout{suffix}",
            family=FAMILY_PRICE_INTEGRITY,
            positive=True,
            path=f"/{segment['checkout']}/{resource[canonical]}",
            justification=(
                "the target's checkout operation honors a client-supplied "
                "price: charging more than the authoritative total "
                "succeeds and is recorded on the follow-up order, so the "
                "charged amount no longer matches the authoritative one"),
        ))
    cases.append(DiscoveryCase(
        case_id="coupon-cross-owner",
        family=FAMILY_PRICE_INTEGRITY,
        positive=True,
        multi_step=True,
        path=f"/{segment['coupons']}/{resource['inv-1']}",
        justification=(
            "the target's promotion operation applies a published "
            "discount code to another account's document without an "
            "owner check; the effect is visible only in a follow-up "
            "read of the resulting order, not in the submission "
            "response (multi-step)"),
    ))
    cases.append(DiscoveryCase(
        case_id="price-enforced-till",
        family=FAMILY_PRICE_INTEGRITY,
        positive=False,
        path=f"/{segment['till']}/{resource['inv-1']}",
        justification=(
            "the target's till operation rejects any amount that "
            "differs from the authoritative total; a benign-error "
            "control: a probe submitting a wrong amount must be "
            "rejected, not confirmed"),
    ))
    for op in ("payments", "wire", "charges"):
        cases.append(DiscoveryCase(
            case_id=f"price-honor-{op}",
            family=FAMILY_PRICE_INTEGRITY,
            positive=False,
            path=f"/{segment[op]}/{resource['inv-1']}",
            justification=(
                "this operation accepts a generic submission and "
                "records no charged amount at all: a missing-price "
                "evidence control, inconclusive by construction, "
                "never confirmable as a price-integrity defect"),
        ))

    # -- workflow identity (cross-owner state change) ---------------
    for i in (3, 4):
        cases.append(DiscoveryCase(
            case_id=f"workflow-cross-owner-{i}",
            family=FAMILY_WORKFLOW_IDENTITY,
            positive=True,
            path=wpath(i),
            justification=(
                "this workflow instance does not enforce owner-only "
                "transitions: a second account's transition is applied "
                "and the instance records the foreign actor as the "
                "transitioner"),
        ))
    for i in (0, 1, 2, 5):
        cases.append(DiscoveryCase(
            case_id=f"workflow-owner-only-{i}",
            family=FAMILY_WORKFLOW_IDENTITY,
            positive=False,
            path=wpath(i),
            justification=(
                "this workflow instance enforces owner-only "
                "transitions; a legitimate-difference control: the "
                "owner can transition it, a foreign account cannot, "
                "so the differential must be rejected here"),
        ))

    # -- workflow order (out-of-order state transitions) -----------
    for i in (4, 5):
        cases.append(DiscoveryCase(
            case_id=f"workflow-out-of-order-{i}",
            family=FAMILY_WORKFLOW_ORDER,
            positive=True,
            path=wpath(i),
            justification=(
                "this workflow instance does not enforce transition "
                "order: approving from the initial draft state is "
                "accepted, skipping the required intermediate state"),
        ))
    for i in (0, 1, 2, 3):
        cases.append(DiscoveryCase(
            case_id=f"workflow-in-order-{i}",
            family=FAMILY_WORKFLOW_ORDER,
            positive=False,
            path=wpath(i),
            justification=(
                "this workflow instance enforces transition order; a "
                "benign-error control: an approval attempt from the "
                "draft state must be rejected with a transition error"),
        ))

    return tuple(cases)


def positives(cases: tuple[DiscoveryCase, ...]) -> dict[str, DiscoveryCase]:
    return {case.path: case for case in cases if case.positive}


def negatives(cases: tuple[DiscoveryCase, ...]) -> dict[str, DiscoveryCase]:
    return {case.path: case for case in cases if not case.positive}


def by_family(
    cases: tuple[DiscoveryCase, ...],
) -> dict[str, list[DiscoveryCase]]:
    grouped: dict[str, list[DiscoveryCase]] = {}
    for case in cases:
        grouped.setdefault(case.family, []).append(case)
    return grouped
