"""appsuite ground truth: labels applied only after investigation.

The labels here are the suite's OWN ground truth, derived from each
app's implementation profile and applied to investigation results
only AFTER the investigation has finished. Nothing under
`webpent.egaie` may import this module; the isolation test in
tests/appsuite/ enforces that, and no app publishes any of these
labels on the wire.

A defect descriptor is (family_key, detail, scope). Engine-facing
families map onto the engine's canonical labels so per-family
TP/FP/FN can be computed. IDEMPOTENT_MUTATION maps to None: no
engine generator covers it by design (L8 §2's untuned family).
"""
from __future__ import annotations

from typing import Any

from webpent.appsuite.berth import BerthApp
from webpent.appsuite.consign import ConsignApp
from webpent.appsuite.docvault import DocVaultApp
from webpent.appsuite.ledgerflow import LedgerFlowApp
from webpent.appsuite.market import MarketApp
from webpent.appsuite.permit import PermitApp
from webpent.appsuite.requisitions import (
    RequisitionsApp,
)
from webpent.appsuite.slots import SlotDeskApp
from webpent.appsuite.ticketflow import (
    TicketFlowApp,
)

# Suite family keys and their engine-facing canonical labels. None
# means the engine has no generator for the family.
ENGINE_FAMILY: dict[str, str | None] = {
    "ownership_write": "IDENTITY_BOUNDARY",
    "pricing": "PRICE_INTEGRITY",
    "workflow_identity": "WORKFLOW_IDENTITY",
    "workflow_order": "WORKFLOW_ORDER",
    "idempotent_mutation": None,
    # L10 generation-3 families: release authority resolved through
    # another resource's ownership record (the pairing table), and
    # a state-conditional authorization skip behind a multi-step
    # conjunctive setup.
    "cross_resource_ownership": "IDENTITY_BOUNDARY",
    "multi_step_business_logic": "WORKFLOW_IDENTITY",
}


def defects_for(app: str, spec: Any) -> list[dict[str, str]]:
    """Declare the defect surface of one suite instance.

    The descriptors are read off the app's own implementation
    (variant flags and scope constants), so the ground truth and the
    defect cannot drift apart. Ground truth is CLEAN for every
    secured lookalike and every ambiguous (documented-behavior)
    variant: a confirmation there is a false positive.
    """
    if app == "docvault":
        app_obj = DocVaultApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "ownership_write", "detail":
                "the write-bit check is skipped for every document",
                "scope": "*"}]
        if spec.variant == "multi_observation":
            return [{
                "family": "ownership_write", "detail":
                "the write-bit check is skipped in one collection "
                f"only ({app_obj.collections[1]})",
                "scope": app_obj.collections[1]}]
        return []
    if app == "market":
        app_obj = MarketApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "pricing", "detail":
                "the order operation charges the client amount "
                "verbatim for every quote",
                "scope": "*"}]
        if spec.variant == "multi_observation":
            return [{
                "family": "pricing", "detail":
                "the order operation charges the client amount "
                "verbatim for one quote bucket only",
                "scope": "bucket-0"}]
        return []
    if app == "ticketflow":
        app_obj = TicketFlowApp(spec)
        out: list[dict[str, str]] = []
        if spec.variant == "defective":
            out.append({
                "family": "workflow_identity", "detail":
                "the assignee check is skipped on one ticket",
                "scope": app_obj._identity_target})
            out.append({
                "family": "workflow_order", "detail":
                "the source-state guard is dropped on one ticket",
                "scope": app_obj._order_target})
            return out
        if spec.variant == "multi_observation":
            out.append({
                "family": "workflow_identity", "detail":
                "the assignee check is skipped on one ticket only",
                "scope": app_obj._identity_target})
            out.append({
                "family": "workflow_order", "detail":
                "the source-state guard is dropped on one ticket "
                "only", "scope": app_obj._order_target})
            return out
        return []
    if app == "slots":
        app_obj = SlotDeskApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "idempotent_mutation", "detail":
                "a duplicate submission re-applies the hold on the "
                f"waitlist class ({app_obj._waitlist_class})",
                "scope": app_obj._waitlist_class}]
        if spec.variant == "multi_observation":
            return [{
                "family": "idempotent_mutation", "detail":
                "a duplicate submission re-applies the hold on the "
                "waitlist class only",
                "scope": app_obj._waitlist_class}]
        return []
    if app == "requisitions":
        app_obj = RequisitionsApp(spec)
        if spec.variant in ("defective", "multi_observation"):
            scope = (
                app_obj.defect_pool
                if spec.variant == "defective"
                else sorted(app_obj._identity_exempt)[0])
            return [{
                "family": "workflow_identity", "detail":
                "the sponsor check is skipped for the exempt "
                "requisitions", "scope": scope}]
        return []
    if app == "ledgerflow":
        app_obj = LedgerFlowApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "workflow_identity", "detail":
                "the countersign approver check is skipped on one "
                "ledger; its exploitable state sits behind the "
                "approver's initiate transition",
                "scope": app_obj._identity_target}]
        return []
    if app == "berth":
        app_obj = BerthApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "workflow_identity", "detail":
                "the confirm holder check is skipped on one berth; "
                "its exploitable window sits behind the holder's "
                "hold transition",
                "scope": app_obj._identity_target}]
        return []
    if app == "consign":
        app_obj = ConsignApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "cross_resource_ownership", "detail":
                "the defect desk's release authority consults the "
                "OTHER desk's pairing entry, so the healthy desk's "
                "custodian of record can settle defect-desk "
                "consignments while the defect desk's own "
                "custodian of record is refused; the release is "
                "only reachable from the funded stage (a funding "
                "record must exist first)",
                "scope": app_obj.defect_desk}]
        # secured, transition_no_vuln, unavailable_prereq: ground
        # truth clean. In unavailable_prereq the flaw exists in the
        # implementation but its prerequisite stage (funded) is
        # unreachable in scope: the honest verdict there is
        # inconclusive, never a clean security verdict and never a
        # finding.
        return []
    if app == "permit":
        app_obj = PermitApp(spec)
        if spec.variant == "defective":
            return [{
                "family": "multi_step_business_logic", "detail":
                "the approval examiner check is skipped on one "
                "permit whenever its checklist is complete; the "
                "flaw is unobservable until the examiner has "
                "performed all three satisfy transitions",
                "scope": app_obj._identity_target}]
        # secured, transition_no_vuln, unavailable_prereq: ground
        # truth clean (unavailable_prereq's prerequisite is
        # unreachable in scope: inconclusive, never a verdict).
        return []
    raise ValueError(app)


def ambiguous_behaviors(app: str, spec: Any) -> list[str]:
    """Documented behaviors that MIMIC violations (ground truth clean).

    A confirmation attributed to one of these is a false positive by
    construction; the evaluation counts it in the false-positive
    denominator.
    """
    if app == "docvault" and spec.variant == "ambiguous":
        return ["documented guest read access to the lobby notice"]
    if app == "market" and spec.variant == "ambiguous":
        return ["documented bulk rule: orders of three or more "
                "units are charged at 80 percent"]
    if app == "ticketflow" and spec.variant == "ambiguous":
        return ["documented shared-desk ticket any on-duty agent "
                "may act on"]
    if app == "requisitions" and spec.variant == "ambiguous":
        return ["documented shared intake pool any on-duty buyer "
                "may act on"]
    if app == "slots" and spec.variant == "ambiguous":
        return ["documented waitlist class records every "
                "submission, duplicates included"]
    if app == "consign" and spec.variant == "transition_no_vuln":
        return ["documented collective escrow policy: any "
                "authenticated agent may append the settlement "
                "record on every consignment"]
    if app == "permit" and spec.variant == "transition_no_vuln":
        return ["documented collective examination desk: any "
                "licensed officer may satisfy requirements and "
                "approve on every permit"]
    return []
