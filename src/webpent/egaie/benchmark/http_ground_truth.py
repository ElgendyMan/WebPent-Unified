"""Versioned ground truth for the EGAIE real-HTTP benchmark.

V1 defines the probe structure for every case against the controlled
HTTP target (src/webpent/egaie/http_target.py): the suspect path, and
the attacker actor's own baseline path (their legitimate access to a
same-type twin resource). These are benchmark fixture definitions,
not detection logic: the detector (EGAIE loop + CausalGuard) never
sees which case is positive or negative, and only sees the paths the
port actually requests.

The six-case in-process fixture benchmark (benchmark.ground_truth)
is a separate, unlike test set and is never pooled with HTTP results.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HTTPCase:
    """One real-HTTP benchmark case."""

    case_id: str
    family: str
    positive: bool
    multi_step: bool
    path: str
    baseline_path: str
    stage2_baseline_path: str = ""
    method: str = "GET"


HTTP_GROUND_TRUTH_V1: tuple[HTTPCase, ...] = (
    HTTPCase(
        case_id="pos-idor-1",
        family="IDOR",
        positive=True,
        multi_step=False,
        path="/api/invoices/inv-1",
        baseline_path="/api/invoices/inv-2",
    ),
    HTTPCase(
        case_id="pos-bola-1",
        family="BOLA",
        positive=True,
        multi_step=False,
        path="/api/documents/doc-1",
        baseline_path="/api/documents/doc-2",
    ),
    HTTPCase(
        case_id="pos-authbypass-1",
        family="AUTH_BYPASS",
        positive=True,
        multi_step=False,
        path="/api/admin/audit",
        # The attacker has no legitimate admin-level access; the
        # baseline is the enforced (patched) route denying them.
        baseline_path="/control/api/admin/audit",
    ),
    HTTPCase(
        case_id="pos-multi-1",
        family="IDOR",
        positive=True,
        multi_step=True,
        path="/api/archive/arc-1",
        baseline_path="/api/archive/arc-2",
        # Stage 2 follows the note path the stage-1 response body
        # reveals; the attacker's own note is the baseline twin.
        stage2_baseline_path="/api/archive/notes/ef01ab23",
    ),
    HTTPCase(
        case_id="neg-record-1",
        family="IDOR",
        positive=False,
        multi_step=False,
        path="/api/records/rec-1",
        baseline_path="/api/records/rec-2",
    ),
    HTTPCase(
        case_id="neg-file-1",
        family="BOLA",
        positive=False,
        multi_step=False,
        path="/api/files/file-1",
        baseline_path="/api/files/file-2",
    ),
)

HTTP_CASE_INDEX: dict[str, HTTPCase] = {
    case.case_id: case for case in HTTP_GROUND_TRUTH_V1
}

HTTP_GROUND_TRUTH_VERSION = "http-v1"


# -- v2: state-changing (POST) families -------------------------------
# V2 adds mutating probes on the same controlled target: the defective
# payment route applies a cross-owner payment (mutating IDOR) and its
# enforced wire sibling denies it. Both stage-1 triples are all-POST:
# baseline is the attacker POSTing to their own twin resource, the
# candidate is the cross-owner POST, the control is the same POST on
# the /control enforced route. Results are reported separately from
# V1 and are never pooled with it.
HTTP_GROUND_TRUTH_V2: tuple[HTTPCase, ...] = (
    HTTPCase(
        case_id="pos-mutid-1",
        family="MUT_IDOR",
        positive=True,
        multi_step=False,
        path="/api/payments/inv-1",
        baseline_path="/api/payments/inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="neg-mutid-1",
        family="MUT_IDOR",
        positive=False,
        multi_step=False,
        path="/api/wire/inv-1",
        baseline_path="/api/wire/inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="pos-mutmulti-1",
        family="MUT_IDOR",
        positive=True,
        multi_step=True,
        # The charge route answers with a generic receipt that carries
        # no ownership context (stage 1 is inconclusive) and reveals
        # the invoice path; confirmation requires the follow-up GET on
        # that path, compared against the attacker's own invoice.
        path="/api/charges/inv-1",
        baseline_path="/api/charges/inv-2",
        stage2_baseline_path="/api/invoices/inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="neg-mutmulti-1",
        family="MUT_IDOR",
        positive=False,
        multi_step=True,
        # Charging the attacker's own invoice is legitimate, but the
        # generic receipt is identical in shape to the defective one,
        # so this case resolves only through the follow-up GET, which
        # reveals ownership and must yield a clean verdict.
        path="/api/charges/inv-2",
        baseline_path="/api/charges/inv-3",
        stage2_baseline_path="/api/invoices/inv-2",
        method="POST",
    ),
)

HTTP_CASE_V2_INDEX: dict[str, HTTPCase] = {
    case.case_id: case for case in HTTP_GROUND_TRUTH_V2
}

HTTP_GROUND_TRUTH_VERSION_V2 = "http-v2"


# -- v3: price-integrity (logic) families ------------------------------
# V3 adds the first Logic Breaker family on the same controlled target:
# server-authoritative pricing that a defective checkout route lets a
# client override, and a defective multi-step coupon route whose generic
# receipt carries no pricing context (confirmation requires the
# follow-up GET on the revealed order path). The enforcing siblings are
# the till route (409 on any price that disagrees with the server total,
# 403 cross-owner) and the /control enforced routes. Baselines are the
# attacker's legitimate own-invoice twins. Results are reported
# separately from V1/V2 and are never pooled with them.
HTTP_GROUND_TRUTH_V3: tuple[HTTPCase, ...] = (
    HTTPCase(
        case_id="pos-price-1",
        family="PRICE_INTEGRITY",
        positive=True,
        multi_step=False,
        path="/api/checkout/inv-1",
        baseline_path="/api/checkout/inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="pos-coupon-1",
        family="PRICE_INTEGRITY",
        positive=True,
        multi_step=True,
        # The coupon route answers with a generic receipt (stage 1 is
        # inconclusive) and reveals the order path; confirmation
        # requires the follow-up GET on that order, compared against
        # the attacker's own order.
        path="/api/coupons/inv-1",
        baseline_path="/api/coupons/inv-2",
        stage2_baseline_path="/api/orders/ord-inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="neg-till-1",
        family="PRICE_INTEGRITY",
        positive=False,
        multi_step=False,
        # Enforcing sibling of the checkout route: the till rejects a
        # tampered price outright.
        path="/api/till/inv-1",
        baseline_path="/api/till/inv-2",
        method="POST",
    ),
    HTTPCase(
        case_id="neg-coupon-1",
        family="PRICE_INTEGRITY",
        positive=False,
        multi_step=True,
        # Applying a coupon to the attacker's own invoice is
        # legitimate; the generic receipt is identical in shape to the
        # defective one, so this case resolves only through the
        # follow-up GET, which must show the discount applied by the
        # order's own owner and yield a clean verdict.
        path="/api/coupons/inv-2",
        baseline_path="/api/coupons/inv-3",
        stage2_baseline_path="/api/orders/ord-inv-2",
        method="POST",
    ),
)

HTTP_CASE_V3_INDEX: dict[str, HTTPCase] = {
    case.case_id: case for case in HTTP_GROUND_TRUTH_V3
}

HTTP_GROUND_TRUTH_VERSION_V3 = "http-v3"
