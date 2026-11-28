#!/usr/bin/env python3
"""UM-DR-52 W1 closeout — the fixture decision delta (gate G5, lab half).

The field half ran on Juice Shop (``umdr52_w1_field_delta.py`` — ORDER
changed, pool +2, outcomes stable on that target shape). The W1/A3
contract (§3) is stricter: ORDER **and** ≥1 OUTCOME must flip, sourced
from the behavioral layer. This measurement drives the REAL decision
code (``rank_with_brain`` + ``estimate_priority_inputs`` +
``prioritization.recommend_action`` with the brain decision map) over
the approved SKG lab fixture (``tests.test_umdr46_phase_a_skg``), where
the behavioral evidence (planted pending→approved workflow skip,
ownership rules, contradiction) is observable by construction.

Arms (deterministic, no network, no LLM):
  OFF — legacy ranking score, ``recommend_action(priority_score=None)``
        (byte-comparable legacy decisions);
  ON  — ``rank_with_brain`` (W3 formula + behavioral terms), the
        ranked score passed as ``priority_score`` so the brain DECIDES.

Writes deliverables/umdr52/W1_FIXTURE_DECISION_DELTA.json.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def _load_pool():
    """The approved-lab pool: hypotheses over the fixture's surface."""
    from uuid import NAMESPACE_URL, uuid5

    from tests.test_umdr46_phase_a_skg import BASE, _lab_state
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    def mk(hid: str, vc: str, conf: float, target: str,
           ig: float | None = None):
        return canonical_hypothesis(
            id=uuid5(NAMESPACE_URL, f"umdr52w1m:{hid}"),
            statement=f"W1 measurement hypothesis {hid}",
            vuln_class=vc,
            origin="heuristic",
            origin_detail="umdr52 w1 fixture delta",
            target_url=target,
            expected_behavior="sanctioned path enforces its preconditions",
            negative_control="replay through the sanctioned state",
            deterministic_match=False,
            confidence_score=conf,
            info_gain=ig,
        )

    # Order matters here: the list deliberately interleaves classes
    # and confidence levels so the two ranking modes must actually
    # disagree to prove the delta (a trivially sorted pool proves
    # nothing).
    pool = [
        mk("h-fasttrack", "idor", 0.55, f"{BASE}/api/orders/123/fasttrack", 0.2),
        mk("h-invoice-read", "idor", 0.50, f"{BASE}/api/invoices/900", 0.15),
        mk("h-transfer", "mass_assignment", 0.48, f"{BASE}/api/transfer", 0.3),
        mk("h-profile-write", "auth_bypass", 0.45, f"{BASE}/api/profile", 0.1),
        mk("h-order-skip", "business_logic", 0.52, f"{BASE}/api/orders/123/status", 0.35),
        mk("h-list-read", "idor", 0.42, f"{BASE}/api/orders", 0.05),
    ]
    return _lab_state(), pool, BASE


def _fp(order: list[dict]) -> list[str]:
    return [f"{r['status']}|{r['target']}|{r['vuln_class']}" for r in order]


def main() -> int:
    from webpent.production.brain_engine import (
        build_brain_context,
        rank_with_brain,
    )
    from webpent.shared.prioritization import (
        rank_open_hypotheses,
        recommend_action,
    )

    state, pool, base = _load_pool()

    # ---- OFF arm: legacy ranking + legacy decisions ----------------
    off_ranked = rank_open_hypotheses(pool, state)
    off_rows, off_actions = [], {}
    for hyp, _score in off_ranked:
        action, sval, rule = recommend_action(hyp, state, priority_score=None)
        target = str(getattr(hyp, "target_url", ""))
        off_actions[target] = action
        off_rows.append({
            "target": target,
            "vuln_class": str(getattr(hyp, "vuln_class", "")),
            "status": str(getattr(action, "value", action)),
            "legacy_score": round(float(sval), 6),
            "rule": rule[:120],
        })

    # ---- ON arm: brain ranking (behavioral terms) + brain decisions -
    ctx = build_brain_context(state)
    if not ctx.built:
        print("CONTEXT BUILD FAILED:", ctx.error)
        return 1
    on_ranked = rank_with_brain(pool, ctx)
    on_rows, on_actions = [], {}
    for hyp, score in on_ranked:
        action, sval, rule = recommend_action(hyp, state, priority_score=score)
        target = str(getattr(hyp, "target_url", ""))
        on_actions[target] = action
        on_rows.append({
            "target": target,
            "vuln_class": str(getattr(hyp, "vuln_class", "")),
            "status": str(getattr(action, "value", action)),
            "brain_priority_score": round(float(score), 6),
            "decision_score": round(float(sval), 6),
            "rule": rule[:120],
        })

    off_fp, on_fp = _fp(off_rows), _fp(on_rows)
    order_changed = off_fp != on_fp

    flipped = []
    for row_o in off_rows:
        row_n = next(r for r in on_rows if r["target"] == row_o["target"])
        if row_o["status"] != row_n["status"]:
            flipped.append({
                "target": row_o["target"],
                "off_action": row_o["status"],
                "on_action": row_n["status"],
                "off_score": row_o["legacy_score"],
                "brain_priority": row_n["brain_priority_score"],
                "decision_score": row_n["decision_score"],
            })

    verdict = {
        "schema": "umdr52-w1-fixture-delta/1.0.0",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "fixture": "tests.test_umdr46_phase_a_skg._lab_state (approved lab)",
        "arms": {
            "off": "legacy rank_open_hypotheses + recommend_action(None)",
            "on": "rank_with_brain(W3 formula + behavioral terms) + "
                  "recommend_action(priority_score=score)",
        },
        "context_built": ctx.built,
        "context_summary": ctx.as_summary(),
        "behavioral_evidence_present": ctx.behavioral is not None and bool(
            getattr(ctx.behavioral, "targets", None) or
            getattr(ctx.behavioral, "invariant_specs", None)),
        "off_order_fingerprint_sha256": hashlib.sha256(
            "\n".join(off_fp).encode()).hexdigest()[:16],
        "on_order_fingerprint_sha256": hashlib.sha256(
            "\n".join(on_fp).encode()).hexdigest()[:16],
        "off_rows": off_rows,
        "on_rows": on_rows,
        "order_changed": order_changed,
        "outcomes_flipped": flipped,
        "gate_g5_fixture": {
            "question": "does the brain, fueled by the behavioral layer, "
                        "change ORDER and ≥1 OUTCOME on the approved "
                        "fixture, without touching confirmation authority?",
            "order_changed": order_changed,
            "outcome_changed": bool(flipped),
            "status": "VERIFIED" if (order_changed and flipped)
            else "FAILED — pool-only or order-only delta",
        },
    }
    out = REPO / "deliverables/umdr52/W1_FIXTURE_DECISION_DELTA.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(verdict, indent=2, default=str) + "\n")
    print(json.dumps(verdict["gate_g5_fixture"], indent=1))
    print("flips:", json.dumps(flipped, indent=1))
    print("wrote", out)
    return 0 if (order_changed and flipped) else 1


if __name__ == "__main__":
    raise SystemExit(main())
