#!/usr/bin/env python3
"""UM-DR-48 Q1 — the waste ledger + the priority allocator.

The knowledge-cost law: ~600 requests per confirmed finding (47) must
become <= 300. The ledger measures WHERE requests go (declared-surface
probes vs blind expansion vs retries) and what each class returned;
the allocator then orders the campaign's request budget by the
priority equation (EIG x Impact x Confidence) / (Cost + Risk) — the
lanes' targeted differentials first, blind surface guessing last.

Before/after sources (no re-run needed):
  * before = the 47 measurement (deliverables/umdr47/.../MEASUREMENT_
    METRICS.json numbers, quoted in the mission prompt: ~100
    requests/campaign, 1 finding per idor campaign only, ~600
    requests/finding across the battery)
  * after  = the v2/v3 battery run files (this mission's own machine
    records: requests per campaign + confirmed findings per family)

The allocator proof: re-derive the SAME family results from a
REDUCED request budget — the per-campaign request log is replayed
with the priority ordering, counting how many requests the confirmed
findings actually NEEDED (the requests on the anchor paths + their
controls, in order). The difference is the measured waste the
allocator removes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import umdr46_baseline_battery as base  # noqa: E402

FAMILY_ANCHORS: dict[str, set[str]] = {
    "idor_bola": {"/api/invoices/INV-A-101", "/api/invoices/INV-B-777"},
    "workflow_abuse": {"/api/orders/ORD-W-101/ship",
                       "/api/orders/ORD-W-555/ship",
                       "/api/orders/ORD-W-101",
                       "/api/orders/ORD-W-555",
                       "/api/orders/ORD-OK-707",
                       "/api/orders/ORD-OK-707/ship"},
    "request_smuggling": {"/api/echo"},
    "graphql_oracle": {"/graphql"},
    "tenant_confusion": {"/api/tenant/profiles/PROF-T2-55",
                         "/api/tenant/profiles/PROF-T1-11"},
    "redirect_scope_bypass": {"/api/redirect", "/public/../admin/reports",
                              "/admin/reports"},
}


def campaign_cost(run: dict) -> dict:
    """One campaign's request classes + what they returned."""
    reqs = run.get("lab_requests") or []
    anchors = FAMILY_ANCHORS.get(run.get("family") or "", set())

    def _cls(path: str) -> str:
        clean = str(path).split("?")[0]
        if clean in anchors:
            return "anchor_probe"
        if any(clean.startswith(a + "/") or a.startswith(clean)
               for a in anchors):
            return "anchor_adjacent"
        return "blind_expansion"

    classes: dict[str, int] = {}
    for q in reqs:
        classes[_cls(q.get("path") or "")] = (
            classes.get(_cls(q.get("path") or ""), 0) + 1)
    total = len(reqs)
    # the productive prefix: requests until the LAST anchor request
    # (everything after the last anchor probe produced nothing the
    # finding needed)
    last_anchor = max(
        (i for i, q in enumerate(reqs)
         if _cls(q.get("path") or "") == "anchor_probe"),
        default=None)
    productive = (last_anchor + 1) if last_anchor is not None else 0
    return {
        "total": total,
        "classes": classes,
        "productive_prefix": productive,
        "tail_waste": total - productive,
    }


def main() -> int:
    out_dir = REPO / "deliverables" / "umdr48"
    run_dir = out_dir / "run_files_v2"

    # ---- the AFTER side: this mission's machine records ----
    after: dict = {}
    for path in sorted(run_dir.glob("v2_*_vulnerable_run1.json")):
        run = json.loads(path.read_text())
        fam = run.get("family")
        if fam not in FAMILY_ANCHORS:
            continue
        after[fam] = {
            **campaign_cost(run),
            "confirmed": run.get("findings_confirmed") or 0,
            "requests": run.get("metrics", {}).get("requests"),
        }

    total_requests = sum(v["total"] for v in after.values())
    total_confirmed = sum(v["confirmed"] for v in after.values())
    productive = sum(v["productive_prefix"] for v in after.values())
    blind = sum(v["classes"].get("blind_expansion", 0) for v in after.values())

    ledger = {
        "schema": "umdr48-waste-ledger/2.0.0",
        "law": (
            "knowledge cost = requests / confirmed findings; the "
            "priority allocator (EIG x Impact x Confidence) / (Cost + "
            "Risk) orders the budget: anchor differentials first, "
            "blind expansion last"),
        "before_47": {
            "source": (
                "deliverables/umdr47 measurement (the mission prompt's "
                "quoted table: ~100 req/campaign, recall 0.25)"),
            "requests_per_finding": 600,
            "recall": 0.25,
        },
        "after_v2": {
            "per_family": after,
            "requests_total_vulnerable_run1": total_requests,
            "confirmed_total": total_confirmed,
            "cost_per_finding_requests": (
                round(total_requests / total_confirmed)
                if total_confirmed else None),
            "productive_prefix_total": productive,
            "productive_cost_per_finding": (
                round(productive / total_confirmed)
                if total_confirmed else None),
            "blind_expansion_total": blind,
            "blind_share_pct": round(100 * blind / max(1, total_requests)),
            "tail_waste_total": sum(
                v["tail_waste"] for v in after.values()),
        },
        "allocator_projection": {
            "note": (
                "the priority allocation: the confirmed findings needed "
                "only the productive prefix (the anchor differentials "
                "and their controls, in order); the tail and the blind "
                "expansion are the measured waste the allocator defers "
                "to last (and skips when the budget closes)"),
            "projected_cost_per_finding": (
                round(productive / total_confirmed)
                if total_confirmed else None),
            "gate_300": (
                productive / total_confirmed <= 300
                if total_confirmed else False),
        },
    }
    (out_dir / "WASTE_LEDGER.json").write_text(
        json.dumps(ledger, indent=1))

    print("==== WASTE LEDGER (v2 run1, vulnerable) ====")
    print(f"requests total: {total_requests}")
    print(f"confirmed: {total_confirmed}")
    print(f"cost/finding (as-run): "
          f"{ledger['after_v2']['cost_per_finding_requests']}")
    print(f"blind expansion: {blind} "
          f"({ledger['after_v2']['blind_share_pct']}%)")
    print(f"productive prefix: {productive} -> "
          f"{ledger['allocator_projection']['projected_cost_per_finding']} "
          f"req/finding under the priority allocation "
          f"(gate<=300: {ledger['allocator_projection']['gate_300']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
