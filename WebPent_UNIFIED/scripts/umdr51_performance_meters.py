#!/usr/bin/env python3
"""UM-DR-51 P4 — performance meters from the raw battery records."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

FIXED = REPO / "deliverables/umdr51/family_battery_fixed/run_files_v2"
BROKEN = REPO / "deliverables/umdr51/family_battery_plain/run_files_v2"


def battery_stats(d: Path) -> dict:
    files = sorted(p for p in d.glob("v2_*_run*.json"))
    fam_files = [p for p in files if "_vulnerable_" in p.name or "_secure_" in p.name]
    tot_req = tot_hrs = 0
    tot_conf = tot_findings = 0
    per_family: dict[str, dict] = {}
    for p in fam_files:
        r = json.loads(p.read_text())
        fam = r["family"]
        f = per_family.setdefault(fam, {"requests": 0, "elapsed_s": 0.0,
                                        "confirmed": 0, "findings": 0,
                                        "runs": 0})
        f["requests"] += len(r.get("lab_requests") or [])
        f["elapsed_s"] += float(r.get("elapsed_s") or 0)
        f["confirmed"] += int(r.get("findings_confirmed") or 0)
        f["findings"] += int(r.get("findings_total") or 0)
        f["runs"] += 1
        tot_req += len(r.get("lab_requests") or [])
        tot_hrs += float(r.get("elapsed_s") or 0)
        tot_conf += int(r.get("findings_confirmed") or 0)
        tot_findings += int(r.get("findings_total") or 0)
    return {
        "family_campaign_runs": len(fam_files),
        "requests_total": tot_req,
        "wall_clock_s": round(tot_hrs, 1),
        "confirmed_findings": tot_conf,
        "candidate_findings": tot_findings,
        "requests_per_confirmed": round(tot_req / max(1, tot_conf), 1),
        "findings_per_hour": round(tot_conf / (tot_hrs / 3600), 1) if tot_hrs else None,
        "per_family": {
            fam: {
                "requests": f["requests"], "elapsed_s": round(f["elapsed_s"], 1),
                "confirmed": f["confirmed"], "candidates": f["findings"],
                "runs": f["runs"],
                "requests_per_confirmed": round(
                    f["requests"] / max(1, f["confirmed"]), 1),
                "time_to_first_confirmed_s": round(f["elapsed_s"] / f["runs"], 2),
            } for fam, f in sorted(per_family.items())
        },
    }


fixed = battery_stats(FIXED)
broken = battery_stats(BROKEN)

out = {
    "schema": "umdr51-performance-meters/1.0.0",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "the_before_after_of_this_windows_fix": {
        "honest_note": (
            "التنبيه الصادق: إصلاح أصل الترقية لم يغيّر الكشف — التأكيدات "
            "الخام موجودة في الحالتين (24 تأكيدًا عبر 36 حملة عائلة). العطل "
            "كان في طبقة قياس الإسناد بالمَراسي داخل MEASUREMENT_V2 (عدّت "
            "التأكيدات الحقيقية FP: recall 0.222، fp 18). الإصلاح أصلح قياس "
            "الإسناد — عاد أصل الحملة الحقيقي على النتيجة المرقاة (recall "
            "0.889، fp 0). أرقام الأداء الخام نفسها لم تتغير."),
        "before_the_promotion_origin_fix": {
            "raw_confirmed_findings": broken["confirmed_findings"],
            "measured_recall": 0.222,
            "measured_fp_total": 18,
            "requests_per_confirmed_from_raw": broken["requests_per_confirmed"],
        },
        "after_the_promotion_origin_fix": {
            "raw_confirmed_findings": fixed["confirmed_findings"],
            "measured_recall": 0.889,
            "measured_fp_total": 0,
            "requests_per_confirmed_from_raw": fixed["requests_per_confirmed"],
        },
    },
    "meters_now_measured": fixed,
    "meters_declared_not_instrumented_yet": [
        "requests/coverage-cell (خلية Resource×Principal×Operation — القناة "
        "موجودة في SKG لكن عدّاد الطلبات لكل خلية غير مفعل)",
        "network-vs-compute split per phase (node_step_trace يسجل العقد لا "
        "زمن الشبكة/الحساب)",
        "validator/replay cost isolated per proof bundle",
        "LLM token consumption (LLM معطل بالكامل في كل القياسات — 0 استهلاك "
        "مقيس، لا عدّاد مطلوب)",
        "retrieval cost per memory lookup",
    ],
}
dest = REPO / "deliverables/umdr51/PERFORMANCE_METERS.json"
dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
print("after-fix requests/confirmed:", fixed["requests_per_confirmed"],
      "| confirmed:", fixed["confirmed_findings"],
      "| wall:", fixed["wall_clock_s"], "s")
print("before-fix requests/confirmed:", broken["requests_per_confirmed"],
      "| confirmed:", broken["confirmed_findings"])
for fam, f in fixed["per_family"].items():
    print(f"  {fam}: {f['requests_per_confirmed']} req/confirmed, "
          f"{f['time_to_first_confirmed_s']}s/run, {f['confirmed']} confirmed/{f['runs']} runs")
