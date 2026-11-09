#!/usr/bin/env python3
"""Ruff ratchet gate — Track 1 (بوابات الجودة) of the unified roadmap.

Roadmap contract (المسار 1، جدول البوابات — Ruff):

    إنشاء baseline أو ratchet لا يسمح بزيادة الملاحظات؛ خفض العدد على
    دفعات حتى الوصول إلى الحد المعتمد.

    ("Create a baseline or ratchet that does not allow the finding count
    to increase; reduce the count in batches until the approved limit.")

Why a ratchet and not `ruff check .` blocking outright
------------------------------------------------------
The 2026-10-27 snapshot measured ~3,750 pre-existing findings that could
not responsibly be cleared in one pass, which is why CI ran ruff as
report-only (`|| true`). Report-only has the known failure mode the
roadmap calls out: the debt CAN silently grow. A ratchet closes exactly
that hole without demanding a big-bang cleanup:

* current findings <= baseline  -> PASS (reductions are encouraged and
  the baseline is then lowered via the documented --update-baseline
  process),
* current findings  > baseline  -> FAIL with the diff (the PR must fix
  its own findings or consciously re-baseline with a documented reason).

Baseline file: ``scripts/quality/ruff_baseline.json`` (checked in). It
records the count, the date, and the context so re-baselining is
auditable.

Usage
-----
    python scripts/check_ruff_ratchet.py                 # gate mode (CI)
    python scripts/check_ruff_ratchet.py --update-baseline --reason "..."
    python scripts/check_ruff_ratchet.py --json          # machine-readable

Exit codes: 0 = within baseline, 1 = regression (increase), 2 = harness
error (ruff itself failed to run).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "quality" / "ruff_baseline.json"


def run_ruff() -> list[dict]:
    """Run ruff over the repo and return the JSON findings list."""
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", ".", "--output-format=json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        # 0 = clean, 1 = findings; anything else is a harness failure.
        print(
            f"ABORT: ruff failed to run: rc={proc.returncode}\n{proc.stderr[:2000]}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    # Fail-closed (G-1 window, 0.29.0): `python -m ruff` on an environment
    # where ruff is NOT installed also exits rc=1 ("No module named ruff")
    # — indistinguishable from a real findings run by return code alone.
    # A genuine ruff rc=1 ALWAYS carries a JSON findings array in stdout
    # (possibly `[]`-adjacent but never empty), so rc=1 with empty stdout
    # is a harness failure and must abort, never count as zero findings.
    if proc.returncode == 1 and not proc.stdout.strip():
        print(
            "ABORT: ruff produced no output on rc=1 — ruff is missing or "
            f"broken in this environment (stderr: {proc.stderr[:500]!r}). "
            "Refusing to count this as zero findings (fail-closed).",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        return json.loads(proc.stdout or "[]")
    except ValueError as exc:
        print(f"ABORT: unparsable ruff output: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def summarize(findings: list[dict]) -> dict:
    by_code: dict[str, int] = {}
    for item in findings:
        code = str(item.get("code", "UNKNOWN"))
        by_code[code] = by_code.get(code, 0) + 1
    return {"total": len(findings), "by_code": dict(sorted(by_code.items(), key=lambda kv: -kv[1]))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="re-baseline to the CURRENT count (requires --reason; documented process)",
    )
    parser.add_argument("--reason", default="", help="why the baseline moved (audit trail)")
    args = parser.parse_args()

    findings = run_ruff()
    current = summarize(findings)

    if args.update_baseline:
        if not args.reason.strip():
            print("ABORT: --update-baseline requires --reason (audit trail)", file=sys.stderr)
            return 2
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "total": current["total"],
            "by_code": current["by_code"],
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "reason": args.reason.strip(),
        }
        BASELINE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"baseline updated: total={current['total']} reason={args.reason.strip()!r}")
        return 0

    if not BASELINE.exists():
        print(
            f"ABORT: missing baseline {BASELINE} — run once with --update-baseline",
            file=sys.stderr,
        )
        return 2
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    allowed = int(baseline.get("total", 0))

    if args.json:
        print(json.dumps({"allowed": allowed, **current, "pass": current["total"] <= allowed}))
    else:
        print(f"ruff ratchet: current={current['total']} baseline={allowed}")
        top = ", ".join(f"{k}×{v}" for k, v in list(current["by_code"].items())[:5])
        if top:
            print(f"  top codes: {top}")

    if current["total"] > allowed:
        extra = current["total"] - allowed
        print(
            f"FAIL: ruff findings increased by {extra} over the frozen baseline.\n"
            "  Fix the new findings in this change (preferred), or — only with a\n"
            "  documented reason — re-baseline via:\n"
            "    python scripts/check_ruff_ratchet.py --update-baseline --reason \"...\""
        )
        return 1
    if current["total"] < allowed and not args.json:
        print(
            "  IMPROVEMENT: count dropped below the baseline — lower it with "
            "--update-baseline so the gain is frozen."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
