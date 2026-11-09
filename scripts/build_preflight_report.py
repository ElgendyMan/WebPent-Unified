"""Build a redacted, side-effect-free startup preflight artifact."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from webpent.shared.preflight import run_preflight

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "docs" / "preflight_report.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Explicit bind host to evaluate; defaults to loopback for local gates.",
    )
    args = parser.parse_args()
    report = run_preflight(host=args.host)
    payload = {
        "schema_version": "webpent-preflight-v1",
        "host_evaluated": args.host,
        "environment_profile": os.getenv("ENVIRONMENT_PROFILE", "lab"),
        "posture": report.get("posture", {}),
        "capability_manifest": report.get("capability_manifest", {}),
        "checks": {
            name: info
            for name, info in report.items()
            if name not in {"posture", "capability_manifest"}
        },
    }
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(OUTPUT_PATH), "state": payload["posture"].get("state")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
