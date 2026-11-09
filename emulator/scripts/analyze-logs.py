#!/usr/bin/env python3
"""Produce the emulator attack report from the shared logs."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logparse import analyze  # noqa: E402


def main() -> int:
    log_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parents[1] / "monitoring" / "nginx-logs"
    report = analyze(log_dir)
    report.generated_at = datetime.now(timezone.utc).isoformat()
    out = report.to_markdown()
    target = log_dir.parent / "attack_report.md"
    target.write_text(out, encoding="utf-8")
    print(out, end="")
    print(f"\nwritten to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
