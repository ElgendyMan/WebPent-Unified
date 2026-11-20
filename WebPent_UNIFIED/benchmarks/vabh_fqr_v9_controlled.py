#!/usr/bin/env python3
"""VABH-FQR v9 benchmark entrypoint; delegates to the offline runner."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))  # noqa: E402

from webpent.vabhfqr_v9.benchmark import VIPBenchmarkSuiteV9  # noqa: E402


def main() -> int:
    suite = VIPBenchmarkSuiteV9.from_recorded_state()
    print(suite.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
