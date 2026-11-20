#!/usr/bin/env python3
"""Offline entrypoint for the VABH-FIL v8 controlled benchmark."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.vabhfil_v8.benchmark import VIPControlledBenchmarkV7  # noqa: E402, I001


if __name__ == "__main__":
    result = VIPControlledBenchmarkV7().run()
    print(f"registered={result['registered_scenario_count']}")
    print(f"scorable={result['scorable_case_count']}")
    print(f"blocked={result['blocked_case_count']}")
    print(f"requests_sent={result['requests_sent']}")
