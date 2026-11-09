#!/usr/bin/env python3
"""Evaluate an observed WebPent result against a versioned benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.metrics import compute_metrics


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--observed", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    benchmark = _load(args.benchmark)
    observed_payload = _load(args.observed)
    expected = benchmark.get("entries", benchmark) if isinstance(benchmark, dict) else benchmark
    observed = (
        observed_payload.get("findings", observed_payload)
        if isinstance(observed_payload, dict)
        else observed_payload
    )
    if not isinstance(expected, list) or not isinstance(observed, list):
        raise SystemExit("expected and observed payloads must be JSON arrays")

    metrics = compute_metrics(expected, observed, confirmed_only=True).as_dict()
    result = {
        "benchmark": str(args.benchmark),
        "observed": str(args.observed),
        "confirmed_only": True,
        "metrics": metrics,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
