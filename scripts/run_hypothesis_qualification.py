#!/usr/bin/env python3
"""M3 UM-DR-17: run the Charter §4.1 qualification harness.

Usage:
    python scripts/run_hypothesis_qualification.py --manifest <path> \
        [--producer-module module:callable --producer-name name] \
        [--store reports/hypothesis_qualification/verdicts.json] \
        [--replay-baseline]

Modes:
  * ``--manifest`` + a producer (module:callable taking one case record
    and returning bool) — measures the producer on the blind_v3 corpus,
    applies the charter gate, stores the verdict, prints the budget
    decision.
  * ``--replay-baseline`` — replays the RECORDED blind_v3 mode_a
    metrics through the gate (verifies the documented baseline matches
    the pinned constants; the deterministic engine is refused budget by
    construction).

Fail-closed: a bad manifest, an unreadable baseline report, or a
producer that cannot be imported all exit non-zero with the reason.
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from webpent.production.hypothesis_qualification_harness import (  # noqa: E402
    HARNESS_STORE_DEFAULT,
    budget_decision_for,
    measure_producer,
    replay_deterministic_baseline,
    save_verdict,
)


def _load_producer(spec: str):
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise ValueError(f"producer spec must be module:callable, got {spec!r}")
    module = importlib.import_module(module_name)
    producer = getattr(module, attribute)
    if not callable(producer):
        raise ValueError(f"producer {spec!r} is not callable")
    return producer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", help="path to the blind_v3 manifest.json")
    parser.add_argument(
        "--producer-module",
        help="module:callable taking one case record -> bool",
    )
    parser.add_argument("--producer-name", default=None)
    parser.add_argument("--store", default=HARNESS_STORE_DEFAULT)
    parser.add_argument("--replay-baseline", action="store_true")
    args = parser.parse_args(argv)

    if args.replay_baseline:
        try:
            verdict = replay_deterministic_baseline()
        except ValueError as exc:
            print(f"BASELINE REPLAY FAILED: {exc}", file=sys.stderr)
            return 2
        save_verdict(verdict, args.store)
        allowed, reason, _ = budget_decision_for(verdict.producer, args.store)
        print(f"producer : {verdict.producer}")
        print(f"corpus   : {verdict.corpus_id}")
        print(f"sample   : {verdict.sample_size}  tp={verdict.true_positives} "
              f"fp={verdict.false_positives} fn={verdict.false_negatives}")
        print(f"recall   : {verdict.recall:.4f}   precision: {verdict.precision:.4f}")
        print(f"verdict  : {'QUALIFIED' if verdict.qualified else 'REFUSED'}")
        for reason_line in verdict.reasons:
            print(f"  reason : {reason_line}")
        print(f"budget   : {'ALLOWED' if allowed else 'REFUSED'} ({reason})")
        return 0

    if not args.manifest or not args.producer_module:
        parser.error("--manifest and --producer-module are required "
                     "(or use --replay-baseline)")
        return 2

    producer_name = args.producer_name or args.producer_module
    try:
        producer = _load_producer(args.producer_module)
        verdict = measure_producer(
            producer,
            producer_name=producer_name,
            manifest_path=args.manifest,
        )
    except (ValueError, ImportError, AttributeError) as exc:
        print(f"HARNESS FAILED: {exc}", file=sys.stderr)
        return 2

    save_verdict(verdict, args.store)
    allowed, reason, _ = budget_decision_for(producer_name, args.store)
    print(f"producer : {verdict.producer}")
    print(f"corpus   : {verdict.corpus_id}")
    print(f"sample   : {verdict.sample_size}  tp={verdict.true_positives} "
          f"fp={verdict.false_positives} fn={verdict.false_negatives}")
    print(f"recall   : {verdict.recall:.4f}   precision: {verdict.precision:.4f}")
    print(f"verdict  : {'QUALIFIED' if verdict.qualified else 'REFUSED'}")
    for reason_line in verdict.reasons:
        print(f"  reason : {reason_line}")
    print(f"budget   : {'ALLOWED' if allowed else 'REFUSED'} ({reason})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
