"""Run the http-v3 Logic Breaker benchmark and print the report verbatim.

Advisory-only, offline, against the controlled loopback target. No
external submission of any result. Used to regenerate the verbatim
benchmark section of docs/logic_breaker/01_price_integrity_results.md.
"""
from __future__ import annotations

import json

from webpent.egaie.benchmark.http_ground_truth import HTTP_GROUND_TRUTH_V3
from webpent.egaie.benchmark.http_runner import run_http_comparison
from webpent.egaie.http_target import ControlledInvestigationTarget


def main() -> None:
    with ControlledInvestigationTarget() as target:
        report = run_http_comparison(
            target, max_rounds=14, repetitions=2,
            cases=HTTP_GROUND_TRUTH_V3,
        )
    data = report.to_dict()
    print(json.dumps(data, indent=2, sort_keys=True, default=str))

    # Confusion matrix over the adaptive loop (ground-truth polarity).
    positive = {case.case_id for case in HTTP_GROUND_TRUTH_V3
                if case.case_id.startswith("pos-")}
    negative = {case.case_id for case in HTTP_GROUND_TRUTH_V3
                if case.case_id.startswith("neg-")}
    confirmed = set(data["adaptive"]["confirmed_case_ids"])
    matrix = {
        "true_positives": sorted(confirmed & positive),
        "false_positives": sorted(confirmed & negative),
        "false_negatives": sorted(positive - confirmed),
        "true_negatives": sorted(negative - confirmed),
    }
    print("CONFUSION_MATRIX")
    print(json.dumps(matrix, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
