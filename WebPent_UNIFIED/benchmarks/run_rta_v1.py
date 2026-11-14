"""Run the RTA v1 real-HTTP benchmark against disposable local applications."""

from __future__ import annotations

import json
from pathlib import Path

from webpent.rta import (
    RtaScope,
    create_target_app,
    default_target_configs,
    discover_loopback_target,
    run_rta_validation,
    serve_loopback,
)


def _metrics(results: tuple) -> dict[str, float | int]:
    tp = sum(result.predicted_vulnerable and result.truth_vulnerable for result in results)
    fp = sum(result.predicted_vulnerable and not result.truth_vulnerable for result in results)
    fn = sum((not result.predicted_vulnerable) and result.truth_vulnerable for result in results)
    tn = sum(
        (not result.predicted_vulnerable) and (not result.truth_vulnerable) for result in results
    )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    predicted_positive = [result for result in results if result.predicted_vulnerable]
    proof_complete = (
        sum(result.proof is not None for result in predicted_positive) / len(predicted_positive)
        if predicted_positive
        else 1.0
    )
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "proof_completeness": proof_complete,
        "case_count": len(results),
    }


def main() -> None:
    target_reports: list[dict] = []
    scope = RtaScope(campaign_id="rta-v1-real-http-benchmark")
    for config in default_target_configs():
        app = create_target_app(config)
        with serve_loopback(app) as base_url:
            discovery = discover_loopback_target(
                base_url,
                config.target_id,
                app.state.rta_runtime_digest,
                scope,
            )
            validation = run_rta_validation(base_url, scope, config)
        target_reports.append(
            {
                "target_id": config.target_id,
                "version": config.version,
                "source_digest": config.source_digest,
                "runtime_digest": validation.runtime_digest,
                "discovery": {
                    "surface_count": len(discovery.surfaces),
                    "parameter_count": sum(
                        len(surface.parameters) for surface in discovery.surfaces
                    ),
                    "auth_required_count": sum(
                        surface.auth_required for surface in discovery.surfaces
                    ),
                    "observation_count": len(discovery.observations),
                },
                "metrics": _metrics(validation.results),
                "cases": [
                    {
                        "case_id": result.case_id,
                        "class": result.vulnerability_class,
                        "predicted": result.predicted_vulnerable,
                        "truth": result.truth_vulnerable,
                        "verdict": result.verdict,
                        "proof_replay_verified": bool(
                            result.proof and result.proof.replay_verified
                        ),
                    }
                    for result in validation.results
                ],
                "governance": validation.governance,
            }
        )
    report = {
        "report": "RTA v1 Realistic Target Assessment",
        "mode": "local_loopback_real_http",
        "target_count": len(target_reports),
        "targets": target_reports,
        "safety": {
            "external_targets": False,
            "real_credentials": False,
            "state_mutation": False,
            "external_callbacks": False,
            "qualification_effect": False,
            "official_isolated_p10_runs_authorized": False,
        },
        "interpretation": (
            "HTTP-backed disposable fixture evidence; not field detection quality "
            "or VIP qualification"
        ),
    }
    output = Path("reports/evaluation/rta_v1_real_http_capability_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
