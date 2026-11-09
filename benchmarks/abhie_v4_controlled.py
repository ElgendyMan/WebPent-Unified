"""Truthful, offline ABHIE v4 benchmark over recorded evidence only.

The runner does not execute a target, create observations, or infer missing
causal evidence.  A class is scorable only when a recorded case satisfies the
historical completeness contract and the source artifact contains a recorded
proof reference.  Missing classes remain blocked and are excluded from
precision/recall accounting.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .abhie_v4_quality import score_report
except ImportError:  # pragma: no cover - direct script execution
    from abhie_v4_quality import score_report

CLASSES = (
    "idor",
    "privilege_escalation",
    "business_logic_authorization_failure",
    "tenant_isolation",
    "workflow_abuse",
    "sensitive_information_exposure",
)

CLASS_ALIASES = {
    "business_logic": "business_logic_authorization_failure",
    "business_logic_authorization": "business_logic_authorization_failure",
    "information_disclosure": "sensitive_information_exposure",
    "sensitive_information_exposure": "sensitive_information_exposure",
    "tenant_isolation": "tenant_isolation",
    "workflow": "workflow_abuse",
    "workflow_state_boundary": "workflow_abuse",
}

READINESS_CONTRACTS = {
    category: {
        "required_semantics": (
            "recorded candidate/control observations",
            "causal oracle result",
            "independent negative control",
            "sealed proof bundle",
            "replay verification",
        ),
        "target_neutral": True,
        "missing_evidence_is_blocking": True,
    }
    for category in CLASSES
}


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("source_artifact_must_be_object")
    return data


def _case_entries(source: dict[str, Any]) -> list[dict[str, Any]]:
    containers: tuple[dict[str, Any], ...] = (source,)
    evaluation = source.get("evaluation")
    if isinstance(evaluation, dict):
        containers = (source, evaluation)
    for container in containers:
        for key in ("cases", "results", "scenarios", "case_results"):
            value = container.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _class_of(case: dict[str, Any]) -> str:
    value = (
        case.get("class")
        or case.get("vulnerability_class")
        or case.get("category")
        or case.get("type")
    )
    normalized = str(value).lower().replace(" ", "_") if value else ""
    return CLASS_ALIASES.get(normalized, normalized)


def _has_recorded_proof_ref(source: dict[str, Any]) -> bool:
    provenance = source.get("provenance")
    if not isinstance(provenance, dict):
        return False
    return bool(provenance.get("source_proof_bundle_ref_recorded"))


def _is_historically_complete(case: dict[str, Any], source: dict[str, Any]) -> bool:
    """Accept only the exact equivalent fields already present in the artifact."""
    return (
        case.get("validation_outcome") == "confirmed"
        and case.get("ground_truth_outcome") == "confirmed"
        and case.get("proof_complete") is True
        and bool(case.get("ground_truth_source"))
        and case.get("hypothesis_generated") is True
        and int(case.get("requests_used", 0) or 0) > 0
        and _has_recorded_proof_ref(source)
    )


def _recorded_case(case: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    provenance = source.get("provenance", {})
    return {
        "case_id": str(case.get("case_id", case.get("id", "unlabelled"))),
        "target_id": case.get("target_id"),
        "evidence_quality": case.get("evidence_quality"),
        "hypothesis_generated": case.get("hypothesis_generated"),
        "ground_truth_outcome": case.get("ground_truth_outcome"),
        "validation_outcome": case.get("validation_outcome"),
        "proof_complete": case.get("proof_complete"),
        "requests_used": case.get("requests_used"),
        "ground_truth_source": case.get("ground_truth_source"),
        "recorded_proof_bundle_ref": provenance.get("source_proof_bundle_ref_recorded"),
        "evidence_basis": "historical_equivalent_fields_only",
    }


def build_report(source_path: Path) -> dict[str, Any]:
    source = _load(source_path)
    entries = _case_entries(source)
    complete_by_class: dict[str, list[dict[str, Any]]] = {category: [] for category in CLASSES}
    for case in entries:
        category = _class_of(case)
        if category in complete_by_class and _is_historically_complete(case, source):
            complete_by_class[category].append(_recorded_case(case, source))

    classes: list[dict[str, Any]] = []
    for category in CLASSES:
        recorded = complete_by_class[category]
        if recorded:
            classes.append(
                {
                    "class": category,
                    "status": "SCORABLE_FROM_RECORDED_ARTIFACT",
                    "scorable": True,
                    "case_count": len(recorded),
                    "cases": recorded,
                    "readiness_contract": READINESS_CONTRACTS[category],
                    "reason": (
                        "only historical validation, ground-truth, proof, hypothesis, "
                        "request, and recorded proof-reference fields were joined"
                    ),
                }
            )
        else:
            classes.append(
                {
                    "class": category,
                    "status": "BLOCKED",
                    "scorable": False,
                    "case_count": 0,
                    "cases": [],
                    "readiness_contract": READINESS_CONTRACTS[category],
                    "reason": (
                        "no complete recorded candidate/control/oracle/proof/replay "
                        "evidence satisfying the readiness contract"
                    ),
                }
            )

    report: dict[str, Any] = {
        "benchmark_id": "ABHIE-v4-six-class-controlled-offline",
        "schema_version": "abhie-v4-controlled-benchmark-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_path),
        "source_artifact_read_only": True,
        "registered_classes": list(CLASSES),
        "classes": classes,
        "execution": {
            "offline": True,
            "requests_sent": 0,
            "credentials_used": False,
            "mutations_performed": False,
            "external_targets_contacted": False,
            "runner_creates_observations": False,
        },
        "governance": {
            "official_isolated_p10_runs_authorized": False,
            "p10_status": "NOT_QUALIFIED",
            "p9_status": "NOT_QUALIFIED",
            "vip_status": "NOT_QUALIFIED",
            "bug_bounty_status": "BLOCKED",
            "human_signoff": False,
            "qualification_effect": False,
        },
    }
    report["quality_score"] = score_report(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-artifact",
        type=Path,
        default=Path("reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.source_artifact)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["quality_score"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
