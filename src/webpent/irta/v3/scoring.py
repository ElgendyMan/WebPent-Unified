"""IRTA v3 case inventory and honest scoring boundary."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from .proof import ProofBundle
from .targets import TargetRuntime


class TruthLabel(StrEnum):
    VULNERABLE = "vulnerable"
    CLEAN = "clean"


@dataclass(frozen=True)
class V3Case:
    case_id: str
    target_id: str
    vulnerability_class: str
    truth: TruthLabel
    bundle: ProofBundle | None = None
    detector_claim: TruthLabel | None = None


@dataclass(frozen=True)
class V3Score:
    targets: int
    cases: int
    classes: int
    tp: int
    fp: int
    fn: int
    blocked: int
    proof_complete: int


def build_case_inventory(targets: Iterable[TargetRuntime]) -> tuple[V3Case, ...]:
    classes = (
        "idor",
        "function-authorization",
        "tenant-isolation",
        "partial-authorization",
        "workflow-ordering",
        "business-logic",
    )
    cases: list[V3Case] = []
    for target in targets:
        for index in range(10):
            vulnerability_class = classes[index % len(classes)]
            cases.append(
                V3Case(
                    case_id=f"{target.target_id}-case-{index + 1:02d}",
                    target_id=target.target_id,
                    vulnerability_class=vulnerability_class,
                    truth=TruthLabel.VULNERABLE if index % 2 == 0 else TruthLabel.CLEAN,
                )
            )
    return tuple(cases)


def score_cases(cases: Iterable[V3Case]) -> V3Score:
    rows = tuple(cases)
    tp = fp = fn = blocked = proof_complete = 0
    eligible = 0
    for row in rows:
        if row.bundle is None or not row.bundle.scoring_eligible():
            blocked += 1
            continue
        eligible += 1
        proof_complete += 1
        if row.truth is TruthLabel.VULNERABLE and row.detector_claim is TruthLabel.VULNERABLE:
            tp += 1
        elif row.truth is TruthLabel.CLEAN and row.detector_claim is TruthLabel.VULNERABLE:
            fp += 1
        elif row.truth is TruthLabel.VULNERABLE and row.detector_claim is TruthLabel.CLEAN:
            fn += 1
    return V3Score(
        targets=len({row.target_id for row in rows}),
        cases=len(rows),
        classes=len({row.vulnerability_class for row in rows}),
        tp=tp,
        fp=fp,
        fn=fn,
        blocked=blocked,
        proof_complete=proof_complete if eligible else 0,
    )
