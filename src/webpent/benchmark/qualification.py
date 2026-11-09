"""Schemas and offline harness for bounded campaign qualification.

These records describe what a qualification run measured.  They do not claim
that a live lab was tested; callers must provide explicit run evidence.  The
harness is deliberately pure: it accepts an injected deterministic fixture
runner and never performs network, browser, provider, or credential I/O.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive

_MAX_CASES = 256
_MAX_OUTCOMES = 512
_MAX_STOP_REASON = 160
_INLINE_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|token|cookie|password|secret|authorization)"
    r"\s*[:=]\s*[^\s,;]+"
)


def _safe_text(value: Any, limit: int = 160) -> str:
    redacted, _ = redact_sensitive(str(value or ""))
    redacted = _INLINE_SECRET.sub("[REDACTED]", redacted)
    return " ".join(redacted.split())[:limit]


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            _safe_text(key, 80): _safe_value(item, depth=depth + 1)
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_value(item, depth=depth + 1) for item in list(value)[:64]]
    if isinstance(value, str):
        return _safe_text(value, 320)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_text(value, 320)


def _unique_safe(values: Iterable[Any], *, limit: int = _MAX_CASES) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = _safe_text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return tuple(result)


def _safe_outcomes(values: Iterable[Any]) -> tuple[tuple[str, str], ...]:
    normalized: dict[str, str] = {}
    for value in values:
        if isinstance(value, Mapping):
            case_id = _safe_text(value.get("case_id"), 160)
            outcome = _safe_text(value.get("outcome") or value.get("status"), 80).lower()
        elif isinstance(value, (list, tuple)) and len(value) >= 2:
            case_id = _safe_text(value[0], 160)
            outcome = _safe_text(value[1], 80).lower()
        else:
            continue
        if case_id and outcome:
            normalized[case_id] = outcome
        if len(normalized) >= _MAX_OUTCOMES:
            break
    return tuple(sorted(normalized.items()))


@dataclass(frozen=True)
class GroundTruthCase:
    """One expected vulnerability class or case in a controlled fixture."""

    case_id: str
    category: str
    expected: bool = True
    source: str = "operator-declared"

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": _safe_text(self.case_id),
            "category": _safe_text(self.category),
            "expected": bool(self.expected),
            "source": _safe_text(self.source),
        }


@dataclass(frozen=True)
class QualificationRun:
    """A single run result tied to one explicit target and evidence artifact.

    ``candidate_case_ids`` measures discovery separately from confirmation.
    ``proof_case_ids`` and ``replay_case_ids`` are supplied by the caller after
    independent checks; the harness never treats an LLM claim as proof.
    """

    run_id: str
    target_ref: str
    evidence_artifact: str
    confirmed_case_ids: tuple[str, ...] = ()
    reviewed_case_ids: tuple[str, ...] = ()
    contacted_target: bool = False
    target_modified: bool = False
    findings_are_live: bool = False
    candidate_case_ids: tuple[str, ...] = ()
    proof_case_ids: tuple[str, ...] = ()
    replay_case_ids: tuple[str, ...] = ()
    unauthorized_attempts: int = 0
    out_of_scope_attempts: int = 0
    budget_spent: float = 0.0
    budget_limit: float = 0.0
    stop_reason: str = ""
    canonical_outcomes: tuple[tuple[str, str], ...] = ()

    def normalized(self) -> QualificationRun:
        """Return a bounded/redacted view used for metrics and persistence."""
        return QualificationRun(
            run_id=_safe_text(self.run_id),
            target_ref=_safe_text(self.target_ref, 320),
            evidence_artifact=_safe_text(self.evidence_artifact, 320),
            confirmed_case_ids=_unique_safe(self.confirmed_case_ids),
            reviewed_case_ids=_unique_safe(self.reviewed_case_ids),
            contacted_target=bool(self.contacted_target),
            target_modified=bool(self.target_modified),
            findings_are_live=bool(self.findings_are_live),
            candidate_case_ids=_unique_safe(self.candidate_case_ids),
            proof_case_ids=_unique_safe(self.proof_case_ids),
            replay_case_ids=_unique_safe(self.replay_case_ids),
            unauthorized_attempts=max(0, int(self.unauthorized_attempts)),
            out_of_scope_attempts=max(0, int(self.out_of_scope_attempts)),
            budget_spent=max(0.0, float(self.budget_spent)),
            budget_limit=max(0.0, float(self.budget_limit)),
            stop_reason=_safe_text(self.stop_reason, _MAX_STOP_REASON),
            canonical_outcomes=_safe_outcomes(self.canonical_outcomes),
        )

    def canonical_digest(self) -> str:
        """Hash only normalized outcome/guardrail data for repeat comparison."""
        run = self.normalized()
        payload = {
            "target_ref": run.target_ref,
            "candidate_case_ids": list(run.candidate_case_ids),
            "confirmed_case_ids": list(run.confirmed_case_ids),
            "proof_case_ids": list(run.proof_case_ids),
            "replay_case_ids": list(run.replay_case_ids),
            "canonical_outcomes": [list(item) for item in run.canonical_outcomes],
            "unauthorized_attempts": run.unauthorized_attempts,
            "out_of_scope_attempts": run.out_of_scope_attempts,
            "stop_reason": run.stop_reason,
        }
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self.normalized())
        result["confirmed_case_ids"] = list(self.normalized().confirmed_case_ids)
        result["reviewed_case_ids"] = list(self.normalized().reviewed_case_ids)
        result["candidate_case_ids"] = list(self.normalized().candidate_case_ids)
        result["proof_case_ids"] = list(self.normalized().proof_case_ids)
        result["replay_case_ids"] = list(self.normalized().replay_case_ids)
        result["canonical_outcomes"] = [list(item) for item in self.normalized().canonical_outcomes]
        return result


@dataclass(frozen=True)
class QualificationFixture:
    """Pure offline input passed to an injected fixture runner."""

    fixture_id: str
    target_ref: str
    ground_truth: tuple[GroundTruthCase, ...] = ()
    scenario: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        safe_scenario = _safe_value(dict(self.scenario))
        return {
            "fixture_id": _safe_text(self.fixture_id),
            "target_ref": _safe_text(self.target_ref, 320),
            "ground_truth": [case.as_dict() for case in self.ground_truth[:_MAX_CASES]],
            "scenario": safe_scenario,
        }


@dataclass
class QualificationMatrix:
    """Deterministic multi-run qualification projection."""

    ground_truth: list[GroundTruthCase] = field(default_factory=list)
    runs: list[QualificationRun] = field(default_factory=list)

    def add_run(self, run: QualificationRun) -> None:
        normalized = run.normalized()
        if any(existing.run_id == normalized.run_id for existing in self.runs):
            raise ValueError(f"duplicate run_id: {normalized.run_id}")
        self.runs.append(normalized)

    def summary(self) -> dict[str, Any]:
        expected = {case.case_id for case in self.ground_truth if case.expected}
        candidate = {
            case_id
            for run in self.runs
            for case_id in run.candidate_case_ids
        }
        confirmed = {
            case_id
            for run in self.runs
            for case_id in run.confirmed_case_ids
            if case_id in expected
        }
        expected_classes = {
            case.category.strip().lower()
            for case in self.ground_truth
            if case.expected and case.category.strip()
        }
        category_by_case = {
            case.case_id: case.category.strip().lower()
            for case in self.ground_truth
            if case.expected and case.category.strip()
        }
        confirmed_classes = {
            category_by_case[case_id]
            for case_id in confirmed
            if case_id in category_by_case
        }
        candidate_false_positives = candidate - expected
        candidate_false_negatives = expected - candidate
        proof_replay_pairs = [
            (set(run.proof_case_ids), set(run.replay_case_ids)) for run in self.runs
        ]
        agreement_denominator = sum(len(proof | replay) for proof, replay in proof_replay_pairs)
        agreement_numerator = sum(len(proof & replay) for proof, replay in proof_replay_pairs)
        run_safety = all(not run.target_modified for run in self.runs)
        return {
            "ground_truth_cases": len(expected),
            "runs": len(self.runs),
            "candidate_cases": len(candidate),
            "confirmed_expected_cases": len(confirmed),
            "coverage": round(len(confirmed) / len(expected), 4) if expected else 0.0,
            "expected_vulnerability_classes": len(expected_classes),
            "confirmed_vulnerability_classes": len(confirmed_classes),
            "class_coverage": (
                round(len(confirmed_classes) / len(expected_classes), 4)
                if expected_classes
                else 0.0
            ),
            "candidate_false_positives": len(candidate_false_positives),
            "candidate_false_negative_cases": len(candidate_false_negatives),
            "proof_replay_agreement_cases": agreement_numerator,
            "proof_replay_disagreement_cases": agreement_denominator - agreement_numerator,
            "proof_replay_agreement_rate": (
                round(agreement_numerator / agreement_denominator, 4)
                if agreement_denominator
                else 0.0
            ),
            "unauthorized_attempts": sum(run.unauthorized_attempts for run in self.runs),
            "out_of_scope_attempts": sum(run.out_of_scope_attempts for run in self.runs),
            "budget_spent": round(sum(run.budget_spent for run in self.runs), 6),
            "budget_limits": round(sum(run.budget_limit for run in self.runs), 6),
            "stop_reasons": sorted({run.stop_reason for run in self.runs if run.stop_reason}),
            "all_runs_target_unchanged": run_safety,
            "live_qualification_proven": all(run.findings_are_live for run in self.runs)
            if self.runs
            else False,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "ground_truth": [case.as_dict() for case in self.ground_truth],
            "runs": [run.as_dict() for run in self.runs],
            "summary": self.summary(),
        }


@dataclass(frozen=True)
class OfflineQualificationResult:
    """Output of repeated deterministic fixture execution."""

    matrix: QualificationMatrix
    run_digests: tuple[str, ...]
    reproducible: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "matrix": self.matrix.as_dict(),
            "run_digests": list(self.run_digests),
            "reproducible": self.reproducible,
        }


def run_offline_qualification(
    fixtures: Iterable[QualificationFixture],
    runner: Callable[[QualificationFixture, int], QualificationRun],
    *,
    repetitions: int = 2,
) -> OfflineQualificationResult:
    """Run pure fixtures repeatedly and compare canonical result digests.

    The runner receives a fixture and one-based repetition number.  It must
    return a ``QualificationRun`` and is responsible for using only offline
    deterministic inputs.  This function performs no I/O and rejects invalid
    repetition counts or duplicate fixture/run identifiers.
    """
    count = int(repetitions)
    if count < 2 or count > 20:
        raise ValueError("repetitions must be between 2 and 20")
    fixture_list = list(fixtures)
    if not fixture_list:
        raise ValueError("at least one fixture is required")
    ground_truth: dict[str, GroundTruthCase] = {}
    matrix = QualificationMatrix()
    digests: list[str] = []
    by_fixture: dict[str, list[str]] = {}
    for fixture in fixture_list:
        fixture_id = _safe_text(fixture.fixture_id)
        if not fixture_id or fixture_id in by_fixture:
            raise ValueError(f"duplicate fixture_id: {fixture_id}")
        by_fixture[fixture_id] = []
        for case in fixture.ground_truth:
            ground_truth.setdefault(_safe_text(case.case_id), case)
        for repetition in range(1, count + 1):
            run = runner(fixture, repetition)
            if not isinstance(run, QualificationRun):
                raise TypeError("offline runner must return QualificationRun")
            normalized = run.normalized()
            if not normalized.run_id:
                raise ValueError("offline runner returned an empty run_id")
            digest = normalized.canonical_digest()
            by_fixture[fixture_id].append(digest)
            digests.append(digest)
            matrix.add_run(normalized)
    matrix.ground_truth = list(ground_truth.values())
    reproducible = all(len(set(values)) == 1 for values in by_fixture.values())
    return OfflineQualificationResult(
        matrix=matrix,
        run_digests=tuple(digests),
        reproducible=reproducible,
    )


def build_qualification_matrix(
    ground_truth: Iterable[GroundTruthCase], runs: Iterable[QualificationRun]
) -> QualificationMatrix:
    matrix = QualificationMatrix(ground_truth=list(ground_truth))
    for run in runs:
        matrix.add_run(run)
    return matrix


__all__ = [
    "GroundTruthCase",
    "OfflineQualificationResult",
    "QualificationFixture",
    "QualificationMatrix",
    "QualificationRun",
    "build_qualification_matrix",
    "run_offline_qualification",
]
