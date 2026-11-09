"""webpent.production.hypothesis_qualification_harness — M3 UM-DR-17:
the recall/precision measurement harness wiring for the Charter §4.1
gate (UM-DR-16 built the gate; this is the corpus harness run).

What exists and what was missing:

* ``production/hypothesis_charter.py`` (UM-DR-16) — the fail-closed
  gate: recall ≥ 0.5 ∧ precision ≥ 0.7 ∧ > deterministic baseline ∧
  sample ≥ 30 ∧ fresh. Built with NO runner: nothing feeds it
  measurements, nothing stores verdicts, and the documented baseline
  (blind_v3 mode_a: recall 0.137 / precision 0.6667 / 120 cases) is
  pinned as constants but never REPLAYED from the recorded report.
* ``reports/goed_v1_8_4/`` — the recorded blind_v3 differential
  (differential_v184.json) and blind execution artifacts. The corpus
  itself (``benchmarks/blind_v3/manifest.json``) lives outside the repo
  — the harness treats it as an operator-supplied input with a
  validated contract, never as an assumption.

This module wires the three together:

1. **Corpus contract** — ``load_blind_v3_ground_truth(manifest_path)``:
   the blind_v3 manifest shape (cases with ``case_id`` /
   ``is_vulnerable`` / ``family``), validated fail-closed.
2. **Producer measurement** — ``measure_producer(...)``: runs a
   ``(case_record) -> bool`` producer over the corpus, classifies
   TP/FP/FN, and returns a ``CharterVerdict`` via the existing gate (a
   crashing case is an honest not-flagged, counted and reported).
3. **Verdict store** — ``save_verdict`` / ``load_latest_verdict``: a
   deterministic JSON store the freshness gate consumes
   (``charter_allows_budget_expansion``).
4. **Baseline replay** — ``replay_deterministic_baseline()``: re-reads
   the RECORDED blind_v3 mode_a metrics from
   ``reports/goed_v1_8_4/differential_v184.json`` and verifies they
   match the charter's pinned constants — the documented baseline is
   wired to the live gate, not just cited in its docstring.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from webpent.production.hypothesis_charter import (
    DETERMINISTIC_BASELINE_PRECISION,
    DETERMINISTIC_BASELINE_RECALL,
    CharterVerdict,
    charter_allows_budget_expansion,
    evaluate_hypothesis_qualification,
)

__all__ = [
    "HARNESS_STORE_DEFAULT",
    "HypothesisProducer",
    "baseline_replay_report_path",
    "load_blind_v3_ground_truth",
    "load_latest_verdict",
    "measure_producer",
    "replay_deterministic_baseline",
    "save_verdict",
]

logger = logging.getLogger(__name__)

#: The verdict store: one JSON document keyed by producer name.
HARNESS_STORE_DEFAULT = "reports/hypothesis_qualification/verdicts.json"

#: The recorded blind_v3 differential report (the documented baseline).
BASELINE_REPLAY_REPORT = Path("reports/goed_v1_8_4/differential_v184.json")

#: A hypothesis producer: takes one corpus case record, returns whether
#: it flags that case as vulnerable.
HypothesisProducer = Callable[[Mapping[str, Any]], bool]

_PRODUCER_ERROR_POLICY = "producer_error_counted_as_not_flagged"


def baseline_replay_report_path() -> Path:
    """The recorded differential report the baseline replay reads."""
    return BASELINE_REPLAY_REPORT


def load_blind_v3_ground_truth(manifest_path: str | os.PathLike[str]) -> dict[str, bool]:
    """Load and validate the blind_v3 manifest's ground truth.

    Fail-closed: the manifest must be a JSON object with a ``cases``
    list (or be a list itself) whose records carry a non-empty string
    ``case_id`` and a boolean ``is_vulnerable``. Any shape violation
    raises ``ValueError`` naming the offending record — a measurement
    on a malformed corpus is worse than no measurement.
    """
    path = Path(manifest_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"blind_v3 manifest unreadable: {path} ({exc})") from exc

    cases = payload.get("cases") if isinstance(payload, Mapping) else payload
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"blind_v3 manifest has no cases: {path}")

    ground_truth: dict[str, bool] = {}
    for index, record in enumerate(cases):
        if not isinstance(record, Mapping):
            raise ValueError(f"blind_v3 case #{index} is not an object: {path}")
        case_id = record.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"blind_v3 case #{index} lacks a string case_id: {path}")
        is_vulnerable = record.get("is_vulnerable")
        if not isinstance(is_vulnerable, bool):
            raise ValueError(
                f"blind_v3 case {case_id!r} lacks a boolean is_vulnerable: {path}"
            )
        if case_id in ground_truth:
            raise ValueError(f"blind_v3 case id {case_id!r} appears twice: {path}")
        ground_truth[case_id] = is_vulnerable
    return ground_truth


def _load_manifest_records(manifest_path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    path = Path(manifest_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, Mapping) else payload
    if not isinstance(cases, list):
        raise ValueError(f"blind_v3 manifest has no cases: {path}")
    return [dict(record) for record in cases if isinstance(record, Mapping)]


def measure_producer(
    producer: HypothesisProducer,
    *,
    producer_name: str,
    manifest_path: str | os.PathLike[str],
    measured_at: datetime | None = None,
) -> CharterVerdict:
    """Run one producer over the corpus and apply the charter gate.

    A producer exception on a case is an honest not-flagged (counted in
    the harness notes on the verdict's reasons when the verdict is
    otherwise qualified — never silently swallowed).
    """
    records = _load_manifest_records(manifest_path)
    ground_truth = load_blind_v3_ground_truth(manifest_path)
    predicted: list[str] = []
    producer_errors = 0
    for record in records:
        case_id = record.get("case_id")
        if case_id not in ground_truth:
            continue
        try:
            flagged = bool(producer(record))
        except Exception as exc:  # noqa: BLE001 — honest not-flagged
            producer_errors += 1
            logger.debug(
                "qualification harness: producer %s crashed on %s: %s",
                producer_name,
                case_id,
                type(exc).__name__,
            )
            continue
        if flagged:
            predicted.append(str(case_id))

    verdict = evaluate_hypothesis_qualification(
        producer=producer_name,
        corpus_id=f"blind_v3:{Path(manifest_path).name}",
        predicted=predicted,
        ground_truth=ground_truth,
        measured_at=measured_at,
    )
    if producer_errors:
        # Immutability: rebuild with the error policy recorded.
        data = verdict.as_dict()
        data["reasons"] = list(data["reasons"]) + [
            f"{_PRODUCER_ERROR_POLICY}:{producer_errors}"
        ]
        verdict = CharterVerdict(
            producer=data["producer"],
            corpus_id=data["corpus_id"],
            sample_size=data["sample_size"],
            true_positives=data["true_positives"],
            false_positives=data["false_positives"],
            false_negatives=data["false_negatives"],
            recall=data["recall"],
            precision=data["precision"],
            measured_at=data["measured_at"],
            qualified=data["qualified"],
            reasons=tuple(data["reasons"]),
        )
    return verdict


def save_verdict(verdict: CharterVerdict, store_path: str | os.PathLike[str]) -> Path:
    """Persist one verdict deterministically (atomic rewrite)."""
    path = Path(store_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    store: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, Mapping):
                store = dict(existing)
        except (OSError, json.JSONDecodeError):
            store = {}
    entry = verdict.as_dict()
    history = list(store.get(verdict.producer) or [])
    history.append(entry)
    store[verdict.producer] = history
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(store, indent=2, sort_keys=True), encoding="utf-8"
    )
    os.replace(temp, path)
    return path


def load_latest_verdict(
    producer: str,
    store_path: str | os.PathLike[str] = HARNESS_STORE_DEFAULT,
) -> CharterVerdict | None:
    """The producer's most recent stored verdict (None when never measured)."""
    path = Path(store_path)
    if not path.exists():
        return None
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    history = store.get(producer) if isinstance(store, Mapping) else None
    if not isinstance(history, list) or not history:
        return None
    latest = history[-1]
    if not isinstance(latest, Mapping):
        return None
    return CharterVerdict(
        producer=str(latest.get("producer") or producer),
        corpus_id=str(latest.get("corpus_id") or ""),
        sample_size=int(latest.get("sample_size") or 0),
        true_positives=int(latest.get("true_positives") or 0),
        false_positives=int(latest.get("false_positives") or 0),
        false_negatives=int(latest.get("false_negatives") or 0),
        recall=float(latest.get("recall") or 0.0),
        precision=float(latest.get("precision") or 0.0),
        measured_at=str(latest.get("measured_at") or ""),
        qualified=bool(latest.get("qualified")),
        reasons=tuple(str(r) for r in (latest.get("reasons") or [])),
    )


def replay_deterministic_baseline(
    report_path: str | os.PathLike[str] | None = None,
    *,
    measured_at: datetime | None = None,
) -> CharterVerdict:
    """Replay the RECORDED blind_v3 mode_a metrics through the gate.

    Reads ``reports/goed_v1_8_4/differential_v184.json`` mode_a_llm_off,
    verifies the recorded metrics match the charter's pinned baseline
    constants (recall 0.137 / precision 0.6667 — a mismatch is a
    ``ValueError``: the documented baseline and the live gate must never
    drift apart silently), and returns the baseline's own verdict: the
    deterministic engine is REFUSED budget expansion by construction
    (it IS the baseline — recall not above itself).
    """
    path = Path(report_path) if report_path else BASELINE_REPLAY_REPORT
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"baseline replay report unreadable: {path} ({exc})") from exc
    mode_a = payload.get("mode_a_llm_off") if isinstance(payload, Mapping) else None
    metrics = (mode_a or {}).get("metrics") if isinstance(mode_a, Mapping) else None
    if not isinstance(metrics, Mapping):
        raise ValueError(f"baseline replay report lacks mode_a_llm_off.metrics: {path}")

    recorded_recall = round(float(metrics.get("recall") or 0.0), 4)
    recorded_precision = round(float(metrics.get("precision") or 0.0), 4)
    if recorded_recall != round(DETERMINISTIC_BASELINE_RECALL, 4) or (
        recorded_precision != round(DETERMINISTIC_BASELINE_PRECISION, 4)
    ):
        raise ValueError(
            "recorded blind_v3 baseline drifted from the charter constants: "
            f"report=({recorded_recall}, {recorded_precision}) "
            f"charter=({DETERMINISTIC_BASELINE_RECALL}, "
            f"{DETERMINISTIC_BASELINE_PRECISION})"
        )

    tp = int(metrics.get("tp") or 0)
    fp = int(metrics.get("fp") or 0)
    fn = int(metrics.get("fn") or 0)
    tn = int(metrics.get("tn") or 0)
    ground_truth_size = tp + fp + fn + tn
    # Reconstruct the classification from the recorded counts: the
    # recorded tp set is unknown (blind), so the replay feeds the gate a
    # synthetic-but-equivalent classification with EXACTLY these counts.
    predicted: list[str] = []
    ground_truth: dict[str, bool] = {}
    index = 0

    def _add(case_is_vulnerable: bool, flagged: bool) -> None:
        nonlocal index
        index += 1
        case_id = f"bv3_replay_{index:03d}"
        ground_truth[case_id] = case_is_vulnerable
        if flagged:
            predicted.append(case_id)

    for _ in range(tp):
        _add(True, True)
    for _ in range(fp):
        _add(False, True)
    for _ in range(fn):
        _add(True, False)
    for _ in range(tn):
        _add(False, False)

    return evaluate_hypothesis_qualification(
        producer="deterministic_engine_blind_v3_mode_a",
        corpus_id=f"blind_v3_replay:{path.name}",
        predicted=predicted,
        ground_truth=ground_truth,
        measured_at=measured_at or datetime.now(timezone.utc),
    )


def budget_decision_for(
    producer: str,
    store_path: str | os.PathLike[str] = HARNESS_STORE_DEFAULT,
    *,
    now: datetime | None = None,
) -> tuple[bool, str, CharterVerdict | None]:
    """The end-to-end wiring: stored verdict → freshness gate decision."""
    verdict = load_latest_verdict(producer, store_path)
    allowed, reason = charter_allows_budget_expansion(verdict, now=now)
    return allowed, reason, verdict
