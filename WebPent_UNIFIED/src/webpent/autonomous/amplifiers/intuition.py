"""Intuition amplifiers (v82, Layer 4 / Tasks 13-15).

Three pure advisory analyzers:

* ``anomaly`` — a statistical baseline of response behavior (median/MAD
  over sizes and latencies, status-code distribution) and deviation
  flags. Anything too rare in the baseline is a signal, not a finding.
* ``cross_target`` — a persistent, cross-target pattern store: per
  technology fingerprint, which vulnerability classes have been proven
  historically. New targets with the same fingerprint get those classes
  as advisory seeds. Same persistence discipline as IntelStore.
* ``hypothesis_quality`` — scores hypotheses for specificity, evidence
  and testability and returns an advisory re-ranking; nothing is dropped
  and nothing is promoted.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_SAMPLES = 128
MAX_FINGERPRINTS = 48
MAX_CLASSES_PER_FINGERPRINT = 16
MAX_HYPOTHESES = 32


# -- Task 13: statistical anomaly detector ---------------------------------


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _mad(values: list[float], median: float) -> float:
    return _median([abs(v - median) for v in values]) if values else 0.0


def build_baseline(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Median/MAD baseline over sizes and latencies plus status counts."""
    if not isinstance(observations, list):
        return {"samples": 0, "advisory": True}
    obs = [o for o in observations[:MAX_SAMPLES] if isinstance(o, dict)]
    sizes = [float(o["size"]) for o in obs if isinstance(o.get("size"), (int, float))]
    latencies = [
        float(o["latency_ms"]) for o in obs if isinstance(o.get("latency_ms"), (int, float))
    ]
    statuses = Counter()
    for o in obs:
        status = o.get("status")
        if isinstance(status, (int, str)):
            statuses[str(status)] += 1
    baseline: dict[str, Any] = {
        "samples": len(obs),
        "status_counts": dict(statuses),
        "advisory": True,
    }
    for name, values in (("size", sizes), ("latency_ms", latencies)):
        if len(values) >= 3:
            med = _median(values)
            mad = _mad(values, med)
            baseline[f"{name}_median"] = med
            baseline[f"{name}_mad"] = mad
    return baseline


def detect_anomalies(
    observation: dict[str, Any], baseline: dict[str, Any], *, robust_k: float = 4.0
) -> dict[str, Any]:
    """Flag deviations from the baseline; advisory only.

    A robust z-score |x - median| / max(MAD, epsilon) beyond ``robust_k``
    is an anomaly signal. Missing baselines yield no signals honestly.
    """
    signals: list[dict[str, Any]] = []
    if not isinstance(observation, dict) or not isinstance(baseline, dict):
        return {"signals": [], "advisory": True}
    for name in ("size", "latency_ms"):
        value = observation.get(name)
        med = baseline.get(f"{name}_median")
        mad = baseline.get(f"{name}_mad")
        if (
            isinstance(value, (int, float))
            and isinstance(med, (int, float))
            and isinstance(mad, (int, float))
        ):
            z = abs(float(value) - float(med)) / max(mad, 1e-9)
            if z > robust_k:
                signals.append(
                    {
                        "kind": f"{name}_deviation",
                        "z": round(z, 2),
                        "value": value,
                        "median": med,
                        "advisory": True,
                    }
                )
    status = observation.get("status")
    if isinstance(status, (int, str)):
        counts = baseline.get("status_counts") or {}
        seen = counts.get(str(status), 0)
        samples = baseline.get("samples", 0)
        if samples >= 5 and seen == 0:
            signals.append(
                {
                    "kind": "rare_status",
                    "status": str(status),
                    "note": "status never observed in baseline",
                    "advisory": True,
                }
            )
    return {"signals": signals, "advisory": True}


# -- Task 14: cross-target pattern recognition ------------------------------


def fingerprint_of(tech_stack: Any) -> str:
    """Stable fingerprint key for a technology list/tuple/str."""
    if isinstance(tech_stack, str):
        items = [tech_stack]
    elif isinstance(tech_stack, (list, tuple, set)):
        items = list(tech_stack)
    else:
        return ""
    cleaned = sorted(
        {redact(str(item)).strip().lower()[:40] for item in items if str(item).strip()}
    )
    return "|".join(cleaned)[:200] if cleaned else ""


class CrossTargetStore:
    """Cross-session, cross-target proven-class memory per fingerprint."""

    def __init__(self, persist_path: Path | str) -> None:
        self.path = Path(persist_path)
        self._patterns: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        self._patterns = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            _LOG.warning("cross-target file unreadable; starting with no memory: %s", self.path)
            return
        if not isinstance(raw, dict):
            return
        for fingerprint, entry in raw.items():
            if not isinstance(fingerprint, str) or not isinstance(entry, dict):
                continue
            classes = entry.get("proven_classes")
            targets = entry.get("targets")
            if isinstance(classes, dict) and isinstance(targets, list):
                self._patterns[fingerprint[:200]] = {
                    "proven_classes": {
                        redact(str(k))[:64]: int(v) if isinstance(v, int) else 1
                        for k, v in list(classes.items())[:MAX_CLASSES_PER_FINGERPRINT]
                    },
                    "targets": [redact(str(t))[:120] for t in targets[:MAX_FINGERPRINTS]],
                }
            if len(self._patterns) >= MAX_FINGERPRINTS:
                break

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._patterns, indent=2, ensure_ascii=False)
        try:
            fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("cross-target save failed (memory stays in-process): %s", exc)

    def record_proven(self, tech_stack: Any, vuln_class: str, target: str) -> bool:
        """One proven class on one target with this fingerprint."""
        fingerprint = fingerprint_of(tech_stack)
        vuln = redact(str(vuln_class or "").strip().lower())[:64]
        if not fingerprint or not vuln:
            return False
        entry = self._patterns.setdefault(
            fingerprint, {"proven_classes": {}, "targets": []}
        )
        entry["proven_classes"][vuln] = entry["proven_classes"].get(vuln, 0) + 1
        if len(entry["proven_classes"]) > MAX_CLASSES_PER_FINGERPRINT:
            entry["proven_classes"] = dict(
                sorted(
                    entry["proven_classes"].items(), key=lambda kv: -kv[1]
                )[:MAX_CLASSES_PER_FINGERPRINT]
            )
        origin = urlsplit(str(target or ""))
        host = origin.hostname or ""
        if origin.port:
            host = f"{host}:{origin.port}"
        target_key = redact(f"{origin.scheme}://{host}"[:120]) if origin.scheme and host else ""
        if target_key and target_key not in entry["targets"]:
            entry["targets"].insert(0, target_key)
            entry["targets"] = entry["targets"][:MAX_FINGERPRINTS]
        return True

    def suggestions_for(self, tech_stack: Any) -> list[dict[str, Any]]:
        """Advisory class suggestions for a new target, ranked by hits."""
        fingerprint = fingerprint_of(tech_stack)
        entry = self._patterns.get(fingerprint)
        if not entry:
            return []
        ranked = sorted(entry["proven_classes"].items(), key=lambda kv: -kv[1])
        return [
            {"vuln_class": vuln, "hits": hits, "advisory": True}
            for vuln, hits in ranked[:MAX_CLASSES_PER_FINGERPRINT]
        ]


# -- Task 15: hypothesis quality scoring ------------------------------------

QUALITY_WEIGHTS = {"specificity": 0.4, "evidence": 0.35, "testability": 0.25}


def score_hypothesis(hypothesis: dict[str, Any]) -> float:
    """Quality score in [0, 1]; pure and deterministic.

    * specificity: a concrete target URL and method beat vague prose,
    * evidence: any non-empty evidence/source field counts,
    * testability: an explicitly small iteration estimate or a validator
      reference.
    """
    if not isinstance(hypothesis, dict):
        return 0.0
    target = str(hypothesis.get("target_url") or "").strip()
    specificity = 1.0 if target.startswith("http") and len(target) > 12 else 0.3
    if hypothesis.get("request_method"):
        specificity = min(1.0, specificity + 0.2)
    evidence_field = str(hypothesis.get("evidence") or hypothesis.get("source") or "")
    evidence = 1.0 if evidence_field.strip() else 0.2
    testability = 0.5
    if hypothesis.get("validator") or hypothesis.get("estimated_iterations") is not None:
        testability = 1.0
    return round(
        QUALITY_WEIGHTS["specificity"] * specificity
        + QUALITY_WEIGHTS["evidence"] * evidence
        + QUALITY_WEIGHTS["testability"] * testability,
        4,
    )


def rank_by_quality(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable advisory re-ranking by quality score; nothing is dropped."""
    if not isinstance(hypotheses, list):
        return []
    items = [dict(item) for item in list(hypotheses)[:MAX_HYPOTHESES] if isinstance(item, dict)]
    for item in items:
        item["quality_score"] = score_hypothesis(item)
    return sorted(items, key=lambda item: -item["quality_score"])
