"""U-VERDICT-4 — Finding Classifier tests (8 tests)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verdict_tool.classifier import ClassificationError, FindingClassifier
from verdict_tool.tracking import Workspace, new_state


@pytest.fixture
def classifier(ws: Workspace) -> FindingClassifier:
    state = ws.load() or new_state()
    return FindingClassifier(state, ws)


def test_register_and_classify_roundtrip(ws: Workspace,
                                         classifier: FindingClassifier
                                         ) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    record = classifier.classify(
        "f-1", "confirmed", re_test_evidence=["shots/f.png"],
        severity_confirmed="high", impact_confirmed="data exposure",
    )
    assert record.classification == "confirmed"
    assert record.impact_confirmed == "data exposure"
    assert record.classified_at
    state = ws.load()
    assert state.findings[0]["classification"] == "confirmed"


def test_unknown_finding_rejected(classifier: FindingClassifier) -> None:
    with pytest.raises(ClassificationError, match="unknown finding"):
        classifier.classify("ghost", "confirmed",
                            re_test_evidence=["x"], impact_confirmed="i")


def test_re_test_evidence_required(classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    with pytest.raises(ClassificationError, match="evidence"):
        classifier.classify("f-1", "confirmed", impact_confirmed="i")
    with pytest.raises(ClassificationError, match="evidence"):
        classifier.classify("f-1", "false_positive", reason="nope")


def test_reason_required_for_fp_and_inconclusive(
        classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    with pytest.raises(ClassificationError, match="reason"):
        classifier.classify("f-1", "false_positive",
                            re_test_evidence=["e.png"])
    classifier.classify("f-1", "false_positive",
                        re_test_evidence=["e.png"],
                        reason="waf interference")
    classifier.register("f-2", "target_a", "sqli", "high", 0.9)
    with pytest.raises(ClassificationError, match="reason"):
        classifier.classify("f-2", "inconclusive",
                            re_test_evidence=["e.png"])
    classifier.classify("f-2", "inconclusive",
                        re_test_evidence=["e.png"],
                        reason="target rate-limited the re-test")


def test_impact_required_for_confirmed(classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    with pytest.raises(ClassificationError, match="impact"):
        classifier.classify("f-1", "confirmed",
                            re_test_evidence=["e.png"])


def test_classification_is_immutable(classifier: FindingClassifier) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    classifier.classify("f-1", "inconclusive", reason="blocked")
    with pytest.raises(ClassificationError, match="immutable"):
        classifier.classify("f-1", "confirmed",
                            re_test_evidence=["e.png"],
                            impact_confirmed="i")
    with pytest.raises(ClassificationError, match="already registered"):
        classifier.register("f-1", "target_a", "sqli", "high", 0.9)


def test_fp_rate_computation(ws: Workspace, classifier: FindingClassifier
                             ) -> None:
    assert classifier.compute_fp_rate() == 0.0
    for i in range(4):
        classifier.register(f"f-{i}", "target_a", "sqli", "high", 0.9)
    classifier.classify("f-0", "confirmed", re_test_evidence=["e.png"],
                        impact_confirmed="i")
    classifier.classify("f-1", "confirmed", re_test_evidence=["e.png"],
                        impact_confirmed="i")
    classifier.classify("f-2", "false_positive", re_test_evidence=["e.png"],
                        reason="r1")
    classifier.classify("f-3", "false_positive", re_test_evidence=["e.png"],
                        reason="r2")
    assert classifier.compute_fp_rate() == pytest.approx(0.5)
    summary = classifier.batch_summary()
    assert summary["confirmed"] == 2
    assert summary["false_positive"] == 2
    assert summary["fp_rate"] == pytest.approx(0.5)
    assert summary["by_target"]["target_a"]["classified"] == 4
    assert ws.load().findings[0]["registered_at"]


def test_export_format(ws: Workspace, classifier: FindingClassifier,
                       tmp_path: Path) -> None:
    classifier.register("f-1", "target_a", "sqli", "high", 0.9)
    classifier.classify("f-1", "confirmed", re_test_evidence=["e.png"],
                        impact_confirmed="i")
    out = classifier.export(tmp_path / "findings_export.json")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert set(payload) == {"exported_at", "summary", "findings"}
    assert payload["findings"][0]["finding_id"] == "f-1"
    assert payload["summary"]["confirmed"] == 1
