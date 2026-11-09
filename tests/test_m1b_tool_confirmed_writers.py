"""M1-B (E-1) Tool-Confirmed writer enforcement tests (2026-11-05).

M0 finding E-1: the "Tool-Confirmed" writer set was a convention (~7
families), the Finding model accepted the literal with no proof
requirement, and service/cost_alerts.py stamped it on lifecycle
NOTIFICATION objects with no evidence at all.

M1-B enforcement (two layers):
  1. MODEL LEVEL — Finding(confidence_level="Tool-Confirmed") requires
     provenance: evidence_bundle (sealed proof) OR an evidence dict
     naming the confirming gate (tool_confirmed_by / validator_tool /
     promotion_guard / oob_confirmed / avi_promoted). No provenance ⇒
     ValueError at construction, regardless of the writer.
  2. REGISTRY LEVEL (AST) — every src module that assigns the literal
     "Tool-Confirmed" to confidence_level must be in the approved
     writer registry below; adding a writer requires a conscious
     registry update (same pattern as the frozen-module gate).
"""

from __future__ import annotations

import ast
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "webpent"

# The approved writer registry (M0 CAPABILITY_WIRING §2 + M1-B edits).
# service/cost_alerts.py was REMOVED from this set by M1-B.
APPROVED_TOOL_CONFIRMED_WRITERS = {
    "agents/validator/agent.py",
    "agents/validator/structural_checks.py",
    "agents/validator/active_checks.py",
    "agents/api_testing/agent.py",
    "agents/access_control/agent.py",
    "graph/builder.py",
    "egaie/finding_bridge.py",
    "memory/db.py",  # mark_oob_confirmed (SQL flip + provenance stamp)
    # Discovered by this registry test during M1-B (missed by the M0
    # inventory): deterministic owner/foreign/negative-control identity
    # differential — legitimate writer, now carries tool_confirmed_by.
    "shared/bac_identity_tester.py",
    # UM-DR-26 (r6c): the lifecycle-notification writer — a PROMOTED alert
    # carries the promotion gate's Tool-Confirmed stamp with
    # tool_confirmed_by="webpent.lifecycle" provenance. Registered
    # consciously here; service/cost_alerts.py itself keeps the M1b
    # source-level ban (no literal) and delegates to this builder.
    "service/lifecycle_findings.py",
}


def _finding(**overrides) -> Finding:
    params = dict(
        id=uuid.uuid4(),
        title="test finding",
        severity="high",
        description="test description",
        tool_name="test",
        url="http://t/x",
        confidence=Confidence.TENTATIVE.value,
        vuln_class=VulnClass.XSS.value,
    )
    params.update(overrides)
    return Finding(**params)


class TestModelLevelProofRequirement:
    def test_tool_confirmed_without_provenance_rejected(self):
        with pytest.raises(ValueError, match="provenance"):
            _finding(confidence_level="Tool-Confirmed")

    def test_tool_confirmed_without_evidence_rejected(self):
        with pytest.raises(ValueError, match="provenance"):
            _finding(confidence_level="Tool-Confirmed", evidence=None)

    def test_tool_confirmed_with_canonical_key_accepted(self):
        f = _finding(
            confidence_level="Tool-Confirmed",
            evidence={"tool_confirmed_by": "test.writer"},
        )
        assert f.confidence_level == "Tool-Confirmed"

    def test_tool_confirmed_with_legacy_validator_key_accepted(self):
        f = _finding(
            confidence_level="Tool-Confirmed",
            evidence={"validator_tool": "sqlmap"},
        )
        assert f.confidence_level == "Tool-Confirmed"

    def test_tool_confirmed_with_promotion_guard_accepted(self):
        f = _finding(
            confidence_level="Tool-Confirmed",
            evidence={"promotion_guard": {"status": "ok"}},
        )
        assert f.confidence_level == "Tool-Confirmed"

    def test_tool_confirmed_with_evidence_bundle_accepted(self):
        f = _finding(
            confidence_level="Tool-Confirmed",
            evidence_bundle={"sealed": True, "negative_control_digest": "sha256:x"},
        )
        assert f.confidence_level == "Tool-Confirmed"

    def test_tool_confirmed_with_oob_key_accepted(self):
        f = _finding(
            confidence_level="Tool-Confirmed",
            evidence={"oob_confirmed": True},
        )
        assert f.confidence_level == "Tool-Confirmed"

    def test_other_levels_need_no_provenance(self):
        assert _finding(confidence_level="Pending").confidence_level == "Pending"
        assert (
            _finding(confidence_level="Needs Human Review").confidence_level
            == "Needs Human Review"
        )

    def test_notification_object_cannot_be_tool_confirmed(self):
        """The cost_alerts bug shape: a lifecycle notification Finding with
        only cosmetic evidence must never construct as Tool-Confirmed."""
        with pytest.raises(ValueError, match="provenance"):
            _finding(
                confidence_level="Tool-Confirmed",
                evidence={"lifecycle_status": "promoted", "notification_only": True},
            )


class TestWriterRegistry:
    """AST scan: every literal Tool-Confirmed assignment lives in an
    approved writer module."""

    def _literal_writers(self) -> set[str]:
        writers: set[str] = set()
        for path in sorted(SRC.rglob("*.py")):
            rel = str(path.relative_to(SRC))
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover - documented template
                continue
            for node in ast.walk(tree):
                # Finding(confidence_level="Tool-Confirmed", ...)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "Finding"
                ):
                    for kw in node.keywords:
                        if kw.arg == "confidence_level" and isinstance(
                            kw.value, ast.Constant
                        ) and kw.value.value == "Tool-Confirmed":
                            writers.add(rel)
                # dict literals / update dicts with
                # "confidence_level": "Tool-Confirmed"
                if isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if (
                            isinstance(key, ast.Constant)
                            and key.value == "confidence_level"
                            and isinstance(value, ast.Constant)
                            and value.value == "Tool-Confirmed"
                        ):
                            writers.add(rel)
                # confidence_level = "Tool-Confirmed" assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id == "confidence_level"
                            and isinstance(node.value, ast.Constant)
                            and node.value.value == "Tool-Confirmed"
                        ):
                            writers.add(rel)
        return writers

    def test_all_literal_writers_are_registered(self):
        writers = self._literal_writers()
        unregistered = writers - APPROVED_TOOL_CONFIRMED_WRITERS
        assert not unregistered, (
            "Unregistered Tool-Confirmed writer(s) found — new writers must "
            "be added to APPROVED_TOOL_CONFIRMED_WRITERS consciously and "
            "must attach proof provenance: "
            f"{sorted(unregistered)}"
        )

    def test_cost_alerts_no_longer_writes_tool_confirmed(self):
        source = (SRC / "service" / "cost_alerts.py").read_text(encoding="utf-8")
        assert 'confidence_level="Tool-Confirmed"' not in source
        assert '"Tool-Confirmed" if' not in source

    def test_registered_writers_attach_provenance_or_bundle(self):
        """Every registered writer file must reference the canonical
        provenance key or build an evidence_bundle on its confirmed path."""
        for rel in sorted(APPROVED_TOOL_CONFIRMED_WRITERS):
            path = SRC / rel
            assert path.exists(), f"registered writer missing: {rel}"
            source = path.read_text(encoding="utf-8")
            if '"Tool-Confirmed"' not in source:
                # memory/db.py flips via SQL constant — check the stamp.
                if rel == "memory/db.py":
                    assert "tool_confirmed_by" in source
                continue
            assert (
                "tool_confirmed_by" in source
                or "evidence_bundle" in source
                or "proof_bundle" in source
            ), (
                f"writer {rel} sets Tool-Confirmed without provenance key "
                "or proof bundle reference"
            )
