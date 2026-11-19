"""U-DEEP-7 — Mass Assignment (10 tests per spec).

Story over pattern, state over string: a finding is only raised when
the server ACCEPTS the extra fields (reflection) or its BEHAVIOR
changes (privilege state), never on a mere echo of the request.
"""
from __future__ import annotations

import pytest

from webpent.deep.mass_assignment import (
    MASS_ASSIGN_PAYLOADS,
    MassAssignmentDetector,
    MassAssignmentFinding,
)


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


def make_send(accepted_fields=(), behavior_change=False, strict=False):
    """Build a fake transport.

    accepted_fields: extra JSON keys the server silently binds.
    behavior_change: the role-escalation actually flips server state
    (response reports admin state even without echoing every field).
    strict: endpoint validates input and rejects everything (422).
    """
    calls = []

    def send(endpoint, body):
        calls.append((endpoint, dict(body)))
        if strict and body:
            return FakeResponse(422, {"error": "extra fields not allowed"})
        echoed = {k: v for k, v in body.items() if k in accepted_fields}
        out = {"username": "victim", "email": "victim@example.com"}
        out.update(echoed)
        if behavior_change and accepted_fields:
            out["role"] = "admin"
        return FakeResponse(200, out)

    send.calls = calls
    return send


# ---------------------------------------------------------------------------
# Corpus (spec payload dicts, verbatim structure)
# ---------------------------------------------------------------------------

def test_payload_corpus_matches_spec():
    assert set(MASS_ASSIGN_PAYLOADS) == {
        "role_escalation", "balance_manipulation", "verification_bypass",
        "internal_flags", "id_manipulation"}
    assert {"role": "admin"} in MASS_ASSIGN_PAYLOADS["role_escalation"]
    assert {"balance": 999999} in MASS_ASSIGN_PAYLOADS["balance_manipulation"]
    assert {"email_verified": True} in MASS_ASSIGN_PAYLOADS["verification_bypass"]
    assert {"debug": True} in MASS_ASSIGN_PAYLOADS["internal_flags"]
    assert {"user_id": 1} in MASS_ASSIGN_PAYLOADS["id_manipulation"]


def test_role_escalation_detected():
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role", "is_admin"}))
    findings = detector.scan("/api/users/1")
    subfamilies = {f.subfamily for f in findings}
    assert "role_escalation" in subfamilies


def test_balance_manipulation_detected():
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"balance"}))
    findings = detector.scan("/api/users/1")
    assert any(f.subfamily == "balance_manipulation" for f in findings)


def test_verification_bypass_detected():
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"email_verified"}))
    findings = detector.scan("/api/users/1")
    assert any(f.subfamily == "verification_bypass" for f in findings)


def test_reflected_in_response():
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role"}))
    findings = detector.scan("/api/users/1")
    finding = next(f for f in findings if f.subfamily == "role_escalation")
    assert finding.accepted_fields
    assert any("reflected" in e for e in finding.evidence)


def test_behavior_change_verified():
    """State flipped server-side counts even beyond plain reflection."""
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role"}, behavior_change=True))
    findings = detector.scan("/api/users/1")
    finding = next(f for f in findings if f.subfamily == "role_escalation")
    assert finding.behavior_changed is True


def test_no_false_positive_on_strict():
    detector = MassAssignmentDetector(send=make_send(strict=True))
    assert detector.scan("/api/users/1") == []


def test_deterministic_payload_generation():
    a = MassAssignmentDetector(send=make_send(accepted_fields={"role"}))
    b = MassAssignmentDetector(send=make_send(accepted_fields={"role"}))
    fa = a.scan("/api/users/1")
    fb = b.scan("/api/users/1")
    assert [(f.subfamily, f.payload) for f in fa] == \
        [(f.subfamily, f.payload) for f in fb]


def test_evidence_includes_before_after():
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role"}))
    findings = detector.scan("/api/users/1")
    finding = findings[0]
    assert any("baseline" in e.lower() for e in finding.evidence)
    assert any("probe" in e.lower() for e in finding.evidence)


def test_integration_with_prism():
    """A Prism-shaped consumer can read the finding's family signal."""
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role"}))
    finding = detector.scan("/api/users/1")[0]
    assert finding.family == "MASS_ASSIGNMENT"
    assert finding.confidence > 0.0


def test_integration_with_campaign():
    """A campaign-shaped hypothesis can be drafted from the finding."""
    detector = MassAssignmentDetector(
        send=make_send(accepted_fields={"role"}))
    finding = detector.scan("/api/users/1")[0]
    assert isinstance(finding, MassAssignmentFinding)
    assert finding.statement
    assert finding.success_indicator
