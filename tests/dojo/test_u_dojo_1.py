"""U-DOJO-1: the Lab Generator (plan: docs/plans/2026-10-16-v85-dojo.md).

Failing-test-first: each test below was written before the module it
proves. Laws exercised: L-1 (offline), L-2 (isolated state), L-3
(ground truth), L-4 (determinism).
"""

from __future__ import annotations

import socket

import pytest

from webpent.dojo.lab_generator import EXTERNAL_LABS, LabGenerator


@pytest.fixture()
def generator() -> LabGenerator:
    return LabGenerator()


def test_start_lab_returns_instance(generator: LabGenerator):
    lab = generator.start("flask_api_with_idor", seed=7)
    assert lab.instance_id
    assert lab.template_id == "flask_api_with_idor"
    assert lab.family == "idor"
    assert lab.seed == 7
    assert lab.routes, "a lab without routes cannot be attacked"
    assert lab.vuln_points, "a lab without a vulnerability is not a lab"


def test_lab_is_isolated_localhost_only(generator: LabGenerator, monkeypatch):
    """L-1: even the constructor path of a lab touches no socket."""
    def boom(*args, **kwargs):
        raise AssertionError("socket use inside the dojo is forbidden")

    monkeypatch.setattr(socket, "socket", boom)
    lab = generator.start("flask_api_with_idor", seed=7)
    assert lab.base_url.startswith("dojo://"), (
        "synthetic labs must never advertise a real address"
    )


def test_reset_restores_original_state(generator: LabGenerator):
    lab = generator.start("flask_api_with_idor", seed=7)
    original_hash = lab.state_hash
    lab.state["records"] = [{"id": 1, "owner": "attacker"}]
    lab.state["polluted"] = True
    restored = generator.reset(lab.instance_id)
    assert restored.state_hash == original_hash
    assert restored.state == {}
    assert restored.instance_id == lab.instance_id


def test_get_vuln_map_returns_ground_truth(generator: LabGenerator):
    """L-3: the trainer's map is the full documented truth."""
    lab = generator.start("express_jwt_confusion", seed=3)
    mapping = generator.get_vuln_map(lab.instance_id)
    assert mapping["template_id"] == "express_jwt_confusion"
    exploitable = [p for p in mapping["vuln_points"] if p.exploitable]
    assert exploitable, "ground truth must contain at least one real vuln"
    for point in exploitable:
        assert point.vuln_class
        assert point.path
        assert point.param
        assert point.signature
    for decoy in mapping["decoys"]:
        assert decoy.exploitable is False


def test_synthetic_template_hash_stable(generator: LabGenerator):
    """L-4: same seed twice must produce a byte-identical lab."""
    first = generator.start("django_ssrf_endpoint", seed=42)
    second = generator.start("django_ssrf_endpoint", seed=42)
    assert first.state_hash == second.state_hash
    assert first.routes == second.routes
    assert first.vuln_points == second.vuln_points
    different = generator.start("django_ssrf_endpoint", seed=43)
    assert different.state_hash != first.state_hash


def test_no_network_calls(generator: LabGenerator, monkeypatch):
    """L-1: the whole generator lifecycle runs with sockets disabled."""
    def boom(*args, **kwargs):
        raise AssertionError("network call attempted inside the dojo")

    monkeypatch.setattr(socket, "socket", boom)
    lab = generator.start("node_race_condition", seed=11)
    generator.reset(lab.instance_id)
    generator.get_vuln_map(lab.instance_id)
    generator.stop(lab.instance_id)


def test_lab_can_be_stopped_cleanly(generator: LabGenerator):
    lab = generator.start("flask_api_with_idor", seed=5)
    generator.stop(lab.instance_id)
    with pytest.raises(KeyError):
        generator.get_vuln_map(lab.instance_id)


def test_five_synthetic_templates_at_least(generator: LabGenerator):
    """DoD: >=5 synthetic templates must be available."""
    available = generator.list_available()
    assert len(available) >= 5
    families = {t.family for t in available}
    assert len(families) >= 5, "templates should span distinct families"


def test_external_labs_need_explicit_enablement(generator: LabGenerator):
    """L-1: external adapters are declared, inert, and operator-gated."""
    assert set(EXTERNAL_LABS) >= {"juice_shop", "dvwa", "webgoat"}
    for spec in EXTERNAL_LABS.values():
        assert spec.get("requires_operator_enablement") is True
    with pytest.raises(ValueError, match="operator"):
        generator.start("juice_shop", seed=1)


def test_unknown_template_rejected(generator: LabGenerator):
    with pytest.raises(KeyError):
        generator.start("no_such_lab", seed=1)
