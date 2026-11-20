import pytest

from webpent.models.proof_bundle import build_proof_bundle


def test_proof_bundle_seal_is_immutable_and_verifiable() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement:test",
        finding_id="finding:test",
        evidence=[{"status": 200, "body_sha256": "abc"}],
        evidence_refs=["obs:1"],
        negative_control={"status": 403},
    )
    sealed = bundle.append_custody(actor="tester", action="validate").seal(actor="tester")
    assert sealed.sealed is True
    assert sealed.verify_seal() is True
    assert sealed.replay(
        [{"status": 200, "body_sha256": "abc"}],
        {"status": 403},
    ) is True
    with pytest.raises(ValueError, match="sealed_proof_bundle_is_immutable"):
        sealed.append_custody(actor="tester", action="mutate")


def test_proof_bundle_replay_fails_on_changed_evidence() -> None:
    sealed = build_proof_bundle(
        engagement_id="engagement:test",
        finding_id="finding:test",
        evidence=[{"status": 200}],
    ).seal()
    assert sealed.replay([{"status": 500}]) is False


def test_proof_bundle_redacts_secret_shaped_evidence_before_hashing() -> None:
    bundle = build_proof_bundle(
        engagement_id="engagement:test",
        finding_id="finding:test",
        evidence=[{"authorization": "Bearer secret-value", "status": 200}],
    ).seal()
    assert "secret-value" not in bundle.model_dump_json()
    assert bundle.verify_seal() is True
