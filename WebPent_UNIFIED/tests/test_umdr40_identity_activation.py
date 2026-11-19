"""UM-DR-40 RC-4 — unit tests for the per-campaign identity
activation mechanism (production)."""
from __future__ import annotations

import sys

REPO = __file__.rsplit("/tests/", 1)[0]
sys.path.insert(0, f"{REPO}/src")

import pytest  # noqa: E402

from webpent.production.identity_activation import (  # noqa: E402
    ALL_CAPABILITIES,
    IDENTITY_CAPABILITY_FLAGS,
    activation_snapshot,
    budget_impact_record,
    identity_campaign_activation,
)


def _live_flags() -> dict[str, bool]:
    from webpent.config.settings import get_settings
    settings = get_settings()
    return {flag: bool(getattr(settings, flag))
            for flag in IDENTITY_CAPABILITY_FLAGS}


def test_activation_turns_all_four_flags_on_and_restores() -> None:
    """Inside the context every capability is live-ON; after exit the
    previous values (the fail-closed defaults) are restored."""
    before = _live_flags()
    assert not any(before.values()), "default must be all-OFF"
    with identity_campaign_activation() as record:
        inside = _live_flags()
        assert all(inside.values()), inside
        assert record["activated"] == dict(ALL_CAPABILITIES)
        assert record["snapshot"]["identity_capabilities"] == inside
    assert _live_flags() == before


def test_activation_restores_on_exception() -> None:
    """A raising campaign still leaves the environment restored."""
    before = _live_flags()
    with pytest.raises(RuntimeError):
        with identity_campaign_activation():
            assert all(_live_flags().values())
            raise RuntimeError("campaign failed")
    assert _live_flags() == before


def test_activation_rejects_unknown_capabilities() -> None:
    """Only the four documented capability flags are settable."""
    with pytest.raises(ValueError):
        with identity_campaign_activation({"enable_llm": True}):
            pass


def test_activation_selective_capability() -> None:
    """A subset activation turns on exactly the requested flags."""
    with identity_campaign_activation(
            {"enable_object_identity": True}):
        live = _live_flags()
        assert live["enable_object_identity"] is True
        assert live["enable_alias_resolution"] is False
        assert live["enable_multi_identity_reasoning"] is False
        assert live["enable_composite_workflows"] is False


def test_activation_enables_the_wired_router_path() -> None:
    """The activation mechanism drives the RC-4 graph wiring: inside
    the context the composed redirect sends strategist-bound
    branches through the identity_workflow node."""
    from webpent.graph.builder import (
        HYPOTHESIS_PATH_MAP,
        NODE_IDENTITY_WORKFLOW,
        NODE_STRATEGIST,
        _research_route_redirects,
    )
    before = _research_route_redirects(HYPOTHESIS_PATH_MAP)
    assert before == HYPOTHESIS_PATH_MAP  # default OFF: byte-identical
    with identity_campaign_activation():
        redirected = _research_route_redirects(HYPOTHESIS_PATH_MAP)
        assert redirected[NODE_STRATEGIST] == NODE_IDENTITY_WORKFLOW
    assert (_research_route_redirects(HYPOTHESIS_PATH_MAP)
            == HYPOTHESIS_PATH_MAP)  # restored


def test_budget_impact_record_measures_the_delta() -> None:
    """The recorded budget impact: request/time deltas plus the
    identity counts extracted from the campaign final states."""
    baseline = {
        "campaign_id": "base-1", "requests_total": 100,
        "duration_seconds": 60.0, "findings_confirmed": 2,
        "authoritative_final_state": {},
    }
    enabled = {
        "campaign_id": "ident-1", "requests_total": 104,
        "duration_seconds": 66.5, "findings_confirmed": 2,
        "authoritative_final_state": {
            "object_identity_registry": {
                "registry": {"identities": {"a": 1, "b": 2}}},
            "multi_identity_reasoning": {
                "principals": [{"ref": "user-a"}, {"ref": "user-b"}],
                "differential_questions": [{"q": 1}],
            },
        },
    }
    impact = budget_impact_record(baseline, enabled)
    assert impact["deltas"]["requests_total"] == 4
    assert impact["deltas"]["duration_seconds"] == pytest.approx(6.5)
    assert impact["deltas"]["findings_confirmed"] == 0
    assert impact["baseline_identity_counts"] == {}
    assert impact["enabled_identity_counts"] == {
        "object_identities": 2,
        "principals_observed": 2,
        "differential_questions": 1,
    }


def test_budget_impact_missing_fields_stay_none() -> None:
    """No field is invented: absent metrics stay None."""
    impact = budget_impact_record(
        {"campaign_id": "a"}, {"campaign_id": "b"})
    assert impact["deltas"]["requests_total"] is None
    assert impact["enabled_identity_counts"] == {}
