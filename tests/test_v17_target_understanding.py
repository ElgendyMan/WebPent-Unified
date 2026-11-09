from __future__ import annotations

import json
from types import SimpleNamespace

from webpent.agents.target_understanding.agent import target_understanding_node
from webpent.graph.builder import (
    NODE_HYPOTHESIS,
    NODE_SCOPE_ENFORCER,
    NODE_TARGET_UNDERSTANDING,
    route_after_auth,
    route_after_infrastructure,
)
from webpent.models.targets import Target


def _target() -> Target:
    return Target(
        url="http://lab.local",
        in_scope_regex=[r"lab\.local"],
    )


def test_target_understanding_is_redacted_and_scope_safe() -> None:
    state = {
        "target": _target(),
        "crawled_data": {
            "endpoints": [
                "http://lab.local/checkout",
                "http://outside.local/leak",
            ],
            "forms": [
                {
                    "action": "http://lab.local/checkout",
                    "method": "POST",
                    "parameters": {"item_id": "secret-item", "quantity": "2"},
                }
            ],
        },
        "session_cookies": {"session": "do-not-store"},
        "identity_profiles": [
            {"name": "buyer", "role": "user", "cookies": {"session": "secret"}}
        ],
    }

    result = target_understanding_node(state)  # type: ignore[arg-type]
    summary = result["target_understanding"]
    serialized = json.dumps(result, default=str)

    assert summary["endpoint_count"] == 1
    assert summary["out_of_scope_endpoint_count"] == 1
    assert summary["form_count"] == 1
    assert summary["identity_count"] == 1
    assert summary["workflow_candidate_count"] == 1
    assert "do-not-store" not in serialized
    assert "secret" not in serialized
    assert "secret-item" not in serialized
    assert result["mental_model"]["nodes"]


def test_target_understanding_node_is_no_network_and_bounded() -> None:
    result = target_understanding_node(
        {"target": _target(), "crawled_data": {}}  # type: ignore[arg-type]
    )
    summary = result["target_understanding"]

    assert summary["endpoint_count"] == 0
    assert summary["coverage_gaps"] == [
        "no-endpoints",
        "no-structured-forms",
        "no-identity-context",
        "no-workflow-candidates",
    ]
    assert result["current_phase"] == "target_understanding"


def test_target_understanding_routing_is_legacy_safe(monkeypatch) -> None:
    import webpent.config.settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_target_understanding=False),
    )
    assert route_after_auth({"skip_recon": True}) == NODE_HYPOTHESIS
    assert route_after_infrastructure({}) == NODE_SCOPE_ENFORCER

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_target_understanding=True),
    )
    assert route_after_auth({"skip_recon": True}) == NODE_TARGET_UNDERSTANDING
    assert route_after_infrastructure({}) == NODE_TARGET_UNDERSTANDING
