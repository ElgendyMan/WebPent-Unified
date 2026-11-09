from __future__ import annotations

import json

from webpent.agents.access_control import agent as access_agent
from webpent.models.targets import Target
from webpent.shared.authorization_matrix import build_authorization_matrix


def _row(
    identity: str, role: str, accessible: bool, status: int, owner: str | None = "alice"
) -> dict:
    return {
        "identity": identity,
        "role": role,
        "owner_identity": owner,
        "object_id": "42",
        "resource_url": "https://lab.local/orders/order-42?token=secret",
        "endpoint": "https://lab.local/orders/order-42?token=secret",
        "method": "GET",
        "accessible": accessible,
        "status_code": status,
        "response_fingerprint": f"fingerprint-{identity}-{status}",
        "evidence_refs": [f"obs:{identity}"],
    }


def test_matrix_models_horizontal_vertical_and_ownership_differentials():
    result = build_authorization_matrix(
        [
            _row("alice", "user", True, 200),
            _row("bob", "user", False, 403),
            _row("support", "support", True, 200),
        ],
        target_url="https://lab.local/",
    )
    assert result["identities"] == ["alice", "bob", "support"]
    assert result["objects"] == ["42"]
    assert result["methods"] == ["GET"]
    assert len(result["rows"]) == 3
    assert len(result["comparisons"]) == 3
    assert any(
        item["comparison_kind"] == "ownership_differential" for item in result["comparisons"]
    )
    assert any(item["comparison_kind"] == "vertical" for item in result["comparisons"])
    assert result["coverage_gaps"] == []
    serialized = json.dumps(result, sort_keys=True)
    assert "secret" not in serialized
    assert "[REDACTED]" in serialized


def test_matrix_is_bounded_and_reports_coverage_gaps():
    result = build_authorization_matrix(
        [_row("alice", "user", True, 200), _row("alice", "user", True, 200)],
        max_rows=1,
        max_comparisons=1,
    )
    assert len(result["rows"]) == 1
    assert "fewer_than_two_identities_observed" in result["coverage_gaps"]
    assert "fewer_than_two_roles_observed" in result["coverage_gaps"]
    assert "insufficient_identity_comparison:42:GET" in result["coverage_gaps"]


def test_access_control_node_emits_matrix_only_when_explicitly_enabled(monkeypatch):
    def fake_probe(url, cookies=None, timeout=10.0, headers=None):
        session = (cookies or {}).get("session")
        return (200, 100) if session == "alice-secret" else (403, 20)

    monkeypatch.setattr(access_agent, "_probe_url", fake_probe)
    state = {
        "target": Target(url="https://lab.local/"),
        "findings": [],
        "crawled_data": {
            "endpoints": [
                {
                    "url": "https://lab.local/orders/42",
                    "method": "GET",
                    "owner_identity": "alice",
                }
            ]
        },
        "identity_profiles": {
            "alice": {"role": "user", "cookies": {"session": "alice-secret"}},
            "bob": {"role": "user", "cookies": {"session": "bob-secret"}},
            "support": {"role": "support", "cookies": {"session": "support-secret"}},
        },
        "enable_authorization_matrix": True,
        "max_authorization_matrix_rows": 20,
        "max_authorization_matrix_comparisons": 20,
    }
    result = access_agent.access_control_node(state)
    matrix = result["authorization_matrix"]
    assert len(matrix["identities"]) == 4  # anonymous plus three authenticated profiles
    assert len(matrix["rows"]) == 4
    assert matrix["comparisons"]
    serialized = json.dumps(result, default=str, sort_keys=True)
    for secret in ("alice-secret", "bob-secret", "support-secret"):
        assert secret not in serialized


def test_access_control_matrix_falls_back_empty_when_flag_is_not_set(monkeypatch):
    monkeypatch.setattr(access_agent, "_probe_url", lambda *args, **kwargs: (403, 20))
    result = access_agent.access_control_node(
        {
            "target": Target(url="https://lab.local/"),
            "findings": [],
            "crawled_data": {"urls": ["https://lab.local/orders/42"]},
            "identity_profiles": {
                "alice": {"role": "user", "cookies": {"session": "secret"}},
                "bob": {"role": "user", "cookies": {"session": "secret-2"}},
            },
        }
    )
    assert result["authorization_matrix"] == {}
    assert "secret" not in json.dumps(result, default=str)
