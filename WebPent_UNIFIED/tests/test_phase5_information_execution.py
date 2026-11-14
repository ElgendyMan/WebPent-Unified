import pytest

from webpent.agents.smart_campaigns.agent import (
    _information_task_from_record,
    smart_campaigns_execution_node,
)


def _base_state() -> dict:
    return {
        "smart_mode": True,
        "engagement_id": "engagement:information-tests",
        "target": {"url": "https://target.test"},
        "smart_governance": {"profile": "safe-smart"},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_task_outcomes": [],
    }


@pytest.mark.parametrize(
    ("method", "expected"),
    [("GET", "GET"), ("HEAD", "HEAD"), ("OPTIONS", "OPTIONS")],
)
def test_information_adapter_allows_only_bounded_read_methods(method: str, expected: str) -> None:
    task = _information_task_from_record(
        {
            "action_id": "research:method",
            "target_ref": "https://target.test/health",
            "method": method,
            "cost": 1.0,
            "expected_information_gain": 0.5,
        },
        state=_base_state(),
        index=0,
    )
    assert task is not None
    assert task.method == expected
    assert task.action_family == "http_read"
    assert task.capability == "http_read"
    assert task.risk_tier.value == "read_only"
    assert task.target_url == "https://target.test/health"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE"])
def test_information_adapter_rejects_mutating_or_unsafe_methods(method: str) -> None:
    assert (
        _information_task_from_record(
            {
                "action_id": "research:unsafe",
                "target_ref": "https://target.test/health",
                "method": method,
            },
            state=_base_state(),
            index=0,
        )
        is None
    )


@pytest.mark.parametrize(
    "target_ref",
    [
        "https://evil.test/health",
        "http://target.test/health",
        "javascript:alert(1)",
        "//evil.test/health",
        "",
    ],
)
def test_information_adapter_fails_closed_for_out_of_scope_targets(target_ref: str) -> None:
    assert (
        _information_task_from_record(
            {"action_id": "research:scope", "target_ref": target_ref, "method": "GET"},
            state=_base_state(),
            index=0,
        )
        is None
    )


def test_information_execution_returns_research_session_and_evidence_ledgers(monkeypatch) -> None:
    class Response:
        status_code = 204
        content = b""
        headers = {"content-type": "text/plain"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url):
            assert url == "https://target.test/health"
            return Response()

    state = _base_state()
    state["smart_information_actions"] = [
        {
            "action_id": "research:health",
            "action_class": "discovery",
            "target_ref": "https://target.test/health",
            "method": "GET",
            "fingerprint": "fp-health",
            "objective": "observe the health endpoint",
            "cost": 1.0,
            "expected_information_gain": 0.6,
        }
    ]
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["status_code"] == 204
    assert result["research_session"]["engagement_id"] == "engagement:information-tests"
    assert result["positive_evidence_ledger"] == []
    assert result["negative_evidence_ledger"] == []
    assert result["research_session"]["next_best_actions"][-1]["outcome"] == "executed"
    assert result["campaign_task_outcomes"][-1]["status"] == "executed"


def test_information_execution_does_not_repeat_completed_fingerprint(monkeypatch) -> None:
    state = _base_state()
    state["research_session"] = {
        "session_id": "session:information-tests",
        "engagement_id": "engagement:information-tests",
        "client_id": "client:test",
        "next_best_actions": [
            {"action_id": "research:health", "fingerprint": "fp-health", "outcome": "executed"}
        ],
    }
    state["smart_information_actions"] = [
        {
            "action_id": "research:health",
            "target_ref": "https://target.test/health",
            "method": "GET",
            "fingerprint": "fp-health",
        }
    ]
    called = False

    def fail_client(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("completed research action must not be sent again")

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client", fail_client
    )
    result = smart_campaigns_execution_node(state)
    assert called is False
    assert result["smart_http_observations"] == []
    assert result["research_session"]["next_best_actions"][-1]["outcome"] == "executed"


def test_information_execution_preserves_existing_positive_and_negative_ledgers() -> None:
    state = _base_state()
    state["research_session"] = {
        "session_id": "session:information-tests",
        "engagement_id": "engagement:information-tests",
        "client_id": "client:test",
        "positive_evidence_ledger": [{"evidence_id": "positive:one"}],
        "negative_evidence_ledger": [{"evidence_id": "negative:one"}],
    }
    result = smart_campaigns_execution_node(state)
    assert result["positive_evidence_ledger"] == [{"evidence_id": "positive:one"}]
    assert result["negative_evidence_ledger"] == [{"evidence_id": "negative:one"}]
    assert result["research_session"]["positive_evidence_ledger"] == [
        {"evidence_id": "positive:one"}
    ]
    assert result["research_session"]["negative_evidence_ledger"] == [
        {"evidence_id": "negative:one"}
    ]


def test_information_adapter_clamps_untrusted_cost_and_information_gain() -> None:
    task = _information_task_from_record(
        {
            "action_id": "research:bounds",
            "target_ref": "https://target.test/health",
            "method": "GET",
            "cost": 999,
            "expected_information_gain": -10,
        },
        state=_base_state(),
        index=2,
    )
    assert task is not None
    assert task.budget == 2.0
    assert task.expected_information_gain == 0.0


def test_execution_returns_empty_research_ledgers_when_no_information_is_planned() -> None:
    result = smart_campaigns_execution_node(_base_state())
    assert result["research_session"]["next_best_actions"] == []
    assert result["positive_evidence_ledger"] == []
    assert result["negative_evidence_ledger"] == []
    assert result["smart_http_observations"] == []
    assert result["smart_replanning"]["status"] == "blocked"
