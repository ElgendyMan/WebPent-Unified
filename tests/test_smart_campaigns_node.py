from webpent.agents.smart_campaigns.agent import (
    build_smart_campaign_tasks,
    smart_campaigns_execution_node,
    smart_campaigns_node,
)
from webpent.config.settings import get_settings
from webpent.models.targets import Target
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.state.initial_state import build_initial_state


def test_safe_smart_governance_is_persisted_in_initial_state(monkeypatch) -> None:
    monkeypatch.setenv("SCAN_PROFILE", "safe-smart")
    get_settings.cache_clear()
    state = build_initial_state(Target(url="https://target.test"), auto_approve=True)
    assert state["scan_mode"] == "safe-smart"
    assert state["smart_governance"]["profile"] == "safe-smart"
    assert state["capability_manifest"]["capabilities"]["http_read"]["available"] is True
    assert state["action_budget"]["max_actions"] > 0


def _state(*, enabled: bool = True) -> dict:
    return {
        "smart_mode": enabled,
        "engagement_id": "engagement:test",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {
                    "record_id": "surface:download:1",
                    "url": "https://target.test/download/1",
                    "method": "GET",
                }
            ]
        },
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {
            "entries": [
                {"id": 1, "key": "download_idor", "status": "not_observed"},
            ]
        },
        "campaign_plan": {
            "entries": [
                {
                    "key": "download_idor",
                    "status": "ready",
                    "validator_id": "idor_validator",
                    "matched_observation_refs": ["surface:download:1"],
                    "gaps": [],
                    "contract": {
                        "preconditions": ["download object reference observed"],
                        "observed_preconditions": ["download object reference observed"],
                        "identities": ["owner", "foreign_user"],
                        "negative_control": ["owner reads own object"],
                        "oracle": ["foreign denial"],
                        "budget": 2,
                        "cleanup": ["read-only"],
                    },
                },
                {
                    "key": "public_backup_disclosure",
                    "status": "not_observed",
                    "validator_id": None,
                    "matched_observation_refs": [],
                    "gaps": ["missing-validator:public_backup_disclosure"],
                    "contract": {},
                },
            ]
        },
    }


def test_disabled_node_is_additive_and_does_not_plan() -> None:
    result = smart_campaigns_node(_state(enabled=False))
    assert result["campaign_task_outcomes"] == []
    assert result["smart_next_actions"] == []
    assert result["smart_replanning"]["status"] == "disabled"


def test_node_plans_observed_campaign_but_never_executes_it() -> None:
    result = smart_campaigns_node(_state())
    assert result["smart_next_actions"]
    assert result["smart_replanning"]["execution_required"] is True
    assert result["smart_replanning"]["proof_required"] is True
    assert any(
        item["reason"] == "planned_not_executed"
        for item in result["campaign_task_outcomes"]
    )


def test_initial_plan_refreshes_from_observed_surface_url() -> None:
    state = _state()
    state["campaign_plan"] = {
        "entries": [
            {
                # A generic campaign key (in GENERIC_CAMPAIGNS), not a
                # lab-specific one — this test only exercises the
                # observed-surface matching mechanism, which must stay
                # target/lab-agnostic. _state()'s default surface_records
                # URL (".../download/1") already matches this campaign's
                # "download"/"path" surface tokens.
                "key": "path_traversal",
                "status": "not_observed",
                "validator_id": "path_traversal",
                "matched_observation_refs": [],
                "gaps": ["missing-surface:path_traversal"],
                "contract": {},
            }
        ]
    }
    result = smart_campaigns_node(state)
    assert result["smart_next_actions"]
    assert any(
        entry["key"] == "path_traversal" and entry["matched_observation_refs"]
        for entry in result["campaign_plan"]["entries"]
    )


def test_crawler_endpoint_strings_become_observed_surface_tasks() -> None:
    state = _state()
    state["crawled_data"] = {"endpoints": ["https://target.test/download/1"]}
    state["campaign_plan"] = {
        "entries": [
            {
                "key": "download_idor",
                "status": "not_observed",
                "validator_id": "idor_validator",
                "matched_observation_refs": [],
                "gaps": ["missing-surface:download_idor"],
                "contract": {},
            }
        ]
    }
    tasks, outcomes = build_smart_campaign_tasks(state)
    assert tasks
    assert len(tasks) <= 3
    assert {task.target_url for task in tasks} == {"https://target.test/download/1"}
    assert all(item["reason"] != "missing_concrete_surface_url" for item in outcomes)


def test_unobserved_or_missing_validator_campaign_is_blocked() -> None:
    tasks, outcomes = build_smart_campaign_tasks(_state())
    assert [task.vulnerability_class for task in tasks] == ["download_idor"]
    assert outcomes[0]["reason"] == "missing_observed_surface"


def test_execution_node_blocks_missing_precondition_before_handler(monkeypatch) -> None:
    state = _state()
    state["campaign_plan"]["entries"][0]["contract"].pop("observed_preconditions", None)
    called = False

    def should_not_execute(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("handler must not run when preconditions are unproven")

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        should_not_execute,
    )
    result = smart_campaigns_execution_node(state)
    assert called is False
    assert result["smart_http_observations"] == []
    assert any(
        item["status"] == "blocked_by_precondition"
        and item["reason"] == "precondition_failed"
        for item in result["campaign_task_outcomes"]
    )


def test_execution_node_uses_bounded_get_and_records_safe_metadata(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b"safe-body"
        headers = {"content-type": "text/html"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url):
            assert url == "https://target.test/download/1"
            return Response()

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(_state())
    assert result["smart_http_observations"][0]["status_code"] == 200
    assert result["smart_http_observations"][0]["content_length"] == 9
    assert "body" not in result["smart_http_observations"][0]
    assert result["smart_replanning"]["get_only"] is True
    assert result["coverage_ledger"]["entries"][0]["attempts"] == 1
    assert result["coverage_ledger"]["entries"][0]["status"] == "inconclusive"


def test_execution_node_does_not_send_cross_origin_targets(monkeypatch) -> None:
    state = _state()
    state["crawled_data"]["surface_records"][0]["url"] = "https://evil.test/download/1"
    called = False

    def fail_client(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("transport must not be opened")

    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        fail_client,
    )
    result = smart_campaigns_execution_node(state)
    assert called is False
    assert result["smart_http_observations"] == []
    assert any(item["status"] == "policy_denied" for item in result["campaign_task_outcomes"])


def test_idempotency_marks_previous_task_as_lower_priority() -> None:
    state = _state()
    first = smart_campaigns_node(state)
    state["campaign_task_outcomes"] = first["campaign_task_outcomes"]
    second = smart_campaigns_node(state)
    assert second["smart_next_actions"]
    assert any("duplication_penalty" in item["reasons"] for item in second["smart_next_actions"])


def test_initial_state_accepts_per_run_authorized_active_override(monkeypatch) -> None:
    monkeypatch.setenv("SCAN_PROFILE", "legacy")
    get_settings.cache_clear()
    state = build_initial_state(
        Target(url="https://target.test"),
        scan_mode="authorized-active",
        auto_approve=True,
    )
    assert state["scan_mode"] == "authorized-active"
    assert state["smart_governance"]["profile"] == "authorized-active"
    assert state["capability_manifest"]["capabilities"]["active_workflow"]["available"] is True
    assert state["decision_trace"] == []


def test_authorized_active_post_requires_evidence_body_and_persists_trace(monkeypatch) -> None:
    class Response:
        status_code = 201
        content = b"created"
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["json"] == {"fixture": "bounded"}
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {"fixture": "bounded"},
            "content_type": "application/json",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["smart_replanning"]["get_only"] is False
    assert result["smart_replanning"]["active_methods_enabled"] is True
    assert result["decision_trace"]
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"


def test_human_review_only_is_a_supported_coverage_status() -> None:
    state = _state()
    state["campaign_ledger"]["entries"][0]["status"] = "human_review_only"
    state["campaign_task_outcomes"] = [
        {"vulnerability_class": "download_idor", "status": "human_review_only"}
    ]
    result = project_coverage_ledger(state)
    assert result["entries"][0]["status"] == "human_review_only"
    assert "human-review-only-validator" in result["entries"][0]["gaps"]


def test_authorized_active_form_submit_uses_typed_form_body(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b"ok"
        headers = {"content-type": "text/html"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["data"] == {"fixture": "bounded"}
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {"fixture": "bounded"},
            "body_schema": "form",
            "content_type": "application/x-www-form-urlencoded",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"


def test_authorized_active_file_upload_is_bounded_and_typed(monkeypatch) -> None:
    class Response:
        status_code = 201
        content = b"uploaded"
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            assert url == "https://target.test/download/1"
            assert kwargs["data"] == {"name": "fixture"}
            uploaded = kwargs["files"]["document"]
            assert uploaded[0] == "sample.csv"
            assert uploaded[1] == b"a,b\\n1,2\\n"
            assert uploaded[2] == "text/csv"
            return Response()

    state = _state()
    state.update(
        {
            "scan_mode": "authorized-active",
            "auto_approve": True,
            "smart_governance": {"profile": "authorized-active"},
            "capability_manifest": {
                "capabilities": {
                    "http_read": {"available": True, "status": "available"},
                    "active_workflow": {"available": True, "status": "available"},
                }
            },
        }
    )
    state["crawled_data"]["surface_records"][0].update(
        {
            "method": "POST",
            "body": {
                "fields": {"name": "fixture"},
                "file": {
                    "field": "document",
                    "filename": "sample.csv",
                    "content": "a,b\\n1,2\\n",
                    "content_type": "text/csv",
                },
            },
            "body_schema": "multipart",
            "content_type": "multipart/form-data",
        }
    )
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )
    result = smart_campaigns_execution_node(state)
    assert result["smart_http_observations"][0]["method"] == "POST"
    assert result["decision_trace"][0]["outcome"]["status"] == "executed"
    assert result["smart_replanning"]["active_methods_enabled"] is True


# End of typed authorized-action regression coverage.


def test_direct_swagger_probe_hardcoded_to_one_lab_was_intentionally_removed() -> None:
    """Regression guard, not a feature test.

    The old ``_swagger_ssrf_finding`` helper only promoted a finding to
    Tool-Confirmed by grepping an HTTP response body for one specific lab's
    literal flag strings ("ipv6-loopback" / "NUA{...}") — hardcoded to that
    one lab, not usable against any other target. GOED removed it without a
    generic replacement, and the project's explicit direction is that core
    campaign/validator logic must stay target-flexible (lab-specific data,
    if any, belongs only in webpent.benchmark.* profile modules — see
    RECONCILIATION_REPORT.md). This asserts it stays gone rather than
    silently reappearing, and documents the capability gap: there is
    currently no generic (differential, target-agnostic) active SSRF
    confirmation path anywhere in the validator stack.
    """
    import webpent.agents.smart_campaigns.agent as smart_campaigns_agent

    assert not hasattr(smart_campaigns_agent, "_swagger_ssrf_finding")


def test_authorized_active_direct_swagger_probe_requires_marker(monkeypatch) -> None:
    class Response:
        status_code = 200
        content = b'{"status":"ok"}'
        headers = {"content-type": "application/json"}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, _url):
            return Response()

    state = _state()
    state["smart_governance"] = {"profile": "authorized-active"}
    state["scan_mode"] = "authorized-active"
    monkeypatch.setattr(
        "webpent.agents.smart_campaigns.agent.make_safe_httpx_client",
        lambda **_kwargs: Client(),
    )

    result = smart_campaigns_execution_node(state)
    assert result["findings"] == []


def test_user_agent_falls_back_to_settings_when_state_has_no_settings(monkeypatch) -> None:
    monkeypatch.setenv(
        "HTTP_USER_AGENT",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 solverfileexpect_2222",
    )
    get_settings.cache_clear()
    from webpent.agents.smart_campaigns.agent import _user_agent

    assert "solverfileexpect_2222" in _user_agent({})
    from types import SimpleNamespace

    default_state = {"settings": SimpleNamespace(http_user_agent="WebPent/0.2 (+https://example.test)")}
    assert "solverfileexpect_2222" in _user_agent(default_state)
    get_settings.cache_clear()


def test_user_agent_fallback_replaces_legacy_default(monkeypatch) -> None:
    from webpent.agents.smart_campaigns.agent import _DEFAULT_BROWSER_USER_AGENT, _user_agent

    monkeypatch.delenv("HTTP_USER_AGENT", raising=False)
    monkeypatch.delenv("WEBPENT_HTTP_USER_AGENT", raising=False)
    get_settings.cache_clear()
    assert _user_agent({"settings": get_settings()}) == _DEFAULT_BROWSER_USER_AGENT
