"""TEAM-1 Phase 1 — OOB database parity acceptance test.

Simulates the deployed three-party topology inside one process:

  * WORKER side: activates a target workspace and persists an SSRF finding
    (with oob_token) into the WORKSPACE database.
  * TARGET side: fires the OOB callback at the API's workspace-scoped route
    (``/api/oob/{thread_id}/{finding_id}/{secret}``).
  * API side: resolves the engagement workspace from the scan registry,
    activates it, and confirms the finding in the WORKSPACE database.
  * VALIDATOR side: polls via ``_poll_for_oob_callback`` under the active
    workspace and observes the Tool-Confirmed status.

Parity law asserted: the OOB event arrives, is persisted, is visible to the
validator, produces the expected finding state, and never creates a second
persistence authority (the default/registry database holds NO findings row).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from webpent.config.settings import activate_settings, get_settings
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.target_workspace import build_target_workspace
from webpent.shared.target_workspace_context import activate_target_workspace


def _make_request(
    method: str = "GET",
    body: bytes = b"",
    path_params: dict | None = None,
) -> Request:
    """Build a minimal ASGI request for the OOB callback handler."""

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/api/oob/x/y/z",
        "raw_path": b"/api/oob/x/y/z",
        "query_string": b"",
        "root_path": "",
        "server": ("api", 8000),
        "headers": [(b"host", b"api")],
        "client": ("203.0.113.7", 4444),
        "path_params": path_params or {},
    }
    return Request(scope, receive)


@pytest.fixture()
def parity_env(tmp_path, monkeypatch):
    """Isolated default DB + workspace root + OOB settings."""
    db_dir = tmp_path / "default-db"
    db_dir.mkdir()
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir()
    monkeypatch.setenv("WEBPENT_DATABASE_URL", f"sqlite:///{db_dir / 'registry.db'}")
    monkeypatch.setenv("WEBPENT_OOB_CALLBACK_SECRET", "team1-test-secret")
    monkeypatch.setenv("WEBPENT_OOB_CALLBACK_BASE_URL", "http://api:8000")
    # Sprint R1 FIX 2: OOB confirmation route is fail-closed-by-default via
    # a separate flag from the secret above. This fixture builds a full
    # round-trip OOB parity test, so the route must be explicitly enabled.
    monkeypatch.setenv("WEBPENT_OOB_CONFIRM_ROUTE_ENABLED", "1")
    monkeypatch.setenv("WEBPENT_TARGET_WORKSPACE_ROOT", str(workspace_root))
    from webpent.config.settings import get_settings as _gs

    _gs.cache_clear()

    from webpent.memory import db as db_module

    db_module._db_manager_singleton = None
    db_module._db_manager_singletons.clear()

    yield {"workspace_root": workspace_root}

    _gs.cache_clear()
    db_module._db_manager_singleton = None
    db_module._db_manager_singletons.clear()


def _finding(oob_token: str) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title="OOB parity fixture",
        severity=Severity.HIGH.value,
        description="ssrf oob parity fixture",
        tool_name="validator",
        payload="http://api:8000/api/oob/canary",
        url="http://lab.local/fetch?url=x",
        confidence=Confidence.TENTATIVE,
        confidence_level="AI-Assessed",
        reasoning="candidate",
        vuln_class=VulnClass.SSRF.value,
        created_at=datetime.now(timezone.utc),
        thread_id=None,  # stamped below
        oob_token=oob_token,
    )


async def test_oob_event_reaches_workspace_db_and_validator(
    parity_env: dict, monkeypatch
) -> None:
    from webpent.agents.validator.agent import _poll_for_oob_callback
    from webpent.api.app import _validate_oob_finding_id, receive_oob_callback_scoped
    from webpent.api.scan_registry import init_scan_registry, register_scan
    from webpent.memory.db import get_db_manager

    thread_id = str(uuid.uuid4())
    token = uuid.uuid4().hex + uuid.uuid4().hex
    finding = _finding(token)
    finding = finding.model_copy(update={"thread_id": thread_id})

    # --- scan dispatch: registry row in the DEFAULT database -------------
    assert init_scan_registry() is True
    assert register_scan(
        thread_id,
        task_id="celery-task-1",
        target_url="http://lab.local",
        owner_username="operator",
        client_id="",
        engagement_id="engagement-1",
    )

    # --- worker side: workspace activation + finding persistence ---------
    settings = get_settings()
    workspace = build_target_workspace(
        settings,
        target_origin="http://lab.local",
        client_id="",
        engagement_id="engagement-1",
    ).ensure()
    workspace_settings = settings.model_copy(update=workspace.settings_overrides())
    with activate_target_workspace(workspace), activate_settings(workspace_settings):
        worker_db = get_db_manager()
        assert str(worker_db._db_path()) == str(workspace.databases_dir / "webpent.sqlite3")
        worker_db.save_finding(finding)

    # The URL the validator issues must carry the engagement scope.
    from webpent.agents.validator.agent import _build_oob_url

    oob_url = _build_oob_url(finding.id, token, thread_id=thread_id)
    assert oob_url is not None
    assert oob_url == f"http://api:8000/api/oob/{thread_id}/{finding.id}/{token}"

    # --- API side: OOB callback arrives on the scoped route --------------
    # NOTE: the API process has NO workspace active here — it must resolve
    # the workspace itself from the registry + thread_id.
    request = _make_request(
        path_params={"secret": token, "thread_id": thread_id, "finding_id": str(finding.id)}
    )
    # UNIFIED MERGE (2026-11-02): native async (P2-107 AST gate).
    response = await receive_oob_callback_scoped(
        thread_id, str(finding.id), request
    )
    assert response.status_code == 204

    # --- validator side: poll observes the ADVISORY record (R3 E-1) ------
    # R3 E-1 (Ruling R3-002 §3.2) CORRECTED BEHAVIOR (C6-listed modification,
    # justified): the demoted callback path never flips confidence, so the
    # frozen validator poll — which waits for Tool-Confirmed — times out BY
    # DESIGN. The callback is observable as the authority-neutral advisory
    # record on the finding; the poll rewire is registered for M2 (the
    # validator is NOT thawed in R3). The pre-R3 assertion
    # (confidence_level == "Tool-Confirmed") pinned the exact violating
    # behavior the ruling removed and may not be preserved.
    with activate_target_workspace(workspace), activate_settings(workspace_settings):
        confirmed = _poll_for_oob_callback(finding.id, timeout_seconds=1.0, max_attempts=5)
        assert confirmed is None, (
            "demoted OOB path must never produce a Tool-Confirmed row for the poll"
        )
        reread = get_db_manager().get_finding(finding.id)
    assert reread is not None
    assert len(reread.advisory_evidence) == 1, "callback recorded as advisory evidence"
    assert reread.advisory_evidence[0]["type"] == "oob_callback_advisory"
    assert reread.confidence_level == "AI-Assessed", "authority unchanged by callback"
    assert "OOB Callback Received" not in (reread.reasoning or ""), (
        "no reasoning/authority mutation via the advisory path"
    )

    # --- parity: the default database holds the REGISTRY, not findings ---
    default_db = get_db_manager()
    assert default_db._db_path() != workspace.databases_dir / "webpent.sqlite3"
    assert default_db.get_finding(finding.id) is None, (
        "finding leaked into the default database — second persistence authority"
    )
    from webpent.api.scan_registry import get_scan_record as _gsr

    assert _gsr(thread_id)["target_url"] == "http://lab.local"

    # validate strict UUID parsing path still rejects junk
    with pytest.raises(HTTPException):
        _validate_oob_finding_id("not-a-uuid")
