# tests/test_m1b_workspace_artifact_ownership.py
"""M1b residual closure — per-type data-ownership enforcement on the
workspace filesystem (reports / artifacts / ledgers / checkpoints).

UM-DR-13 recorded the M1b residual: "per-type data-ownership enforcement
tests for reports/artifacts on the workspace filesystem."

The ownership column (``DATA_SOURCE_OF_TRUTH`` in ``models/contracts.py``)
names the filesystem-typed stores; ``shared/target_workspace.py`` derives a
deterministic per-(client, engagement, origin) namespace and
``shared/target_workspace_context.py`` activates it fail-closed. These tests
pin the whole enforcement chain on the real filesystem:

1. workspace identity is deterministic and DISTINCT per client/engagement/
   origin — two engagements can never share a root (isolation by construction
   on the filesystem axis, complementing the sqlite-axis isolation test in
   ``test_m1b_domain_contracts.py``);
2. the per-type layout matches the documented source-of-truth registry;
3. storage settings overrides (output_dir / database_url / ledger paths)
   BIND writes to the owning workspace — a report written under engagement
   A's overrides never appears inside engagement B's tree;
4. the active-workspace context resolves per-type storage (decision log,
   session checkpoints) to the active workspace and REFUSES a mid-run
   switch to a different workspace;
5. artifact file names derived from finding ids cannot traverse paths.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.models.contracts import DATA_SOURCE_OF_TRUTH
from webpent.shared.target_workspace import (
    TargetWorkspace,
    build_target_workspace,
)
from webpent.shared.target_workspace_context import (
    activate_target_workspace,
    get_active_target_workspace,
)


# ---------------------------------------------------------------------------
# 1. Identity: deterministic, distinct, normalized
# ---------------------------------------------------------------------------


def test_workspace_identity_is_deterministic_and_distinct(tmp_path):
    root = tmp_path / "workspaces"
    a1 = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-1",
    )
    a2 = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-1",
    )
    assert a1.workspace_id == a2.workspace_id, "same identity must map to one workspace"

    variants = {
        "client": TargetWorkspace.for_target(
            workspace_root=root,
            target_origin="https://app.example",
            client_id="client-2",
            engagement_id="eng-1",
        ),
        "engagement": TargetWorkspace.for_target(
            workspace_root=root,
            target_origin="https://app.example",
            client_id="client-1",
            engagement_id="eng-2",
        ),
        "origin": TargetWorkspace.for_target(
            workspace_root=root,
            target_origin="https://other.example",
            client_id="client-1",
            engagement_id="eng-1",
        ),
        "no-identity": TargetWorkspace.for_target(
            workspace_root=root,
            target_origin="https://app.example",
        ),
    }
    ids = {a1.workspace_id} | {ws.workspace_id for ws in variants.values()}
    assert len(ids) == 5, "every identity axis change must yield a distinct workspace"

    # normalization: default port and host case collapse to the same origin
    explicit_http = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="http://APP.example:80",
        client_id="client-1",
        engagement_id="eng-1",
    )
    implicit_http = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="http://app.example",
        client_id="client-1",
        engagement_id="eng-1",
    )
    assert explicit_http.target_origin == "http://app.example"
    assert explicit_http.workspace_id == implicit_http.workspace_id, (
        "default port and host case must normalize to one workspace"
    )


def test_workspace_requires_absolute_http_origin():
    with pytest.raises(ValueError):
        TargetWorkspace.for_target(
            workspace_root="/tmp/x", target_origin="app.example"
        )
    with pytest.raises(ValueError):
        TargetWorkspace.for_target(workspace_root="/tmp/x", target_origin="ftp://x.example")


# ---------------------------------------------------------------------------
# 2. Per-type layout matches DATA_SOURCE_OF_TRUTH
# ---------------------------------------------------------------------------


def test_workspace_layout_matches_data_source_of_truth(tmp_path):
    # the registry names the stores; the workspace must provide them
    assert "langgraph sqlite" in DATA_SOURCE_OF_TRUTH["campaign_state_checkpoints"]["store"]
    assert "sqlite" in DATA_SOURCE_OF_TRUTH["decision_log"]["store"]
    assert "filesystem" in DATA_SOURCE_OF_TRUTH["reports"]["store"]
    assert "chroma" in DATA_SOURCE_OF_TRUTH["embeddings_vector"]["store"]
    assert "JSONL" in DATA_SOURCE_OF_TRUTH["retest_ledger"]["store"]

    ws = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-1",
    ).ensure()

    root = ws.root
    assert ws.reports_dir == root / "reports" and ws.reports_dir.is_dir()
    assert ws.artifacts_dir == root / "artifacts" and ws.artifacts_dir.is_dir()
    assert ws.sessions_dir == root / "sessions" and ws.sessions_dir.is_dir()
    assert ws.rag_dir == root / "rag" and ws.rag_dir.is_dir()
    assert ws.databases_dir == root / "databases" and ws.databases_dir.is_dir()
    assert ws.ledger_dir == root / "ledgers" and ws.ledger_dir.is_dir()

    assert ws.sessions_database_path == root / "sessions" / "checkpoints.sqlite3"
    assert ws.decision_log_database_path == root / "databases" / "decision_log.sqlite3"
    assert ws.findings_ledger_path == root / "ledgers" / "findings.sqlite3"
    assert ws.action_ledger_path == root / "ledgers" / "actions.sqlite3"
    assert ws.chroma_path == root / "rag" / "chroma_db"
    assert ws.database_url == f"sqlite:///{(root / 'databases' / 'webpent.sqlite3').as_posix()}"

    # the descriptor is checkpoint-safe and complete
    descriptor = ws.as_dict()
    for key in ("workspace_id", "workspace_root", "reports_dir", "sessions_database_path"):
        assert key in descriptor


# ---------------------------------------------------------------------------
# 3. Storage overrides bind writes to the owning workspace
# ---------------------------------------------------------------------------


def test_storage_overrides_bind_reports_to_the_owning_workspace(tmp_path):
    root = tmp_path / "workspaces"
    eng_a = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-a",
    ).ensure()
    eng_b = TargetWorkspace.for_target(
        workspace_root=root,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-b",
    ).ensure()
    assert eng_a.root != eng_b.root

    overrides = eng_a.settings_overrides()
    assert Path(overrides["output_dir"]) == eng_a.reports_dir
    assert Path(overrides["findings_ledger_path"]) == eng_a.findings_ledger_path
    assert Path(overrides["action_ledger_path"]) == eng_a.action_ledger_path
    assert overrides["reauth_vault_database_url"] == overrides["database_url"]
    for key in ("output_dir", "database_url", "findings_ledger_path", "action_ledger_path"):
        value = overrides[key]
        text = str(value).replace("sqlite:///", "")
        assert text.startswith(str(eng_a.root)), (
            f"{key} must resolve inside the owning workspace root"
        )

    # a report written under engagement A's storage settings lands in A's
    # reports dir and is invisible inside engagement B's tree
    report = Path(overrides["output_dir"]) / "campaign_report.html"
    report.write_text("<html>eng-a report</html>", encoding="utf-8")
    assert report.is_file() and report.parent == eng_a.reports_dir

    files_in_b = [p for p in eng_b.root.rglob("*") if p.is_file()]
    assert files_in_b == [], "engagement B's workspace must not contain A's artifacts"
    assert report.read_text(encoding="utf-8") == "<html>eng-a report</html>"

    # build_target_workspace honors the settings root attribute
    class _Settings:
        target_workspace_root = root

    via_settings = build_target_workspace(
        _Settings(),
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-a",
    )
    assert via_settings.workspace_id == eng_a.workspace_id


# ---------------------------------------------------------------------------
# 4. Active-workspace context: per-type resolution + fail-closed switching
# ---------------------------------------------------------------------------


def test_active_workspace_context_resolves_and_refuses_switch(tmp_path):
    from webpent.memory import decision_log as decision_log_module

    ws_a = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-a",
    )
    ws_b = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-b",
    )

    assert get_active_target_workspace() is None
    assert decision_log_module._active_workspace_database_url() is None

    with activate_target_workspace(ws_a):
        assert get_active_target_workspace() is ws_a
        # per-type resolution: decision log -> the ACTIVE workspace's database
        assert decision_log_module._active_workspace_database_url() == (
            f"sqlite:///{ws_a.decision_log_database_path.as_posix()}"
        )
        # fail-closed: a DIFFERENT workspace may not activate mid-run
        with pytest.raises(RuntimeError, match="target_workspace_switch_blocked"):
            with activate_target_workspace(ws_b):
                pass
        # re-activating the SAME workspace is idempotent and allowed
        with activate_target_workspace(ws_a):
            assert get_active_target_workspace() is ws_a
        assert get_active_target_workspace() is ws_a  # inner same-ws exit keeps outer

    assert get_active_target_workspace() is None
    assert decision_log_module._active_workspace_database_url() is None


def test_checkpointer_resolves_to_the_active_workspace(tmp_path):
    from webpent.graph.checkpoints import get_checkpointer

    ws = TargetWorkspace.for_target(
        workspace_root=tmp_path,
        target_origin="https://app.example",
        client_id="client-1",
        engagement_id="eng-a",
    ).ensure()

    with activate_target_workspace(ws):
        with get_checkpointer() as saver:
            row = saver.conn.execute("PRAGMA database_list").fetchone()
            live_path = Path(row[2]).resolve()
    assert live_path == ws.sessions_database_path.resolve(), (
        "the checkpoint store must resolve to the active workspace's sessions db"
    )


# ---------------------------------------------------------------------------
# 5. Artifact naming cannot traverse
# ---------------------------------------------------------------------------


def test_poc_artifact_stem_cannot_traverse_paths():
    from webpent.reporter.poc_recorder import safe_artifact_stem

    hostile = "../../../etc/passwd"
    stem = safe_artifact_stem(hostile)
    assert "/" not in stem and "\\" not in stem and ".." not in stem
    assert Path(stem).name == stem

    assert safe_artifact_stem("") == "finding"
    assert safe_artifact_stem("..") == "finding"
    assert safe_artifact_stem(None) == "finding"
    # a legitimate id survives untouched
    assert safe_artifact_stem("3f2a9c1e") == "3f2a9c1e"
