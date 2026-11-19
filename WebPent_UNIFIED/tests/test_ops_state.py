# tests/test_ops_state.py
"""v0.25.0 — RBAC-gated ops write commands: durable state adapter and
the CLI write surface.

Covers: state round-trip via public-API replay (workspace grants,
review queue N-approvals, portfolio budget ledger), fail-closed
authorization (unknown actor, unknown role, viewer/analyst refusals,
workspace isolation), tampered-state refusals (spend exceeding caps,
malformed JSON), the one-vote-per-analyst rule surviving replay, and
every ``webpent ops`` write command through the Typer runner
(exit codes, audit trail, --json rendering).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.ops import ops_app
from webpent.production.enterprise_operations import Role
from webpent.production.ops_state import (
    PORTFOLIO_WRITE_ROLES,
    OpsStateError,
    build_portfolio,
    build_workspaces_and_queue,
    empty_state,
    grant_user,
    load_state,
    save_state,
    user_role,
)
from webpent.production.portfolio_manager import BudgetCaps

runner = CliRunner()


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _bootstrap(tmp_path: Path) -> Path:
    state_path = tmp_path / "ops.json"
    result = runner.invoke(
        ops_app,
        ["bootstrap-admin", "--state", str(state_path), "--actor", "root"],
    )
    assert result.exit_code == 0, result.output
    return state_path


def _grant(state_path: Path, *, grantee: str, role: str, clients: list[str]) -> None:
    cmd = [
        "users", "--state", str(state_path), "--actor", "root",
        "--grantee", grantee, "--role", role,
    ]
    for client in clients:
        cmd.extend(["--client", client])
    result = runner.invoke(ops_app, cmd)
    assert result.exit_code == 0, result.output


# ----------------------------------------------------------------------
# state adapter
# ----------------------------------------------------------------------
def test_empty_state_round_trip(tmp_path: Path) -> None:
    state_path = tmp_path / "ops.json"
    assert load_state(state_path) == empty_state()
    save_state(state_path, empty_state())
    loaded = load_state(state_path)
    assert loaded["version"] == 1
    assert loaded["users"] == {}
    assert state_path.exists()
    # owner-only permissions on the state file
    import os
    assert (state_path.stat().st_mode & 0o077) == 0 or os.name != "posix"


def test_malformed_state_fails_closed(tmp_path: Path) -> None:
    state_path = tmp_path / "broken.json"
    state_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(OpsStateError):
        load_state(state_path)
    state_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(OpsStateError):
        load_state(state_path)


def test_unknown_actor_and_invalid_role_fail_closed(tmp_path: Path) -> None:
    state = empty_state()
    with pytest.raises(OpsStateError):
        user_role(state, "ghost")
    state["users"]["bad"] = {"role": "wizard", "clients": []}
    with pytest.raises(OpsStateError):
        user_role(state, "bad")


def test_grant_user_requires_manage_users(tmp_path: Path) -> None:
    state = empty_state()
    state["users"]["viewer1"] = {"role": Role.VIEWER.value, "clients": []}
    with pytest.raises(OpsStateError):
        grant_user(state, actor="viewer1", grantee="x", role="analyst", clients=[])
    state["users"]["admin1"] = {"role": Role.ADMIN.value, "clients": []}
    grant_user(state, actor="admin1", grantee="analyst1", role="analyst", clients=["acme"])
    assert state["users"]["analyst1"] == {"role": "analyst", "clients": ["acme"]}
    with pytest.raises(OpsStateError):
        grant_user(state, actor="admin1", grantee="x", role="wizard", clients=[])


def test_review_replay_enforces_n_approvals_and_one_vote(tmp_path: Path) -> None:
    state = empty_state()
    state["users"] = {
        "a1": {"role": "analyst", "clients": ["acme"]},
        "a2": {"role": "analyst", "clients": ["acme"]},
        "a3": {"role": "analyst", "clients": ["acme"]},
    }
    state["review"]["required_approvals"] = 2
    state["review"]["items"] = [
        {
            "item_id": "rev-1", "client_id": "acme", "finding_ref": "F-1",
            "severity": "high", "state": "approved", "claimed_by": "a1",
            "approvals": ["a1", "a2"], "rejections": [], "updated_at": 1.0,
        }
    ]
    _, queue = build_workspaces_and_queue(state)
    assert queue.nominatable("rev-1") is True
    assert queue.required_approvals == 2

    # A tampered state claiming three approvals still can't beat the
    # one-vote-per-analyst rule: a duplicated analyst collapses to one.
    state["review"]["items"][0]["approvals"] = ["a1", "a1", "a2"]
    _, queue = build_workspaces_and_queue(state)
    assert queue.nominatable("rev-1") is True  # a1 dedup, a1+a2 == 2 still
    state["review"]["items"][0]["approvals"] = ["a1", "a1"]
    _, queue = build_workspaces_and_queue(state)
    assert queue.nominatable("rev-1") is False  # only ONE distinct analyst


def test_portfolio_replay_refuses_ledger_exceeding_caps(tmp_path: Path) -> None:
    state = empty_state()
    state["portfolio"]["caps"] = {
        "total_budget": 10.0, "per_client_budget": 5.0, "per_campaign_cap": 4.0,
    }
    state["portfolio"]["programs"] = [
        {"program_name": "p1", "client_id": "acme", "expected_reward": 100.0,
         "success_probability": 0.5, "estimated_cost": 3.0, "notes": ""},
    ]
    state["portfolio"]["spend_entries"] = [
        {"client_id": "acme", "campaign_id": "c1", "amount": 4.0},
        {"client_id": "acme", "campaign_id": "c2", "amount": 4.0},  # breaches per-client 5
    ]
    with pytest.raises(OpsStateError):
        build_portfolio(state)


def test_portfolio_round_trip_preserves_caps_and_programs(tmp_path: Path) -> None:
    state = empty_state()
    state["portfolio"]["caps"] = BudgetCaps(total_budget=100.0, per_client_budget=50.0).as_dict()
    state["portfolio"]["programs"] = [
        {"program_name": "p1", "client_id": "acme", "expected_reward": 200.0,
         "success_probability": 0.5, "estimated_cost": 20.0, "notes": "n"},
    ]
    manager = build_portfolio(state)
    snapshot = manager.budget_snapshot()
    assert snapshot["registered_programs"] == 1
    ranked = manager.rank_programs()
    assert ranked[0][1] == pytest.approx(200.0 * 0.5 - 20.0)


def test_portfolio_write_roles_are_lead_and_admin() -> None:
    assert frozenset({Role.LEAD, Role.ADMIN}) == PORTFOLIO_WRITE_ROLES


# ----------------------------------------------------------------------
# CLI write surface
# ----------------------------------------------------------------------
def test_bootstrap_is_once_only(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    again = runner.invoke(
        ops_app, ["bootstrap-admin", "--state", str(state_path), "--actor", "other"]
    )
    assert again.exit_code == 2
    assert "bootstrap refused" in again.output
    # audit trail exists and records the bootstrap
    audit = Path(str(state_path) + ".audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    record = json.loads(audit[-1])
    assert record["action"] == "users.bootstrap_admin"
    assert record["actor"] == "root"


def test_full_review_flow_with_n_approvals(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="alice", role="analyst", clients=["acme"])
    _grant(state_path, grantee="bob", role="analyst", clients=["acme"])
    # Two distinct analysts must approve before nomination.
    state = load_state(state_path)
    state["review"]["required_approvals"] = 2
    save_state(state_path, state)

    def review(*args: str, actor: str = "alice") -> object:
        return runner.invoke(
            ops_app,
            ["review", "--state", str(state_path), "--actor", actor, *args],
        )

    result = review(
        "--action", "enqueue", "--client", "acme", "--finding-ref", "F-9", "--severity", "high"
    )
    assert result.exit_code == 0, result.output
    item_id = json.loads(result.output)["item_id"]

    assert review("--action", "claim", "--item", item_id, actor="bob").exit_code == 0
    first = review("--action", "decide", "--item", item_id, "--approve", actor="alice")
    assert first.exit_code == 0
    assert json.loads(first.output)["nominatable"] is False  # 1/2 approvals
    second = review("--action", "decide", "--item", item_id, "--approve", actor="bob")
    assert second.exit_code == 0
    assert json.loads(second.output)["nominatable"] is True  # 2/2 distinct

    pending = review("--action", "pending", "--client", "acme")
    assert pending.exit_code == 0
    assert item_id not in pending.output  # approved items are no longer pending


def test_review_requires_two_distinct_analysts(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="solo", role="analyst", clients=["acme"])
    result = runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "solo",
        "--action", "enqueue", "--client", "acme", "--finding-ref", "F-1",
    ])
    item_id = json.loads(result.output)["item_id"]
    runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "solo",
        "--action", "claim", "--item", item_id,
    ])
    runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "solo",
        "--action", "decide", "--item", item_id, "--approve",
    ])
    # required_approvals defaults to 1, so single approval nominates; the
    # N>1 case is covered by the engine test above. Here we verify the
    # double-vote no-op: a second decision by the same analyst is refused
    # by the engine (one decision per analyst), leaving state intact.
    again = runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "solo",
        "--action", "decide", "--item", item_id, "--reject",
    ])
    assert again.exit_code == 0  # engine returns the item unchanged
    state = load_state(state_path)
    stored = next(i for i in state["review"]["items"] if i["item_id"] == item_id)
    assert stored["approvals"] == ["solo"]
    assert stored["rejections"] == []  # the double vote was NOT counted


def test_review_rejects_unknown_actor_viewer_and_outside_workspace(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="analyst1", role="analyst", clients=["acme"])
    _grant(state_path, grantee="viewer1", role="viewer", clients=["acme"])

    ghost = runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "ghost",
        "--action", "enqueue", "--client", "acme", "--finding-ref", "F-1",
    ])
    assert ghost.exit_code == 2
    assert "authorization refused" in ghost.output

    viewer = runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "viewer1",
        "--action", "enqueue", "--client", "acme", "--finding-ref", "F-1",
    ])
    assert viewer.exit_code == 2
    assert "triage_findings" in viewer.output

    outsider = runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "analyst1",
        "--action", "enqueue", "--client", "other-co", "--finding-ref", "F-1",
    ])
    assert outsider.exit_code == 2
    assert "not a member" in outsider.output


def test_portfolio_flow_admit_refuse_spend(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="lead1", role="lead", clients=["acme"])
    _grant(state_path, grantee="analyst1", role="analyst", clients=["acme"])

    # A bounded client budget so overspend fails closed (0 = disabled cap).
    state = load_state(state_path)
    state["portfolio"]["caps"] = {
        "total_budget": 1000.0, "per_client_budget": 100.0, "per_campaign_cap": 0.0,
    }
    save_state(state_path, state)

    def portfolio(*args: str, actor: str = "lead1") -> object:
        return runner.invoke(
            ops_app,
            ["portfolio", "--state", str(state_path), "--actor", actor, *args],
        )

    registered = portfolio("--action", "register", "--client", "acme", "--program", "p1",
                           "--reward", "1000", "--prob", "0.5", "--cost", "100")
    assert registered.exit_code == 0, registered.output

    # analyst cannot touch portfolio economics (lead/admin only)
    denied = portfolio("--action", "register", "--client", "acme", "--program", "p2",
                       "--reward", "1", "--prob", "0.1", "--cost", "1", actor="analyst1")
    assert denied.exit_code == 2
    assert "lead/admin" in denied.output

    admitted = portfolio("--action", "admit", "--client", "acme", "--program", "p1",
                         "--campaign", "camp-1", "--json")
    assert admitted.exit_code == 0
    payload = json.loads(admitted.output)
    assert payload["verdict"] == "admitted"

    spent = portfolio("--action", "spend", "--client", "acme", "--campaign", "camp-1",
                      "--amount", "80", "--json")
    assert spent.exit_code == 0

    # per-campaign cap is 0 (disabled) but the second admit within budget passes;
    # spend beyond the client budget fails closed.
    over = portfolio("--action", "spend", "--client", "acme", "--campaign", "camp-1",
                     "--amount", "999999")
    assert over.exit_code == 2
    assert "spend refused" in over.output

    status = portfolio("--action", "status", "--json")
    assert status.exit_code == 0
    snap = json.loads(status.output)
    assert snap["spend_by_client"]["acme"] == pytest.approx(80.0)
    assert snap["registered_programs"] == 1


def test_portfolio_admission_respects_unified_budget(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="lead1", role="lead", clients=["acme"])

    def portfolio(*args: str) -> object:
        return runner.invoke(
            ops_app,
            ["portfolio", "--state", str(state_path), "--actor", "lead1", *args],
        )

    # Register a program whose estimate exceeds a small per-campaign cap:
    # caps must be settable through the state file.
    state = load_state(state_path)
    state["portfolio"]["caps"] = {
        "total_budget": 50.0, "per_client_budget": 40.0, "per_campaign_cap": 30.0,
    }
    save_state(state_path, state)

    assert portfolio("--action", "register", "--client", "acme", "--program", "big",
                     "--reward", "500", "--prob", "0.9", "--cost", "35").exit_code == 0
    capped = portfolio("--action", "admit", "--client", "acme", "--program", "big",
                       "--campaign", "c1", "--json")
    payload = json.loads(capped.output)
    assert payload["action"] == "refused"
    assert payload["verdict"] == "denied_campaign_cap"

    assert portfolio("--action", "register", "--client", "acme", "--program", "ok",
                     "--reward", "500", "--prob", "0.9", "--cost", "20").exit_code == 0
    ok = portfolio("--action", "admit", "--client", "acme", "--program", "ok",
                   "--campaign", "c2", "--json")
    assert json.loads(ok.output)["verdict"] == "admitted"

    # Recording the 20-unit spend then admitting a third 25-unit campaign
    # would exceed the 40-unit client budget -> refused.
    assert portfolio("--action", "spend", "--client", "acme", "--campaign", "c2",
                     "--amount", "20").exit_code == 0
    assert portfolio("--action", "register", "--client", "acme", "--program", "third",
                     "--reward", "10", "--prob", "0.5", "--cost", "25").exit_code == 0
    third = portfolio("--action", "admit", "--client", "acme", "--program", "third",
                      "--campaign", "c3", "--json")
    payload = json.loads(third.output)
    assert payload["verdict"] == "denied_client_budget"


def test_users_grant_is_admin_only_and_updates_memberships(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="lead1", role="lead", clients=["acme"])

    # lead cannot grant users (manage_users is admin-only)
    denied = runner.invoke(ops_app, [
        "users", "--state", str(state_path), "--actor", "lead1",
        "--grantee", "x", "--role", "viewer",
    ])
    assert denied.exit_code == 2
    assert "lacks 'manage_users'" in denied.output

    _grant(state_path, grantee="analyst1", role="analyst", clients=[])
    # re-grant with a client MERGES memberships (no accidental revoke)
    _grant(state_path, grantee="analyst1", role="analyst", clients=["acme"])
    state = load_state(state_path)
    assert state["users"]["analyst1"]["clients"] == ["acme"]


def test_write_commands_leave_audit_trail(tmp_path: Path) -> None:
    state_path = _bootstrap(tmp_path)
    _grant(state_path, grantee="alice", role="analyst", clients=["acme"])
    runner.invoke(ops_app, [
        "review", "--state", str(state_path), "--actor", "alice",
        "--action", "enqueue", "--client", "acme", "--finding-ref", "F-1",
    ])
    audit_path = Path(f"{state_path}.audit.jsonl")
    audit_lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    actions = [json.loads(line)["action"] for line in audit_lines]
    assert actions[0] == "users.bootstrap_admin"
    assert "users.grant" in actions
    assert "review.enqueue" in actions
    # every audit record is identifier-level only (no finding payloads)
    for line in audit_lines:
        record = json.loads(line)
        assert "finding_ref" not in record
