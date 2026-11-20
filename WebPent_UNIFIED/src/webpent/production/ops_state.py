# src/webpent/production/ops_state.py
"""Durable state adapter for RBAC-gated ``webpent ops`` WRITE commands
(v0.25.0 — the "limited write commands behind RBAC" follow-up from the
0.24.0 worklog).

Why this exists
---------------
The 0.23.0 enterprise layer (``enterprise_operations.py``) is a pure
in-memory decision engine: RBAC matrix, workspace registry, review
queue. That is correct for library use, but a CLI invocation is a new
process each time — without durable state, ``ops review decide`` would
forget every grant between two commands. This adapter persists the
MINIMAL identifier-level state as one JSON file (mode 0600) plus an
append-only JSONL audit trail, and rebuilds the enterprise objects via
their PUBLIC replay APIs only:

* ``WorkspaceRegistry.grant`` for memberships,
* ``ReviewQueue.enqueue/claim/submit_decision`` for queue replay
  (one-vote-per-analyst and the N-approvals rule are re-enforced by
  the engine itself during replay — the adapter cannot smuggle a
  decision past them),
* ``PortfolioManager.register_program/record_spend`` for the budget
  ledger (caps are re-enforced during replay; a state file that
  exceeds the recorded caps fails closed with a typed error).

Security posture
----------------
* Fail-closed everywhere: a missing/malformed actor, role, or client
  reference is an error, never a silent fallback to privilege.
* The actor's role and workspace memberships come from the state
  file's ``users`` map (the operator's local identity book) — the CLI
  never accepts a self-asserted role.
* The frozen RBAC matrix in ``enterprise_operations.py`` is used
  AS-IS (no matrix edits in this window). Portfolio economics are a
  documented lead/admin capability enforced in this adapter's role
  check (``PORTFOLIO_WRITE_ROLES``), NOT by changing the frozen
  enterprise vocabulary.
* Redaction-first: identifiers and amounts only — no finding payloads,
  no raw evidence, no secrets in either file.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from webpent.production.enterprise_operations import (
    ReviewItem,
    ReviewQueue,
    ReviewState,
    Role,
    WorkspaceRegistry,
)
from webpent.production.portfolio_manager import (
    BudgetCaps,
    PortfolioManager,
    ProgramEstimate,
)

logger = logging.getLogger(__name__)

__all__ = [
    "OpsStateError",
    "PORTFOLIO_WRITE_ROLES",
    "empty_state",
    "load_state",
    "save_state",
    "get_user",
    "user_role",
    "grant_user",
    "build_workspaces_and_queue",
    "serialize_queue",
    "build_portfolio",
    "serialize_portfolio",
    "append_ops_audit",
]


class OpsStateError(Exception):
    """Typed, fail-closed state/authorization error for the ops CLI."""


#: Portfolio economics are lead/admin territory (documented adapter-level
#: extension; the frozen enterprise matrix is intentionally NOT edited).
PORTFOLIO_WRITE_ROLES: frozenset[Role] = frozenset({Role.LEAD, Role.ADMIN})

_STATE_VERSION = 1


# ----------------------------------------------------------------------
# state file I/O (atomic, 0600, fail-closed)
# ----------------------------------------------------------------------
def empty_state() -> dict[str, Any]:
    return {
        "version": _STATE_VERSION,
        "users": {},  # actor -> {"role": str, "clients": [str, ...]}
        "review": {"required_approvals": 1, "items": []},
        "portfolio": {
            "caps": {"total_budget": 0.0, "per_client_budget": 0.0, "per_campaign_cap": 0.0},
            "programs": [],
            "spend_entries": [],
        },
    }


def load_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load the ops state file; an absent file yields the empty skeleton
    (bootstrap), a malformed one raises (fail-closed)."""
    file_path = Path(path)
    if not file_path.exists():
        return empty_state()
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OpsStateError(f"ops state unreadable: {type(exc).__name__}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("users", {}), dict):
        raise OpsStateError("ops state malformed: expected an object with a users map")
    state = empty_state()
    state["users"] = raw.get("users", {})
    review = raw.get("review") or {}
    state["review"] = {
        "required_approvals": int(review.get("required_approvals", 1)),
        "items": list(review.get("items", [])),
    }
    portfolio = raw.get("portfolio") or {}
    caps = portfolio.get("caps") or {}
    state["portfolio"] = {
        "caps": {
            "total_budget": float(caps.get("total_budget", 0.0)),
            "per_client_budget": float(caps.get("per_client_budget", 0.0)),
            "per_campaign_cap": float(caps.get("per_campaign_cap", 0.0)),
        },
        "programs": list(portfolio.get("programs", [])),
        "spend_entries": list(portfolio.get("spend_entries", [])),
    }
    return state


def save_state(path: str | os.PathLike[str], state: dict[str, Any]) -> None:
    """Atomically persist the state (tmp + replace, owner-only perms)."""
    file_path = Path(path)
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = file_path.with_suffix(file_path.suffix + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
        os.replace(tmp, file_path)
        with contextlib.suppress(OSError):
            os.chmod(file_path, 0o600)
    except OSError as exc:
        raise OpsStateError(f"ops state not saved: {type(exc).__name__}") from exc


# ----------------------------------------------------------------------
# users (local identity book — role + memberships, fail-closed)
# ----------------------------------------------------------------------
def get_user(state: dict[str, Any], actor: str) -> dict[str, Any]:
    user = state["users"].get(str(actor))
    if not isinstance(user, dict):
        raise OpsStateError(f"unknown actor '{actor}' — ask an admin to grant access first")
    return user


def user_role(state: dict[str, Any], actor: str) -> Role:
    user = get_user(state, actor)
    try:
        return Role(str(user.get("role", "")))
    except ValueError as exc:
        raise OpsStateError(f"actor '{actor}' has an invalid role — access refused") from exc


def grant_user(
    state: dict[str, Any], *, actor: str, grantee: str, role: str, clients: list[str]
) -> dict[str, Any]:
    """Admin-only user grant (MANAGE_USERS via the frozen matrix)."""
    from webpent.production.enterprise_operations import RbacPolicy

    actor_role = user_role(state, actor)
    if not RbacPolicy.authorize(actor_role, "manage_users"):
        raise OpsStateError(f"actor '{actor}' ({actor_role.value}) may not manage users")
    try:
        granted = Role(str(role))
    except ValueError as exc:
        raise OpsStateError(f"unknown role '{role}'") from exc
    existing = state["users"].get(grantee, {"role": granted.value, "clients": []})
    merged_clients = sorted(
        {str(c) for c in existing.get("clients", [])} | set(clients)
    )
    state["users"][grantee] = {"role": granted.value, "clients": merged_clients}
    return state["users"][grantee]


# ----------------------------------------------------------------------
# enterprise adapters (public-API replay only)
# ----------------------------------------------------------------------
def build_workspaces_and_queue(
    state: dict[str, Any],
) -> tuple[WorkspaceRegistry, ReviewQueue]:
    """Rebuild workspace grants + the review queue from state.

    Replay goes through the queue's own public decisions API, so the
    one-vote-per-analyst rule and the N-approvals threshold are
    re-enforced by the engine during reconstruction — a tampered state
    file cannot manufacture approvals the engine would not grant.
    """
    workspace = WorkspaceRegistry()
    for actor, user in sorted(state["users"].items()):
        if not isinstance(user, dict):
            continue
        for client in user.get("clients", []):
            workspace.grant(actor, str(client))

    required = max(1, int(state["review"].get("required_approvals", 1)))
    queue = ReviewQueue(workspace, required_approvals=required)
    restored: dict[str, ReviewItem] = {}
    for raw in state["review"].get("items", []):
        item_id = str(raw.get("item_id", ""))
        client_id = str(raw.get("client_id", ""))
        finding_ref = str(raw.get("finding_ref", ""))
        if not item_id or not client_id or not finding_ref:
            raise OpsStateError("review state has an item missing id/client/finding_ref")
        # enqueue is workspace-checked when an actor is passed; replay is
        # operator-authorized upstream, so it goes in without an actor.
        item = queue.enqueue(
            item_id, client_id, finding_ref, severity=str(raw.get("severity", "info"))
        )
        if item is None:  # pragma: no cover — defensive
            raise OpsStateError(f"review replay refused item '{item_id}'")
        claimed_by = str(raw.get("claimed_by", ""))
        if claimed_by and item.state is ReviewState.PENDING:
            claimed = queue.claim(item_id, claimed_by)
            if claimed is None:
                raise OpsStateError(f"review replay could not restore claim on '{item_id}'")
        for analyst in [str(a) for a in raw.get("approvals", [])]:
            queue.submit_decision(item_id, analyst, approve=True)
        for analyst in [str(a) for a in raw.get("rejections", [])]:
            queue.submit_decision(item_id, analyst, approve=False)
        restored[item_id] = queue._items[item_id]
        restored[item_id].updated_at = (
            float(raw.get("updated_at", 0.0)) or restored[item_id].updated_at
        )
    return workspace, queue


def serialize_queue(state: dict[str, Any], queue: ReviewQueue) -> None:
    """Write the queue's live items back into the state dict."""
    items = []
    for item in sorted(queue._items.values(), key=lambda i: (i.client_id, i.item_id)):
        items.append(item.as_dict())
    state["review"]["items"] = items


# ----------------------------------------------------------------------
# portfolio adapter
# ----------------------------------------------------------------------
def build_portfolio(state: dict[str, Any]) -> PortfolioManager:
    """Rebuild the portfolio: caps directly, programs via registration,
    spend via ordered public ``record_spend`` replay (caps re-enforced —
    a ledger that breaches the recorded caps fails closed)."""
    caps_raw = state["portfolio"].get("caps", {})
    manager = PortfolioManager(
        caps=BudgetCaps(
            total_budget=float(caps_raw.get("total_budget", 0.0)),
            per_client_budget=float(caps_raw.get("per_client_budget", 0.0)),
            per_campaign_cap=float(caps_raw.get("per_campaign_cap", 0.0)),
        )
    )
    for raw in state["portfolio"].get("programs", []):
        manager.register_program(
            ProgramEstimate(
                program_name=str(raw.get("program_name", "")),
                client_id=str(raw.get("client_id", "")),
                expected_reward=float(raw.get("expected_reward", 0.0)),
                success_probability=float(raw.get("success_probability", 0.0)),
                estimated_cost=float(raw.get("estimated_cost", 0.0)),
                notes=str(raw.get("notes", "")),
            )
        )
    for entry in state["portfolio"].get("spend_entries", []):
        recorded, reason = manager.record_spend(
            str(entry.get("client_id", "")),
            str(entry.get("campaign_id", "")),
            float(entry.get("amount", 0.0)),
        )
        if not recorded:
            raise OpsStateError(
                "portfolio state inconsistent with recorded caps "
                f"(spend replay refused: {reason}) — fix the state file first"
            )
    return manager


def serialize_portfolio(state: dict[str, Any], manager: PortfolioManager) -> None:
    """Write caps + programs back into the state dict.

    ``spend_entries`` is intentionally LEFT UNTOUCHED here: it is an
    append-only ledger maintained by the CLI (each successful
    ``record_spend`` appends one entry), and ``build_portfolio`` replays
    it in order — rewriting it here would risk desynchronizing the
    replay source. Entry-level history also lives in the audit JSONL.
    """
    state["portfolio"]["caps"] = dict(manager.caps.as_dict())
    # Programs come from rank_programs (deterministic, public).
    state["portfolio"]["programs"] = [
        program.as_dict() for program, _ in manager.rank_programs()
    ]


# ----------------------------------------------------------------------
# audit trail (append-only JSONL next to the state file)
# ----------------------------------------------------------------------
def append_ops_audit(
    state_path: str | os.PathLike[str], *, action: str, actor: str, **fields: Any
) -> None:
    """Append one redacted audit record. Never raises (auditing must not
    break the command it documents — failures are logged)."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": str(action),
        "actor": str(actor),
        **fields,
    }
    try:
        audit_path = Path(state_path).with_suffix(Path(str(state_path)).suffix + ".audit.jsonl")
        audit_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
    except OSError:
        logger.warning("ops audit write failed for action=%s", action, exc_info=True)
