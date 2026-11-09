"""Execution-local target workspace context.

The context is intentionally process-local and is never serialized.  Managers
use it only to select target-scoped resources when callers do not pass an
explicit path, preserving legacy APIs while preventing cross-target reuse.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from webpent.shared.target_workspace import TargetWorkspace

_ACTIVE_WORKSPACE: ContextVar[TargetWorkspace | None] = ContextVar(
    "webpent_active_target_workspace", default=None
)


def get_active_target_workspace() -> TargetWorkspace | None:
    """Return the workspace active in the current execution context."""
    return _ACTIVE_WORKSPACE.get()


@contextmanager
def activate_target_workspace(
    workspace: TargetWorkspace,
) -> Iterator[TargetWorkspace]:
    """Activate one workspace for the current graph/worker execution.

    A nested activation for a different target is rejected rather than
    silently switching resources mid-run.  This is fail-closed isolation.
    """
    current = _ACTIVE_WORKSPACE.get()
    if current is not None and current.workspace_id != workspace.workspace_id:
        raise RuntimeError(
            "target_workspace_switch_blocked: a different target workspace is "
            "already active in this execution context"
        )
    token = _ACTIVE_WORKSPACE.set(workspace)
    try:
        workspace.ensure()
        yield workspace
    finally:
        _ACTIVE_WORKSPACE.reset(token)
