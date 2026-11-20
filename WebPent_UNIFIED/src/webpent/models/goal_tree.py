# src/webpent/models/goal_tree.py
"""webpent.models.goal_tree

V7 Cognitive Upgrade — Phase 6: Goal Tree.

A small tree structure layered on top of the Hypothesis pool + Mental
Model. Per the plan:

    "One root node per engagement. Child nodes represent active
    investigation threads: standard sweep goals (mirroring today's
    fixed pipeline stages) plus, once Rabbit Hole exists, dynamically
    created branch goals. Each node: status (``active``, ``paused``,
    ``succeeded``, ``abandoned``), parent reference, associated
    hypothesis/finding IDs, budget consumed and budget remaining
    (actions, not wall-clock — deterministic and reproducible)."

The tree lives in ``PentestState.goal_tree`` as a dict (serialised
via Pydantic's ``model_dump``), with the ``merge_dicts`` reducer
handling parallel-branch writes — same discipline as ``mental_model``.

Purpose (per Phase 6 spec):

  * Dynamic Prioritization (Phase 3) selects from the tree's open
    leaves rather than from a flat list.
  * "Abandon this branch" (Phase 5 Self-Critique) has somewhere
    concrete to point at — it marks the Goal Tree node ``abandoned``.
  * Phase 7 Rabbit Hole branch goals are dynamically created as
    children of the standard sweep goals.

The tree is deliberately NOT a graph — it's a strict tree (one parent
per node). A hypothesis that depends on multiple goals is referenced
from multiple Goal Tree nodes via ``hypothesis_ids``, but each Goal
Tree node has exactly one parent. This keeps "abandon this branch"
unambiguous.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GoalStatus(str, Enum):
    """Lifecycle states for a Goal Tree node.

    State machine (one-way per branch):

        active -> paused -> active   (reversible — pause/resume)
        active -> succeeded          (terminal — found what we were looking for)
        active -> abandoned          (terminal — gave up, e.g. Phase 5 Self-Critique)

    A node that reaches ``succeeded`` or ``abandoned`` is terminal —
    it does NOT transition back to ``active``. Dynamic Prioritization
    only selects from ``active`` (and ``paused``) leaves.
    """

    ACTIVE = "active"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    ABANDONED = "abandoned"


class GoalType(str, Enum):
    """Closed set of Goal Tree node types.

    ``STANDARD_SWEEP`` goals mirror today's fixed pipeline stages
    (recon, crawler, hypothesis, deep-probers, etc.) — one per
    pipeline stage that produces discoveries. ``RABBIT_HOLE_BRANCH``
    goals are dynamically created by Phase 7 when a Rabbit Hole
    branch is entered.
    """

    ROOT = "root"
    STANDARD_SWEEP = "standard_sweep"
    RABBIT_HOLE_BRANCH = "rabbit_hole_branch"


class GoalTreeNode(BaseModel):
    """A single node in the Goal Tree.

    Attributes:
        id: Stable UUID-style string. Generated at creation time;
            used as the dict key in ``GoalTree.nodes`` and as the
            ``parent_id`` on children.
        goal_type: The :class:`GoalType`. ROOT for the engagement
            root; STANDARD_SWEEP for pipeline-stage goals;
            RABBIT_HOLE_BRANCH for dynamically-created branch goals.
        parent_id: Parent node ID. None for the ROOT node. Every
            non-root node has exactly one parent (strict tree).
        status: :class:`GoalStatus`. See the state machine in
            GoalStatus's docstring.
        label: Human-readable label (e.g. "recon", "hypothesis",
            "rabbit_hole:backup.zip@depth_2"). Used in the Decision
            Log and the final report's explainability appendix.
        hypothesis_ids: UUIDs (as strings) of Hypotheses associated
            with this goal. A hypothesis may be referenced from
            multiple goals (e.g. a hypothesis spawned by a rabbit
            hole is referenced from both the branch goal and the
            standard sweep goal it ultimately re-enters).
        finding_ids: UUIDs (as strings) of Findings produced while
            pursuing this goal. Populated as findings are confirmed.
        budget_consumed: Actions consumed so far (NOT wall-clock —
            deterministic and reproducible). Incremented each time
            a node in pursuit of this goal takes an action.
        budget_remaining: Actions remaining before this goal hits
            its action cap. When this reaches 0, the goal is
            abandoned (normal termination, NOT a crash).
        created_at: UTC timestamp of creation.
        updated_at: UTC timestamp of last status change.
        metadata: Free-form dict for goal-type-specific extras (e.g.
            the parent_hypothesis_id for a RABBIT_HOLE_BRANCH goal,
            the branch_depth, the artifact identity_key that
            triggered the branch).
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: str = Field(
        ...,
        min_length=1,
        description="Stable UUID-style string ID.",
    )
    goal_type: GoalType = Field(
        ...,
        description="The goal type. See GoalType.",
    )
    parent_id: str | None = Field(
        default=None,
        description=(
            "Parent node ID. None for the ROOT node. Every non-root "
            "node has exactly one parent (strict tree)."
        ),
    )
    status: GoalStatus = Field(
        default=GoalStatus.ACTIVE,
        description="Lifecycle state. See GoalStatus.",
    )
    label: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable label for the Decision Log and report.",
    )
    hypothesis_ids: list[str] = Field(
        default_factory=list,
        description="UUIDs (as strings) of associated Hypotheses.",
    )
    finding_ids: list[str] = Field(
        default_factory=list,
        description="UUIDs (as strings) of produced Findings.",
    )
    budget_consumed: int = Field(
        default=0,
        ge=0,
        description="Actions consumed so far (NOT wall-clock).",
    )
    budget_remaining: int = Field(
        default=10,
        ge=0,
        description="Actions remaining before this goal hits its cap.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of creation.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of last status change.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form dict for goal-type-specific extras.",
    )

    @field_validator("goal_type", mode="before")
    @classmethod
    def _normalise_goal_type(cls, v: str | GoalType | None) -> GoalType:
        if v is None:
            raise ValueError("goal_type cannot be None.")
        if isinstance(v, GoalType):
            return v
        return GoalType(str(v).lower())

    @field_validator("status", mode="before")
    @classmethod
    def _normalise_status(cls, v: str | GoalStatus | None) -> GoalStatus:
        if v is None:
            return GoalStatus.ACTIVE
        if isinstance(v, GoalStatus):
            return v
        return GoalStatus(str(v).lower())

    def is_open(self) -> bool:
        """Return True if this goal is still worth pursuing.

        ``active`` and ``paused`` are open; ``succeeded`` and
        ``abandoned`` are terminal. Dynamic Prioritization only
        selects from open leaves.
        """
        return self.status in (GoalStatus.ACTIVE.value, GoalStatus.PAUSED.value)

    def is_terminal(self) -> bool:
        """Return True if this goal has reached a terminal state."""
        return self.status in (
            GoalStatus.SUCCEEDED.value,
            GoalStatus.ABANDONED.value,
        )


class GoalTree(BaseModel):
    """The Goal Tree structure stored in ``PentestState.goal_tree``.

    Stored as a dict (serialised via Pydantic's ``model_dump``) with
    the ``merge_dicts`` reducer handling parallel-branch writes —
    same discipline as ``mental_model``.

    The tree is stored as a flat ``{node_id: GoalTreeNode_dict}`` map
    with parent references (``parent_id`` on each node), NOT as a
    nested structure. This makes ``merge_dicts`` merges safe: two
    parallel branches adding different child nodes both end up in the
    merged tree without clobbering each other.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    nodes: dict[str, GoalTreeNode] = Field(
        default_factory=dict,
        description="Node ID -> GoalTreeNode.",
    )

    def to_dict_for_state(self) -> dict[str, Any]:
        """Serialise to the dict shape stored in PentestState.goal_tree.

        ``PentestState.goal_tree`` is ``Annotated[dict[str, Any],
        merge_dicts]`` — the reducer deep-merges dict values.
        """
        return {
            "nodes": {
                nid: (
                    n.model_dump(mode="json")
                    if isinstance(n, GoalTreeNode)
                    else dict(n)
                )
                for nid, n in self.nodes.items()
            }
        }


# ---------------------------------------------------------------------------
# Tree-construction + query helpers — pure functions, no side effects.
# ---------------------------------------------------------------------------
def create_root_goal(label: str = "engagement_root") -> GoalTreeNode:
    """Create the single ROOT goal node for an engagement.

    Every engagement has exactly one ROOT node. All standard sweep
    goals and rabbit hole branch goals are descendants of it.
    """
    return GoalTreeNode(
        id=f"root-{uuid4().hex[:16]}",
        goal_type=GoalType.ROOT.value,
        parent_id=None,
        label=label,
        budget_remaining=10000,  # effectively unbounded — the root never hits a cap
    )


def create_standard_sweep_goal(
    *,
    parent_id: str,
    label: str,
    budget_remaining: int = 50,
    hypothesis_ids: list[str] | None = None,
) -> GoalTreeNode:
    """Create a STANDARD_SWEEP goal (mirrors a fixed pipeline stage)."""
    return GoalTreeNode(
        id=f"sweep-{uuid4().hex[:16]}",
        goal_type=GoalType.STANDARD_SWEEP.value,
        parent_id=parent_id,
        label=label,
        budget_remaining=budget_remaining,
        hypothesis_ids=list(hypothesis_ids or []),
    )


def create_rabbit_hole_branch_goal(
    *,
    parent_id: str,
    label: str,
    branch_depth: int,
    parent_hypothesis_id: str | None = None,
    trigger_artifact_identity: str | None = None,
    budget_remaining: int = 10,
) -> GoalTreeNode:
    """Create a RABBIT_HOLE_BRANCH goal (dynamically created by Phase 7).

    The ``metadata`` dict carries the branch-specific context the
    Phase 7 Rabbit Hole node and the Phase 5 Self-Critique node need:
    ``branch_depth``, ``parent_hypothesis_id``, and
    ``trigger_artifact_identity`` (the normalised identity key of the
    artifact that triggered this branch — used by Loop Prevention).
    """
    return GoalTreeNode(
        id=f"rabbit-{uuid4().hex[:16]}",
        goal_type=GoalType.RABBIT_HOLE_BRANCH.value,
        parent_id=parent_id,
        label=label,
        budget_remaining=budget_remaining,
        metadata={
            "branch_depth": branch_depth,
            "parent_hypothesis_id": parent_hypothesis_id,
            "trigger_artifact_identity": trigger_artifact_identity,
        },
    )


def _coerce_goal_tree(tree_state: Any) -> GoalTree | None:
    """Coerce serialized state into the canonical GoalTree model."""
    if isinstance(tree_state, GoalTree):
        return tree_state
    if not isinstance(tree_state, dict):
        return None
    try:
        return GoalTree(**tree_state)
    except Exception:
        return None


def find_root_goal_id(tree_state: Any) -> str | None:
    """Return the canonical ROOT node id, or ``None`` for invalid state."""
    tree = _coerce_goal_tree(tree_state)
    if tree is None:
        return None
    roots = [node.id for node in tree.nodes.values() if node.goal_type == GoalType.ROOT.value]
    return sorted(roots)[0] if roots else None


def count_goal_nodes(tree_state: Any, goal_type: GoalType | str) -> int:
    """Count nodes of one type through the canonical GoalTree model."""
    tree = _coerce_goal_tree(tree_state)
    if tree is None:
        return 0
    normalized = goal_type.value if isinstance(goal_type, GoalType) else str(goal_type)
    return sum(1 for node in tree.nodes.values() if node.goal_type == normalized)


def curiosity_budget_consumed(tree_state: Any) -> float:
    """Return rabbit-hole budget consumption as a bounded tree-derived ratio."""
    tree = _coerce_goal_tree(tree_state)
    if tree is None:
        return 0.0
    total = sum(node.budget_consumed for node in tree.nodes.values())
    rabbit = sum(
        node.budget_consumed
        for node in tree.nodes.values()
        if node.goal_type == GoalType.RABBIT_HOLE_BRANCH.value
    )
    return min(1.0, rabbit / total) if total else 0.0


def get_open_leaves(tree_state: Any) -> list[GoalTreeNode]:
    """Return all open leaf nodes (no open children) in the tree.

    Used by Dynamic Prioritization (Phase 3) to select from the
    tree's open leaves rather than from a flat list. A "leaf" is a
    node with no open children — a node with only terminal children
    is itself a leaf.
    """
    if not tree_state:
        return []
    if isinstance(tree_state, GoalTree):
        nodes = tree_state.nodes
    elif isinstance(tree_state, dict):
        raw_nodes = tree_state.get("nodes") or {}
        nodes: dict[str, GoalTreeNode] = {}
        for nid, nd in raw_nodes.items():
            try:
                nodes[str(nid)] = (
                    nd if isinstance(nd, GoalTreeNode) else GoalTreeNode(**nd)
                )
            except Exception:
                continue
    else:
        return []

    # Collect IDs of nodes that have at least one open child.
    parent_ids_with_open_children: set[str] = set()
    for node in nodes.values():
        if node.parent_id and node.is_open():
            parent_ids_with_open_children.add(node.parent_id)

    leaves = [
        node for node in nodes.values()
        if node.is_open() and node.id not in parent_ids_with_open_children
    ]
    # Deterministic sort: by created_at asc, then by id asc.
    leaves.sort(
        key=lambda n: (
            n.created_at.isoformat()
            if hasattr(n.created_at, "isoformat")
            else str(n.created_at),
            n.id,
        )
    )
    return leaves


def mark_goal_abandoned(
    tree_state: Any,
    goal_id: str,
    *,
    reason: str = "",
) -> dict[str, Any]:
    """Return a state update that marks a goal as abandoned.

    This is a **pure function** — it does NOT mutate the input
    ``tree_state``. It returns a partial state update (shaped for
    ``merge_dicts``) that the caller applies by returning it from a
    LangGraph node.

    Per Phase 5 Self-Critique: when Self-Critique recommends ABANDON,
    the caller calls this helper to produce the state update that
    marks the Goal Tree node abandoned. The node's status transitions
    to ``abandoned`` (terminal) and the ``updated_at`` timestamp is
    refreshed. The ``reason`` is recorded in ``metadata.abandon_reason``.
    """
    if not tree_state or not goal_id:
        return {"nodes": {}}

    if isinstance(tree_state, GoalTree):
        nodes = tree_state.nodes
    elif isinstance(tree_state, dict):
        raw_nodes = tree_state.get("nodes") or {}
        nodes = {}
        for nid, nd in raw_nodes.items():
            try:
                nodes[str(nid)] = (
                    nd if isinstance(nd, GoalTreeNode) else GoalTreeNode(**nd)
                )
            except Exception:
                continue
    else:
        return {"nodes": {}}

    if goal_id not in nodes:
        return {"nodes": {}}

    node = nodes[goal_id]
    updated = node.model_copy(update={
        "status": GoalStatus.ABANDONED.value,
        "updated_at": datetime.now(timezone.utc),
        "metadata": {**node.metadata, "abandon_reason": reason},
    })
    return {"nodes": {goal_id: updated.model_dump(mode="json")}}


def increment_budget_consumed(
    tree_state: Any,
    goal_id: str,
    *,
    delta: int = 1,
) -> dict[str, Any]:
    """Return a state update that increments a goal's budget_consumed.

    Pure function — returns a partial state update for ``merge_dicts``.
    Called by nodes that take an action in pursuit of a goal (e.g.
    the Phase 7 Rabbit Hole node when it emits a new Hypothesis from
    a branch). When ``budget_remaining`` reaches 0, the caller should
    also mark the goal abandoned via :func:`mark_goal_abandoned`.
    """
    if not tree_state or not goal_id or delta <= 0:
        return {"nodes": {}}

    if isinstance(tree_state, GoalTree):
        nodes = tree_state.nodes
    elif isinstance(tree_state, dict):
        raw_nodes = tree_state.get("nodes") or {}
        nodes = {}
        for nid, nd in raw_nodes.items():
            try:
                nodes[str(nid)] = (
                    nd if isinstance(nd, GoalTreeNode) else GoalTreeNode(**nd)
                )
            except Exception:
                continue
    else:
        return {"nodes": {}}

    if goal_id not in nodes:
        return {"nodes": {}}

    node = nodes[goal_id]
    new_consumed = node.budget_consumed + delta
    new_remaining = max(0, node.budget_remaining - delta)
    updated = node.model_copy(update={
        "budget_consumed": new_consumed,
        "budget_remaining": new_remaining,
        "updated_at": datetime.now(timezone.utc),
    })
    return {"nodes": {goal_id: updated.model_dump(mode="json")}}
