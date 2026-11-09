# src/webpent/config/policies.py
"""webpent.config.policies

Security policy models for the WebPent Framework V2 execution sandbox.

Defines a :class:`SandboxPolicy` Pydantic model that constrains how
payloads are executed inside Docker containers. The policy is enforced
by :mod:`webpent.tools.infrastructure.docker` when launching containers
for the execution-sandbox agent.

V7 Cognitive Upgrade — Phase 6: adds :class:`RabbitHolePolicy`, which
governs the Rabbit Hole recursive-follow-up feature (Phase 7) with
the same Pydantic-validated, centralized, auditable conventions
already established by :class:`SandboxPolicy`.

Centralising the policies in Pydantic models (rather than scattering
magic values through the codebase) gives us:

  * **Validation** — invalid values (negative timeout, malformed memory
    limit, zero max_depth) are rejected at construction time.
  * **Auditability** — the policies can be logged or serialised to JSON
    alongside engagement artifacts for compliance.
  * **Extensibility** — new constraints (CPU limits, read-only
    filesystems, capability drops, new Rabbit Hole caps) can be added
    without touching the Docker runner or the Rabbit Hole node.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Regex for Docker's --memory / --memory-swap syntax: a number followed
# by an optional unit suffix (b, k, m, g, or their uppercase
# equivalents). Docker also accepts a bare integer (bytes), so we
# allow that too. See:
# https://docs.docker.com/config/containers/resource_constraints/#memory
_MEMORY_PATTERN = re.compile(
    r"^\d+(\.\d+)?[bBkKmMgG]?$"
)


class SandboxPolicy(BaseModel):
    """Constraints applied to a Docker-based execution sandbox.

    Attributes:
        max_memory: Maximum memory the container may use, in Docker's
            ``--memory`` syntax (e.g. ``"256m"``, ``"1g"``, ``"512m"``).
            A bare integer is interpreted as bytes.
        network_disabled: If ``True``, the container runs with
            ``--network none`` — no inbound or outbound network access.
            This is the safe default for payload execution because it
            prevents a malicious payload from exfiltrating data or
            attacking other hosts.
        timeout_seconds: Maximum wall-clock time the container may run
            before it is killed. Protects against infinite loops and
            time-based blind payloads that would otherwise stall the
            engagement.
        cpu_quota: Optional CPU quota in microseconds per 100ms period
            (Docker's ``--cpu-quota``). ``None`` means no limit. A
            value of ``50000`` restricts the container to 50% of one
            CPU core.
        read_only_root: If ``True``, the container's root filesystem is
            mounted read-only (``--read-only``). Forces payloads to
            write to explicit tmpfs volumes (if any) rather than
            polluting the container's writable layer.
        cap_drop: List of Linux capabilities to drop from the container
            (Docker's ``--cap-drop``). Defaults to dropping ``ALL``
            capabilities for maximum isolation; specific capabilities
            can be added via :attr:`cap_add`.
        cap_add: List of Linux capabilities to add back (after dropping
            all). Only set if the payload genuinely needs a capability
            (e.g. ``NET_RAW`` for certain ICMP-based payloads).
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    max_memory: str = Field(
        default="256m",
        description=(
            "Maximum memory the container may use, in Docker's --memory "
            "syntax (e.g. '256m', '1g'). A bare integer is bytes."
        ),
    )
    network_disabled: bool = Field(
        default=True,
        description=(
            "If True, the container runs with --network none — no "
            "inbound or outbound network access. Safe default for "
            "payload execution."
        ),
    )
    timeout_seconds: int = Field(
        default=30,
        gt=0,
        le=3600,
        description=(
            "Maximum wall-clock time the container may run before "
            "being killed. Protects against infinite loops."
        ),
    )
    cpu_quota: int | None = Field(
        default=None,
        ge=1000,
        description=(
            "Optional CPU quota in microseconds per 100ms period "
            "(Docker's --cpu-quota). 50000 = 50% of one core."
        ),
    )
    read_only_root: bool = Field(
        default=True,
        description=(
            "If True, the container's root filesystem is mounted "
            "read-only (--read-only)."
        ),
    )
    cap_drop: list[str] = Field(
        default_factory=lambda: ["ALL"],
        description=(
            "Linux capabilities to drop from the container. Defaults "
            "to ['ALL'] for maximum isolation."
        ),
    )
    cap_add: list[str] = Field(
        default_factory=list,
        description=(
            "Linux capabilities to add back (after dropping all). Only "
            "set if the payload genuinely needs a capability."
        ),
    )

    # -- Validators ---------------------------------------------------------
    @field_validator("max_memory")
    @classmethod
    def _validate_memory_format(cls, v: str) -> str:
        if not _MEMORY_PATTERN.match(v):
            raise ValueError(
                f"Invalid memory format {v!r}. Expected a number "
                f"optionally followed by a unit suffix (b, k, m, g), "
                f"e.g. '256m' or '1g'."
            )
        return v.lower()

    # -- Convenience --------------------------------------------------------
    def to_docker_kwargs(self) -> dict[str, Any]:
        """Convert the policy into kwargs for ``docker.models.containers.run``.

        This is a convenience helper used by the Docker runner. Keeping
        the translation logic on the policy object itself (rather than
        in the runner) means the runner stays a thin wrapper and the
        policy can be unit-tested in isolation.
        """
        kwargs: dict[str, Any] = {
            "mem_limit": self.max_memory,
            "network_disabled": self.network_disabled,
            "read_only": self.read_only_root,
            "cap_drop": self.cap_drop,
        }
        if self.cap_add:
            kwargs["cap_add"] = self.cap_add
        if self.cpu_quota is not None:
            kwargs["cpu_quota"] = self.cpu_quota
        return kwargs


# ===========================================================================
# V7 Cognitive Upgrade — Phase 6: RabbitHolePolicy
# ===========================================================================
class ForcedHITLCategory(str, Enum):
    """Discovery categories that force a mandatory HITL pause.

    Per Phase 6 / Section 6: "Discovering real credentials should be
    one of the ``RabbitHolePolicy`` categories that forces a mandatory
    HITL pause *regardless of ``auto_approve``* — mirroring the way Dev
    Mode already forces the HITL pause today independent of the
    engagement's own ``auto_approve`` setting."

    The closed set is deliberately conservative — every category here
    is one where "merely reading the file" is materially different from
    "acting on what was read," and the latter needs a human sign-off
    before the system proceeds.

    Adding a new category is a code change, not an LLM output — keeps
    the HITL-gating vocabulary stable and auditable.
    """

    CREDENTIAL_MATERIAL = "credential_material"
    APPARENT_PRODUCTION_DATASTORE = "apparent_production_datastore"
    OUT_OF_SCOPE_HOST = "out_of_scope_host"


class RabbitHolePolicy(BaseModel):
    """Constraints applied to Rabbit Hole recursive follow-up (Phase 7).

    V7 Cognitive Upgrade — Phase 6: follows the exact same convention
    set by :class:`SandboxPolicy` (Pydantic-validated, centralized,
    auditable). The Rabbit Hole node (Phase 7) reads this policy on
    every branch-entry decision and **fail-closes** when any cap is
    hit — exactly like :class:`webpent.agents.scope_enforcer.agent`'s
    existing kill-switch design.

    Attributes:
        max_depth: Maximum recursion depth per branch. A branch that
            would exceed this depth is abandoned (normal termination,
            NOT a crash — per Section 6: "Budget exhaustion should
            degrade gracefully, not abort noisily"). Default 3 —
            calibrated so the example chain (admin panel -> backup.zip
            -> docker-compose.yml -> Postgres creds -> git repo ->
            secrets -> internal IPs) fits in one branch with a small
            margin, but a runaway chain stops well before
            ``settings.max_graph_steps``.
        max_branches: Maximum total branches per engagement. When the
            engagement's branch count reaches this, no new branches
            are entered. Default 5 — bounds the worst-case engagement
            time without being so tight that a genuinely interesting
            target can't be explored.
        max_actions_per_branch: Maximum actions (read-only parse /
            extract steps + Hypothesis/Finding emissions) per branch.
            A branch that hits this is abandoned. Default 10 — the
            inner-loop bound that prevents a single branch from
            consuming the entire engagement's action budget.
        forced_hitl_categories: Discovery categories that force a
            mandatory HITL pause regardless of ``auto_approve``. See
            :class:`ForcedHITLCategory`. Default: all three categories
            — credentials, apparent production datastores, out-of-scope
            hosts. Operators can narrow this list, but the default is
            maximally conservative.
        curiosity_budget_ceiling: Maximum percentage (0.0-1.0) of the
            total engagement action budget that curiosity-driven
            exploration may consume. Prevents Rabbit Hole from eating
            the whole engagement. Default 0.3 (30%) — leaves the
            majority of the budget for the deterministic pipeline.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    max_depth: int = Field(
        default=3,
        ge=1,
        le=10,
        description=(
            "Maximum recursion depth per branch. A branch that would "
            "exceed this is abandoned (normal termination, NOT a crash)."
        ),
    )
    max_branches: int = Field(
        default=5,
        ge=1,
        le=20,
        description=(
            "Maximum total branches per engagement. When the branch "
            "count reaches this, no new branches are entered."
        ),
    )
    max_actions_per_branch: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Maximum actions (parse/extract + Hypothesis/Finding "
            "emissions) per branch. A branch that hits this is abandoned."
        ),
    )
    forced_hitl_categories: list[str] = Field(
        default_factory=lambda: [c.value for c in ForcedHITLCategory],
        description=(
            "Discovery categories that force a mandatory HITL pause "
            "regardless of auto_approve. See ForcedHITLCategory."
        ),
    )
    curiosity_budget_ceiling: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description=(
            "Maximum percentage (0.0-1.0) of the total engagement "
            "action budget that curiosity-driven exploration may consume."
        ),
    )
    max_revisit_depth: int = Field(
        default=3,
        ge=0,
        le=10,
        description=(
            "Maximum depth for targeted adaptive revisit tasks. Revisit "
            "depth is independent from artifact-branch depth and is always "
            "bounded before scheduling."
        ),
    )
    max_revisit_tasks: int = Field(
        default=10,
        ge=0,
        le=50,
        description=(
            "Maximum number of deduplicated targeted revisit tasks emitted "
            "in one adaptive scheduling pass."
        ),
    )
    max_loop_back_iterations: int = Field(
        default=1,
        ge=0,
        le=3,
        description=(
            "V8 P0 A2: Maximum number of times the graph may route "
            "from rabbit_hole_node back to strategist_node in a single "
            "engagement. Each re-entry lets the Strategist promote "
            "RABBIT_HOLE-origin hypotheses (the ones Rabbit Hole just "
            "created) to Findings — closing the loop that the V7 graph "
            "left one-directional. Default 1 = one re-entry allowed; "
            "0 = loop-back disabled (V7 behaviour); 3 = aggressive. "
            "Bounded by 3 to prevent unbounded cycling even if a "
            "future change adds more producers of RABBIT_HOLE-origin "
            "hypotheses."
        ),
    )

    # -- Validators ---------------------------------------------------------
    @field_validator("forced_hitl_categories", mode="before")
    @classmethod
    def _normalise_hitl_categories(cls, v: Any) -> list[str]:
        """Normalise the category list to a list of string values.

        Accepts enum members, strings, or a mix. Rejects unknown
        category strings at construction time so a typo surfaces
        immediately rather than silently failing to gate.
        """
        if v is None:
            return [c.value for c in ForcedHITLCategory]
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list):
            raise ValueError(
                f"forced_hitl_categories must be a list; got {type(v).__name__}"
            )
        valid = {c.value for c in ForcedHITLCategory}
        result: list[str] = []
        for item in v:
            if isinstance(item, ForcedHITLCategory):
                result.append(item.value)
            elif isinstance(item, str):
                item_lower = item.strip().lower()
                if item_lower not in valid:
                    raise ValueError(
                        f"Unknown forced_hitl_category {item!r}. "
                        f"Valid: {sorted(valid)}."
                    )
                result.append(item_lower)
            else:
                raise ValueError(
                    f"forced_hitl_category entries must be strings or "
                    f"ForcedHITLCategory members; got {type(item).__name__}"
                )
        return result

    # -- Convenience --------------------------------------------------------
    def requires_forced_hitl(self, category: str) -> bool:
        """Return True if ``category`` forces a mandatory HITL pause.

        Convenience predicate the Phase 7 Rabbit Hole node uses after
        classifying a discovered artifact. Pure string comparison —
        no LLM, no heuristic.
        """
        if not category:
            return False
        return category.strip().lower() in (self.forced_hitl_categories or [])
