"""L9 §6 baseline D: an independently generated fixed prerequisite
strategy.

The mission demands a fair comparison against the L9 stateful
planner (baseline B) and its ablation (baseline C): a fixed
prerequisite strategy whose setup recipes were written WITHOUT
reading the planner's derivation logic, from the same public
surface description only. This module is that baseline.

What it is NOT: it does not import ``webpent.egaie.planner``, it
derives no dependency graph, computes no minimal transition
sequences, and keeps no per-precondition verification ledger. It
holds a STATIC per-family recipe list — the recipe for the
WORKFLOW_IDENTITY family is "fire the surface's first published
workflow action on the probe's workflow path, as the resource's
recorded owner, once, then verify with a read-only re-read" — and
fires it verbatim whenever a discriminating outcome came back as a
blocked precondition. Where the recipe happens to reach the state
the probe needed (a two-stage forward machine), it confirms like
the planner; where the chain is deeper or the first published
action is not the needed one, it fails closed like everything else
in the engine: the outcome stays inconclusive evidence, never a
negative security verdict.

What it SHARES, by design and documented in the mission's fairness
requirements: the candidate generation (the same differential
proposer), the observation contract, the validation oracle, the
sealed-bundle port, the ActionAuthority/ActionExecutor execution
path, the idempotency discipline, and the request budgets. Only
the setup derivation differs.

The module's tally() feeds the §6 metrics (prerequisites
identified/verified/failed/unknown) without consulting any planner
structure.

These are synthetic loopback comparisons over fixture applications:
they support no real-world generalization claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.egaie.differential import (
    ProbeStep,
    RelationshipTracker,
)

# The static recipe list, per engine family. A recipe is an ordered
# tuple of step NAMES; each name maps to one fixed action in
# _apply_recipe below. Nothing here reads the planner, the ledger's
# precondition structures, or any state chain.
RECIPES: dict[str, tuple[str, ...]] = {
    "WORKFLOW_IDENTITY": ("advance-first-published-action",),
}


@dataclass(frozen=True)
class RecipeTransition:
    """One setup transition built from the recipe, shaped for the
    port's shared setup path: a state-changing POST carrying its own
    idempotency key, followed by a read-only re-read of the same
    path. HTTP success alone never proves a transition; the re-read
    is what the strategy verifies against."""

    action_id: str
    path: str
    actor: str
    params: tuple[tuple[str, str], ...]
    idempotency_key: str

    def to_steps(self, idem_param: str,
                 verify_path: str) -> tuple[ProbeStep, ...]:
        return (
            ProbeStep(
                purpose="baseline",
                label=f"{self.action_id}-setup",
                method="POST",
                path=self.path,
                actor=self.actor,
                params=self.params + ((idem_param,
                                       self.idempotency_key),)),
            ProbeStep(
                purpose="baseline",
                label=f"{self.action_id}-verify",
                method="GET",
                path=verify_path,
                actor=self.actor),
        )


class FixedPrerequisiteRemediator:
    """The baseline-D remediation strategy wired into the
    orchestrator's remediation hook."""

    def __init__(self, max_setup_actions: int = 8) -> None:
        self.max_setup_actions = max_setup_actions
        self._setup_count = 0
        # §6 accounting: per family, how many remediation cycles
        # identified a recipe, verified a state change by re-read,
        # failed to produce a readable re-read, or ended unknown
        # (the recipe fired but the state did not move — the
        # strategy cannot tell whether that state was already the
        # required one, so the re-run decides, fail-closed).
        self.tally: dict[str, dict[str, int]] = {}

    def _count(self, family: str, slot: str) -> None:
        slot_tally = self.tally.setdefault(family, {
            "identified": 0, "verified": 0, "failed": 0,
            "unknown": 0})
        slot_tally[slot] = slot_tally.get(slot, 0) + 1

    def remediate(
            self, port: Any, experiment: Any,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        """One fixed remediation cycle: fire the family's recipe
        through the port's ordinary setup path, verify with the
        re-read, and re-run the experiment once so it is judged on
        comparable state. Returns None (the outcome stands as
        inconclusive evidence, never a verdict) when the family has
        no recipe, the recipe is exhausted, no owner or published
        action is derivable, or the re-read produced nothing
        readable."""
        family = experiment.family
        recipe = RECIPES.get(family)
        if not recipe:
            self._count(family, "unknown")
            return None
        if self._setup_count >= self.max_setup_actions:
            self._count(family, "failed")
            return None
        try:
            plan = port.plan_for(experiment.signature)
        except KeyError:
            self._count(family, "failed")
            return None
        view = RelationshipTracker(
            port.ledger, bindings=port.bindings).view()
        probe_paths = sorted({
            step.path for step in plan.steps
            if step.method == "POST"
            and step.path in view.workflow_paths})
        if not probe_paths:
            self._count(family, "failed")
            return None
        action_param = view.action_param or "action"
        fired_any = False
        for path in probe_paths:
            # The recipe is static and cannot tell which of the
            # plan's workflow paths is the one the candidate leg
            # needs, so it fires on EVERY POST path the plan
            # probes, in the plan's own order, advancing each
            # resource one step. Advancing a control resource is
            # harmless to the fail-closed oracle (its own-workflow
            # control applies from the advanced state); advancing
            # the target is the point.
            owner = view.workflow_owner.get(path)
            published = view.workflow_action_targets.get(path, {})
            if not owner or not published:
                continue
            action_name = next(iter(published))
            self._count(family, "identified")
            self._setup_count += 1
            if self._setup_count > self.max_setup_actions:
                self._count(family, "failed")
                break
            action_id = f"fixed-setup-{self._setup_count:02d}"
            transition = RecipeTransition(
                action_id=action_id,
                path=path,
                actor=owner,
                params=((action_param, action_name),),
                idempotency_key=(
                    f"{action_id}:{path.replace('/', '-')}"),
            )
            records = port.run_setup_steps(
                transition.to_steps(port.bindings.idem_param, path),
                f"fixed-{experiment.experiment_id}",
            )
            verify = records.get(f"{action_id}-verify")
            pre_state = view.workflow_state.get(path)
            structured = (
                verify.structured if verify is not None else None)
            observed = (
                structured.get(port.bindings.state_field)
                if isinstance(structured, dict) else None)
            if verify is None or observed is None:
                self._count(family, "failed")
                continue
            fired_any = True
            if observed == pre_state:
                # The recipe fired and the re-read shows no
                # movement: the machine may already sit in the
                # state the probe needed (the recipe cannot tell —
                # that is what makes it fixed rather than
                # reasoning). The re-run decides, fail-closed.
                self._count(family, "unknown")
            else:
                self._count(family, "verified")
        if not fired_any:
            return None
        port.mark_remediated(experiment.experiment_id)
        return port.execute(experiment)
