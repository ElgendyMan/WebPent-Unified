"""Expert-level, target-neutral security mental model builder."""

from __future__ import annotations

from hashlib import sha256

from .contracts import SecurityMentalModel, V7Status
from .utils import refs, text, values


class SecurityMentalModelBuilderV7:
    """Build a descriptive model; unresolved fields remain explicit."""

    def build(
        self,
        *,
        engagement_id: str,
        target_id: str,
        world_model: object | None = None,
        attack_graph: object | None = None,
        knowledge: object | None = None,
        evidence_refs: tuple[str, ...] = (),
    ) -> SecurityMentalModel:
        nodes = values(attack_graph, "nodes")
        graph_relations = values(attack_graph, "relations", "edges")
        assets = tuple(
            dict.fromkeys(
                text(item, "label", "name", "id", "node_id", default="asset")
                for item in nodes
                if text(item, "kind", "category", default="asset").lower()
                in {"asset", "resource", "data", "service"}
            )
        )
        if not assets:
            assets = tuple(
                dict.fromkeys(
                    text(item, "name", "id", "asset", default="asset")
                    for item in values(world_model, "assets", "critical_assets")
                )
            )
        business_logic = tuple(
            dict.fromkeys(
                text(item, "description", "statement", "label", "name", default="business rule")
                for item in values(world_model, "business_logic", "business_intents", "rules")
            )
        )
        journeys = tuple(
            dict.fromkeys(
                text(item, "journey", "name", "label", "description", default="user journey")
                for item in values(world_model, "user_journeys", "journeys", "workflows")
            )
        )
        trust = tuple(
            dict.fromkeys(
                text(item, "relation", "label", "description", default="trust relationship")
                for item in graph_relations
                if any(
                    token in text(item, "relation", "kind", "label").lower()
                    for token in ("trust", "owns", "calls", "depends")
                )
            )
        )
        boundaries = tuple(
            dict.fromkeys(
                text(item, "label", "relation", "description", default="authorization boundary")
                for item in graph_relations
                if any(
                    token in text(item, "relation", "kind", "label").lower()
                    for token in (
                        "permission",
                        "privilege",
                        "identity",
                        "role",
                        "tenant",
                        "owner",
                        "boundary",
                    )
                )
            )
        )
        states = tuple(
            dict.fromkeys(
                text(item, "state", "name", "label", "description", default="state transition")
                for item in values(world_model, "state_machines", "states", "transitions")
            )
        )
        workflows = tuple(
            dict.fromkeys(
                text(item, "description", "name", "label", default="sensitive workflow")
                for item in values(
                    world_model, "sensitive_workflows", "workflows", "critical_workflows"
                )
            )
        )
        assumptions = tuple(
            dict.fromkeys(
                text(
                    item,
                    "statement",
                    "assumption",
                    "description",
                    default="unrecorded security assumption",
                )
                for item in values(world_model, "invariants", "assumptions", "security_assumptions")
            )
        )
        if not assumptions:
            assumptions = (
                "authorization boundaries match the modeled identity and role context",
                "sensitive state transitions require the intended preconditions",
                "critical assets are reachable only through validated trust relationships",
            )
        unresolved = []
        for label, collection in (
            ("critical assets", assets),
            ("authorization boundaries", boundaries),
            ("state transitions", states),
            ("sensitive workflows", workflows),
        ):
            if not collection:
                unresolved.append(f"{label} are not sufficiently evidenced")
        all_refs = tuple(
            dict.fromkeys(
                (
                    *evidence_refs,
                    *(ref for item in (*nodes, *graph_relations) for ref in refs(item)),
                )
            )
        )[:64]
        confidence = min(
            1.0,
            0.25
            + 0.12
            * sum(
                bool(group)
                for group in (
                    assets,
                    business_logic,
                    journeys,
                    trust,
                    boundaries,
                    states,
                    workflows,
                )
            ),
        )
        model_id = (
            "mental-model:"
            + sha256(f"{engagement_id}|{target_id}|{all_refs}|{assets}".encode()).hexdigest()[:16]
        )
        return SecurityMentalModel(
            model_id=model_id,
            protected_assets=assets,
            business_logic=business_logic,
            user_journeys=journeys,
            trust_relationships=trust,
            authorization_boundaries=boundaries,
            state_machines=states,
            sensitive_workflows=workflows,
            security_assumptions=assumptions,
            unresolved_questions=tuple(unresolved),
            evidence_refs=all_refs,
            confidence=round(confidence, 3),
            status=V7Status.ADVISORY if unresolved else V7Status.READY,
        )


__all__ = ["SecurityMentalModelBuilderV7"]
