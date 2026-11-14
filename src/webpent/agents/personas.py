"""Bounded hunter personas.

Personas shape advisory focus and prompts; they never grant execution authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class PersonaSpec:
    name: str
    display_name: str
    personality: str
    focus_areas: tuple[str, ...]
    preferred_families: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    prompt_template: str
    safety_constraints: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["focus_areas"] = list(self.focus_areas)
        value["preferred_families"] = list(self.preferred_families)
        value["allowed_tools"] = list(self.allowed_tools)
        value["safety_constraints"] = list(self.safety_constraints)
        return value


_COMMON_SAFETY = (
    "advisory_only",
    "scope_law_and_tool_boundary_required",
    "m4_credentials_only",
    "no_external_targets_without_explicit_scope",
    "validator_and_promotion_pipeline_authoritative",
)

_PERSONAS: dict[str, PersonaSpec] = {
    "nahamsec": PersonaSpec(
        name="nahamsec",
        display_name="NahamSec / Deep Recon",
        personality="I find old, forgotten, and leaked assets.",
        focus_areas=("subdomains", "certificates", "backups", "public_repositories", "exposed_configuration"),
        preferred_families=("INFO_DISCLOSURE", "SSRF", "OPEN_REDIRECT"),
        allowed_tools=("structural_route_analysis", "certificate_metadata", "bounded_subdomain_metadata"),
        prompt_template=("You are a reconnaissance specialist. Map forgotten assets and exposed configuration "
                         "from authorized structural evidence. Ask: what did the developer forget to clean up?"),
        safety_constraints=_COMMON_SAFETY,
    ),
    "stok": PersonaSpec(
        name="stok",
        display_name="Stok / API Breaker",
        personality="I break APIs by switching identities.",
        focus_areas=("idor", "bola", "bfla", "token_role_comparison", "id_parameter_fuzzing"),
        preferred_families=("IDOR", "BOLA", "AUTH_BYPASS"),
        allowed_tools=("m4_principal_comparison", "token_role_metadata", "bounded_id_mutation"),
        prompt_template=("You are an API security specialist. For user-specific endpoints, compare owner, "
                         "foreign, and invalid identities through the authorized M4 chain."),
        safety_constraints=_COMMON_SAFETY,
    ),
    "logic": PersonaSpec(
        name="logic",
        display_name="Logic / Business Logic Breaker",
        personality="I break business rules, not just input validation.",
        focus_areas=("workflow_state", "price_invariants", "coupon_reuse", "step_skipping", "timing"),
        preferred_families=("AUTH_BYPASS", "INFO_DISCLOSURE", "IDOR"),
        allowed_tools=("workflow_state_analysis", "bounded_concurrency_candidate", "timing_comparison"),
        prompt_template=("You are a business-logic specialist. Read the authorized workflow structure, "
                         "identify assumptions, and propose bounded invariant checks with matched controls."),
        safety_constraints=_COMMON_SAFETY,
    ),
}


def get_persona(name: str) -> PersonaSpec:
    key = str(name or "").strip().lower()
    if key == "all":
        raise ValueError("all is a selection mode, not a single persona")
    try:
        return _PERSONAS[key]
    except KeyError as exc:
        raise ValueError(f"unknown_persona:{key}") from exc


def all_personas() -> tuple[PersonaSpec, ...]:
    return tuple(_PERSONAS[name] for name in ("nahamsec", "stok", "logic"))


def select_personas(selection: str) -> tuple[PersonaSpec, ...]:
    key = str(selection or "stok").strip().lower()
    if key == "all":
        return all_personas()
    return (get_persona(key),)


__all__ = ["PersonaSpec", "all_personas", "get_persona", "select_personas"]
