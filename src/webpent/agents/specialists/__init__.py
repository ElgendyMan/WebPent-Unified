"""Passive specialist proposal facades."""

from webpent.agents.specialists.passive_planner import (
    SpecialistProposal,
    propose_access_control_tasks,
    propose_api_surface_tasks,
    propose_business_logic_tasks,
    propose_specialist_tasks,
)

__all__ = [
    "SpecialistProposal",
    "propose_access_control_tasks",
    "propose_api_surface_tasks",
    "propose_business_logic_tasks",
    "propose_specialist_tasks",
]
