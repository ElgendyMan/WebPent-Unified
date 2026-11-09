"""Passive business-logic analysis facades.

The package emits observations, candidates, and evidence requirements only.
Execution remains behind scope policy, ActionAuthority, and the central proof
bundle/replay validators.
"""

from .abuse_case_generator import AbuseCaseGenerator, AbuseCaseProposal
from .invariant_checker import InvariantChecker, InvariantResult
from .state_transition import StateTransitionAnalyzer, TransitionCandidate
from .workflow_analyzer import WorkflowAnalysis, WorkflowAnalyzer

__all__ = [
    "AbuseCaseGenerator",
    "AbuseCaseProposal",
    "InvariantChecker",
    "InvariantResult",
    "StateTransitionAnalyzer",
    "TransitionCandidate",
    "WorkflowAnalysis",
    "WorkflowAnalyzer",
]
