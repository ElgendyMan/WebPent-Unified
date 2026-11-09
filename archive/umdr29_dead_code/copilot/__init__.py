"""Proposal-only Copilot interfaces."""

from webpent.copilot.critic import LLMCritic
from webpent.copilot.explainer import LLMExplainer
from webpent.copilot.planner import LLMPlanner

__all__ = ["LLMCritic", "LLMExplainer", "LLMPlanner"]
