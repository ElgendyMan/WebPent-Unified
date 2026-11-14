"""
WebPent Agents — OPTIONAL LAYER
================================
This layer provides LLM-powered agents for enhanced workflows.
It is NOT part of the core GOED engine and requires optional dependencies:
langchain_core, langgraph, bcrypt, celery, etc.

Core engine lives in: webpent.families, webpent.cqa_v2, webpent.models, webpent.smart
"""

# Core marker — this module is optional
OPTIONAL_LAYER = "agents"
OPTIONAL_DEPENDENCIES = ["langchain_core", "langgraph"]

def _try_import():
    """Lazy import of agent modules. Returns (success, message)."""
    try:
        import langchain_core  # noqa: F401
        return True, "Optional dependencies available"
    except ImportError:
        return False, "langchain_core not installed — agent layer unavailable"

LAYER_AVAILABLE, LAYER_STATUS = _try_import()

__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]
