"""
WebPent Graph — OPTIONAL LAYER
Requires: langgraph
Core engine: webpent.families, webpent.cqa_v2, webpent.models, webpent.smart
"""
OPTIONAL_LAYER = "graph"
try:
    import langgraph  # noqa: F401
    LAYER_AVAILABLE = True
    LAYER_STATUS = "Optional dependencies available"
except ImportError:
    LAYER_AVAILABLE = False
    LAYER_STATUS = "langgraph not installed — graph layer unavailable"
__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]
