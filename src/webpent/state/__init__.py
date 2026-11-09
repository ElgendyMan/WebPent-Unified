"""
WebPent State — OPTIONAL LAYER
Requires: langchain_core
Core engine: webpent.families, webpent.cqa_v2, webpent.models, webpent.smart
"""
OPTIONAL_LAYER = "state"
try:
    import langchain_core  # noqa: F401
    LAYER_AVAILABLE = True
    LAYER_STATUS = "Optional dependencies available"
except ImportError:
    LAYER_AVAILABLE = False
    LAYER_STATUS = "langchain_core not installed — state layer unavailable"
__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]
