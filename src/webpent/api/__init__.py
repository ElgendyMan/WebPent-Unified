"""
WebPent API — OPTIONAL LAYER
Requires: bcrypt, fastapi
Core engine: webpent.families, webpent.cqa_v2, webpent.models, webpent.smart
"""
OPTIONAL_LAYER = "api"
try:
    import bcrypt  # noqa: F401
    LAYER_AVAILABLE = True
    LAYER_STATUS = "Optional dependencies available"
except ImportError:
    LAYER_AVAILABLE = False
    LAYER_STATUS = "bcrypt not installed — API layer unavailable"
__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]
