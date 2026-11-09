"""
WebPent Workers — OPTIONAL LAYER
Requires: celery
Core engine: webpent.families, webpent.cqa_v2, webpent.models, webpent.smart
"""
OPTIONAL_LAYER = "workers"
try:
    import celery  # noqa: F401
    LAYER_AVAILABLE = True
    LAYER_STATUS = "Optional dependencies available"
except ImportError:
    LAYER_AVAILABLE = False
    LAYER_STATUS = "celery not installed — workers layer unavailable"
__all__ = ["OPTIONAL_LAYER", "LAYER_AVAILABLE", "LAYER_STATUS"]
