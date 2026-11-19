# src/webpent/jsintel/__init__.py
"""webpent.jsintel — unified JavaScript intelligence pipeline (ق8).

One pass from every JS bundle to direct hypotheses: the proposal calls
this the **API surface shadow**. The heavy lifting lives in the
existing (frozen) engines — ``shared/javascript_intelligence`` for
per-bundle routes/sinks/secrets/auth-hints, ``agents/
sourcemap_analysis`` for map disclosures, ``agents/js_discovery`` for
surface discovery — this package is the thin orchestration + hypothesis
layer that proposal ق8 asked for. See ``api_surface_shadow.py``.
"""

from webpent.jsintel.api_surface_shadow import (
    ApiSurfaceShadow,
    ShadowHypothesis,
    build_api_surface_shadow,
    shadow_from_crawl_surfaces,
)
from webpent.jsintel.js_reversing import reverse_javascript_source

__all__ = [
    "ApiSurfaceShadow",
    "ShadowHypothesis",
    "build_api_surface_shadow",
    "reverse_javascript_source",
    "shadow_from_crawl_surfaces",
]
