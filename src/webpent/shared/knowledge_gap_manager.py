"""Canonical knowledge-gap manager surface.

WebPent already owns the gap lifecycle in ``research_intelligence``.  This
module exposes the integration-plan name without duplicating ranking,
authorization, or execution policy.
"""

from webpent.shared.research_intelligence import KnowledgeGap, KnowledgeGapEngine

__all__ = ["KnowledgeGap", "KnowledgeGapEngine"]
