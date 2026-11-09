"""Canonical finding-review adapter.

The implementation intentionally lives in :mod:`plan_review` so WebPent has
one deterministic review policy.  This module provides the explicit surface
named by the integration plan without introducing a second reviewer.
"""

from webpent.shared.plan_review import FindingReviewDecision, FindingReviewer

__all__ = ["FindingReviewDecision", "FindingReviewer"]
