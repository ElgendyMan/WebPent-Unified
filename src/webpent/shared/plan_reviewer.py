"""Canonical plan-review adapter.

The policy implementation remains in :mod:`plan_review`; this named module is
only an explicit integration-plan surface and never authorizes execution.
"""

from webpent.shared.plan_review import PlanReviewDecision, PlanReviewer

__all__ = ["PlanReviewDecision", "PlanReviewer"]
