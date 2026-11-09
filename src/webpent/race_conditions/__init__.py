"""Race-condition (TOCTOU / concurrency) family — passive analyzers.

Execution (synchronized bursts) lives in the deterministic validator
behind scope policy; this package only emits candidates and evidence
requirements.
"""
from .analyzer import BurstPatternDetector, IdempotencyInvariant
from .scenarios import RACE_SCENARIOS

__all__ = ["BurstPatternDetector", "IdempotencyInvariant", "RACE_SCENARIOS"]
