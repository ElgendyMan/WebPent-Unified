"""Advisory round-budget allocator (v81, Task 2).

Pure functions turning a target's dead-end density into conservative
recommendations. They can only *reduce* effort and always keep a floor of
one: no recommendation ever exceeds the operator's bounds, and none of
this touches authorization, gates, or request minting.
"""

from __future__ import annotations

REHYPOTHESIZE_BASE = 3
REHYPOTHESIZE_FLOOR = 1


def _clamp01(ratio: float) -> float:
    return max(0.0, min(1.0, float(ratio)))


def recommend_rehypothesize_rounds(
    dead_end_ratio: float, *, base: int = REHYPOTHESIZE_BASE, floor: int = REHYPOTHESIZE_FLOOR
) -> int:
    """Quiet-round rehypothesize budget: full on a fresh target, floor on a
    mapped one. Round-half-up for determinism; always within [floor, base].
    """
    ratio = _clamp01(dead_end_ratio)
    scaled = int(base * (1.0 - ratio) + 0.5)
    return max(floor, min(base, scaled))


def recommend_round_budget(max_iterations: int, dead_end_ratio: float) -> int:
    """Advisory iteration recommendation in [1, max_iterations]: at most a
    halving at full dead-end density, never zero, never a raise.
    """
    iterations = max(1, int(max_iterations))
    ratio = _clamp01(dead_end_ratio)
    scaled = int(iterations * (1.0 - 0.5 * ratio) + 0.5)
    return max(1, min(iterations, scaled))
