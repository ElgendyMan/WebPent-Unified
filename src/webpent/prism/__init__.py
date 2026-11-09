"""THE PRISM (v89): where noise becomes signal, and signal becomes value.

Five layers: evidence taxonomy (U-PRISM-1/2), evidence scorer
(U-PRISM-3/4), campaign ledger + pattern learning (U-PRISM-5..7),
curiosity filters (U-PRISM-8..10) and advisory-only brain integration
(U-PRISM-11..15). Everything here is advisory-only (PRISM-L-2),
deterministic (PRISM-L-9), offline and PII-free.
"""

from __future__ import annotations

from webpent.prism.errors import PrismLawError

PREAMBLE_LINE = (
    "PRISM advisory: ranks, flags and suggests only — "
    "it never blocks or executes a decision (PRISM-L-2)."
)

__all__ = ["PREAMBLE_LINE", "PrismLawError"]
