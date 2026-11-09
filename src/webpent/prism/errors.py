"""THE PRISM — shared errors (v89).

PRISM-L-1/L-4: a Prism law breach (unscored evidence, unvalidated config,
an adjustment without a reason) raises PrismLawError — never a silent
default.
"""

from __future__ import annotations


class PrismLawError(ValueError):
    """A configuration or action would violate a Prism law."""

    law: str = ""

    def __init__(self, message: str, law: str = "") -> None:
        super().__init__(message)
        self.law = law


__all__ = ["PrismLawError"]
