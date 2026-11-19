"""M1-B (E-2) prioritization guard tests (2026-11-05).

M0 finding E-2: IDOR was listed in ``_DETERMINISTIC_STRUCTURAL_CLASSES``
while ``_deterministic_promotion_allowed`` excluded it via an early
``return False`` — i.e. the exclusion lived in STATEMENT ORDER, not in
data. A silent reorder would have made IDOR deterministically promotable
from a path-match alone (no owner-vs-foreign differential), the exact
false-positive class the project's evidence pipeline exists to reject.

M1-B removes the dead entry; these tests pin the contract structurally so
the protection survives refactors:
  * IDOR is NOT in the set (data-level exclusion);
  * ``_deterministic_promotion_allowed("idor", deterministic_match=True)``
    is False regardless of how the function's internals are ordered;
  * the IDOR early-return guard still exists in source (belt and braces);
  * a legit structural class still passes (no over-rotation).
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.shared.prioritization import (  # noqa: E402
    _DETERMINISTIC_STRUCTURAL_CLASSES,
    _deterministic_promotion_allowed,
)


class TestIDORNeverDeterministicallyPromotable:
    def test_idor_not_in_structural_classes(self):
        from webpent.models.findings import VulnClass

        assert VulnClass.IDOR.value not in _DETERMINISTIC_STRUCTURAL_CLASSES

    def test_idor_promotion_denied_with_deterministic_match(self):
        """The decisive guard: even with deterministic_match=True, IDOR
        must never be deterministically promotable."""
        from webpent.models.findings import VulnClass

        assert (
            _deterministic_promotion_allowed(
                VulnClass.IDOR.value, deterministic_match=True
            )
            is False
        )

    def test_idor_early_return_guard_exists_in_source(self):
        """Belt and braces: the explicit early-return remains in the
        function body (defense in depth against set-level regressions)."""
        source = inspect.getsource(_deterministic_promotion_allowed)
        assert "IDOR" in source
        assert "return False" in source

    def test_legit_structural_class_still_allowed(self):
        """No over-rotation: a class with a real deterministic validator
        (e.g. CSP structural check) still bypasses with a match."""
        from webpent.models.findings import VulnClass

        assert (
            _deterministic_promotion_allowed(
                VulnClass.CSP.value, deterministic_match=True
            )
            is True
        )

    def test_unknown_class_fails_closed_without_match(self):
        assert _deterministic_promotion_allowed("quantum_injection") is False
