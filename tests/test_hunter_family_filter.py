from __future__ import annotations

import pytest

from webpent.agents.hunter_runner import _normalize_requested_families


def test_family_filter_normalizes_aliases_and_whitespace() -> None:
    assert _normalize_requested_families(" xss, sqli,  BOLA ") == {
        "XSS",
        "SQLI",
        "BOLA",
    }


def test_family_filter_rejects_unregistered_families() -> None:
    with pytest.raises(ValueError, match="unsupported experiment family filter"):
        _normalize_requested_families("XSS,NOT_A_REAL_FAMILY")
