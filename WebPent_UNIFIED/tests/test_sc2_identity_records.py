"""DEFECT SC-2 locks — report-safe identity_records must reach state.

Discovered by the scenario campaign (2026-09-15): secondary identities
were bootstrapped (and used by the BAC differential tester) but NO node
ever wrote the ``identity_records`` channel — the report could not
attribute findings to principals. auth_node now emits a report-safe
projection (NO cookies/headers/credentials) at every return that carries
``identity_profiles``.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from webpent.agents.authentication.agent import (
    _identity_records_projection,
    auth_node,
)

AGENT_SOURCE = Path(inspect.getsourcefile(auth_node)).read_text(encoding="utf-8")


def _profile(**overrides):
    base = {
        "name": "user_b",
        "role": "secondary",
        "cookies": {"sess": "SECRET-TOKEN"},
        "headers": {"authorization": "Bearer SECRET"},
        "validated": True,
        "metadata": {"auth_source": "playwright_login", "extra": "x"},
        "owned_object_ids": ["182"],
        "credentials": {"username": "user_b", "password": "SECRET"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Projection unit contract
# ---------------------------------------------------------------------------

def test_projection_is_report_safe_and_attribute_per_principal() -> None:
    records = _identity_records_projection({"user_b": _profile()})
    record = records["user_b"]
    assert record["identity_id"] == "user_b"
    assert record["role"] == "secondary"
    assert record["validated"] is True
    assert record["auth_source"] == "playwright_login"
    assert record["owned_object_ids"] == ["182"]
    # Session/credential material must NEVER appear in the projection.
    blob = repr(records)
    for secret in ("SECRET-TOKEN", "Bearer SECRET", "SECRET", "cookies", "headers",
                   "password"):
        assert secret not in blob, f"leaked {secret!r} in identity_records"


def test_projection_handles_empty_and_malformed_profiles() -> None:
    assert _identity_records_projection(None) == {}
    assert _identity_records_projection({}) == {}
    records = _identity_records_projection({"broken": "not-a-dict", "ok": None})
    assert records == {}


# ---------------------------------------------------------------------------
# Wiring contract: every identity_profiles return also emits identity_records
# ---------------------------------------------------------------------------

def test_auth_node_emits_identity_records_alongside_identity_profiles() -> None:
    """AST walk: no return carrying identity_profiles may omit identity_records."""
    tree = ast.parse(AGENT_SOURCE)
    missing: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        keys = [
            k.value for k in node.value.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
        if "identity_profiles" in keys and "identity_records" not in keys:
            missing.append(node.lineno)
    assert not missing, (
        f"auth_node returns identity_profiles without identity_records at "
        f"lines {missing} — principal attribution silently lost"
    )


def test_identity_records_state_channel_exists() -> None:
    from webpent.state.state import PentestState

    assert "identity_records" in PentestState.__annotations__
