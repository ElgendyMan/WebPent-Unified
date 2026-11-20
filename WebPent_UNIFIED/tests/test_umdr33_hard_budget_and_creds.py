"""UM-DR-33 Phase 2 (Workstream C) — external-budget and config-safety
regressions.

Pins two frozen-window fixes:

1. ``graph/budget_governor.py`` — a ``node_step_trace`` key that is
   PRESENT but not a list/tuple is agent-side corruption (no legit write
   path persists a non-list; the channel is append-only and the builder
   materialises ``[entry]`` whenever the previous value is not a list).
   Corruption must never RESET consumed budget: the governor now fails
   closed with the budget fully consumed
   (``reason="fail_closed_corrupted_trace"``). A genuinely ABSENT key
   keeps the documented legacy-checkpoint deactivation.

2. ``cli/loaders.py`` — secret values that are template placeholders
   (CHANGE-ME family, REPLACE_ME_*, replace-at-runtime, and the obvious
   exact markers) are rejected fail-closed at load time, so a copied
   credentials_template.json that was never filled in can never look
   production-ready (§5.5).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.cli.loaders import load_creds_file  # noqa: E402
from webpent.graph.budget_governor import budget_pressure  # noqa: E402


def _state(**overrides):
    base = {
        "enable_step_budget": True,
        "max_graph_steps": 40,
        "node_step_trace": [{"node": "recon"}, {"node": "crawler"}],
    }
    base.update(overrides)
    return base


class TestCorruptedTraceFailsClosed:
    def test_corrupted_trace_string_consumes_entire_budget(self) -> None:
        result = budget_pressure(_state(node_step_trace="corrupted"))
        assert result["reason"] == "fail_closed_corrupted_trace"
        assert result["active"] is True
        assert result["consumed"] == result["max_steps"]
        assert result["remaining"] == 0
        assert result["research_active"] is False

    def test_corrupted_trace_int_fails_closed(self) -> None:
        result = budget_pressure(_state(node_step_trace=99999))
        assert result["reason"] == "fail_closed_corrupted_trace"
        assert result["remaining"] == 0

    def test_corrupted_trace_none_when_key_present_fails_closed(self) -> None:
        result = budget_pressure(_state(node_step_trace=None))
        assert result["reason"] == "fail_closed_corrupted_trace"

    def test_absent_key_keeps_legacy_deactivation(self) -> None:
        state = _state()
        del state["node_step_trace"]
        result = budget_pressure(state)
        assert result["reason"] == "inactive_no_trace"
        assert result["active"] is False

    def test_healthy_trace_behaves_unchanged(self) -> None:
        result = budget_pressure(_state())
        assert result["reason"] not in (
            "fail_closed_corrupted_trace", "inactive_no_trace",
        )
        assert result["consumed"] == 2

    @pytest.mark.parametrize("junk", [["ok"], (), []])
    def test_valid_shapes_do_not_fail_closed(self, junk) -> None:
        result = budget_pressure(_state(node_step_trace=junk))
        assert result["reason"] != "fail_closed_corrupted_trace"


class TestPlaceholderCredentialRejection:
    def _write(self, tmp_path: Path, payload: dict) -> Path:
        path = tmp_path / "creds.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_replace_me_password_is_rejected(self, tmp_path) -> None:
        path = self._write(tmp_path, {
            "owner": {
                "role": "owner", "auth_type": "form_session",
                "username": "owner@example.test",
                "password": "REPLACE_ME_OWNER_PASSWORD",
            }
        })
        with pytest.raises(ValueError, match="placeholder"):
            load_creds_file(path)

    @pytest.mark.parametrize("bad", [
        "change-me", "ChangeMe", "CHANGEME", "replace-me-anything",
        "replace-at-runtime", "password", "placeholder", "todo",
    ])
    def test_placeholder_family_rejected(self, tmp_path, bad) -> None:
        path = self._write(tmp_path, {
            "owner": {"username": "u@example.test", "password": bad}
        })
        with pytest.raises(ValueError, match="placeholder"):
            load_creds_file(path)

    def test_real_credentials_still_load(self, tmp_path) -> None:
        path = self._write(tmp_path, {
            "owner": {
                "role": "owner", "auth_type": "form_session",
                "username": "owner@example.test",
                "password": "a-real-runtime-secret-123",
            }
        })
        profiles = load_creds_file(path)
        assert profiles["owner"]["password"] == "a-real-runtime-secret-123"

    def test_nested_credentials_mapping_is_covered(self, tmp_path) -> None:
        path = self._write(tmp_path, {
            "owner": {
                "credentials": {"username": "u", "password": "changeme"},
            }
        })
        with pytest.raises(ValueError, match="placeholder"):
            load_creds_file(path)

    def test_shipped_template_is_rejected_with_named_field(self) -> None:
        with pytest.raises(ValueError) as excinfo:
            load_creds_file(ROOT / "credentials_template.json")
        assert "password" in str(excinfo.value)
        assert "placeholder" in str(excinfo.value)
