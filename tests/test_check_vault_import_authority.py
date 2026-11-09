# tests/test_check_vault_import_authority.py
"""Sprint I-1, item 3.1 — tests for scripts/check_vault_import_authority.py
(M4 v2.1 OQ-3 / §3.3.3, Layer 2 static CI gate)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = ROOT / "scripts" / "check_vault_import_authority.py"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("check_vault_import_authority", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate():
    return _load_gate_module()


class TestRealTree:
    def test_real_tree_has_no_violations(self, gate):
        violations = gate.find_violations()
        assert violations == [], f"Unexpected vault import violations: {violations}"

    def test_main_exits_zero_on_real_tree(self, gate, monkeypatch):
        monkeypatch.setattr("sys.argv", ["check_vault_import_authority.py", "--quiet"])
        assert gate.main() == 0

    def test_allowlist_matches_table_2_2_file_count(self, gate):
        """Pins the Table 2-2 file count so a silent addition/removal from
        TABLE_2_2_ALLOWLIST in the gate script doesn't go unnoticed.

        UM-DR-25: 8 -> 9 — the M3 UM-DR-17 q7 identity runner added
        auth/worker_session_factory.py to the allowlist (adjudicated onto
        Table 2-2 after deliberate review in the UM-DR-24 release-gate
        sweep) without updating this pin."""
        assert len(gate.TABLE_2_2_ALLOWLIST) == 9

    def test_all_ten_symbols_watched(self, gate):
        assert len(gate.WATCHED_SYMBOLS) == 10


class TestSyntheticViolations:
    """Proves the gate is a real check — synthetic violations in a scratch
    tree, covering each import form M4 explicitly requires coverage for."""

    def test_direct_import_from_reauth_vault(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "evil"
        fake_src.mkdir(parents=True)
        (fake_src / "bad.py").write_text(
            "from webpent.auth.reauth_vault import unseal_reauth_secret\n"
        )
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert len(violations) == 1
        assert "unseal_reauth_secret" in violations[0][2]

    def test_reexported_symbol_import(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "evil"
        fake_src.mkdir(parents=True)
        (fake_src / "bad.py").write_text("from webpent.auth import seal_reauth_secret\n")
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert len(violations) == 1

    def test_bare_module_import(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "evil"
        fake_src.mkdir(parents=True)
        (fake_src / "bad.py").write_text("import webpent.auth.reauth_vault\n")
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert len(violations) == 1

    def test_aliased_import_still_caught_and_reports_real_name(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "evil"
        fake_src.mkdir(parents=True)
        (fake_src / "bad.py").write_text(
            "from webpent.auth.reauth_vault import seal_reauth_secret as sneaky\n"
        )
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert len(violations) == 1
        assert "seal_reauth_secret" in violations[0][2]

    def test_multiline_import_caught(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "evil"
        fake_src.mkdir(parents=True)
        (fake_src / "bad.py").write_text(
            "from webpent.auth.reauth_vault import (\n"
            "    seal_reauth_secret,\n"
            "    unseal_reauth_secret,\n"
            ")\n"
        )
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert len(violations) == 1

    def test_comment_only_mention_not_flagged(self, gate, tmp_path):
        """Regression for a real false positive found during this sprint's
        implementation: a naive substring check flagged files that only
        mention "reauth_vault" in a comment/docstring
        (state/state.py:551, utils/task_crypto.py:20-21,62 in the real
        tree). AST-based detection must not repeat that mistake."""
        fake_src = tmp_path / "src" / "webpent" / "fine"
        fake_src.mkdir(parents=True)
        (fake_src / "fine.py").write_text(
            "# See webpent.auth.reauth_vault for how passwords are sealed.\n"
            "# from webpent.auth import seal_reauth_secret  (example, not real)\n"
            "x = 1\n"
        )
        gate.ROOT = tmp_path
        violations = gate.find_violations()
        assert violations == []

    def test_allowlisted_file_not_flagged(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "workers"
        fake_src.mkdir(parents=True)
        target = fake_src / "pentest_worker.py"
        target.write_text("from webpent.auth.reauth_vault import unseal_reauth_secret\n")
        gate.ROOT = tmp_path
        gate.TABLE_2_2_ALLOWLIST = frozenset({target})
        # ALLOWLIST is derived once at module-load time from the pieces
        # above — reassign it directly too, since mutating one of its
        # source frozensets after the fact doesn't recompute the union.
        gate.ALLOWLIST = frozenset({target})
        violations = gate.find_violations()
        assert violations == []
