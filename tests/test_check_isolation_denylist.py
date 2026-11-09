# tests/test_check_isolation_denylist.py
"""Sprint I-1, item 2.2 (+ Continuation 03, item 2.1 completion) -- tests
for scripts/check_isolation_denylist.py (the S-1 static CI gate, M3 v1.0
Section 5.2.1 / v1.1 F-03).

Covers D-01, D-02 (both qualified_required and bare_match), D-03, D-04,
and the A-01 unknown-third-party-import closure check, using the now-
complete config/isolation_denylist.yaml (Sprint I-1 Continuation 03
supplied the genuine M3 v1.0 base document; the file previously stubbed
D-01/D-02/D-03/D-05/A-01/A-02 as pending_v1_0_source).
"""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = ROOT / "scripts" / "check_isolation_denylist.py"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("check_isolation_denylist", GATE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def gate():
    return _load_gate_module()


def _fresh_case(gate_module, filename: str, content: str) -> Path:
    """Isolated scratch tree per case -- NOT reused across calls, since
    find_*_violations() walks the whole gate.SRC tree and a shared
    directory would silently accumulate files from earlier cases in the
    same test (a real bug caught during this sprint's own verification
    -- see the sprint changelog)."""
    tmpdir = Path(tempfile.mkdtemp())
    fake_src = tmpdir / "webpent" / "evil"
    fake_src.mkdir(parents=True)
    (fake_src / filename).write_text(content)
    gate_module.SRC = tmpdir
    return tmpdir


class TestContractLoading:
    def test_contract_loads(self, gate):
        contract = gate.load_contract()
        assert "denylist_groups" in contract
        assert "D-04" in contract["denylist_groups"]

    def test_no_pending_groups_remain(self, gate):
        """Sprint I-1 Continuation 03: the genuine M3 v1.0 document
        arrived and every group is now fully_specified. This test
        replaces the earlier version that pinned the (now-resolved)
        pending_v1_0_source gap -- if this ever regresses, someone
        reverted the contract to stubs without updating this test,
        which should fail loudly."""
        contract = gate.load_contract()
        pending = gate.report_pending_groups(contract)
        assert pending == []

    def test_all_six_groups_present_and_specified(self, gate):
        contract = gate.load_contract()
        for group_id in ("D-01", "D-02", "D-03", "D-04", "D-05"):
            assert contract["denylist_groups"][group_id]["status"] == "fully_specified"
        for group_id in ("A-01", "A-02"):
            assert contract["allowlist_groups"][group_id]["status"] == "fully_specified"


class TestRealTree:
    def test_real_tree_has_no_violations(self, gate):
        contract = gate.load_contract()
        d01 = gate.find_d01_d03_violations(contract, "D-01")
        d02 = gate.find_d02_violations(contract)
        d03 = gate.find_d01_d03_violations(contract, "D-03")
        d04_violations, d04_ok = gate.find_d04_violations(contract)
        a01 = gate.find_a01_closure_violations(contract)
        assert d01 == [], f"D-01 violations: {d01}"
        assert d02 == [], f"D-02 violations: {d02}"
        assert d03 == [], f"D-03 violations: {d03}"
        assert d04_violations == [], f"D-04 violations: {d04_violations}"
        assert a01 == [], f"A-01 closure violations: {a01}"
        # FINAL-CLOSURE RULING R2: 7 -> 8. New verified site added by the I-2
        # M4 module: src/webpent/production/context_authority.py:207,
        # `__import__("json")` (literal, inside mint_decision_token's arguments
        # digest). Legitimate — context_authority.py is the designed M4 module
        # (introduced by sprint_i2.patch). Verified OK by D-04 like the other
        # 7 pinned sites; no denylist violation.
        # FINAL-CLOSURE RULING R3: 8 -> 9. New verified site added by the v88
        # Oracle (U-ORACLE-12): src/webpent/cli/oracle.py:312,
        # `spec_from_file_location('oracle_operator_fetchers', ...)` — a
        # compile-time string literal as first argument, the operator-injected
        # fetcher loader for `webpent oracle gather --fetcher-module`. No
        # network code ships in the package; the module path is supplied by
        # the operator at invocation time. Verified OK by D-04 like the other
        # 8 pinned sites; no denylist violation.
        # MERGE 2026-10-26 RULING: 9 -> 11. The merged tree carries two more
        # D-04-verified-OK dynamic-import sites contributed by the absorbed
        # donorC/track123 lineage (the five-family execution node's literal
        # spec_from_file_location in families/execution_node.py, and the
        # identity-provisioning-era __import__ pair that surfaces at
        # cli/commands.py after the merge). The checker verifies every one of
        # them OK (compile-time literals / internal-list-derived arguments);
        # no denylist violation. Same convention as RULING R2/R3 above.
        # UM-DR-25 RULING: 11 -> 14. The M0-M12 engineering windows
        # contributed three more D-04-verified-OK dynamic-import sites
        # (campaign_worker.py __import__('os') literal,
        # causal_reasoning_v2/integration_layer.py __import__('pathlib')
        # literal, and the causal agent's triple __import__('logging')
        # literals) — every one compile-time-literal / internal-list
        # derived; no denylist violation. Same convention as R2/R3 above.
        assert len(d04_ok) == 14  # pinned canary, see item 2.2's original test

    def test_main_exits_zero_on_real_tree(self, gate, monkeypatch):
        monkeypatch.setattr("sys.argv", ["check_isolation_denylist.py", "--quiet"])
        assert gate.main() == 0


class TestD01SyntheticViolations:
    def test_bare_strix_mention_caught(self, gate):
        _fresh_case(gate, "d01.py", "# integrates with strix somehow\nx = 1\n")
        contract = gate.load_contract()
        v = gate.find_d01_d03_violations(contract, "D-01")
        assert len(v) == 1

    def test_no_mention_not_flagged(self, gate):
        _fresh_case(gate, "d01.py", "# mentions a foreign tool by name here\nx = 1\n")
        contract = gate.load_contract()
        v = gate.find_d01_d03_violations(contract, "D-01")
        assert v == []


class TestD02SyntheticViolations:
    """The critical false-positive guard: WebPent has its own legitimate
    build_sarif_report (reporter/export.py), record_coverage
    (agents/strategist/agent.py), and scope_rules (a dataclass field
    used throughout live_hunter/) -- verified via direct grep before any
    matching logic was written (see sprint changelog). Every "safe" case
    below reproduces one of those real, legitimate usage shapes."""

    def test_bare_match_name_caught_via_import(self, gate):
        _fresh_case(gate, "d02.py", "from somewhere import write_sarif\n")
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert len(v) == 1

    def test_qualified_required_import_from_strix_caught(self, gate):
        _fresh_case(gate, "d02.py", "from strix.report import build_sarif_report\n")
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert len(v) == 1

    def test_qualified_attribute_off_strix_named_object_caught(self, gate):
        _fresh_case(gate, "d02.py", "strix_module.build_sarif_report(1)\n")
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert len(v) == 1

    def test_bare_define_and_call_not_flagged(self, gate):
        """Reproduces WebPent's own real usage shape: a same-named local
        function, called bare (no import, no dotted strix-qualified
        access)."""
        _fresh_case(gate, "d02.py", "def build_sarif_report(x): return x\nreport = build_sarif_report(1)\n")
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert v == []

    def test_dotted_field_access_off_non_strix_object_not_flagged(self, gate):
        """Reproduces WebPent's own real usage shape: self.context.scope_rules."""
        _fresh_case(gate, "d02.py", "class X:\n    def f(self):\n        return self.context.scope_rules\n")
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert v == []

    def test_bare_method_call_not_flagged(self, gate):
        """Reproduces WebPent's own real usage shape: self.record_coverage(...)."""
        _fresh_case(
            gate, "d02.py",
            "class Y:\n    def record_coverage(self, x): pass\n    def g(self):\n        self.record_coverage(1)\n",
        )
        contract = gate.load_contract()
        v = gate.find_d02_violations(contract)
        assert v == []


class TestD03SyntheticViolations:
    def test_destination_string_caught(self, gate):
        _fresh_case(gate, "d03.py", 'path = "findings.sarif"\n')
        contract = gate.load_contract()
        v = gate.find_d01_d03_violations(contract, "D-03")
        assert len(v) == 1


class TestD04SyntheticViolation:
    def test_variable_argument_import_is_flagged(self, gate):
        tmpdir = _fresh_case(
            gate, "evil.py",
            "import importlib\nattacker_controlled = input()\nimportlib.import_module(attacker_controlled)\n",
        )
        contract = gate.load_contract()
        violations, _ = gate.find_d04_violations(contract)
        assert len(violations) == 1
        assert "evil.py" in str(violations[0][0])

    def test_literal_argument_import_is_not_flagged(self, gate):
        _fresh_case(gate, "fine.py", "import importlib\nimportlib.import_module('webpent.tools.recon.nuclei')\n")
        contract = gate.load_contract()
        violations, ok_sites = gate.find_d04_violations(contract)
        assert violations == []
        assert len(ok_sites) == 1

    def test_manual_review_ok_site_suppresses_violation(self, gate, tmp_path):
        fake_src = tmp_path / "src" / "webpent" / "fake_module"
        fake_src.mkdir(parents=True)
        target = fake_src / "reviewed.py"
        target.write_text("import importlib\npath_var = 'webpent.something'\nimportlib.import_module(path_var)\n")
        gate.SRC = tmp_path / "src"
        gate.ROOT = tmp_path
        contract = gate.load_contract()
        contract["denylist_groups"]["D-04"]["manual_review_ok"] = [
            {"path": "src/webpent/fake_module/reviewed.py", "line": 3}
        ]
        violations, ok_sites = gate.find_d04_violations(contract)
        assert violations == []
        assert len(ok_sites) == 1


class TestA01ClosureSyntheticViolations:
    def test_unknown_third_party_import_caught(self, gate):
        _fresh_case(gate, "a01.py", "import some_random_unapproved_package\n")
        contract = gate.load_contract()
        v = gate.find_a01_closure_violations(contract)
        assert len(v) == 1

    def test_allowlisted_import_not_flagged(self, gate):
        _fresh_case(gate, "a01.py", "import fastapi\n")
        contract = gate.load_contract()
        v = gate.find_a01_closure_violations(contract)
        assert v == []

    def test_stdlib_import_not_flagged(self, gate):
        _fresh_case(gate, "a01.py", "import hashlib\n")
        contract = gate.load_contract()
        v = gate.find_a01_closure_violations(contract)
        assert v == []

    def test_webpent_own_import_not_flagged(self, gate):
        _fresh_case(gate, "a01.py", "import webpent.shared.exceptions\n")
        contract = gate.load_contract()
        v = gate.find_a01_closure_violations(contract)
        assert v == []
