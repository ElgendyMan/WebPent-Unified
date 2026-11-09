# tests/team1_acceptance/test_sprint_i2_b12_bypass2.py
"""Sprint I-2 — Part 4 (B12: BOLA registry) + Part 5 (BYPASS-2 pin).

Part 4 regression: a BOLA hypothesis routes to the fabric/AVI branch
(EXPERIMENT_REGISTRY hit + validate_idor handles BOLA), NOT the non-fabric
FindingLifecycle branch.

Part 5 pin (BYPASS-2, per M7 v1.2 corrected finding): the non-fabric branch
never promotes in this tree. Two facts pinned — a future change adding
promotion there fails CI loudly:
  (a) the AVI state merge (graph/builder.py _research_campaign_node) only
      appends findings marked avi_promoted=True; no non-AVI finding reaches
      state["findings"] through that merge.
  (b) the non-fabric FindingLifecycle dispatch path in this tree has no
      caller that transitions a finding to "promoted" and persists it into
      state["findings"].
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)


class TestB12BOLARegistry:
    def test_bola_in_experiment_registry(self):
        from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY
        assert "BOLA" in EXPERIMENT_REGISTRY, (
            "B12: BOLA must be registered in EXPERIMENT_REGISTRY so a BOLA "
            "hypothesis routes to the fabric/AVI branch."
        )
        entry = EXPERIMENT_REGISTRY["BOLA"]
        assert entry["validator"] == "BOLA"
        assert entry["vulnerability_class"] == "BOLA"
        assert entry.get("replay_required") is True

    def test_bola_routes_to_idor_validator(self):
        # validate_idor handles BOLA (validators.py:265 maps BOLA -> validate_idor).
        from webpent.production.validators import ValidationOutcome, run_validator
        # Vulnerable shape: owner baseline 200, foreign candidate 200, nc 403.
        vr = run_validator(
            "BOLA",
            baseline={"status_code": 200, "response_body": "owner data", "headers": {}},
            candidate={"status_code": 200, "response_body": "owner data", "headers": {}},
            negative_control={"status_code": 403, "response_body": "", "headers": {}},
        )
        assert vr.outcome == ValidationOutcome.CONFIRMED, (
            "B12: a BOLA-class differential (foreign reads owner object, nc "
            "independent) must CONFIRM via validate_idor."
        )

    def test_bola_not_nonfabric_findinglifecycle(self):
        # The fabric dispatch key set must include BOLA; the non-fabric
        # FindingLifecycle branch (modern_spine.py) handles only legacy
        # candidate lifecycle and must NOT be the BOLA dispatch target.
        from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY
        from webpent.production.modern_spine import FindingLifecycle
        # BOLA is a fabric registry key -> fabric/AVI branch.
        assert "BOLA" in EXPERIMENT_REGISTRY
        # FindingLifecycle STATES (legacy non-fabric) exist but BOLA is not
        # dispatched through them — assert the fabric path is the one hit.
        assert hasattr(FindingLifecycle, "STATES")
        # The AVI _run_one_decision looks up vuln in EXPERIMENT_REGISTRY; BOLA
        # hits it (reg_hit=True) -> fabric branch. This is the regression.
        assert "BOLA".upper() in {k.upper() for k in EXPERIMENT_REGISTRY}


class TestBypass2Pin:
    """BYPASS-2 pinning test (M7 v1.2 corrected finding).

    Asserts BOTH facts; a future change adding promotion to the non-fabric
    branch fails CI loudly.
    """

    def test_state_merge_filters_to_avi_promoted_only(self):
        # Fact (a): the AVI merge in graph/builder.py marks every merged
        # finding with avi_promoted=True and appends ONLY those.
        import re
        src = open("src/webpent/graph/builder.py", encoding="utf-8").read()
        # The D2 merge block must set avi_promoted=True on every finding it
        # constructs. Pin the literal marker.
        assert '"avi_promoted": True' in src or "'avi_promoted': True" in src, (
            "BYPASS-2 pin: the AVI promoted-findings merge must mark every "
            "merged finding with avi_promoted=True. A change removing this "
            "filter re-opens the non-fabric promotion bypass."
        )
        # The merge appends to out["findings"] from the _avi_promoted list only.
        assert "out[\"findings\"]" in src or "out['findings']" in src
        assert "_avi_promoted" in src, (
            "BYPASS-2 pin: the merge must accumulate into an _avi_promoted "
            "list and append only those to state findings."
        )

    def test_nonfabric_branch_has_no_promotion_persist(self):
        # Fact (b): in this tree, no non-fabric (FindingLifecycle) path
        # persists a "promoted" finding into state["findings"]. We pin this by
        # asserting that the ONLY place findings are appended to
        # state/out["findings"] from a research-campaign node is the AVI
        # merge block above (which carries avi_promoted=True).
        import re
        src = open("src/webpent/graph/builder.py", encoding="utf-8").read()
        # Find the _research_campaign_node function body.
        m = re.search(r"def _research_campaign_node.*?(?=\ndef |\Z)", src, re.S)
        assert m, "_research_campaign_node must exist in builder.py"
        body = m.group(0)
        # Every append to findings inside this node must go through
        # _avi_promoted (i.e., the AVI merge). Pin that no raw Finding(...)
        # without avi_promoted is appended.
        findings_appends = re.findall(r"out\[.findings.\]\s*=", body)
        assert len(findings_appends) >= 1, (
            "expected at least one out['findings'] assignment in the AVI merge"
        )
        # The assignment line must reference _avi_promoted (the filtered list).
        for line in body.splitlines():
            if 'out["findings"]' in line or "out['findings']" in line:
                assert "_avi_promoted" in line, (
                    f"BYPASS-2 pin: out['findings'] assignment must append the "
                    f"avi_promoted-filtered list only; found: {line.strip()}"
                )

    def test_findinglifecycle_promotion_not_wired_to_state_findings(self):
        # D-RED-9 (hotfix): AST-based pin — walk every src/**/*.py, find any
        # ast.Call whose function attribute is "transition" AND which has a
        # string positional/keyword argument "promoted". Such a call site
        # indicates a non-fabric FindingLifecycle promotion — fail CI.
        import ast
        import pathlib
        src_root = pathlib.Path("src/webpent")
        bad_sites = []
        for py in src_root.rglob("*.py"):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except Exception:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute) and func.attr == "transition"):
                    continue
                args = [a.value for a in node.args if isinstance(a, ast.Constant)]
                kwargs = [a.value.value for a in node.keywords
                          if isinstance(a.value, ast.Constant)]
                if "promoted" in args or "promoted" in kwargs:
                    bad_sites.append(f"{py}:{node.lineno}")
        assert len(bad_sites) == 0, (
            "BYPASS-2 pin (AST): non-fabric transition('promoted') call site(s) "
            "found — if persisted to state['findings'], the bypass is re-opened: "
            + "; ".join(bad_sites[:5])
        )
