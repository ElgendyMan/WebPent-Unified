# tests/test_tc4_condition_closure.py
"""TC-4 (Dispatch #043) — the V15-V condition-closure pins.

One test per condition contract, so the hygiene the verifier demanded can
never silently regress again (the same discipline as the frozen gate):

  C1(a) curiosity.py — the U-1/GAP-5 narrowed excepts: NO bare
        ``except:`` handler survives in the module (AST-pinned), the
        justification comments are present, and the fallback behavior
        (non-JSON bodies take the heuristic path, not raise) holds.
  C1(c) Makefile test-count — the recipe calls verify_test_count.py's
        REAL interface and carries NO hand-typed ``--minimum`` literal
        (Sprint I-1b item 1.2's anti-pattern, re-allowed by regression).
  C4   runner neg-leg — the patched-lane refutation leg is NATIVE: a
        PROVEN proposal is by design not rebuildable (pinned), the neg
        lane builds its OWN proposal from the PATCHED lane's own
        observation (spinning the patched lane and reading its registry
        through the owner/admin surface), and the runner source carries
        that construction (source-pinned).
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

cc = importlib.import_module("webpent.production.chain_composer")
curiosity = importlib.import_module("webpent.brain.curiosity")

CURIOSITY_SRC = (
    ROOT / "src" / "webpent" / "brain" / "curiosity.py").read_text()
MAKEFILE_SRC = (ROOT / "Makefile").read_text()
RUNNER_SRC = (
    ROOT / "scripts" / "run_v1_chain_composer.py").read_text()

REGISTRY_BODY = {
    "service": "doc-registry",
    "config_path": "/app/internal/registry.json",
    "credential_ref": "secret:internal-registry-ro",
    "registry": {
        "User_A": {"email": "user-a@lab.internal",
                   "document_ids": ["DOC-A-11"]},
        "User_B": {"email": "user-b@lab.internal",
                   "document_ids": ["DOC-B-PUB", "DOC-B-7f3a91c"]},
    },
}


def _disclosure_finding() -> cc.ChainFinding:
    return cc.ChainFinding(
        finding_id="tc4_f_disc", family="INFO_DISCLOSURE",
        path="/api/admin/debug", engagement_id="tc4_e1", promoted_at="t",
        evidence_ref="p1", observed=REGISTRY_BODY, resource_owner="")


def _idor_finding() -> cc.ChainFinding:
    return cc.ChainFinding(
        finding_id="tc4_f_idor", family="IDOR",
        path="/api/documents/{doc_id}", engagement_id="tc4_e2",
        promoted_at="t", evidence_ref="p2", observed={},
        resource_owner="User_B", covered_object_ids=["DOC-B-PUB"])


def _record_proven(composer: cc.ChainComposer, proposal) -> None:
    """Drive a proposal to PROVEN through the same gates the runner uses
    (digest match + the semantic owner/viewer gate)."""
    hyp = composer.build_chain_hypothesis(
        proposal.chain_id, engagement_id="tc4_chain",
        step1_observed=REGISTRY_BODY)
    assert hyp is not None
    used = hyp["requests"]["candidate"]["path"].rsplit("/", 1)[-1]
    record = composer.record_execution(
        proposal.chain_id, step1_promoted=True,
        step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED",
        step2_used_value=used,
        step2_response_body={"owner": "User_B", "viewer": "User_A"},
        proof_ref="p_tc4")
    assert record.status == "PROVEN"


# ---------------------------------------------------------------------------
# C1(a) — curiosity.py narrowed excepts
# ---------------------------------------------------------------------------
class TestC1aCuriosityNarrowedExcepts:
    def test_no_bare_except_handler_in_module(self):
        """AST pin: every ExceptHandler in curiosity.py names exception
        types — a bare ``except:`` (type=None) must not survive the
        lineage again."""
        tree = ast.parse(CURIOSITY_SRC)
        bare = [n.lineno for n in ast.walk(tree)
                if isinstance(n, ast.ExceptHandler) and n.type is None]
        assert bare == [], f"bare except: handlers at lines {bare}"

    def test_u1_gap5_justification_markers_present(self):
        """The narrowed handlers carry their justification comments — the
        undocumented-regression pattern is what this program polices."""
        assert CURIOSITY_SRC.count("U-1/GAP-5 (restored TC-4 C1a)") >= 3
        assert "KeyboardInterrupt" in CURIOSITY_SRC
        assert "yaml.YAMLError" in CURIOSITY_SRC

    def test_config_defaults_ssot_feeds_the_frozensets(self):
        """The hoisted fallback SSOT is what the module-level sets read —
        the fallback contract is unchanged from the pre-regression form."""
        assert "odd_params" in curiosity._CONFIG_DEFAULTS
        assert "shape_divergence_exclusions" in curiosity._CONFIG_DEFAULTS
        assert curiosity.ODD_PARAMS_SET >= {"debug", "admin", "token"}
        assert curiosity.SHAPE_EXCLUSIONS >= {"token", "csrf"}

    def test_non_json_body_takes_heuristic_path_not_raise(self):
        """A non-JSON body must fall through to the heuristic path — the
        expected case the narrowed (TypeError, ValueError) handlers are
        justified for.  (The heuristic leg's own len() contract on a None
        payload is outside this module's caller contract and is NOT pinned
        here — the narrowing changes nothing about it.)"""
        big = "x" * 500
        sigs = curiosity.extract_data_behind_4xx(404, big)
        assert sigs, "large non-JSON body must yield the heuristic signal"
        assert sigs[0].type == "data_behind_4xx"
        assert curiosity._extract_json_fields("<html/>") == set()
        assert curiosity._extract_json_fields(None) == set()


# ---------------------------------------------------------------------------
# C1(c) — Makefile test-count real interface
# ---------------------------------------------------------------------------
class TestC1cMakefileTestCount:
    def test_no_hand_typed_minimum_literal(self):
        """Sprint I-1b item 1.2's anti-pattern must not survive in the
        recipe: no `--minimum <n>` hand-typed literal."""
        for line in MAKEFILE_SRC.splitlines():
            if line.strip().startswith("@PYTHONPATH=src"):
                assert "--minimum" not in line, line

    def test_recipe_calls_the_scripts_real_interface(self):
        """The recipe invokes verify_test_count.py (whose real interface
        is --tests/--floor-file/--update; the floor lives in the checked-in
        JSON SSOT)."""
        recipe = [ln for ln in MAKEFILE_SRC.splitlines()
                  if "verify_test_count.py" in ln and ln.startswith("\t")]
        assert recipe, "test-count recipe must invoke verify_test_count.py"
        assert any("scripts/verify_test_count.py" in ln for ln in recipe)

    def test_floor_file_is_the_ssot_and_green(self):
        """The floor SSOT exists, is well-formed, and the script accepts
        its own real interface (smoke: --help exits 0)."""
        floor = ROOT / "scripts" / "test_count_floor.json"
        payload = __import__("json").loads(floor.read_text())
        assert isinstance(payload.get("minimum"), int)
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_test_count.py"),
             "--help"], capture_output=True, text=True)
        assert proc.returncode == 0
        assert "--floor-file" in proc.stdout and "--update" in proc.stdout


# ---------------------------------------------------------------------------
# C4 — the runner's native neg-leg
# ---------------------------------------------------------------------------
class TestC4RunnerNegLeg:
    def test_proven_proposal_is_not_rebuildable(self):
        """THE TRAP the runner fell into — pinned as designed behavior:
        once a proposal is PROVEN, build_chain_hypothesis returns None
        (a proven chain is never re-executed).  The runner must therefore
        never ask the proven composer to rebuild for a neg leg."""
        composer = cc.ChainComposer()
        composer.ingest(_disclosure_finding())
        (proposal,) = composer.ingest(_idor_finding())
        _record_proven(composer, proposal)
        assert composer.build_chain_hypothesis(
            proposal.chain_id, engagement_id="tc4_chain_neg",
            step1_observed=REGISTRY_BODY) is None
        # and the proven surface still carries exactly the one chain
        assert len(composer.proven_chains()) == 1

    def test_neg_lane_builds_own_proposal_from_patched_lane_observation(self):
        """The dispatch's fix, exercised against the REAL patched lane:
        the patched lane's own registry observation (owner/admin surface)
        grounds a FRESH composer's own still-PROPOSED proposal; the built
        hypothesis selects the non-enumerable object and the acting
        principal is refused on the patched lane (the patch under test)."""
        from tests.lab.chain_lab_target import start_chain_lab_server

        server, url = start_chain_lab_server(vulnerable=False)
        try:
            # the patch under test: the acting principal is refused...
            refused = httpx.get(f"{url}/api/admin/debug",
                                headers={"X-User": "User_A"}, timeout=10)
            assert refused.status_code == 403
            # ...while the patched lane's own observation comes from ITS
            # owner/admin surface (the same registry, honestly served).
            resp = httpx.get(f"{url}/api/admin/debug",
                             headers={"X-User": "User_B"}, timeout=10)
            assert resp.status_code == 200
            patched_observed = resp.json()
            assert patched_observed["registry"]["User_B"]["document_ids"] \
                == ["DOC-B-PUB", "DOC-B-7f3a91c"]

            neg_composer = cc.ChainComposer()
            neg_composer.ingest(_disclosure_finding())
            (neg_proposal,) = neg_composer.ingest(_idor_finding())
            assert neg_proposal.status == "PROPOSED"
            neg_hyp = neg_composer.build_chain_hypothesis(
                neg_proposal.chain_id, engagement_id="tc4_chain_neg",
                step1_observed=patched_observed)
            assert neg_hyp is not None, \
                "the neg lane's own proposal must be buildable"
            cand = neg_hyp["requests"]["candidate"]
            assert cand["path"] == "/api/documents/DOC-B-7f3a91c"
            assert cand["headers"]["X-User"] == "User_A"
            # and on the patched lane the chain step's read is refused —
            # the honest refutation the runner now executes natively.
            step2 = httpx.get(f"{url}{cand['path']}",
                              headers={"X-User": "User_A"}, timeout=10)
            assert step2.status_code == 403
        finally:
            server.should_exit = True

    def test_runner_source_pins_the_native_construction(self):
        """Source pin on the runner: the neg leg uses a FRESH composer and
        the PATCHED lane's own observation — it never re-asks the proven
        composer to rebuild, and it records the refutation."""
        assert "neg_composer = ChainComposer()" in RUNNER_SRC
        assert '"/api/admin/debug"' in RUNNER_SRC
        assert 'engagement_id="v1_materialize_neg"' in RUNNER_SRC
        assert "step1_observed=neg_observed" in RUNNER_SRC
        assert "refutation_ran_natively" in RUNNER_SRC
        # the defective form is gone: no rebuild against the proven composer
        assert "neg_hyp = composer.build_chain_hypothesis(" not in RUNNER_SRC
