# tests/test_blind_v3_replica.py
"""blind_v3 replica + stateful prober — the UM-DR-25 discipline tests.

What these tests pin (the honesty contract of the M10-unblock track):
  1. SPEC FIDELITY — the replica's compiled tables match the committed
     ground truth exactly (per-family vulnerable sets and counts).
  2. NO LEAKAGE — the server's responses and source carry none of the
     ground-truth vocabulary (mechanism names, labels, family words);
     neither the server nor the prober reads ground truth at runtime.
  3. BEHAVIOR GRAMMAR — simple vulns observable on plain GET; safe
     candidates deny; reasoning vulns clean pre-transition and
     differential post-transition; compositional vulns need BOTH
     transitions; controls always deny.
  4. PROBER DISCIPLINE — guarded_causal_evaluate remains the only
     confirmation authority; the per-case budget is bounded and
     enforced; verdicts are deterministic; the read-only phase alone
     cannot confirm transition cases.
"""
from __future__ import annotations

import importlib.util
import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.cqa_v2 import guarded_causal_evaluate  # noqa: E402
from webpent.production.stateful_probe import (  # noqa: E402
    MAX_REQUESTS_PER_CASE,
    StatefulCaseProber,
    make_observation,
)

REPLICA_DIR = ROOT / "benchmarks" / "blind_v3_replica"
MANIFEST = ROOT / "benchmarks" / "blind_v3" / "manifest.json"
GROUND_TRUTH = ROOT / "benchmarks" / "blind_v3" / "ground_truth.json"
PORT = 9221


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replica = _load_module("replica_target", REPLICA_DIR / "replica_target.py")
gt = json.loads(GROUND_TRUTH.read_text())
manifest_cases = {c["case_id"]: c for c in json.loads(MANIFEST.read_text())["cases"]}


# ---------------------------------------------------------------------------
# 1. Spec fidelity
# ---------------------------------------------------------------------------
def _family_case_numbers(label: str, family: str) -> set[int]:
    return {
        int(manifest_cases[cid]["candidate"].rsplit("_", 1)[-1])
        for cid, g in gt.items()
        if g["case_family"] == family and g["expected_label"] == label
    }


@pytest.mark.parametrize("family,table", [
    ("simple", replica.SIMPLE_VULN),
    ("reasoning", replica.REASONING_VULN),
    ("compositional", replica.COMPOSITIONAL_VULN),
])
def test_spec_tables_match_ground_truth(family, table):
    assert table == _family_case_numbers("vulnerable", family)
    remaining = _family_case_numbers("safe", family)
    all_numbers = _family_case_numbers("vulnerable", family) | remaining
    assert len(table) + len(remaining) == len(all_numbers) == 40


def test_corpus_shape_matches_recorded_baseline():
    """73 vulnerable / 47 safe / 120 total — the recorded blind_v3 shape."""
    vuln = sum(1 for g in gt.values() if g["expected_label"] == "vulnerable")
    assert (vuln, len(gt) - vuln, len(gt)) == (73, 47, 120)


# ---------------------------------------------------------------------------
# 2. No leakage
# ---------------------------------------------------------------------------
def test_replica_source_carries_no_truth_vocabulary():
    source = (REPLICA_DIR / "replica_target.py").read_text(encoding="utf-8")
    # Mechanism names and ground-truth metadata keys must never appear
    # anywhere in the serving logic (comments included, so a lazy edit
    # cannot smuggle them into a response).
    for word in ("ownership_bypass", "state_transition_violation",
                 "delayed_effect", "workflow_invariant",
                 "representation_equivalence", "business_logic_constraint",
                 "cross_resource_auth", "direct_auth_mismatch",
                 "expected_label", "case_family", "difficulty"):
        assert word not in source, f"truth vocabulary leaked into source: {word}"


def test_runtime_observables_carry_no_truth_vocabulary(server):
    """The live no-leakage property: every response body + header value
    over a sample of routes stays free of the ground-truth vocabulary."""
    forbidden = ("vulnerable", "safe", "ownership_bypass", "reasoning",
                 "compositional", "simple", "expected_label", "mechanism")
    paths = [
        f"/bv3/simp/{route}_{n}" for n in (1, 3) for route in ("own", "target", "ctrl")
    ] + [
        f"/bv3/rsng/{route}_{n}" for n in (41, 42) for route in ("own", "target", "ctrl")
    ] + ["/bv3/comp/state_82", "/bv3/comp/flag_82"]
    with _client(server) as c:
        for path in paths:
            r = c.get(path, headers={"X-Actor": "attacker"})
            blob = r.text.lower() + " ".join(
                f"{k}:{v}" for k, v in r.headers.items()).lower()
            for word in forbidden:
                assert word not in blob, f"{word} leaked from {path}"


def test_prober_module_never_reads_ground_truth():
    source = (ROOT / "src" / "webpent" / "production" / "stateful_probe.py").read_text(
        encoding="utf-8")
    for word in ("ground_truth", "expected_label", "blind_v3/"):
        assert word not in source, f"prober references truth material: {word}"


# ---------------------------------------------------------------------------
# 3+4. Live behavior + prober discipline (one shared server per test)
# ---------------------------------------------------------------------------
@pytest.fixture()
def server():
    proc = subprocess.Popen(
        [sys.executable, str(REPLICA_DIR / "replica_target.py")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    for _ in range(60):
        try:
            httpx.get(f"http://127.0.0.1:{PORT}/", timeout=0.2)
            break
        except Exception:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{PORT}"
    try:
        os_kill = getattr(__import__("os"), "killpg")
        os_kill(__import__("os").getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def _client(base):
    return httpx.Client(timeout=5, base_url=base)


def _simple_case(n: int, vuln: bool):
    return {
        "case_id": f"simp_{n}",
        "baseline": f"/bv3/simp/own_{n}",
        "candidate": f"/bv3/simp/target_{n}",
        "control": f"/bv3/simp/ctrl_{n}",
        "requires_state_transition": False,
        "_vuln": vuln,
    }


class TestBehaviorGrammar:
    def test_simple_vulnerable_observable_on_plain_get(self, server):
        with _client(server) as c:
            rc = c.get("/bv3/simp/target_1", headers={"X-Actor": "attacker"})
            assert rc.status_code == 200
            assert rc.headers["x-authorization-outcome"] == "granted_full"
            assert rc.headers["x-resource-owner"] != "attacker"

    def test_simple_safe_denies(self, server):
        with _client(server) as c:
            # 3 is not in SIMPLE_VULN -> safe
            rc = c.get("/bv3/simp/target_3", headers={"X-Actor": "attacker"})
            assert rc.status_code == 403
            assert rc.headers["x-authorization-outcome"] == "denied"

    def test_control_always_denies(self, server):
        with _client(server) as c:
            for path in ("/bv3/simp/ctrl_1", "/bv3/rsng/ctrl_41",
                         "/bv3/comp/ctrl_81"):
                r = c.get(path, headers={"X-Actor": "attacker"})
                assert r.status_code == 403, path
                assert r.headers["x-authorization-outcome"] == "denied"

    def test_reasoning_clean_pre_transition_differential_after(self, server):
        with _client(server) as c:
            pre = c.get("/bv3/rsng/target_41", headers={"X-Actor": "attacker"})
            assert pre.headers["x-resource-owner"] == "attacker"  # looks clean
            c.post("/bv3/rsng/state_41", headers={"X-Actor": "attacker"})
            post = c.get("/bv3/rsng/target_41", headers={"X-Actor": "attacker"})
            assert post.status_code == 200
            assert post.headers["x-resource-owner"] != "attacker"

    def test_reasoning_safe_stays_denied_after_transition(self, server):
        with _client(server) as c:
            # 42 not in REASONING_VULN -> safe
            c.post("/bv3/rsng/state_42", headers={"X-Actor": "attacker"})
            r = c.get("/bv3/rsng/target_42", headers={"X-Actor": "attacker"})
            assert r.status_code == 403

    def test_compositional_needs_both_transitions(self, server):
        with _client(server) as c:
            # 82 is in COMPOSITIONAL_VULN
            c.post("/bv3/comp/state_82", headers={"X-Actor": "attacker"})
            one = c.get("/bv3/comp/target_82", headers={"X-Actor": "attacker"})
            assert one.headers["x-resource-owner"] == "attacker"  # still clean
            c.post("/bv3/comp/flag_82", headers={"X-Actor": "attacker"})
            both = c.get("/bv3/comp/target_82", headers={"X-Actor": "attacker"})
            assert both.status_code == 200
            assert both.headers["x-resource-owner"] != "attacker"


class TestProberDiscipline:
    def test_read_only_phase_cannot_confirm_transition_case(self, server):
        """The methodology ceiling, pinned: 3 GETs on a transition case
        never confirms (INCONCLUSIVE at best)."""
        case = {
            "case_id": "bv3_041",
            "baseline": "/bv3/rsng/own_41",
            "candidate": "/bv3/rsng/target_41",
            "control": "/bv3/rsng/ctrl_41",
            "requires_state_transition": True,
        }
        with _client(server) as c:
            prober = StatefulCaseProber(c, base_url=server)
            out = prober.probe({**case, "requires_state_transition": False})
            assert out.verdict != "CONFIRMED"
            assert out.phase == 1
            assert out.requests_issued == 3

    def test_stateful_prober_confirms_reasoning_case(self, server):
        case = {
            "case_id": "bv3_041",
            "baseline": "/bv3/rsng/own_41",
            "candidate": "/bv3/rsng/target_41",
            "control": "/bv3/rsng/ctrl_41",
            "requires_state_transition": True,
        }
        with _client(server) as c:
            prober = StatefulCaseProber(c, base_url=server)
            out = prober.probe(case)
        assert out.verdict == "CONFIRMED"
        assert out.phase == 2
        assert out.requests_issued <= MAX_REQUESTS_PER_CASE
        assert any("state" in t for t in out.transitions_applied)

    def test_stateful_prober_confirms_compositional_case(self, server):
        case = {
            "case_id": "bv3_comp",
            "baseline": "/bv3/comp/own_82",
            "candidate": "/bv3/comp/target_82",
            "control": "/bv3/comp/ctrl_82",
            "requires_state_transition": True,
        }
        with _client(server) as c:
            prober = StatefulCaseProber(c, base_url=server)
            out = prober.probe(case)
        assert out.verdict == "CONFIRMED"
        assert out.phase == 2
        assert len(out.transitions_applied) >= 2  # the composition

    def test_stateful_prober_refuses_safe_case(self, server):
        case = {
            "case_id": "bv3_safe",
            "baseline": "/bv3/rsng/own_42",
            "candidate": "/bv3/rsng/target_42",
            "control": "/bv3/rsng/ctrl_42",
            "requires_state_transition": True,
        }
        with _client(server) as c:
            prober = StatefulCaseProber(c, base_url=server)
            out = prober.probe(case)
        assert out.verdict != "CONFIRMED"

    def test_budget_is_bounded_and_enforced(self, server):
        case = {
            "case_id": "bv3_budget",
            "baseline": "/bv3/comp/own_99",   # safe comp case
            "candidate": "/bv3/comp/target_99",
            "control": "/bv3/comp/ctrl_99",
            "requires_state_transition": True,
        }
        with _client(server) as c:
            prober = StatefulCaseProber(c, base_url=server, max_requests=10)
            out = prober.probe(case)
        assert out.requests_issued <= 10
        assert out.verdict != "CONFIRMED"

    def test_deterministic_verdicts(self, server):
        case = {
            "case_id": "bv3_det",
            "baseline": "/bv3/rsng/own_43",
            "candidate": "/bv3/rsng/target_43",
            "control": "/bv3/rsng/ctrl_43",
            "requires_state_transition": True,
        }
        outcomes = []
        with _client(server) as c:
            for _ in range(3):
                outcomes.append(StatefulCaseProber(c, base_url=server).probe(case))
        # Verdicts are deterministic. (Request COUNTS may legitimately
        # differ across re-probes of one case on the same server: the
        # first probe applies the transitions, later probes confirm in
        # the read-only phase against the already-mutated state — the
        # outcome is what the scorer reads, and it is stable.)
        assert len({o.verdict for o in outcomes}) == 1
        assert outcomes[0].verdict == "CONFIRMED"


class TestGuardStaysTheAuthority:
    def test_confirmation_requires_the_causal_guard(self, server):
        """The prober never confirms on its own: a post-transition read
        WITHOUT the guard's differential (candidate == control) must not
        confirm. Feeding the guard equal observations yields CLEAN."""
        with _client(server) as c:
            b = make_observation(c.get("/bv3/simp/own_3"), "/bv3/simp/own_3")
            cand = make_observation(c.get("/bv3/simp/target_3"), "/bv3/simp/target_3")
            ctrl = make_observation(c.get("/bv3/simp/ctrl_3"), "/bv3/simp/ctrl_3")
        result = guarded_causal_evaluate(b, cand, ctrl)
        assert result.verdict.value != "CONFIRMED"
