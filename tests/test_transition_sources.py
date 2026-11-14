"""UM-DR-27 tests — grammar-free transition discovery (transition_sources)
+ the source-driven stateful prober + the generalization fixture.

Coverage contract:
  1. ObservedSurfaceSource — case-scoping, stateful filtering (flag
     honored), dedup, stable order, plain-path strings.
  2. NameGrammarSource — the EXACT UM-DR-25 legacy grammar (byte pin).
  3. CompositeTransitionSource — observed-first, dedup by (method, path).
  4. observed_source_from_campaign_state — the family_feeds production
     adapter (OpenAPI routes / crawl surface / forms → candidates).
  5. The prober's source-driven phase 2 — singles, bounded pairs, budget
     honesty, 404-skip, backward-compat default (no source = grammar).
  6. The generalization fixture — spec fidelity, no truth-vocabulary
     leakage (source + runtime), the grammar control (must NOT confirm
     token-route cases), observed-source detection (reasoning +
     compositional + safe-case precision), and the full-corpus pin
     (recall 1.0 / precision 1.0 on the fixture, honestly labeled).
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.production.stateful_probe import (  # noqa: E402
    MAX_REQUESTS_PER_CASE,
    StatefulCaseProber,
)
from webpent.production.transition_sources import (  # noqa: E402
    MAX_COMPOSITION_CANDIDATES,
    CompositeTransitionSource,
    NameGrammarSource,
    ObservedSurfaceSource,
    observed_source_from_campaign_state,
)

REPLICA_DIR = ROOT / "benchmarks" / "blind_v3_replica"
MANIFEST = ROOT / "benchmarks" / "blind_v3" / "manifest.json"
GROUND_TRUTH = ROOT / "benchmarks" / "blind_v3" / "ground_truth.json"
PORT = 9222


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_module("generalization_target", REPLICA_DIR / "generalization_target.py")
gt = json.loads(GROUND_TRUTH.read_text())
manifest_cases = {c["case_id"]: c for c in json.loads(MANIFEST.read_text())["cases"]}


# ---------------------------------------------------------------------------
# 1. ObservedSurfaceSource
# ---------------------------------------------------------------------------
CASE_46 = {
    "case_id": "bv3_046",
    "baseline": "/bv3/rsng/own_46",
    "candidate": "/bv3/rsng/target_46",
    "control": "/bv3/rsng/ctrl_46",
    "requires_state_transition": True,
}


def test_observed_source_scopes_by_directory_and_resource_id():
    entries = [
        {"method": "POST", "path": "/bv3/rsng/sda18_46"},       # in scope
        {"method": "POST", "path": "/bv3/rsng/fa8e1_46"},       # in scope
        {"method": "POST", "path": "/bv3/rsng/s0aaa_47"},       # wrong id
        {"method": "POST", "path": "/bv3/comp/sda18_46"},       # wrong dir
        {"method": "GET", "path": "/bv3/rsng/target_46"},       # not stateful
        {"method": "POST", "path": "/bv3/rsng/reset_all"},      # decoy, no id
    ]
    out = ObservedSurfaceSource(entries).candidates(CASE_46)
    assert [c.path for c in out] == ["/bv3/rsng/sda18_46", "/bv3/rsng/fa8e1_46"]
    assert all(c.method == "POST" for c in out)
    assert all(c.origin == "observed" for c in out)


def test_observed_source_honors_stateful_flag_and_dedup():
    entries = [
        {"method": "GET", "path": "/bv3/rsng/x_46", "stateful": True},  # flag wins
        {"method": "POST", "path": "/bv3/rsng/y_46"},
        {"method": "POST", "path": "/bv3/rsng/y_46"},                    # dup
        {"method": "POST", "path": "https://h/bv3/rsng/z_46"},           # absolute URL
    ]
    out = ObservedSurfaceSource(entries).candidates(CASE_46)
    assert [(c.method, c.path) for c in out] == [
        ("GET", "/bv3/rsng/x_46"),
        ("POST", "/bv3/rsng/y_46"),
        ("POST", "/bv3/rsng/z_46"),
    ]


def test_observed_source_accepts_plain_path_strings():
    out = ObservedSurfaceSource(["/bv3/rsng/q_46"]).candidates(CASE_46)
    assert [(x.method, x.path) for x in out] == [("POST", "/bv3/rsng/q_46")]


def test_observed_source_no_scope_no_candidates():
    empty_case = {"case_id": "x", "candidate": "/only"}
    assert ObservedSurfaceSource(["/bv3/rsng/q_46"]).candidates(empty_case) == []
    assert ObservedSurfaceSource([]).candidates(CASE_46) == []


def test_observed_source_deterministic_order_and_cap():
    """Stable first-observed order, capped at MAX_COMPOSITION_CANDIDATES + 4
    candidates (the documented prober-side bound)."""
    cap = MAX_COMPOSITION_CANDIDATES + 4
    entries = [{"method": "POST", "path": f"/bv3/rsng/t{k}_46"} for k in range(9)]
    a = ObservedSurfaceSource(entries).candidates(CASE_46)
    b = ObservedSurfaceSource(list(reversed(entries))).candidates(CASE_46)
    assert len(a) == cap
    assert [c.path for c in a] == [f"/bv3/rsng/t{k}_46" for k in range(cap)]
    # order follows the OBSERVED order (stable, not sorted) — reversed
    # input yields reversed output: provenance-honest first-seen order.
    assert [c.path for c in b] == [f"/bv3/rsng/t{k}_46" for k in list(reversed(range(9)))[:cap]]


# ---------------------------------------------------------------------------
# 2. NameGrammarSource — the legacy byte pin
# ---------------------------------------------------------------------------
def test_namegrammar_exact_legacy_paths():
    out = NameGrammarSource().candidates(CASE_46)
    assert [c.path for c in out] == [
        "/bv3/rsng/state_46",
        "/bv3/rsng/transition_46",
        "/bv3/rsng/activate_46",
        "/bv3/rsng/flag_46",
    ]
    assert all(c.method == "POST" for c in out)
    assert all(c.origin == "grammar" for c in out)


def test_namegrammar_matches_legacy_prober_order():
    """The grammar source emits exactly the routes the legacy prober's
    loops would build (singles then the extra composition verb)."""
    legacy_singles = ("state", "transition", "activate")
    legacy_composition = ("state", "flag")
    out = NameGrammarSource().candidates(CASE_46)
    verbs = [c.path.rsplit("/", 1)[-1].rsplit("_", 1)[0] for c in out]
    assert verbs == list(legacy_singles) + [
        v for v in legacy_composition if v not in legacy_singles
    ]


# ---------------------------------------------------------------------------
# 3. CompositeTransitionSource
# ---------------------------------------------------------------------------
def test_composite_observed_first_and_dedup():
    observed = ObservedSurfaceSource([{"method": "POST", "path": "/bv3/rsng/s1_46"}])
    composite = CompositeTransitionSource(observed, NameGrammarSource())
    out = composite.candidates(CASE_46)
    assert out[0].origin == "observed"
    assert out[0].path == "/bv3/rsng/s1_46"
    keys = [c.key() for c in out]
    assert len(keys) == len(set(keys))
    assert any(c.path == "/bv3/rsng/state_46" for c in out)


# ---------------------------------------------------------------------------
# 4. Production adapter (family_feeds)
# ---------------------------------------------------------------------------
def test_campaign_state_adapter_openapi_routes():
    state = {
        "crawled_data": {
            "openapi_routes": [
                {"method": "POST", "path": "/bv3/rsng/sda18_46"},
                {"method": "GET", "path": "/bv3/rsng/target_46"},
            ]
        }
    }
    source = observed_source_from_campaign_state(state)
    out = source.candidates(CASE_46)
    assert [(c.method, c.path) for c in out] == [("POST", "/bv3/rsng/sda18_46")]
    assert out[0].provenance.startswith("family_feeds:")


def test_campaign_state_adapter_forms_and_links():
    state = {
        "crawled_data": {
            "forms": [
                {"action": "/bv3/rsng/fa8e1_46", "method": "POST"},
            ],
            "endpoints": [
                "http://h/bv3/rsng/target_46",
            ],
        }
    }
    out = observed_source_from_campaign_state(state).candidates(CASE_46)
    assert [c.path for c in out] == ["/bv3/rsng/fa8e1_46"]


def test_campaign_state_adapter_fail_soft_on_garbage():
    source = observed_source_from_campaign_state({"crawled_data": None})
    assert source.candidates(CASE_46) == []
    source2 = observed_source_from_campaign_state(object())
    assert source2.candidates(CASE_46) == []


# ---------------------------------------------------------------------------
# 5. Prober source-driven phase 2 (fake client — no server)
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text
        self.headers: dict[str, str] = {}

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class ScriptedClient:
    """Deterministic fake: routes → responses, counting requests."""

    def __init__(self, routes: dict[tuple[str, str], int]) -> None:
        self._routes = routes
        self.requests: list[tuple[str, str]] = []

    def request(self, method: str, path: str, headers=None):
        self.requests.append((method, path))
        return FakeResponse(self._routes.get((method, path), 404), "{}")

    def get(self, path: str, headers=None):
        return self.request("GET", path, headers)

    def post(self, path: str, headers=None):
        return self.request("POST", path, headers)


def _confirming_evaluate(b, c, ctrl):  # shape-compatible stub
    class R:
        verdict = type("V", (), {"value": "CONFIRMED"})()
        confidence = 0.9
    return R()


def _inconclusive_evaluate(b, c, ctrl):
    class R:
        verdict = type("V", (), {"value": "INCONCLUSIVE"})()
        confidence = 0.0
    return R()


def test_source_driven_single_confirms_and_stops():
    client = ScriptedClient({("POST", "/bv3/rsng/sda18_46"): 200})
    source = ObservedSurfaceSource([{"method": "POST", "path": "/bv3/rsng/sda18_46"}])
    calls = {"n": 0}

    def evaluate(b, c, ctrl):  # phase-1 inconclusive, post-transition confirm
        calls["n"] += 1

        class R:
            verdict = type("V", (), {"value": "CONFIRMED" if calls["n"] > 1 else "INCONCLUSIVE"})()
            confidence = 0.9 if calls["n"] > 1 else 0.0
        return R

    prober = StatefulCaseProber(client, evaluate=evaluate, transition_source=source)
    out = prober.probe(CASE_46)
    assert out.verdict == "CONFIRMED"
    assert out.phase == 2
    assert out.transitions_applied == ["/bv3/rsng/sda18_46"]
    assert out.transition_origin == "observed"
    # phase1 reads + 1 transition + 1 re-evaluate — then STOP (no waste)
    posts = [r for r in client.requests if r[0] == "POST"]
    assert posts == [("POST", "/bv3/rsng/sda18_46")]


def test_source_driven_skips_errored_transitions_without_reeval():
    """A 404 transition candidate is skipped — no 3-GET re-evaluation is
    wasted on a route the target says does not exist (budget honesty)."""
    client = ScriptedClient({})  # everything 404s
    source = ObservedSurfaceSource([
        {"method": "POST", "path": f"/bv3/rsng/t{k}_46"} for k in range(4)
    ])
    prober = StatefulCaseProber(
        client, evaluate=_inconclusive_evaluate, transition_source=source
    )
    out = prober.probe(CASE_46)
    assert out.verdict == "INCONCLUSIVE"
    # 3 reads (phase1) + 4 POSTs (404, skipped) + pair phase can't afford
    # 5 for any pair after budget math? 3+4=7 used, pair needs 5 → 12 ≤ 30
    # so pairs run too: 4 POSTs (404) → 11 used… but every pair POST 404s,
    # so no re-evals happen at all.
    gets = [r for r in client.requests if r[0] == "GET"]
    assert len(gets) == 3  # only the phase-1 reads — zero wasted re-evals
    assert out.requests_issued == client.requests.__len__()


def test_source_driven_respects_budget():
    client = ScriptedClient({})  # all 404
    many = [
        {"method": "POST", "path": f"/bv3/rsng/t{k}_46"} for k in range(8)
    ]
    source = ObservedSurfaceSource(many)
    prober = StatefulCaseProber(
        client, evaluate=_inconclusive_evaluate, transition_source=source,
        max_requests=6,
    )
    out = prober.probe(CASE_46)
    assert out.requests_issued <= 6
    assert out.verdict == "INCONCLUSIVE"


def test_no_source_means_legacy_grammar_paths():
    client = ScriptedClient({})
    prober = StatefulCaseProber(client, evaluate=_inconclusive_evaluate)
    out = prober.probe(CASE_46)
    posts = [p for m, p in client.requests if m == "POST"]
    assert posts  # grammar transitions were attempted
    assert all(
        p.rsplit("/", 1)[-1].rsplit("_", 1)[0]
        in ("state", "transition", "activate", "flag")
        for p in posts
    )
    assert out.transition_origin is None  # legacy shape preserved


def test_source_driven_method_safety_boundaries():
    """(a) unflagged GET filtered by the source; (b) DELETE refused by
    the prober even when the source asserts it (non-destructive probe
    contract — the prober is the safety boundary); (c) explicit
    stateful=True GET passes source AND prober (observer's assertion
    wins over the method heuristic)."""
    # (a) source-level filtering: unflagged GET is not stateful
    assert ObservedSurfaceSource([
        {"method": "GET", "path": "/bv3/rsng/g_46"}
    ]).candidates(CASE_46) == []
    # (b) DELETE: the source passes it (stateful method), the prober refuses
    delete_source = ObservedSurfaceSource([
        {"method": "DELETE", "path": "/bv3/rsng/d_46"}
    ])
    assert len(delete_source.candidates(CASE_46)) == 1
    client = ScriptedClient({("DELETE", "/bv3/rsng/d_46"): 200})
    out = StatefulCaseProber(
        client, evaluate=_inconclusive_evaluate, transition_source=delete_source
    ).probe(CASE_46)
    assert ("DELETE", "/bv3/rsng/d_46") not in client.requests
    assert out.verdict == "INCONCLUSIVE"
    # (c) stateful=True GET: end-to-end the observer's assertion wins
    get_source = ObservedSurfaceSource([
        {"method": "GET", "path": "/bv3/rsng/g_46", "stateful": True}
    ])
    assert len(get_source.candidates(CASE_46)) == 1
    client2 = ScriptedClient({("GET", "/bv3/rsng/g_46"): 200})
    StatefulCaseProber(
        client2, evaluate=_inconclusive_evaluate, transition_source=get_source
    ).probe(CASE_46)
    assert ("GET", "/bv3/rsng/g_46") in client2.requests


# ---------------------------------------------------------------------------
# 6. The generalization fixture (live)
# ---------------------------------------------------------------------------
@pytest.fixture()
def server():
    proc = subprocess.Popen(
        [sys.executable, str(REPLICA_DIR / "generalization_target.py")],
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


def _case(cid: str) -> dict:
    return manifest_cases[cid]


class TestGeneralizationFixture:
    def test_route_index_matches_manifest_numbering(self):
        """604 routes: 1 map + 3 decoys + 600 case routes (3 families x
        40 cases x 5 routes) — and every manifest case number appears."""
        routes = gen.route_index()
        assert len(routes) == 604
        for family, lo, hi in (("simp", 1, 40), ("rsng", 41, 80), ("comp", 81, 120)):
            for n in range(lo, hi + 1):
                own = f"/bv3/{family}/own_{n}"
                assert {"method": "GET", "path": own} in routes

    def test_token_routes_never_match_the_legacy_grammar(self):
        """No advertised POST route may be reachable by the legacy name
        grammar — that is the fixture's whole point."""
        routes = gen.route_index()
        for r in routes:
            if r["method"] != "POST":
                continue
            seg = r["path"].rsplit("/", 1)[-1].rsplit("_", 1)[0]
            assert seg not in ("state", "transition", "activate", "flag"), r["path"]

    def test_source_never_reads_ground_truth(self):
        source = (REPLICA_DIR / "generalization_target.py").read_text(encoding="utf-8")
        for word in ("expected_label", "case_family", "difficulty",
                     "ownership_bypass", "state_transition_violation",
                     "representation_equivalence", "business_logic_constraint"):
            assert word not in source, f"truth vocabulary leaked: {word}"

    def test_transition_sources_never_read_ground_truth(self):
        for rel in ("src/webpent/production/transition_sources.py",
                    "src/webpent/production/stateful_probe.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            for word in ("ground_truth", "expected_label", "blind_v3/"):
                assert word not in source, f"{rel} references truth material"

    def test_runtime_no_truth_vocabulary(self, server):
        forbidden = ("vulnerable", "safe", "ownership_bypass", "mechanism",
                     "expected_label", "granted_full_owner_user_b")
        with _client(server) as c:
            idx = c.get("/").text.lower()
            r = c.get("/bv3/rsng/target_46", headers={"X-Actor": "attacker"})
            blob = r.text.lower() + " ".join(
                f"{k}:{v}" for k, v in r.headers.items()).lower()
            for word in forbidden:
                assert word not in blob
                assert word not in idx


class TestGrammarControl:
    def test_grammar_prober_cannot_confirm_token_cases(self, server):
        """THE CONTROL: the legacy name grammar must NOT lift recall on
        this fixture (its POSTs all 404)."""
        with _client(server) as c:
            for cid in ("bv3_046", "bv3_043", "bv3_082", "bv3_119"):
                case = _case(cid)
                out = StatefulCaseProber(c, base_url=server).probe(case)
                assert out.verdict != "CONFIRMED", cid


class TestObservedSourceDetection:
    def test_reasoning_case_confirmed_via_discovered_token(self, server):
        with _client(server) as c:
            routes = c.get("/").json()["routes"]
            source = ObservedSurfaceSource(routes)
            out = StatefulCaseProber(
                c, base_url=server, transition_source=source
            ).probe(_case("bv3_046"))
        assert out.verdict == "CONFIRMED"
        assert out.phase == 2
        assert out.transition_origin == "observed"
        assert len(out.transitions_applied) == 1  # single transition suffices

    def test_compositional_case_confirmed_with_full_evidence(self, server):
        """A composition confirmed via accumulating singles records EVERY
        applied transition in application order (evidence integrity —
        the outcome must not under-report the causal chain)."""
        with _client(server) as c:
            routes = c.get("/").json()["routes"]
            source = ObservedSurfaceSource(routes)
            out = StatefulCaseProber(
                c, base_url=server, transition_source=source
            ).probe(_case("bv3_082"))
        assert out.verdict == "CONFIRMED"
        assert len(out.transitions_applied) == 2  # state + flag, in order
        assert out.requests_issued <= MAX_REQUESTS_PER_CASE

    def test_safe_cases_stay_unconfirmed_precision(self, server):
        """Safe reasoning/compositional cases must NOT confirm even after
        their discovered transitions apply — the causal guard refuses."""
        with _client(server) as c:
            routes = c.get("/").json()["routes"]
            source = ObservedSurfaceSource(routes)
            for cid in ("bv3_042", "bv3_081"):  # safe per ground truth
                out = StatefulCaseProber(
                    c, base_url=server, transition_source=source
                ).probe(_case(cid))
                assert out.verdict != "CONFIRMED", cid

    def test_campaign_state_adapter_detects_reasoning_case(self, server):
        """The PRODUCTION path: the route index folded into campaign
        state (the OpenAPI-routes shape — methods preserved) →
        family_feeds → source → prober."""
        with _client(server) as c:
            routes = c.get("/").json()["routes"]
            state = {"crawled_data": {"openapi_routes": [
                {"method": r["method"], "path": r["path"]}
                for r in routes if r["method"] == "POST"
            ]}}
            source = observed_source_from_campaign_state(state)
            out = StatefulCaseProber(
                c, base_url=server, transition_source=source
            ).probe(_case("bv3_046"))
        assert out.verdict == "CONFIRMED"


class TestFullCorpusPin:
    def test_full_corpus_observed_source_recall_and_precision(self, server):
        """The honest full-corpus fixture pin: recall 1.0 / precision 1.0
        through grammar-free discovery (the runner records the report;
        this test pins the capability so it cannot silently regress)."""
        cases = json.loads(MANIFEST.read_text())["cases"]
        per_case = {}
        with _client(server) as c:
            routes = c.get("/").json()["routes"]
            source = ObservedSurfaceSource(routes)
            for case in cases:
                out = StatefulCaseProber(
                    c, base_url=server, transition_source=source
                ).probe(case)
                per_case[case["case_id"]] = out
        tp = fp = fn = tn = 0
        for cid, out in per_case.items():
            truth = gt[cid]["expected_label"] == "vulnerable"
            flagged = out.verdict == "CONFIRMED"
            if flagged and truth:
                tp += 1
            elif flagged and not truth:
                fp += 1
            elif not flagged and truth:
                fn += 1
            else:
                tn += 1
        assert (tp, fp, fn, tn) == (73, 0, 0, 47)
        assert all(o.requests_issued <= MAX_REQUESTS_PER_CASE for o in per_case.values())
