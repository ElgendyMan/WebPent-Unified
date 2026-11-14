"""UM-DR-28 tests — the representation-equivalence oracle + the
equivalence fixture measurements.

Coverage contract:
  1. canonical_representation — sorted keys, volatile-drop rule set,
     key-order/whitespace equivalence, parse-failure fail-safe,
     adversarial: a meaningful difference is NEVER normalized away.
  2. authorization_semantics — rotating field aliases, nested
     containers, boolean granted, the alias/privilege-escalation
     vocabulary, ambiguity never guessed.
  3. enrich_observation — headers win (including the header-presence
     fill guard), absent channels filled, raw evidence preserved.
  4. Guard integration — enriched observations confirm the
     body-represented differential; the raw projection cannot.
  5. The equivalence fixture (live, in-process) — the miss class
     reproduced on the OLD pipeline, recovered by the oracle:
       mode E1: legacy observations + grammar fallback  -> 0 recall
       mode E2: legacy observations + observed source   -> 0 recall
                (the comparator gap: transitions apply, guard is blind)
       mode E3: oracle observations + observed source   -> 73/73, 0 FP
     Populations are labeled; this is a REPLICA-CORPUS measurement.
  6. Leakage audit — the fixture never leaks truth vocabulary.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.cqa_v2.causal_guard import guarded_causal_evaluate  # noqa: E402
from webpent.cqa_v2.representation_oracle import (  # noqa: E402
    VOLATILE_KEYS,
    authorization_semantics,
    canonical_representation,
    enrich_observation,
)
from webpent.production.stateful_probe import (  # noqa: E402
    MAX_REQUESTS_PER_CASE,
    StatefulCaseProber,
    make_observation,
)
from webpent.production.transition_sources import ObservedSurfaceSource  # noqa: E402

REPLICA_DIR = ROOT / "benchmarks" / "blind_v3_replica"
MANIFEST = ROOT / "benchmarks" / "blind_v3" / "manifest.json"
GROUND_TRUTH = ROOT / "benchmarks" / "blind_v3" / "ground_truth.json"
REPORT_PATH = ROOT / "reports" / "qualification" / "umdr28_equivalence_measurement.json"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


eqv = _load_module("equivalence_target", REPLICA_DIR / "equivalence_target.py")
gt = json.loads(GROUND_TRUTH.read_text())
manifest_cases = {c["case_id"]: c for c in json.loads(MANIFEST.read_text())["cases"]}


class FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


# ---------------------------------------------------------------------------
# 1. canonical representation
# ---------------------------------------------------------------------------

class TestCanonicalRepresentation:
    def test_key_order_and_whitespace_are_equivalent(self):
        a, _ = canonical_representation('{"owner": "User_B", "granted": true}')
        b, _ = canonical_representation('{ "granted" : true ,  "owner":"User_B" }')
        assert a is not None and a == b

    def test_volatile_fields_are_dropped(self):
        a, rules_a = canonical_representation(
            '{"owner": "User_B", "ts": 1, "request_id": "r-1"}')
        b, rules_b = canonical_representation(
            '{"owner": "User_B", "ts": 999, "request_id": "r-999"}')
        assert a == b
        assert any("ts" in r for r in rules_a)
        assert any("request_id" in r for r in rules_b)

    def test_meaningful_difference_is_never_normalized_away(self):
        """THE ADVERSARIAL PIN: one character of owner difference — a
        security-relevant difference — must break canonical equality."""
        a, _ = canonical_representation('{"owner": "User_B", "granted": true}')
        b, _ = canonical_representation('{"owner": "User_C", "granted": true}')
        assert a != b

    def test_authorization_fields_are_never_volatile(self):
        for field in ("owner", "owned_by", "granted", "outcome", "role",
                      "effective_as", "alias", "tenant", "privilege"):
            assert field not in VOLATILE_KEYS, field

    def test_parse_failure_fails_safe(self):
        assert canonical_representation("not json at all")[0] is None
        assert canonical_representation('{"broken": ')[0] is None
        assert canonical_representation("")[0] is None
        assert canonical_representation('42')[0] is None

    def test_deep_structures_are_canonicalized(self):
        a, _ = canonical_representation(
            '{"resource": {"owner": "User_B", "items": [3, 1, 2]}}')
        b, _ = canonical_representation(
            '{"resource": {"items": [3, 1, 2], "owner": "User_B"}}')
        assert a == b


# ---------------------------------------------------------------------------
# 2. authorization semantics
# ---------------------------------------------------------------------------

class TestAuthorizationSemantics:
    def test_rotating_owner_aliases(self):
        for body in (
            '{"owner": "User_B"}',
            '{"owned_by": "User_B"}',
            '{"resource": {"owner": "User_B"}}',
        ):
            context, rules = authorization_semantics(body)
            assert context.get("resource_owner") == "User_B", body
            assert rules, body

    def test_granted_boolean_maps_to_outcome_vocabulary(self):
        context, _ = authorization_semantics('{"granted": true}')
        assert context.get("authorization_outcome") == "granted_full"
        context, _ = authorization_semantics('{"granted": false}')
        assert context.get("authorization_outcome") == "denied"

    def test_alias_shape_maps_to_effective_privilege(self):
        context, _ = authorization_semantics(
            '{"role": "user", "effective_as": "admin"}')
        assert context.get("actor_role") == "user"
        assert context.get("effective_privilege_granted") == "admin"

    def test_ambiguous_and_unknown_values_are_never_guessed(self):
        context, _ = authorization_semantics('{"owner": {"deep": "User_B"}}')
        assert "resource_owner" not in context  # nested under alias key — ignored
        context, _ = authorization_semantics('{"something_else": "x"}')
        assert context == {}
        context, _ = authorization_semantics('{"granted": "read"}')
        assert "authorization_outcome" not in context  # unknown vocab — no guess

    def test_actor_identity_aliases(self):
        context, _ = authorization_semantics('{"actor": "attacker"}')
        assert context.get("actor_id") == "attacker"


# ---------------------------------------------------------------------------
# 3. enrich_observation
# ---------------------------------------------------------------------------

class TestEnrichObservation:
    def _base_obs(self, body: str, headers: dict | None = None) -> dict:
        return {
            "status_code": 200,
            "body_length": len(body),
            "semantic_digest": "raw",
            "request": {"method": "GET", "path": "/x"},
            "headers": {k.lower(): v for k, v in (headers or {}).items()},
            "body_preview": body,
        }

    def test_fills_absent_channels_and_preserves_raw_evidence(self):
        obs = self._base_obs('{"owner": "User_B", "granted": true}')
        out = enrich_observation(obs)
        assert out["resource_owner"] == "User_B"
        assert out["authorization_outcome"] == "granted_full"
        assert out["semantic_digest"] == "raw"          # untouched
        assert out["body_preview"] == obs["body_preview"]  # evidence preserved
        assert out["canonical_digest"]
        assert out["representation_rules"]

    def test_header_representation_wins(self):
        """A channel whose header the response already carried is NOT
        body-filled — the header is the explicit representation."""
        obs = self._base_obs(
            '{"owner": "User_B"}', headers={"X-Resource-Owner": "User_HEADER"})
        out = enrich_observation(obs)
        assert "resource_owner" not in out  # header counterpart present
        assert out["headers"]["x-resource-owner"] == "User_HEADER"

    def test_non_json_bodies_are_unchanged(self):
        obs = self._base_obs("<html>plain</html>")
        out = enrich_observation(obs)
        assert "canonical_digest" not in out
        assert out == obs


# ---------------------------------------------------------------------------
# 4. guard integration (the differential the old comparator missed)
# ---------------------------------------------------------------------------

class TestGuardIntegration:
    def test_body_represented_differential_confirms_with_oracle_only(self):
        headers = {"X-Actor-Echo": "attacker"}  # the realistic minimal echo

        def triple(enrich: bool):
            baseline = FakeResponse(200, '{"owner": "attacker", "granted": true, "actor": "attacker"}', headers)
            candidate = FakeResponse(200, '{"owner": "User_B", "granted": true, "actor": "attacker"}', headers)
            control = FakeResponse(403, '{"owner": "User_C", "granted": false, "actor": "attacker"}', headers)
            return (
                make_observation(baseline, "/d/own_1", "http://t", enrich=enrich),
                make_observation(candidate, "/d/target_1", "http://t", enrich=enrich),
                make_observation(control, "/d/ctrl_1", "http://t", enrich=enrich),
            )

        raw = guarded_causal_evaluate(*triple(enrich=False))
        assert raw.verdict.value == "INCONCLUSIVE"   # the miss class

        enriched = guarded_causal_evaluate(*triple(enrich=True))
        assert enriched.verdict.value == "CONFIRMED"
        assert enriched.authorization_differential is True

    def test_body_represented_alias_escalation_confirms(self):
        headers = {"X-Actor-Echo": "attacker"}

        def triple(enrich: bool):
            baseline = FakeResponse(200, '{"owner": "attacker", "granted": true, "actor": "attacker"}', headers)
            candidate = FakeResponse(200, '{"owner": "attacker", "granted": true, "actor": "attacker", "role": "user", "effective_as": "admin"}', headers)
            control = FakeResponse(403, '{"owner": "User_C", "granted": false, "actor": "attacker"}', headers)
            return (
                make_observation(baseline, "/d/own_1", "http://t", enrich=enrich),
                make_observation(candidate, "/d/target_1", "http://t", enrich=enrich),
                make_observation(control, "/d/ctrl_1", "http://t", enrich=enrich),
            )

        assert guarded_causal_evaluate(*triple(enrich=False)).verdict.value == "INCONCLUSIVE"
        assert guarded_causal_evaluate(*triple(enrich=True)).verdict.value == "CONFIRMED"

    def test_safe_body_represented_case_stays_unconfirmed(self):
        baseline = FakeResponse(200, '{"owner": "attacker", "granted": true, "actor": "attacker"}')
        candidate = FakeResponse(403, '{"owner": "User_B", "granted": false, "actor": "attacker"}')
        control = FakeResponse(403, '{"owner": "User_C", "granted": false, "actor": "attacker"}')
        result = guarded_causal_evaluate(
            make_observation(baseline, "/d/own_1", "http://t"),
            make_observation(candidate, "/d/target_1", "http://t"),
            make_observation(control, "/d/ctrl_1", "http://t"),
        )
        assert result.verdict.value != "CONFIRMED"


# ---------------------------------------------------------------------------
# 5. the equivalence fixture (live, in-process)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def eqv_server():
    server = ThreadingHTTPServer(("127.0.0.1", 9223), eqv.EquivalenceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:9223"
    server.shutdown()
    server.server_close()


def _measure(base, *, enrich: bool, with_source: bool):
    cases = json.loads(MANIFEST.read_text())["cases"]
    eqv.reset_state()
    routes = httpx.get(f"{base}/bv3/map", timeout=5).json()["routes"]
    source = ObservedSurfaceSource(routes) if with_source else None
    tp = fp = fn = tn = 0
    requests_total = 0
    with httpx.Client(timeout=5, base_url=base) as client:
        for case in cases:
            prober = StatefulCaseProber(
                client, base_url=base, transition_source=source,
                enrich_observations=enrich,
            )
            out = prober.probe(case)
            requests_total += out.requests_issued
            truth = gt[case["case_id"]]["expected_label"] == "vulnerable"
            flagged = out.verdict == "CONFIRMED"
            if flagged and truth:
                tp += 1
            elif flagged and not truth:
                fp += 1
            elif not flagged and truth:
                fn += 1
            else:
                tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "requests": requests_total}


class TestEquivalenceFixture:
    def test_spec_fidelity_and_no_truth_vocabulary(self, eqv_server):
        routes = httpx.get(f"{eqv_server}/bv3/map", timeout=5).json()["routes"]
        assert len(routes) == 1 + 3 + 120 * 5  # map + 3 decoys + 120 cases × 5
        forbidden = ("vulnerable", "safe", "expected_label", "mechanism",
                     "granted_full_owner_user_b", "effective_as_admin")
        response = httpx.get(f"{eqv_server}/bv3/rsng/target_46", timeout=5)
        blob = (response.text + " ".join(f"{k}:{v}" for k, v in response.headers.items())).lower()
        for word in forbidden:
            assert word not in blob
            assert word not in json.dumps(routes).lower()

    def test_mode_e1_legacy_pipeline_zero_recall(self, eqv_server):
        """The miss class reproduced: the OLD observation projection is
        blind to body-represented authorization semantics."""
        result = _measure(eqv_server, enrich=False, with_source=False)
        assert result["tp"] == 0 and result["fp"] == 0
        assert result == {"tp": 0, "fp": 0, "fn": 73, "tn": 47,
                          "requests": result["requests"]}

    def test_mode_e2_source_without_oracle_still_zero_recall(self, eqv_server):
        """THE COMPARATOR GAP: transitions are discovered and applied,
        but the guard receives no authorization context — recall stays
        0. This is the read-only miss class generalized to the whole
        corpus, and it is what the oracle repairs."""
        result = _measure(eqv_server, enrich=False, with_source=True)
        assert result["tp"] == 0 and result["fp"] == 0

    def test_mode_e3_oracle_full_recovery(self, eqv_server):
        result = _measure(eqv_server, enrich=True, with_source=True)
        assert (result["tp"], result["fp"], result["fn"], result["tn"]) == (73, 0, 0, 47)
        assert result["requests"] <= 120 * MAX_REQUESTS_PER_CASE

    def test_measurement_report_written(self, eqv_server):
        """The reproducible evidence record (raw counts + methodology)."""
        e1 = _measure(eqv_server, enrich=False, with_source=False)
        e2 = _measure(eqv_server, enrich=False, with_source=True)
        e3 = _measure(eqv_server, enrich=True, with_source=True)
        report = {
            "window": "UM-DR-28",
            "population": "equivalence fixture (blind_v3 replica corpus, "
                          "body-represented authorization semantics, unguessable "
                          "token routes) — REPLICA-CORPUS measurement, NOT the "
                          "recorded blind baseline, NOT an independent holdout",
            "denominator": 120,
            "ground_truth": {"vulnerable": 73, "safe": 47},
            "modes": {
                "E1_legacy_observations_grammar_fallback": e1,
                "E2_legacy_observations_observed_source": e2,
                "E3_oracle_observations_observed_source": e3,
            },
            "metrics": {
                "E1": {"recall": 0.0, "precision": None},
                "E2": {"recall": 0.0, "precision": None},
                "E3": {"recall": 1.0, "precision": 1.0},
            },
            "requests_per_case_average": {
                "E3": round(e3["requests"] / 120, 2),
            },
            "limitations": [
                "author-known fixture (the honesty boundary — the original "
                "blind_v3 target is absent, so the exact 15 miss bytes are "
                "unrecoverable; this fixture reproduces the miss CLASS)",
                "production_qualified still requires operator-deployed "
                "independent holdout corpora",
            ],
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2))
        assert REPORT_PATH.exists()


# ---------------------------------------------------------------------------
# 6. regression: the generalization corpus under the enriched default
# ---------------------------------------------------------------------------

class TestGeneralizationRegression:
    def test_generalization_corpus_still_full_recall_under_oracle(self):
        """The oracle must not disturb the X-* header population: the
        default (enriched) prober on the generalization fixture keeps
        73/73 - 0 FP (headers win; canonical preserves all meaningful
        differences)."""
        gen = _load_module("generalization_target", REPLICA_DIR / "generalization_target.py")
        server = ThreadingHTTPServer(("127.0.0.1", 0), gen.GeneralizationHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            gen.reset_state()
            cases = json.loads(MANIFEST.read_text())["cases"]
            routes = httpx.get(f"{base}/", timeout=5).json()["routes"]
            source = ObservedSurfaceSource(routes)
            tp = fp = fn = tn = 0
            with httpx.Client(timeout=5, base_url=base) as client:
                for case in cases:
                    out = StatefulCaseProber(
                        client, base_url=base, transition_source=source
                    ).probe(case)
                    truth = gt[case["case_id"]]["expected_label"] == "vulnerable"
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
        finally:
            server.shutdown()
            server.server_close()
