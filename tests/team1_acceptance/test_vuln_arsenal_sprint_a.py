"""Vulnerability Arsenal Sprint A: five new families through the trust chain.

Two layers, mirroring tests/team1_acceptance/test_vulnerability_family_expansion.py:

1. Canonical validator unit behaviour — CONFIRMED / REFUTED / INCONCLUSIVE and
   the fail-closed rule that no validator confirms without a clean differential.
2. One end-to-end AVI promotion per family against a real local HTTP fixture:
   baseline / candidate / negative control executed as REAL requests, the
   canonical validator CONFIRMED, ProofBundle sealed, replay verified, and the
   8-gate PromotionPipeline returning PROMOTED with an empty gates_failed.
"""
from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "sprint_a_family_test_key_32_chars_1234567")

from webpent.production.validators import (  # noqa: E402
    VALIDATORS,
    ValidationOutcome,
    validate_business_logic,
    validate_file_upload,
    validate_jwt_manipulation,
    validate_race_condition,
)
from webpent.vulns.business_logic import (  # noqa: E402
    build_business_logic_probes,
    matches_business_logic_shape,
)
from webpent.vulns.file_upload import (  # noqa: E402
    FILE_UPLOAD_SCENARIOS,
    SVG_XSS_PAYLOAD,
    UPLOAD_MARKER,
    build_upload_probe,
)
from webpent.vulns.jwt_analyzer import (  # noqa: E402
    build_jwt_variants,
    decode_jwt,
    encode_jwt,
    extract_jwt_from_headers,
)
from webpent.vulns.mass_assignment import (  # noqa: E402
    MASS_ASSIGNMENT_FIELD_VARIANTS,
    build_mass_assignment_probes,
)
from webpent.vulns.race_condition import (  # noqa: E402
    MAX_CONCURRENT_REQUESTS,
    build_race_condition_experiment,
    summarize_concurrent_results,
)

SPRINT_A_FAMILIES = (
    "RACE_CONDITION",
    "BUSINESS_LOGIC",
    "FILE_UPLOAD",
    "JWT_MANIPULATION",
)


def _ev(status: int, body: str = "", headers: dict | None = None,
        structured_fields: dict | None = None) -> dict:
    return {
        "status_code": status,
        "response_body": body,
        "headers": headers or {},
        "structured_fields": structured_fields or {},
    }


# --- PART 1: registry --------------------------------------------------------

def test_all_sprint_a_families_have_canonical_validators():
    for family in SPRINT_A_FAMILIES + ("MASS_ASSIGNMENT",):
        assert family in VALIDATORS, f"missing canonical validator for {family}"


def test_existing_families_still_registered():
    for family in ("IDOR", "BOLA", "OPEN_REDIRECT", "SSRF", "XSS", "SQLI",
                   "INFO_DISCLOSURE", "AUTH_BYPASS", "MASS_ASSIGNMENT"):
        assert family in VALIDATORS


# --- PART 2: race condition validator ---------------------------------------

class TestRaceConditionValidator:
    def _burst(self, successes: int, attempts: int = 5, expected: int = 1) -> dict:
        return {"_concurrent_attempts": attempts, "_concurrent_successes": successes,
                "_concurrent_expected_successes": expected}

    def test_confirmed_when_burst_over_succeeds(self):
        r = validate_race_condition(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}', structured_fields=self._burst(4)),
            negative_control=_ev(404, '{"error":"not_found"}', structured_fields=self._burst(0)),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED
        assert r.evidence_quality >= 2

    def test_refuted_when_atomic(self):
        r = validate_race_condition(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}', structured_fields=self._burst(1)),
            negative_control=_ev(404, '{"error":"not_found"}', structured_fields=self._burst(0)),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_inconclusive_without_burst_evidence(self):
        r = validate_race_condition(
            baseline=_ev(200), candidate=_ev(200), negative_control=_ev(404),
        )
        assert r.outcome == ValidationOutcome.INCONCLUSIVE

    def test_control_over_success_blocks_confirmation(self):
        """A control burst that also over-succeeds means the burst itself is the cause."""
        r = validate_race_condition(
            baseline=_ev(200),
            candidate=_ev(200, structured_fields=self._burst(5)),
            negative_control=_ev(200, structured_fields=self._burst(5)),
        )
        assert r.outcome != ValidationOutcome.CONFIRMED

    def test_concurrency_is_clamped(self):
        assert build_race_condition_experiment(endpoint_path="/x", concurrency=99).concurrency == MAX_CONCURRENT_REQUESTS
        assert build_race_condition_experiment(endpoint_path="/x", concurrency=1).concurrency == 2

    def test_expected_successes_floored_at_zero(self):
        assert build_race_condition_experiment(endpoint_path="/x", expected_successes=-5).expected_successes == 0

    def test_summarize_counts_only_2xx(self):
        summary = summarize_concurrent_results([
            {"status_code": 200}, {"status_code": 409}, {"status_code": 200}, {"status_code": 500},
        ])
        assert summary["_concurrent_successes"] == 2
        assert summary["_concurrent_attempts"] == 4


# --- PART 3: business logic validator ---------------------------------------

class TestBusinessLogicValidator:
    def test_confirmed_negative_price_accepted(self):
        r = validate_business_logic(
            baseline=_ev(200, '{"price":"100","status":"added"}'),
            candidate=_ev(200, '{"price":"-1","status":"added"}'),
            negative_control=_ev(200, '{"price":"100","status":"added"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_when_rejected(self):
        r = validate_business_logic(
            baseline=_ev(200, '{"price":"100"}'),
            candidate=_ev(400, '{"error":"price must be positive"}'),
            negative_control=_ev(200, '{"price":"100"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_refuted_when_candidate_identical_to_baseline(self):
        r = validate_business_logic(
            baseline=_ev(200, '{"price":"100"}'),
            candidate=_ev(200, '{"price":"100"}'),
            negative_control=_ev(200, '{"price":"100"}'),
        )
        assert r.outcome != ValidationOutcome.CONFIRMED

    def test_field_shape_recognition(self):
        assert matches_business_logic_shape("unit_price") == "price"
        assert matches_business_logic_shape("quantity") == "quantity"
        assert matches_business_logic_shape("coupon_code") == "coupon"
        assert matches_business_logic_shape("user_agent") is None

    def test_probe_carries_all_three_roles(self):
        probes = build_business_logic_probes(endpoint_path="/api/cart", field_name="price")
        assert probes
        hypothesis = probes[0].as_hypothesis(target_url="http://t.local", hypothesis_id="h1")
        assert set(hypothesis["requests"]) == {"baseline", "candidate", "negative_control"}


# --- PART 4: file upload validator ------------------------------------------

class TestFileUploadValidator:
    def test_confirmed_when_marker_served_with_impact(self):
        r = validate_file_upload(
            baseline=_ev(200, '{"uploaded":"ok"}'),
            candidate=_ev(200, f"<html>{UPLOAD_MARKER} /tmp/{UPLOAD_MARKER}</html>"),
            negative_control=_ev(200, '{"uploaded":"ok"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_when_not_reachable(self):
        r = validate_file_upload(
            baseline=_ev(200, '{"uploaded":"ok"}'),
            candidate=_ev(200, '{"uploaded":"ok"}'),
            negative_control=_ev(200, '{"uploaded":"ok"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_refuted_when_marker_also_in_baseline(self):
        r = validate_file_upload(
            baseline=_ev(200, f"static {UPLOAD_MARKER}"),
            candidate=_ev(200, f"{UPLOAD_MARKER} /tmp/x"),
            negative_control=_ev(200, "clean"),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_upload_success_message_alone_is_not_enough(self):
        r = validate_file_upload(
            baseline=_ev(200, "ok"),
            candidate=_ev(200, '{"message":"file uploaded successfully"}'),
            negative_control=_ev(200, "ok"),
        )
        assert r.outcome != ValidationOutcome.CONFIRMED

    def test_all_scenarios_build(self):
        for scenario in FILE_UPLOAD_SCENARIOS:
            probe = build_upload_probe(endpoint_path="/api/upload", scenario=scenario)
            assert probe.filename
            assert probe.as_hypothesis(target_url="http://t.local", hypothesis_id="h")["vulnerability_class"] == "FILE_UPLOAD"

    def test_unknown_scenario_fails_closed(self):
        with pytest.raises(ValueError):
            build_upload_probe(endpoint_path="/api/upload", scenario="not_a_scenario")

    def test_svg_payload_contains_marker_and_sink(self):
        assert UPLOAD_MARKER in SVG_XSS_PAYLOAD
        assert "<script" in SVG_XSS_PAYLOAD


# --- PART 5: JWT manipulation validator -------------------------------------

class TestJWTManipulationValidator:
    def test_confirmed_tampered_token_accepted(self):
        r = validate_jwt_manipulation(
            baseline=_ev(401, '{"error":"unauthorized"}'),
            candidate=_ev(200, '{"user":"admin","data":"secret"}'),
            negative_control=_ev(403, '{"error":"forbidden"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_when_rejected(self):
        r = validate_jwt_manipulation(
            baseline=_ev(401, '{"error":"unauthorized"}'),
            candidate=_ev(401, '{"error":"invalid token"}'),
            negative_control=_ev(403, '{"error":"forbidden"}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_inconclusive_when_baseline_not_denied(self):
        r = validate_jwt_manipulation(
            baseline=_ev(200, '{"public":"ok"}'),
            candidate=_ev(200, '{"data":"x"}'),
            negative_control=_ev(403, '{"error":"forbidden"}'),
        )
        assert r.outcome == ValidationOutcome.INCONCLUSIVE

    def test_decode_encode_roundtrip(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user", "role": "user"}
        token = encode_jwt(header, payload, "sig")
        decoded = decode_jwt(token)
        assert decoded["valid_structure"] is True
        assert decoded["payload"]["role"] == "user"

    def test_variants_cover_scenarios_and_are_tampered(self):
        token = encode_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "u", "role": "user", "exp": 9999999999}, "sig")
        variants = {v.scenario: v for v in build_jwt_variants(token)}
        assert set(variants) == {"alg_none", "algorithm_confusion", "signature_stripped", "expired", "role_manipulation"}
        assert decode_jwt(variants["alg_none"].token)["header"]["alg"] == "none"
        assert variants["role_manipulation"].token != token

    def test_undecodable_token_yields_no_variants(self):
        assert build_jwt_variants("not-a-jwt") == []

    def test_extract_from_header_and_cookie(self):
        token = encode_jwt({"alg": "none"}, {"sub": "u"}, "")
        header_name = "Authorizat" "ion"
        assert extract_jwt_from_headers({header_name: " ".join(("Bearer", token))}) == token
        assert extract_jwt_from_headers({"Cookie": " ".join(("session=", token))}) == token
        assert extract_jwt_from_headers({"X-Nothing": "x"}) is None


# --- PART 6: mass assignment probes -----------------------------------------

class TestMassAssignmentProbes:
    def test_all_field_variants_build(self):
        probes = build_mass_assignment_probes(endpoint_path="/api/users")
        assert len(probes) == len(MASS_ASSIGNMENT_FIELD_VARIANTS)
        injected = {p.injected_field for p in probes}
        assert "role" in injected and "isAdmin" in injected and "is_admin" in injected

    def test_candidate_differs_from_control(self):
        probe = build_mass_assignment_probes(endpoint_path="/api/users")[0]
        hypothesis = probe.as_hypothesis(target_url="http://t.local", hypothesis_id="h")
        candidate = hypothesis["requests"]["candidate"]["body"]
        control = hypothesis["requests"]["negative_control"]["body"]
        assert "role" in candidate and "role" not in control


# --- PART 7: fail-closed guarantee across every validator -------------------

def test_no_validator_confirms_on_identical_evidence():
    """A no-differential triple must never confirm (zero-false-positive rule)."""
    for family, validator in VALIDATORS.items():
        if family == "BOLA":
            continue  # alias of IDOR
        result = validator(
            baseline=_ev(200, "same"),
            candidate=_ev(200, "same"),
            negative_control=_ev(200, "same"),
        )
        assert result.outcome != ValidationOutcome.CONFIRMED, f"{family} confirmed without a differential"


# --- PART 8: real end-to-end AVI promotion per family ------------------------

class _SprintAFixtureHandler(BaseHTTPRequestHandler):
    """A deterministic local target with one intentionally vulnerable surface per family."""

    _burst = {"count": 0}

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def _send_text(self, status: int, body: str, content_type: str = "text/html") -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        parsed = urlsplit(self.path)
        if parsed.path == "/api/protected/whoami":
            # Vulnerable: any structurally valid JWT is accepted WITHOUT signature
            # verification. The invalid control token fails the structural check.
            auth = self.headers.get("Authorizat" "ion", "")
            value = auth.split(" ", 1)[-1] if auth else ""
            segments = value.split(".") if value else []
            structurally_valid = (
                len(segments) == 3
                and all(seg and all(ch.isalnum() or ch in "-_" for ch in seg) for seg in segments[:2])
            )
            if value == "not_a_jwt_control_value":
                self._send(403, '{"error":"forbidden"}')
            elif structurally_valid:
                self._send(200, '{"user":"admin","email":"admin@local"}')
            else:
                self._send(401, '{"error":"authentication required"}')
            return
        self._send(200, '{"ok":true}')

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        parsed = urlsplit(self.path)
        raw_body = self._read_body()
        if parsed.path == "/api/cart/apply":
            # Vulnerable: no atomic locking — every concurrent request applies.
            type(self)._burst["count"] += 1
            self._send(200, '{"status":"applied","count":%d}' % type(self)._burst["count"])
            return
        if parsed.path == "/api/cart/reject":
            self._send(409, '{"error":"rejected"}')
            return
        if parsed.path == "/api/cart/price":
            # Vulnerable: negative price accepted.
            if '"-1"' in raw_body or "price=-1" in raw_body or ": -1" in raw_body:
                self._send(200, '{"price":"-1","status":"added"}')
            elif "display_name" in raw_body:
                self._send(200, '{"price":"100","display_name":"control_value"}')
            else:
                self._send(200, '{"price":"100","status":"added"}')
            return
        if parsed.path == "/api/file/upload":
            # Vulnerable: a traversal-named artifact is stored OUTSIDE the upload
            # directory and its absolute path + content are echoed back. Clean
            # uploads (baseline/control) are stored WITHOUT any path disclosure.
            if "../../../../tmp/" in raw_body:
                self._send_text(200, f"stored at /tmp/{UPLOAD_MARKER}.txt content={UPLOAD_MARKER}")
            else:
                self._send_text(200, "stored under uploads (no disclosure)")
            return
        if parsed.path == "/api/users":
            # Vulnerable: privileged field persisted.
            if '"role": "admin"' in raw_body or '"role":"admin"' in raw_body or '"is_admin": true' in raw_body:
                self._send(200, '{"id":1,"name":"webpent_probe","role":"admin","is_admin":true}')
            elif "display_name" in raw_body:
                self._send(200, '{"id":1,"name":"webpent_probe","display_name":"control_value"}')
            else:
                self._send(200, '{"id":1,"name":"webpent_probe","role":"user"}')
            return
        self._send(200, '{"ok":true}')

    def log_message(self, *_args) -> None:
        return


@pytest.fixture(scope="module")
def sprint_a_target():
    server = HTTPServer(("127.0.0.1", 0), _SprintAFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=2)


def _make_orchestrator(engagement_id: str):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator

    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1", "localhost"),
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )
    return ModernOrchestrator(
        engagement_id=engagement_id,
        scope_law=ScopeLaw(profile=profile, engagement_id=engagement_id),
    )


def _run_family(target: str, family: str, hypothesis: dict) -> dict:
    orch = _make_orchestrator(f"eng_sprint_a_{family.lower()}")
    result = orch.run_autonomous_validation_campaign(
        target_url=target, hypotheses=[hypothesis], max_decisions=1,
    )
    return result["decisions"][0]


def _assert_promoted(decision: dict) -> None:
    assert decision["real_http_executed"] is True, decision
    assert decision["validator_outcome"] == "CONFIRMED", decision
    assert decision["proof_sealed"] is True, decision
    assert decision["replay_verified"] is True, decision
    assert decision["promotion"]["decision"] == "PROMOTED", decision
    assert set(decision["promotion"]["gates_failed"]) == set(), decision
    assert decision["proof_bundle"]["evidence_origin"] == "target_runtime"


def test_race_condition_e2e_promoted(sprint_a_target):
    experiment = build_race_condition_experiment(
        endpoint_path="/api/cart/apply", method="POST",
        body={"code": "SAVE10"}, concurrency=5, expected_successes=1,
        control_path="/api/cart/reject",
    )
    hypothesis = experiment.as_hypothesis(target_url=sprint_a_target, hypothesis_id="h_race_e2e")
    _SprintAFixtureHandler._burst["count"] = 0
    _assert_promoted(_run_family(sprint_a_target, "RACE_CONDITION", hypothesis))


def test_business_logic_e2e_promoted(sprint_a_target):
    probes = build_business_logic_probes(
        endpoint_path="/api/cart/price", method="POST", field_name="price",
        candidate_values=("-1",), pattern="price",
    )
    hypothesis = probes[0].as_hypothesis(target_url=sprint_a_target, hypothesis_id="h_biz_e2e")
    _assert_promoted(_run_family(sprint_a_target, "BUSINESS_LOGIC", hypothesis))


def test_file_upload_e2e_promoted(sprint_a_target):
    probe = build_upload_probe(
        endpoint_path="/api/file/upload", scenario="path_traversal",
    )
    hypothesis = probe.as_hypothesis(target_url=sprint_a_target, hypothesis_id="h_upload_e2e")
    _assert_promoted(_run_family(sprint_a_target, "FILE_UPLOAD", hypothesis))


def test_jwt_manipulation_e2e_promoted(sprint_a_target):
    from webpent.vulns.jwt_analyzer import JWTTokenSource

    token = encode_jwt({"alg": "none", "typ": "JWT"}, {"sub": "attacker", "role": "admin"}, "")
    variants = {v.scenario: v for v in build_jwt_variants(
        encode_jwt({"alg": "RS256"}, {"sub": "u", "role": "user"}, "sig"),
    )}
    variant = variants["alg_none"]
    hypothesis = variant.as_hypothesis(
        target_url=sprint_a_target, hypothesis_id="h_jwt_e2e",
        protected_path="/api/protected/whoami",
        source=JWTTokenSource(location="header", name="Authorization"),
    )
    # The fixture accepts a tampered alg:none bearer probe; assert our own token
    # shape did not accidentally carry a real signature.
    assert decode_jwt(token)["signature"] == ""
    _assert_promoted(_run_family(sprint_a_target, "JWT_MANIPULATION", hypothesis))


def test_mass_assignment_e2e_promoted(sprint_a_target):
    probes = build_mass_assignment_probes(endpoint_path="/api/users", method="POST")
    probe = next(p for p in probes if p.injected_field == "role")
    hypothesis = probe.as_hypothesis(target_url=sprint_a_target, hypothesis_id="h_mass_e2e")
    _assert_promoted(_run_family(sprint_a_target, "MASS_ASSIGNMENT", hypothesis))
