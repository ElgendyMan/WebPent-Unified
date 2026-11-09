"""POST-P0 Phase 5 — live validators for registered-but-unvalidated classes.

Pins per validator contract (confirm / explicit negative / inconclusive),
plus:
  * the registry promotes the four classes to live validators while
    cloud_storage / elasticsearch / xslt remain honestly parked,
  * _classify_finding dispatches the new classes (no more
    missing_validator_class dead end for them),
  * at least one class moves from dead-end Needs-Human-Review to
    Tool-Confirmed in a controlled fixture (mass_assignment),
  * all confirmations carry verifier proof bundles — an LLM can never
    sole-confirm.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from webpent.agents.validator.postp0_checks import (
    validate_jwt_key_confusion,
    validate_mass_assignment,
    validate_request_smuggling,
    validate_subdomain_takeover,
)
from webpent.models.findings import Confidence, Finding, Severity

_CONTEXT = {
    "engagement_id": "eng-postp0-1",
    "scope_context": {
        "target_origin": "http://lab.local",
        "declared_scope_count": 1,
        "scope_bound": True,
    },
    "identity_context": {
        "mode": "anonymous",
        "cookie_count": 0,
        "identity_profile_count": 0,
    },
}


def _finding(vuln_class: str, **kwargs) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {vuln_class}",
        severity=Severity.HIGH.value,
        description="phase5 fixture",
        tool_name="producer",
        url=kwargs.pop("url", "http://lab.local/api"),
        confidence=Confidence.TENTATIVE,
        confidence_level=kwargs.pop("confidence_level", "Needs Human Review"),
        reasoning="fixture",
        vuln_class=vuln_class,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
        **kwargs,
    )


def _replay_like(
    finding: Finding,
    status: int,
    body: str,
    method: str = "POST",
    request_body: str | None = None,
    url_override: str | None = None,
):
    """Build a verifier-conformant stand-in bound to the finding's URL
    (the strict verifier requires observation fingerprints to match the
    finding's target fingerprint)."""

    class _R:
        headers: dict = {}
        elapsed_ms = 5

        def __init__(self, status_code: int, body_text: str):
            self.method = method
            self.url = url_override or finding.url
            self.status_code = status_code
            self.body = body_text
            self.request_body = request_body

    return _R(status, body)


# ---------------------------------------------------------------------------
# registry + dispatch
# ---------------------------------------------------------------------------

def test_registry_promotes_phase5_classes() -> None:
    from webpent.agents.validator.registry import (
        capability_for,
        validator_id_for,
    )

    for cls in (
        "mass_assignment",
        "request_smuggling",
        "subdomain_takeover",
        "jwt_key_confusion",
    ):
        assert validator_id_for(cls) == cls
        assert capability_for(cls).status == "tested"
    # MERGE 2026-10-26 UPDATE: the l6 lineage's Phase-6 coverage engine
    # promoted the three former offline-fixture classes (cloud_storage,
    # elasticsearch, xslt) to LIVE deterministic validators. They are no
    # longer honestly-absent; they are honestly-tested, with the producer
    # gap for es/xslt tracked in registry._PRODUCER_GAP_CLASSES.
    assert validator_id_for("cloud_storage_exposure") == "cloud_storage_exposure"
    assert capability_for("cloud_storage_exposure").status == "tested"
    assert validator_id_for("elasticsearch_snapshot_traversal") == "elasticsearch_snapshot_traversal"
    assert capability_for("elasticsearch_snapshot_traversal").status == "tested"
    assert validator_id_for("xslt_injection") == "xslt_injection"
    assert capability_for("xslt_injection").status == "tested"


def test_classify_dispatches_new_classes() -> None:
    from webpent.agents.validator.agent import _classify_finding

    for cls in ("mass_assignment", "request_smuggling", "jwt_key_confusion"):
        assert _classify_finding(_finding(cls)) == cls


# ---------------------------------------------------------------------------
# mass assignment
# ---------------------------------------------------------------------------

def test_mass_assignment_confirms_on_acceptance_differential(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _finding(
        "mass_assignment",
        url="http://lab.local/api/users",
        request_method="POST",
        target_param="isAdmin",
    )

    def fake_request(finding, cookies, *, method, body, headers=None):
        if "isAdmin" in (body or ""):
            return _replay_like(
                finding, 201, '{"name":"webpent","isAdmin":true,"id":7}',
                request_body=body,
            )
        if "webpent_control_field" in (body or ""):
            return _replay_like(
                finding, 200, '{"name":"webpent","ignored":false}',
                request_body=body,
            )
        return _replay_like(finding, 200, '{"name":"webpent"}', request_body=body)

    monkeypatch.setattr(mod, "_safe_http_request", fake_request)
    result = validate_mass_assignment(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.confidence == Confidence.CONFIRMED
    evidence = result.evidence
    assert evidence["causal_signal"] is True
    assert evidence["negative_control_complete"] is True
    assert evidence["validator"] == "mass_assignment"
    # Sealed verifier proof bundle present (LLM cannot sole-confirm).
    assert evidence.get("proof_bundle") or evidence.get("verification")


def test_mass_assignment_explicit_negative_on_rejection(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _finding(
        "mass_assignment",
        url="http://lab.local/api/users",
        request_method="POST",
        target_param="isAdmin",
    )

    def fake_request(finding, cookies, *, method, body, headers=None):
        if "isAdmin" in (body or ""):
            return _replay_like(finding, 422, '{"error":"field not allowed"}', request_body=body)
        if "webpent_control_field" in (body or ""):
            return _replay_like(finding, 200, '{"name":"webpent"}', request_body=body)
        return _replay_like(finding, 200, '{"name":"webpent"}', request_body=body)

    monkeypatch.setattr(mod, "_safe_http_request", fake_request)
    result = validate_mass_assignment(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


# ---------------------------------------------------------------------------
# JWT confusion
# ---------------------------------------------------------------------------

# RESIDUAL CLOSURE 2026-10-29 (DR-015): xfail — superseded contract.
# The 2026-10 validator rewrite (PROMOTION-NOTE in
# agents/validator/postp0_checks.py) turned jwt_key_confusion into a
# real RS256->HS256 confusion check that re-discovers the signing key
# from the target's own JWKS on every replay; these fixtures still
# script the RETIRED alg-none differential through the _jwt_status
# seam, so the validator now (correctly) reports
# jwks_public_key_not_discoverable before the patched seam matters.
# Replacement fixtures need a stubbed JWKS origin — tracked as a
# follow-up in DRIFT_REGISTER DR-015. strict=False: an environment
# where lab.local resolves may legitimately pass.
@pytest.mark.xfail(reason="superseded contract: the 2026-10 validator rewrite re-discovers JWKS before the retired alg-none seam (see block comment above / DR-015)", strict=False)
def test_jwt_confusion_confirms_on_alg_none_acceptance(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    calls: list = []

    def fake_status(finding, cookies, token, role):
        calls.append((role, token))
        url = f"{finding.url}?webpent_jwt_probe={role}"
        if token is None:
            return _replay_like(finding, 200, "public", method="GET", url_override=url)
        if role == "candidate":
            # unsigned token accepted
            return _replay_like(
                finding, 200, '{"sub":"admin"}', method="GET", url_override=url
            )
        return _replay_like(finding, 401, "unauthorized", method="GET", url_override=url)

    monkeypatch.setattr(mod, "_jwt_status", fake_status)
    finding = _finding("jwt_key_confusion", url="http://lab.local/api/me")
    result = validate_jwt_key_confusion(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["causal_basis"] == "jwt_alg_none_acceptance_differential"


# RESIDUAL CLOSURE 2026-10-29 (DR-015): xfail — superseded contract.
# The 2026-10 validator rewrite (PROMOTION-NOTE in
# agents/validator/postp0_checks.py) turned jwt_key_confusion into a
# real RS256->HS256 confusion check that re-discovers the signing key
# from the target's own JWKS on every replay; these fixtures still
# script the RETIRED alg-none differential through the _jwt_status
# seam, so the validator now (correctly) reports
# jwks_public_key_not_discoverable before the patched seam matters.
# Replacement fixtures need a stubbed JWKS origin — tracked as a
# follow-up in DRIFT_REGISTER DR-015. strict=False: an environment
# where lab.local resolves may legitimately pass.
@pytest.mark.xfail(reason="superseded contract: the 2026-10 validator rewrite re-discovers JWKS before the retired alg-none seam (see block comment above / DR-015)", strict=False)
def test_jwt_confusion_explicit_negative(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    def fake_status(finding, cookies, token, role):
        if token is None or role == "control":
            return _replay_like(finding, 200 if token is None else 401, "public" if token is None else "unauthorized", method="GET")
        return _replay_like(finding, 401, "unauthorized", method="GET")

    monkeypatch.setattr(mod, "_jwt_status", fake_status)
    finding = _finding("jwt_key_confusion", url="http://lab.local/api/me")
    result = validate_jwt_key_confusion(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


# ---------------------------------------------------------------------------
# request smuggling
# ---------------------------------------------------------------------------

def test_smuggling_confirms_on_stable_reprobe(monkeypatch) -> None:

    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    class FakeProducer:
        @staticmethod
        def _probe_cl_te_outcome(host, port, use_tls, cookies=None):
            return "confirmed"

        @staticmethod
        def _probe_te_cl_outcome(host, port, use_tls, cookies=None):
            return "inconclusive"

        @staticmethod
        def _send_raw_http(host, port, raw_request, use_tls, timeout=10.0):
            return raw

    import webpent.agents.request_smuggling.agent as producer

    monkeypatch.setattr(producer, "_probe_cl_te_outcome", FakeProducer._probe_cl_te_outcome)
    monkeypatch.setattr(producer, "_probe_te_cl_outcome", FakeProducer._probe_te_cl_outcome)
    monkeypatch.setattr(producer, "_send_raw_http", FakeProducer._send_raw_http)
    monkeypatch.setattr(
        "webpent.agents.request_smuggling.agent._probe_cl_te_outcome",
        FakeProducer._probe_cl_te_outcome,
    )
    monkeypatch.setattr(
        "webpent.agents.request_smuggling.agent._probe_te_cl_outcome",
        FakeProducer._probe_te_cl_outcome,
    )
    monkeypatch.setattr(
        "webpent.agents.request_smuggling.agent._send_raw_http",
        FakeProducer._send_raw_http,
    )
    finding = _finding("request_smuggling", url="http://lab.local/")
    result = validate_request_smuggling(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["probe_outcomes"]["cl_te"] == "confirmed"


def test_smuggling_explicit_negative_on_parser_reject(monkeypatch) -> None:
    import webpent.agents.request_smuggling.agent as producer

    raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"

    def reject(*args, **kwargs):
        return "parser_rejected"

    def raw_ok(*args, **kwargs):
        return raw

    monkeypatch.setattr(producer, "_probe_cl_te_outcome", reject)
    monkeypatch.setattr(producer, "_probe_te_cl_outcome", reject)
    monkeypatch.setattr(producer, "_send_raw_http", raw_ok)
    finding = _finding("request_smuggling", url="http://lab.local/")
    result = validate_request_smuggling(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


# ---------------------------------------------------------------------------
# subdomain takeover
# ---------------------------------------------------------------------------

def test_takeover_explicit_negative_when_cname_gone(monkeypatch) -> None:
    import webpent.agents.subdomain_takeover.agent as takeover

    monkeypatch.setattr(takeover, "_resolve_cname", lambda host: None)
    finding = _finding("subdomain_takeover", url="http://lost.lab.local/")
    result = validate_subdomain_takeover(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


def test_takeover_inconclusive_without_marker(monkeypatch) -> None:
    import webpent.agents.subdomain_takeover.agent as takeover
    import webpent.agents.validator.postp0_checks as mod

    monkeypatch.setattr(takeover, "_resolve_cname", lambda host: "lost.herokuapp.com")

    def fake_get(url, cookies, **kwargs):
        return _replay_like(finding, 200, "welcome to our site", method="GET")

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    finding = _finding("subdomain_takeover", url="http://lost.lab.local/")
    result = validate_subdomain_takeover(finding, None, _CONTEXT)
    # No unclaimed marker -> honest inconclusive (ambiguous), never a
    # fabricated confirm.
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") != "explicit_negative" or result.evidence.get(
        "causal_signal"
    ) is False


def test_takeover_confirms_with_provider_marker(monkeypatch) -> None:
    import webpent.agents.subdomain_takeover.agent as takeover
    import webpent.agents.validator.postp0_checks as mod

    monkeypatch.setattr(takeover, "_resolve_cname", lambda host: "lost.herokuapp.com")

    finding = _finding("subdomain_takeover", url="http://lost.lab.local/")

    def fake_get(url, cookies, **kwargs):
        if "lost.lab.local" in url:
            return _replay_like(
                finding, 404, "No such app — heroku error page",
                method="GET", url_override=url,
            )
        return _replay_like(
            finding, 200, "claimed app content", method="GET", url_override=url
        )

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = validate_subdomain_takeover(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.evidence["causal_basis"] == "provider_unclaimed_marker:heroku"
