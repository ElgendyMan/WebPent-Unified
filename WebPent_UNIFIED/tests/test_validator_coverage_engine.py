"""Validator coverage engine (Phase 6) — tests.

Covers the last three offline-fixture classes promoted to live
deterministic validators (postp0_checks.py, section 6):

  * cloud_storage_exposure          — bucket-listing marker differential
  * elasticsearch_snapshot_traversal — snapshot-JSON + identity differential
  * xslt_injection                  — benign stylesheet canary differential

Each validator is pinned across all outcomes: deterministic confirm
(sealed verifier proof bundle, LLM can never sole-confirm), explicit
negative, and inconclusive-when-the-control-is-not-clean.  Registry,
dispatch, and campaign posture transitions are asserted too: the
offline-fixture parking lot is empty and the classes route through the
same strict replay verifier as the Phase 5 promotions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.agents.validator.postp0_checks import _XSLT_CANARY
from webpent.models.findings import Confidence, Finding, Severity

_CONTEXT = {
    "engagement_id": "eng-coverage-engine-1",
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
        description="coverage-engine fixture",
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
    method: str = "GET",
    request_body: str | None = None,
    url_override: str | None = None,
):
    """Verifier-conformant stand-in bound to the given URL (defaults to
    the finding's URL so observation fingerprints match the target)."""

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
# registry / dispatch / campaign posture
# ---------------------------------------------------------------------------

def test_registry_promotes_coverage_engine_classes() -> None:
    from webpent.agents.validator.registry import (
        _OFFLINE_FIXTURE_VALIDATORS,
        capability_for,
        validator_id_for,
    )

    for cls in (
        "cloud_storage_exposure",
        "elasticsearch_snapshot_traversal",
        "xslt_injection",
    ):
        assert validator_id_for(cls) == cls
        cap = capability_for(cls)
        assert cap.status == "tested"
        assert cap.evidence_mode == "deterministic"
    # The offline-fixture parking lot is empty — nothing is left parked.
    assert _OFFLINE_FIXTURE_VALIDATORS == {}


def test_classify_dispatches_coverage_engine_classes() -> None:
    from webpent.agents.validator.agent import _classify_finding

    for cls in (
        "cloud_storage_exposure",
        "elasticsearch_snapshot_traversal",
        "xslt_injection",
    ):
        assert _classify_finding(_finding(cls)) == cls


def test_campaigns_no_longer_human_review_parked() -> None:
    from webpent.shared.campaigns import CAMPAIGN_HUMAN_REVIEW

    assert "elasticsearch_snapshot_traversal" not in CAMPAIGN_HUMAN_REVIEW
    assert "xslt_injection" not in CAMPAIGN_HUMAN_REVIEW
    assert frozenset() == CAMPAIGN_HUMAN_REVIEW


# ---------------------------------------------------------------------------
# cloud_storage_exposure
# ---------------------------------------------------------------------------

_BUCKET_LISTING = (
    '<?xml version="1.0"?><ListBucketResult>'
    "<Name>bucket</Name><Key>backups/db.sql</Key>"
    "</ListBucketResult>"
)

_CONTROL_BODY = '<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>'


def _cloud_finding() -> Finding:
    return _finding("cloud_storage_exposure", url="http://files.lab.local/bucket")


def test_cloud_storage_confirms_on_listing_differential(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _cloud_finding()

    def fake_get(url, cookies, *, headers=None):
        if "webpent-negative-control" in url:
            return _replay_like(finding, 200, _CONTROL_BODY, url_override=url)
        return _replay_like(finding, 200, _BUCKET_LISTING, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_cloud_storage_exposure(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.confidence == Confidence.CONFIRMED
    evidence = result.evidence
    assert evidence["causal_signal"] is True
    assert evidence["negative_control_complete"] is True
    assert evidence["causal_basis"] == "bucket_listing_marker_differential"
    # Sealed verifier proof bundle present (LLM cannot sole-confirm).
    assert evidence.get("proof_bundle") or evidence.get("verification")


def test_cloud_storage_explicit_negative_when_listing_gone(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _cloud_finding()

    def fake_get(url, cookies, *, headers=None):
        return _replay_like(finding, 404, "not found", url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_cloud_storage_exposure(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"
    assert result.evidence.get("causal_signal") is False


def test_cloud_storage_inconclusive_when_control_also_lists(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _cloud_finding()

    def fake_get(url, cookies, *, headers=None):
        # Even the random control path returns a listing body: the marker
        # match cannot be separated from the bucket path.
        return _replay_like(finding, 200, _BUCKET_LISTING, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_cloud_storage_exposure(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "inconclusive"
    assert result.evidence.get("negative_control_complete") is False


def test_cloud_storage_inconclusive_on_transport_failure(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _cloud_finding()
    monkeypatch.setattr(mod, "_safe_http_get", lambda *a, **k: None)
    result = mod.validate_cloud_storage_exposure(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("validation_unavailable") is True
    assert result.evidence.get("reason") == "replay_transport_failed"


# ---------------------------------------------------------------------------
# elasticsearch_snapshot_traversal
# ---------------------------------------------------------------------------

_ES_SNAPSHOT = (
    '{"repositories":[{"name":"backups"}],'
    '"cluster_name":"docker-cluster","cluster_uuid":"a1b2c3"}'
)
_ES_ERROR = '{"error":{"root_cause":[{"type":"index_not_found_exception"}]}}'


def _es_finding() -> Finding:
    return _finding(
        "elasticsearch_snapshot_traversal", url="http://lab.local:9200/_snapshot"
    )


def test_elasticsearch_confirms_on_snapshot_differential(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _es_finding()

    def fake_get(url, cookies, *, headers=None):
        if "_webpent-nonexistent-" in url:
            return _replay_like(finding, 404, _ES_ERROR, url_override=url)
        return _replay_like(finding, 200, _ES_SNAPSHOT, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_elasticsearch_snapshot_traversal(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.confidence == Confidence.CONFIRMED
    evidence = result.evidence
    assert evidence["causal_signal"] is True
    assert evidence["negative_control_complete"] is True
    assert evidence["causal_basis"] == "es_snapshot_json_differential"
    assert evidence.get("proof_bundle") or evidence.get("verification")


def test_elasticsearch_explicit_negative_when_signature_gone(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _es_finding()

    def fake_get(url, cookies, *, headers=None):
        return _replay_like(finding, 401, _ES_ERROR, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_elasticsearch_snapshot_traversal(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


def test_elasticsearch_identity_keys_required(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _es_finding()
    # Listing keys without cluster identity: could be any JSON-echoing
    # service, so the validator must NOT confirm.
    body_without_identity = '{"repositories":[{"name":"backups"}]}'

    def fake_get(url, cookies, *, headers=None):
        return _replay_like(finding, 200, body_without_identity, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_elasticsearch_snapshot_traversal(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


def test_elasticsearch_inconclusive_when_control_also_marked(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _es_finding()

    def fake_get(url, cookies, *, headers=None):
        # Wildcard/echo handler returns snapshot JSON everywhere.
        return _replay_like(finding, 200, _ES_SNAPSHOT, url_override=url)

    monkeypatch.setattr(mod, "_safe_http_get", fake_get)
    result = mod.validate_elasticsearch_snapshot_traversal(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "inconclusive"
    assert result.evidence.get("negative_control_complete") is False


# ---------------------------------------------------------------------------
# xslt_injection
# ---------------------------------------------------------------------------

_XSLT_PROBE = (
    '<?xml version="1.0"?><xsl:stylesheet version="1.0" '
    'xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
    f"<xsl:template match=\"/\"><xsl:value-of select=\"'{_XSLT_CANARY}'\"/>"
    "</xsl:template></xsl:stylesheet>"
)


def _xslt_finding() -> Finding:
    return _finding(
        "xslt_injection",
        url="http://lab.local/transform",
        request_method="POST",
        target_param="xslt_doc",
        request_data={"xslt_doc": "<old/>"},
    )


def test_xslt_confirms_on_canary_differential(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _xslt_finding()

    def fake_request(finding, cookies, *, method, body, headers=None, url_override=None):
        if _XSLT_CANARY in (body or ""):
            return _replay_like(
                finding, 200, f"<out>{_XSLT_CANARY}</out>", method="POST",
                request_body=body,
            )
        return _replay_like(
            finding, 200, "<out>static</out>", method="POST", request_body=body
        )

    monkeypatch.setattr(mod, "_safe_http_request", fake_request)
    result = mod.validate_xslt_injection(finding, None, _CONTEXT)
    assert result.confidence_level == "Tool-Confirmed"
    assert result.confidence == Confidence.CONFIRMED
    evidence = result.evidence
    assert evidence["causal_signal"] is True
    assert evidence["negative_control_complete"] is True
    assert evidence["causal_basis"] == "xslt_canary_differential"
    assert evidence.get("proof_bundle") or evidence.get("verification")


def test_xslt_explicit_negative_when_canary_absent(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _xslt_finding()

    def fake_request(finding, cookies, *, method, body, headers=None, url_override=None):
        return _replay_like(
            finding, 200, "<out>static</out>", method="POST", request_body=body
        )

    monkeypatch.setattr(mod, "_safe_http_request", fake_request)
    result = mod.validate_xslt_injection(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


def test_xslt_no_confirm_when_baseline_echoes_canary(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _xslt_finding()

    def fake_request(finding, cookies, *, method, body, headers=None, url_override=None):
        # A server that echoes any input would show the canary in the
        # baseline replay too — the differential must fail closed.
        return _replay_like(
            finding, 200, f"<out>{(body or '')[:40]}</out>", method="POST",
            request_body=body,
        )

    monkeypatch.setattr(mod, "_safe_http_request", fake_request)
    result = mod.validate_xslt_injection(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("outcome") == "explicit_negative"


def test_xslt_fails_closed_without_request_template() -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _finding("xslt_injection", url="http://lab.local/transform")
    result = mod.validate_xslt_injection(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("validation_unavailable") is True
    assert result.evidence.get("reason") == "no_replayable_request_template"


def test_xslt_inconclusive_on_replay_transport_failure(monkeypatch) -> None:
    import webpent.agents.validator.postp0_checks as mod

    finding = _xslt_finding()
    monkeypatch.setattr(mod, "_safe_http_request", lambda *a, **k: None)
    result = mod.validate_xslt_injection(finding, None, _CONTEXT)
    assert result.confidence_level != "Tool-Confirmed"
    assert result.evidence.get("reason") == "replay_transport_failed"
