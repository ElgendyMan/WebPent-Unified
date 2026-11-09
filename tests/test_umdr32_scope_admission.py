"""UM-DR-32 §10.1 — origin scheme admission consistency (security regression).

The reviewed ``_admit_endpoint()`` extracted the campaign origin scheme
but compared only host and effective port: an authorized origin
``https://lab.example:443`` would admit a candidate endpoint
``http://lab.example:443/api/x`` because host and numeric port match.
Those are DIFFERENT origins. The fix requires the complete normalized
origin — scheme + host + effective port — to match.

This matrix is defense in depth at hypothesis admission; the
executor's authoritative scope enforcement is unchanged and must remain
the final gate.
"""
from __future__ import annotations

from typing import Any

from webpent.production.adaptive_research import (
    _admit_endpoint,
    _campaign_origin,
)


def _state(**extra: Any) -> dict[str, Any]:
    """Minimal campaign state with the standard lab base_url."""
    base = {
        "base_url": "https://shop.example.com",
        "target_url": "https://shop.example.com",
        "workflow_observations": [],
    }
    base.update(extra)
    return base


class TestOriginSchemeAdmission:
    """The complete normalized origin must match (scheme+host+port)."""

    def test_https_origin_rejects_http_endpoint_same_port(self) -> None:
        # the exact defect: host and numeric port match, scheme differs
        origin = _campaign_origin("https://lab.example:443")
        assert origin is not None
        admitted, reason = _admit_endpoint(
            "http://lab.example:443/api/x", origin, "https://lab.example:443",
        )
        assert admitted == ""
        assert reason.startswith("scheme_mismatch")

    def test_http_origin_rejects_https_endpoint_same_port(self) -> None:
        origin = _campaign_origin("http://lab.example:80")
        assert origin is not None
        admitted, reason = _admit_endpoint(
            "https://lab.example:80/api/x", origin, "http://lab.example:80",
        )
        assert admitted == ""
        assert reason.startswith("scheme_mismatch")

    def test_https_origin_rejects_http_default_port_endpoint(self) -> None:
        # https origin (implicit 443) vs http endpoint with EXPLICIT 443:
        # effective ports match numerically, schemes differ -> rejected
        origin = _campaign_origin("https://lab.example")
        assert origin == ("https", "lab.example", 443)
        admitted, reason = _admit_endpoint(
            "http://lab.example:443/api/x", origin, "https://lab.example",
        )
        assert admitted == ""
        assert reason.startswith("scheme_mismatch")

    def test_http_origin_rejects_https_default_port_endpoint(self) -> None:
        origin = _campaign_origin("http://lab.example")
        assert origin == ("http", "lab.example", 80)
        admitted, reason = _admit_endpoint(
            "https://lab.example/api/x", origin, "http://lab.example",
        )
        assert admitted == ""
        assert reason.startswith("scheme_mismatch")

    def test_same_scheme_admitted_with_explicit_default_port(self) -> None:
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint(
            "https://lab.example:443/api/x", origin, "https://lab.example",
        )
        assert admitted and not reason
        # normalization preserves the explicit port; origin equality was
        # already established via effective ports
        assert admitted.startswith("https://lab.example")

    def test_same_scheme_admitted_without_explicit_port(self) -> None:
        origin = _campaign_origin("https://lab.example:443")
        admitted, reason = _admit_endpoint(
            "https://lab.example/api/x", origin, "https://lab.example:443",
        )
        assert admitted and not reason

    def test_port_mismatch_still_rejected_same_scheme(self) -> None:
        origin = _campaign_origin("https://lab.example:443")
        admitted, reason = _admit_endpoint(
            "https://lab.example:8443/api/x", origin, "https://lab.example:443",
        )
        assert admitted == ""
        assert reason == "port_mismatch"

    def test_host_case_normalized_same_scheme(self) -> None:
        origin = _campaign_origin("https://LAB.Example.COM")
        admitted, reason = _admit_endpoint(
            "https://lab.example.com/api/x", origin, "https://LAB.Example.COM",
        )
        assert admitted and not reason
        assert "lab.example.com" in admitted

    def test_invalid_scheme_rejected(self) -> None:
        origin = _campaign_origin("https://lab.example")
        for endpoint in (
            "ftp://lab.example/api/x",
            "file:///etc/passwd",
            "gopher://lab.example/x",
        ):
            admitted, reason = _admit_endpoint(endpoint, origin, "https://lab.example")
            assert admitted == "", endpoint
            assert reason.startswith("scheme_not_http_s"), endpoint

    def test_scheme_like_relative_reference_joined_as_path(self) -> None:
        # "javascript:alert(1)" contains no "//" so it is joined as a
        # RELATIVE PATH segment under the campaign base — it never
        # reaches the executor as a javascript: scheme URL.
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint(
            "javascript:alert(1)", origin, "https://lab.example",
        )
        assert admitted.startswith("https://lab.example/javascript")
        assert not reason

    def test_malformed_url_rejected(self) -> None:
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint(
            "https://[::1:not-a-port/x", origin, "https://lab.example",
        )
        assert admitted == ""
        assert reason in {"malformed_url", "malformed_url_no_host"}

    def test_missing_origin_fails_closed(self) -> None:
        assert _campaign_origin("") is None
        assert _campaign_origin(None) is None  # type: ignore[arg-type]
        admitted, reason = _admit_endpoint("https://lab.example/api/x", None, "")
        assert admitted == ""
        assert reason == "no_campaign_origin"

    def test_relative_endpoint_resolved_through_base_url_scheme(self) -> None:
        # a relative reference inherits the campaign base scheme — the
        # join must produce an admitted absolute URL of the SAME scheme
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint(
            "/api/vaults/vlt_1", origin, "https://lab.example",
        )
        assert admitted.startswith("https://lab.example/api/vaults/vlt_1")
        assert not reason

    def test_relative_endpoint_without_base_rejected(self) -> None:
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint("/api/x", origin, "")
        assert admitted == ""
        assert reason == "no_campaign_origin"

    def test_empty_endpoint_rejected(self) -> None:
        origin = _campaign_origin("https://lab.example")
        admitted, reason = _admit_endpoint("", origin, "https://lab.example")
        assert admitted == ""
        assert reason == "empty_endpoint"


class TestSchemeAdmissionThroughInventory:
    """The fix must hold through the real research_signal_inventory path
    (the production caller of _admit_endpoint)."""

    def _wf(self, endpoint: str) -> dict[str, Any]:
        return {
            "fingerprint": "f" * 16,
            "endpoint": endpoint,
            "method": "POST",
            "authorization_boundary": "cross_identity",
            "scope_decision": "allowed",
        }

    def test_https_campaign_rejects_http_workflow_endpoint(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(
            base_url="https://lab.example:443",
            target_url="https://lab.example:443",
            workflow_observations=[self._wf("http://lab.example:443/api/x")],
        )
        inventory = research_signal_inventory(state)
        assert inventory["workflow_boundaries"] == []
        assert inventory["scope_violations"], "scheme mismatch must be recorded"
        assert inventory["scope_violations"][0]["reason"].startswith(
            "scheme_mismatch"
        )

    def test_https_campaign_accepts_https_workflow_endpoint(self) -> None:
        from webpent.production.adaptive_research import research_signal_inventory

        state = _state(
            base_url="https://lab.example:443",
            target_url="https://lab.example:443",
            workflow_observations=[self._wf("https://lab.example:443/api/x")],
        )
        inventory = research_signal_inventory(state)
        assert len(inventory["workflow_boundaries"]) == 1
        assert inventory["scope_violations"] == []
