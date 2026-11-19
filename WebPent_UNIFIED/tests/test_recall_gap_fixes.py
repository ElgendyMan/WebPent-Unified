from __future__ import annotations

from webpent.production.experiment_fabric import normalize_observation
from webpent.production.validators import ValidationOutcome, validate_idor
from webpent.recon.payload_advisor import PayloadAdvice, advice_mapping


def _evidence(status: int, body: str) -> dict:
    return {"status_code": status, "response_body": body, "headers": {}}


def test_idor_accepts_juice_shop_200_null_invalid_resource_control() -> None:
    owner = '{"status":"success","data":{"Products":[{"id":1}]}}'
    invalid = '{"status":"success","data":null}'
    result = validate_idor(
        baseline=_evidence(200, owner),
        candidate=_evidence(200, owner),
        negative_control=_evidence(200, invalid),
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_html_search_payload_mapping_uses_executable_script_fallback() -> None:
    mapping = advice_mapping(
        [
            PayloadAdvice(
                route="/search?q=",
                parameter="q",
                family="XSS",
                payload_id="xss_script_marker",
                payload_value="webpent_xss_probe_7f1",
            )
        ]
    )
    selected = mapping["/search?q=|q|XSS"]
    assert selected["payload_id"] == "xss_script_tag"
    assert selected["source"] == "payload_library_compatibility_fallback"
    assert selected["payload_value"] == "<script>alert(1)</script>"


def test_normalized_observation_preserves_safe_request_metadata() -> None:
    normalized = normalize_observation(
        "exp_test",
        "candidate",
        {
            "status_code": 200,
            "response_body": '{"data":null}',
            "headers": {"content-type": "application/json"},
            "structured_fields": {"json_data_null": True},
            "request_url": "http://127.0.0.1:3000/rest/basket/99999999",
        },
    )
    assert normalized.request_url.endswith("/rest/basket/99999999")
    assert normalized.structured_fields["json_data_null"] is True
    assert normalized.redacted_body == '{"data":null}'
    non_enveloped = normalize_observation(
        "exp_test", "baseline", {"status_code": 200, "response_body": '{"id":1}', "headers": {}}
    )
    assert non_enveloped.structured_fields.get("json_data_null", False) is False
