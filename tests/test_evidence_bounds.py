from webpent.shared.grounding import capture_evidence_bundle


def test_evidence_bundle_redacts_sensitive_headers_and_body() -> None:
    bundle = capture_evidence_bundle(
        request_method="POST",
        request_url="https://target.test/api",
        request_headers={
            "Authorization": "Bearer super-secret",
            "Content-Type": "application/json",
        },
        request_body='password="top-secret"&value=ok',
        response_status_code=200,
        response_headers={"Set-Cookie": "session=secret-value"},
        response_body="token=private-token",
        tool_output="secret=tool-secret",
    )

    serialized = repr(bundle)
    assert "super-secret" not in serialized
    assert "top-secret" not in serialized
    assert "secret-value" not in serialized
    assert "private-token" not in serialized
    assert "tool-secret" not in serialized
    assert bundle["request"]["method"] == "POST"
    assert bundle["response"]["status_code"] == 200


def test_evidence_bundle_caps_persisted_text() -> None:
    body = "A" * 40_000
    output = "B" * 20_000
    bundle = capture_evidence_bundle(
        request_method="GET",
        request_url="https://target.test/large",
        request_body=body,
        response_body=body,
        tool_output=output,
    )

    request_body = bundle["request"]["body"]
    response_body = bundle["response"]["body"]
    tool_output = bundle["tool_output"]
    assert isinstance(request_body, str)
    assert isinstance(response_body, str)
    assert isinstance(tool_output, str)
    assert len(request_body) < len(body)
    assert len(response_body) < len(body)
    assert len(tool_output) < len(output)
    assert request_body.endswith("...[truncated at 32768 chars]")
    assert tool_output.endswith("...[truncated at 16384 chars]")


def test_evidence_bundle_keeps_none_values() -> None:
    bundle = capture_evidence_bundle(
        request_method="GET",
        request_url="https://target.test/empty",
    )
    assert bundle["request"]["body"] is None
    assert bundle["response"]["body"] is None
    assert bundle["tool_output"] is None
    assert bundle["response"]["headers"] == {}
