from webpent.shared.exceptions import ToolExecutionError
from webpent.shared.redaction import redact_text, redact_value


def test_redact_text_removes_common_secret_forms():
    text = (
        "Authorization: Bearer bearer-secret Cookie: sid=cookie-secret; "
        "password=plain-password token=plain-token api_key=plain-key"
    )
    redacted = redact_text(text)
    assert "bearer-secret" not in redacted
    assert "cookie-secret" not in redacted
    assert "plain-password" not in redacted
    assert "plain-token" not in redacted
    assert "plain-key" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_value_preserves_diagnostic_shape():
    value = {"cmd": ["tool", "--token=secret"], "nested": ("password=secret", 7)}
    redacted = redact_value(value)
    assert redacted["cmd"][0] == "tool"
    assert "secret" not in str(redacted)
    assert redacted["nested"][1] == 7


def test_tool_execution_error_does_not_leak_secrets():
    error = ToolExecutionError(
        cmd=["curl", "-H", "Authorization: Bearer command-secret"],
        returncode=7,
        stdout="Cookie: sid=stdout-secret",
        stderr="password=stderr-secret",
        message="request failed token=message-secret",
    )
    rendered = str(error)
    assert "command-secret" not in rendered
    assert "stdout-secret" not in rendered
    assert "stderr-secret" not in rendered
    assert "message-secret" not in rendered
    assert "[REDACTED]" in rendered
