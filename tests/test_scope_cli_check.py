from pathlib import Path

from typer.testing import CliRunner

from webpent.cli.commands import app


runner = CliRunner()


def test_scope_check_is_local_and_redacted(tmp_path: Path) -> None:
    policy = tmp_path / "scope.yaml"
    policy.write_text(
        """
in_scope:
  - url: https://api.example.test
out_of_scope:
  - url: https://api.example.test/private
""".lstrip(),
        encoding="utf-8",
    )

    allowed = runner.invoke(
        app,
        ["scope", "check", "--url", "https://api.example.test/v1/users", "--scope", str(policy)],
    )
    assert allowed.exit_code == 0, allowed.stdout
    assert '"allowed": true' in allowed.stdout
    assert '"status": "IN_SCOPE"' in allowed.stdout
    assert "private" not in allowed.stdout

    denied = runner.invoke(
        app,
        ["scope", "check", "--url", "https://api.example.test/private", "--scope", str(policy)],
    )
    assert denied.exit_code == 0, denied.stdout
    assert '"allowed": false' in denied.stdout
    assert '"violation_category": "explicit_out_of_scope"' in denied.stdout
