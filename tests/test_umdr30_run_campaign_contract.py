"""UM-DR-30 — run_campaign.sh must wrap the REAL CLI contract.

The wrapper was built against a CLI interface that no longer exists
(--target/--scope/--credentials-file/--artifact-root) — it failed at the
first flag before any pre-flight value mattered (the 0.34.2 backlog
"run_campaign.sh rewrite", closed here). This suite pins the fixed
contract mechanically:

1. SYNTAX — bash -n parses the script.
2. FLAG CONTRACT — every ``--flag`` the script passes to
   ``webpent.cli hunt`` exists in the CLI's real help signature (a
   future CLI change that breaks the wrapper fails HERE, not in an
   operator's terminal).
3. SECURITY POSTURE — the authorization mandate is mirrored at the
   wrapper level (required env, no default), the URL scheme gate is
   present, and the POC blocks are preserved.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_campaign.sh"


def _script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _cli_help_signature() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "webpent.cli", "hunt", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert result.returncode == 0, f"CLI hunt --help failed: {result.stderr[-400:]}"
    return result.stdout


def _script_cli_flags() -> set[str]:
    """Extract the flags the script passes to the hunt invocation."""
    text = _script_text()
    # long flags inside CLI_ARGS+=(--flag ...) and the final invocation
    flag_re = (
        r"--(?:url|authorization|scope-file|authorization-manifest"
        r"|engagement-id|creds|cookies|no-llm)\b"
    )
    flags: set[str] = set()
    for m in re.finditer(flag_re, text):
        flags.add(m.group(0))
    return flags


class TestSyntax:
    def test_bash_n_parses(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"bash -n failed: {result.stderr}"


class TestFlagContract:
    def test_every_script_flag_exists_in_the_real_cli(self) -> None:
        help_text = _cli_help_signature()
        script_flags = _script_cli_flags()
        assert script_flags, "no CLI flags found in the script — extraction broken"
        missing = sorted(f for f in script_flags if f not in help_text)
        assert not missing, (
            f"run_campaign.sh passes flags the real CLI does not accept: {missing}"
        )

    def test_stale_flags_are_gone(self) -> None:
        """The flags that broke the wrapper must not come back — scoped
        to the ``webpent.cli hunt`` invocation (``--artifact-root`` is a
        valid flag of the POC scripts, not of the hunt CLI). Comments and
        the header docstring may reference the history — only the
        executable lines carry the contract."""
        executable = "\n".join(
            line for line in _script_text().splitlines() if not line.lstrip().startswith("#")
        )
        # the hunt invocation line and the CLI_ARGS assembly lines
        hunt_context = "\n".join(
            line
            for line in executable.splitlines()
            if "webpent.cli hunt" in line or "CLI_ARGS+=(" in line
        )
        for stale in ("--target", "--credentials-file", "--artifact-root", '"--scope"'):
            assert stale not in hunt_context, f"stale hunt flag reappeared: {stale}"

    def test_required_cli_mandates_are_assembled(self) -> None:
        """The CLI hard-requires --url and --authorization; the wrapper
        must assemble both."""
        text = _script_text()
        assert '--url "$TARGET_URL"' in text
        assert '--authorization "$AUTHORIZATION_REF"' in text


class TestSecurityPosture:
    def test_authorization_is_required_at_the_wrapper_level(self) -> None:
        text = _script_text()
        assert ': "${AUTHORIZATION_REF:?set AUTHORIZATION_REF' in text
        # no default authorization value — the mandate cannot be bypassed
        assert 'AUTHORIZATION_REF:-' not in text

    def test_target_url_scheme_gate_present(self) -> None:
        text = _script_text()
        assert "http://*|https://*" in text

    def test_poc_blocks_preserved(self) -> None:
        text = _script_text()
        assert "poc_smoke_real_browser.py" in text
        assert "poc_watcher.py" in text
        assert "WEBPENT_POC_ENABLED" in text

    def test_referenced_scripts_exist(self) -> None:
        for name in (
            "scripts/poc_smoke_real_browser.py",
            "scripts/poc_watcher.py",
            "scripts/verify_campaign.sh",
            "scripts/export_findings.sh",
        ):
            assert (ROOT / name).exists(), f"referenced script missing: {name}"
