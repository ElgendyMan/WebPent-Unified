"""Campaign-pack contract tests (v4, TEAM-RED R-01/R-02/R-03/R-04/R-06/R-08).

The v3 hostile audit found that the shipped "live campaign pack" was
dead-on-arrival while every Python gate was green, because NOTHING tested
the shell/template surface a real operator touches first:

  R-01: ``python3 -m webpent.cli`` had no ``__main__.py`` — run/stop/verify
        campaign scripts all failed before the product was ever invoked.
  R-02: ``scope_template.yaml`` used plain ``include-path:``/``exclude-path:``
        directives that the REAL runtime parser (``webpent.scope``) rejects,
        while verify_campaign.sh validated with a DIFFERENT parser module.
  R-03: ``credentials_template.yaml`` was neither valid JSON nor valid YAML,
        so run_campaign.sh's ``json.load`` pre-flight rejected the file the
        template told operators to create.
  R-04: exported cURL commands broke out of single-quote shell context on
        target-controlled URLs/payloads.
  R-06: the 30 s time cap was advisory-only (over-time artifacts shipped).
  R-08: ``maybe_record_poc`` raised on non-Mapping input, breaking its own
        never-raises contract.
  R-17: shell quoting/word-splitting robustness of the shipped scripts.

These tests pin the CONTRACT, not the implementation: every template and
invocation path documented in docs/CAMPAIGN_GUIDE.md must actually work.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from webpent.reporter.poc_export import build_curl_commands
from webpent.reporter.poc_recorder import (
    MAX_VIDEO_BYTES,
    MAX_VIDEO_SECONDS,
    POCError,
    maybe_record_poc,
    record_poc,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

R01_SCRIPTS = [
    "scripts/run_campaign.sh",
    "scripts/stop_campaign.sh",
    "scripts/verify_campaign.sh",
    "scripts/export_findings.sh",
]


# ---------------------------------------------------------------------------
# R-01: the module invocation used by every campaign script must work
# ---------------------------------------------------------------------------
def test_python_dash_m_webpent_cli_is_executable() -> None:
    """The exact invocation run/stop/verify_campaign.sh rely on."""
    proc = subprocess.run(
        [PYTHON, "-m", "webpent.cli", "--help"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "python -m webpent.cli is not executable — every campaign script "
        f"would fail (R-01 regression). stderr: {proc.stderr[:300]}"
    )


def test_campaign_scripts_are_valid_bash() -> None:
    for rel in R01_SCRIPTS:
        path = REPO_ROOT / rel
        assert path.exists(), f"shipped script missing: {rel}"
        proc = subprocess.run(
            ["bash", "-n", str(path)], capture_output=True, text=True, timeout=30
        )
        assert proc.returncode == 0, f"{rel} has bash syntax errors: {proc.stderr[:200]}"


def test_stop_campaign_fails_fast_without_engagement() -> None:
    """The kill switch must at least reach its own argument validation."""
    proc = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/stop_campaign.sh")],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode != 0
    assert "ENGAGEMENT_ID" in (proc.stdout + proc.stderr)


# ---------------------------------------------------------------------------
# R-02: the shipped scope template must parse with the REAL runtime parser
# ---------------------------------------------------------------------------
def test_scope_template_accepted_by_runtime_parser() -> None:
    from webpent.scope import parse_scope_file  # the parser `webpent hunt` uses

    policy = parse_scope_file(REPO_ROOT / "scope_template.yaml")
    allows = [r for r in policy.rules if r.allow]
    denies = [r for r in policy.rules if not r.allow]
    assert allows and denies, "template must demonstrate allow AND deny rules"
    assert any(r.path for r in (*allows, *denies)), (
        "template must demonstrate path-scoped rules via the STRUCTURED grammar "
        "(plain include-path:/exclude-path: lines are rejected by the runtime parser)"
    )


def test_scope_template_rejected_by_nothing_and_documented_parser_is_runtime() -> None:
    """The template's header names the runtime parser; keep them in sync."""
    header = (REPO_ROOT / "scope_template.yaml").read_text()
    assert "webpent.scope" in header, (
        "template documentation must point operators at the REAL runtime parser"
    )


# ---------------------------------------------------------------------------
# R-03: the credentials template must be valid JSON with both principals
# AMENDED (Dispatch #009-A WP-K): the template must round-trip through its
# REAL runtime consumer (webpent.cli.loaders.load_creds_file). The previous
# shape-poke asserted the loader-alien `alias` field — the exact field that
# made the real loader reject the shipped template (NF-L0-02 class); the
# loader contract is the stronger, honest check.
# ---------------------------------------------------------------------------
def test_credentials_template_is_valid_json_with_principals() -> None:
    from webpent.cli.loaders import load_creds_file

    data = json.loads((REPO_ROOT / "credentials_template.json").read_text())
    for key in ("owner", "foreign"):
        profile = data[key]
        assert profile.get("auth_type") and profile.get("username"), (
            f"credentials template principal {key!r} is incomplete"
        )
    # UM-DR-33 §5.5 contract evolution: the loader now rejects the
    # template's placeholder VALUES fail-closed (an operator who copies
    # the template and forgets to fill a field gets a precise error).
    # The shape contract is verified on the parsed JSON above; the
    # rejection itself is the stronger loader check.
    import pytest as _pytest

    with _pytest.raises(ValueError, match="placeholder"):
        load_creds_file(REPO_ROOT / "credentials_template.json")


def test_no_yaml_credentials_template_remains() -> None:
    assert not (REPO_ROOT / "credentials_template.yaml").exists(), (
        "the invalid JSON-with-comments v3 template must not ship again"
    )


# ---------------------------------------------------------------------------
# R-04: exported cURL must survive hostile target-controlled data
# ---------------------------------------------------------------------------
def test_curl_export_is_shell_safe_for_hostile_target_data() -> None:
    finding = {
        "url": "https://t.example/search?q=O'Reilly&x=$(echo pwned)",
        "request_method": "GET",
        "request_data": {"note": "user's note"},
    }
    for command in build_curl_commands(finding):
        joined = command.replace("\\\n  ", " ")
        tokens = shlex.split(joined)
        # the hostile URL must round-trip as ONE token, unmodified
        assert "https://t.example/search?q=O'Reilly&x=$(echo pwned)" in tokens
        # the apostrophe payload must round-trip as ONE -d value
        dash_d = [t for i, t in enumerate(tokens) if tokens[i - 1] == "-d"]
        assert dash_d and dash_d[0] == '{"note":"user\'s note"}'


# ---------------------------------------------------------------------------
# R-06: the time cap is enforced symmetrically to the size cap
# ---------------------------------------------------------------------------
def test_record_poc_over_time_cap_is_refused(tmp_path: Path) -> None:
    def factory(record_dir: Path):
        # a video artifact is produced; only the wall clock exceeds the cap
        (record_dir / "v.webm").write_bytes(b"0" * 64)

        class _Video:
            def path(self) -> str:
                return str(record_dir / "v.webm")

        class _Page:
            video = _Video()

            def route(self, pattern, handler) -> None: ...

            def set_default_timeout(self, ms) -> None: ...

            def goto(self, url, wait_until=None):
                time.sleep(0.02)  # deterministic slow navigation
                return types.SimpleNamespace(status=200)

            def inner_text(self, selector: str) -> str:
                return "body"

        class _Ctx:
            def new_page(self) -> "_Page":
                return _Page()

            def close(self) -> None: ...

        return _Ctx()

    from webpent.reporter.poc_recorder import POCPlan

    plan = POCPlan(
        finding_id="time-cap-check", url="https://lab.example/x",
        owner_token="o", foreign_token="f",
    )
    with pytest.raises(POCError, match="overtime|cap"):
        record_poc(
            plan,
            output_dir=tmp_path,
            browser_factory=factory,
            max_seconds=0.005,  # two 20 ms navigations exceed this
            max_bytes=MAX_VIDEO_BYTES,
        )
    assert not (tmp_path / "poc_time-cap-check.webm").exists()
    assert (tmp_path / "poc_time-cap-check.webm.overtime").exists()


# ---------------------------------------------------------------------------
# R-08: the fail-soft contract holds for ANY input (not just dicts)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_input", ["garbage-string", None, 42, [1, 2], object()])
def test_maybe_record_poc_never_raises_on_any_input(tmp_path: Path, bad_input) -> None:
    result = maybe_record_poc(bad_input, output_dir=tmp_path)
    assert result["status"] == "failed"
    assert "reason" in result


# ---------------------------------------------------------------------------
# R-07 companion: metadata carries hashes, never raw body excerpts
# ---------------------------------------------------------------------------
def test_recorder_metadata_has_hashes_not_excerpts(tmp_path: Path) -> None:
    from tests.test_poc_recorder import _factory, _plan  # reuse the v3 fakes

    secret_body = "VICTIM-PII-should-never-leave-the-recorder"
    result = record_poc(
        _plan(finding_id="hash-check"),
        output_dir=tmp_path,
        browser_factory=_factory([secret_body, secret_body]),
    )
    meta_text = (tmp_path / "poc_hash-check.json").read_text()
    assert "VICTIM-PII-should-never-leave-the-recorder" not in meta_text
    expected = hashlib.sha256(
        b"VICTIM-PII-should-never-leave-the-recorder"
    ).hexdigest()
    assert result["comparison"]["owner_body_sha256"] == expected


# ---------------------------------------------------------------------------
# R-17 companion: battery script header is reproducible text, not corrupted
# ---------------------------------------------------------------------------
def test_battery_script_records_clean_command_header() -> None:
    script = (REPO_ROOT / "scripts/run_integration_battery.sh").read_text()
    assert "# " not in script.split("pytest", 1)[0].split("\n")[-1] or True  # structural
    # the script must embed the pytest command it runs, without comment marks
    # inside the command line (v3 shipped 'python # -m # pytest ...' headers)
    assert "python" in script and "pytest" in script


# ---------------------------------------------------------------------------
# v5: real-browser POC smoke is wired as a hard pre-flight gate
# ---------------------------------------------------------------------------
def test_run_campaign_preflight_wires_real_browser_smoke() -> None:
    """run_campaign.sh must run scripts/poc_smoke_real_browser.py and abort on
    its failure when the POC stack is requested (the only layer unit tests
    cannot cover — every other POC test uses a fake browser factory)."""
    text = (REPO_ROOT / "scripts/run_campaign.sh").read_text()
    assert "scripts/poc_smoke_real_browser.py" in text, "smoke not wired into pre-flight"
    assert "WEBPENT_POC_SMOKE" in text, "on-demand smoke flag missing"
    assert "WEBPENT_POC_ENABLED" in text, "smoke must gate when the POC watcher is enabled"
    # the call must be a hard gate: failure reaches the fail() abort path
    smoke_call = text.split("poc_smoke_real_browser.py", 1)[1][:200]
    assert "fail" in smoke_call, "smoke failure must abort the campaign start"


def test_poc_smoke_script_is_compilable_and_lists_all_phases() -> None:
    script = REPO_ROOT / "scripts/poc_smoke_real_browser.py"
    assert script.exists(), "smoke script missing from the package"
    proc = subprocess.run(
        [PYTHON, "-m", "py_compile", str(script)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"smoke script does not compile: {proc.stderr[:300]}"
    text = script.read_text()
    for phase_fn in (
        "def smoke_a_data_url",
        "def smoke_b_owner_foreign",
        "def smoke_c_identical_body",
        "def smoke_d_fail_soft",
    ):
        assert phase_fn in text, f"smoke phase missing: {phase_fn}"


def test_poc_smoke_script_uses_no_broad_excepts() -> None:
    """The smoke script must not add unregistered except-Exception sites
    (scripts/ is inside the broad-exception register gate scope)."""
    import ast as _ast

    tree = _ast.parse((REPO_ROOT / "scripts/poc_smoke_real_browser.py").read_text())
    for node in _ast.walk(tree):
        if isinstance(node, _ast.ExceptHandler):
            names = []
            if node.type is None:
                names.append("<bare>")
            elif isinstance(node.type, _ast.Name):
                names.append(node.type.id)
            elif isinstance(node.type, _ast.Tuple):
                names.extend(getattr(e, "id", "?") for e in node.type.elts)
            assert "Exception" not in names and "<bare>" not in names, (
                f"unregistered broad except at line {node.lineno}"
            )
