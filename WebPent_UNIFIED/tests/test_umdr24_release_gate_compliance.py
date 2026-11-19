"""UM-DR-24 (2026-11-06) — post-window release-gate compliance pins.

Running the FULL 14-gate release chain (RELEASE_PROCESS.md §1) on the
post-window tree exposed four red gates that the per-phase windows (which
run the frozen gate + test-count + coverage ratchet subsets) had not
exercised end-to-end. This file pins each closure so none of them can
silently regress:

1. state-contract law — the three OAST correlation channels the M3
   UM-DR-17 node writes ARE declared on PentestState, with the advisory
   reducer semantics documented in state.py;
2. the oast_correlation_node's fail-soft returns write ONLY declared keys;
3. vault import authority — auth/worker_session_factory.py is the
   reviewed Table 2-2 call site (UM-DR-17 seam, deliberate-review route);
4. secret scan — every UM-DR-24 waive key is present with a reason;
5. build-info honesty — the committed suite_count stays coherent with the
   recorded floor and carries the re-freeze evidence statement.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import re
import sys
import types
from pathlib import Path
from typing import Annotated, get_args, get_origin, get_type_hints

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"

OAST_KEYS = (
    "oast_correlation_status",
    "oast_sessions_armed",
    "oast_candidate_findings",
)


def _load_script(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"umdr24_{name}", REPO / "scripts" / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(f"umdr24_{name}", module)
    # the gate scripts parse sys.argv at module level — isolate them from
    # pytest's argv during load
    saved_argv = sys.argv
    sys.argv = [str(spec.origin)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    return module


def _run_gate_main(module: types.ModuleType) -> int:
    """Run a gate script's main() with pytest's argv kept out of it."""
    saved_argv = sys.argv
    sys.argv = [str(module.__file__)]
    try:
        return int(module.main())
    finally:
        sys.argv = saved_argv


def _declared_state_keys() -> dict[str, str]:
    """The state-contract law's own declaration parser (single source)."""
    checker = _load_script("check_state_contract")
    return checker.declared_state_keys()


# ---------------------------------------------------------------------------
# 1 — the state-contract law closure
# ---------------------------------------------------------------------------


def test_oast_channels_declared_on_penteststate() -> None:
    declared = _declared_state_keys()
    for key in OAST_KEYS:
        assert key in declared, (
            f"{key} must be declared on PentestState — the state-contract "
            "law refuses node-written undeclared keys"
        )


def test_oast_channel_reducer_semantics() -> None:
    from webpent.state.reducers import merge_lists
    from webpent.state.state import PentestState

    hints = get_type_hints(PentestState, include_extras=True)
    candidates = hints["oast_candidate_findings"]
    assert get_origin(candidates) is Annotated, (
        "oast_candidate_findings must carry an explicit reducer annotation"
    )
    assert merge_lists in get_args(candidates)[1:], (
        "oast_candidate_findings accumulates with merge_lists (the "
        "detector_results precedent — advisory candidates, validator authority)"
    )
    for scalar in ("oast_correlation_status", "oast_sessions_armed"):
        hint = hints[scalar]
        assert get_origin(hint) is not Annotated, (
            f"{scalar} is a per-run scalar: last-write-wins (no reducer), "
            "matching scope_compile_status / dynamic_step_budget precedent"
        )


def test_oast_node_fail_soft_paths_write_only_declared_keys() -> None:
    declared = set(_declared_state_keys())
    import webpent.graph.oast_nodes as oast_nodes

    # flag-off path (the real default settings: enable_oast is fail-closed False)
    result_off = oast_nodes.oast_correlation_node({})
    assert result_off == {"oast_correlation_status": "disabled"}
    assert set(result_off) <= declared

    # enabled-but-unavailable path (local provider default ⇒ honest refusal)
    stub = types.SimpleNamespace(
        enable_oast=True,
        oob_provider="local",
        interactsh_binary="interactsh-client",
        interactsh_server="",
        interactsh_token="",
        oob_poll_timeout_seconds=5.0,
        oob_poll_max_attempts=3,
        audit_secret_key="",
    )
    original_get_settings = oast_nodes.get_settings
    try:
        oast_nodes.get_settings = lambda: stub  # type: ignore[assignment]
        result_unavailable = oast_nodes.oast_correlation_node({})
    finally:
        oast_nodes.get_settings = original_get_settings  # type: ignore[assignment]
    assert result_unavailable == {"oast_correlation_status": "provider_unavailable"}
    assert set(result_unavailable) <= declared


# ---------------------------------------------------------------------------
# 2 — the vault-import authority closure
# ---------------------------------------------------------------------------


def test_identity_runner_seam_is_the_reviewed_table_2_2_site() -> None:
    checker = _load_script("check_vault_import_authority")
    seam = checker.ROOT / "src" / "webpent" / "auth" / "worker_session_factory.py"
    assert seam in checker.TABLE_2_2_ALLOWLIST, (
        "the ق7 identity runner's vault-bridging seam must stay on the "
        "reviewed Table 2-2 allowlist (UM-DR-24 deliberate-review route)"
    )
    # the two adjudicated import sites are exactly the seam's design:
    # unseal what the worker sealed + mirror the sealing key shape
    source = seam.read_text(encoding="utf-8")
    assert "from webpent.auth.reauth_vault import unseal_identity_profiles" in source
    assert "from webpent.auth.reauth_vault import identity_vault_key" in source
    # and the gate itself passes on the current tree
    assert _run_gate_main(checker) == 0


# ---------------------------------------------------------------------------
# 3 — the secret-scan closure
# ---------------------------------------------------------------------------

UMDR24_WAIVE_KEYS = [
    ("docs/operator_credentials.example.json", "generic-secret-assignment", "b21a59b583df"),
    ("tests/test_identity_ladder_r6.py", "generic-secret-assignment", "b49becdcb9f5"),
    ("tests/test_identity_ladder_r6.py", "generic-secret-assignment", "b6e078b05e54"),
    ("tests/test_login_validation_r6.py", "generic-secret-assignment", "846e1dc41c51"),
    ("tests/test_js_discovery.py", "generic-secret-assignment", "d673a09878ca"),
    ("tests/test_js_discovery.py", "generic-secret-assignment", "89c1fbb9cbe4"),
    ("tests/test_secrets_scanner.py", "slack-token", "ac99401cc098"),
    ("tests/test_secrets_scanner.py", "private-key-block", "8bcac7908eb9"),
    ("tests/test_m3_js_ast_reversing.py", "generic-secret-assignment", "7922426647f4"),
    ("tests/test_m3_research_wiring.py", "generic-secret-assignment", "61d8f162d42c"),
    ("tests/auth/test_identity_orchestrator.py", "generic-secret-assignment", "ee7a7258cc70"),
    ("tests/jsintel/test_api_surface_shadow.py", "generic-secret-assignment", "fd4b4fbd8b8e"),
]


def test_umdr24_secret_waives_present_with_reasons() -> None:
    data = json.loads(
        (REPO / "scripts" / "quality" / "secrets_allowlist.json").read_text(encoding="utf-8")
    )
    entries = {
        (e["file"], e["rule"], e["fingerprint"]): e for e in data.get("allowlist", [])
    }
    for key in UMDR24_WAIVE_KEYS:
        entry = entries.get(key)
        assert entry is not None, f"missing UM-DR-24 waive key: {key}"
        assert str(entry.get("reason", "")).strip(), f"waive without a reason: {key}"


def test_secret_scan_passes_on_current_tree() -> None:
    checker = _load_script("check_secrets")
    assert _run_gate_main(checker) == 0, "secret scan must report 0 detections"


# ---------------------------------------------------------------------------
# 3b — the dependency-CVE gate harness fix (UM-DR-24)
# ---------------------------------------------------------------------------


def test_deps_gate_offline_evaluation_path_passes() -> None:
    """The harness defect fix: pip-audit rc=1 ('findings') was conflated
    with 'could not run' (rc=2 abort), which silently skipped the
    allowlist/waive accounting. The documented offline mode
    (--input <recorded release scan>) must evaluate and PASS: every
    recorded vulnerability is waived with a documented reason."""
    checker = _load_script("check_deps_gate")
    saved_argv = sys.argv
    sys.argv = [str(checker.__file__), "--input", "docs/pip_audit_release.json"]
    try:
        assert checker.main() == 0, (
            "the recorded release scan's findings must all be allow-listed"
        )
    finally:
        sys.argv = saved_argv


def test_deps_gate_run_pip_audit_semantics() -> None:
    """run_pip_audit must treat a parseable report as a successful audit
    (pip-audit exits 1 when findings exist) and abort ONLY on no report."""
    import subprocess as _subprocess

    checker = _load_script("check_deps_gate")
    report = {"dependencies": [{"name": "x", "version": "1", "vulns": []}]}

    class _Proc:
        def __init__(self, rc: int, out: str) -> None:
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    original_run = checker.subprocess.run
    try:
        # rc=1 WITH a parseable report = successful audit with findings
        checker.subprocess.run = lambda *a, **k: _Proc(
            1, json.dumps(report)
        )  # type: ignore[assignment]
        assert checker.run_pip_audit() == report
        # rc=1 with NO report = true harness failure → fail-closed abort
        checker.subprocess.run = lambda *a, **k: _Proc(
            1, ""
        )  # type: ignore[assignment]
        try:
            checker.run_pip_audit()
            raise AssertionError("missing report must SystemExit(2)")
        except SystemExit as exc:
            assert exc.code == 2
    finally:
        checker.subprocess.run = original_run  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# 4 — the build-info honesty closure (committed numbers' coherence)
# ---------------------------------------------------------------------------


def test_build_info_suite_count_coherent_with_collected_reality() -> None:
    """The honesty gate's rule-5 band, pinned: suite_count never inflates
    past collected reality and never lags it by more than 200 (the same
    probe scripts/check_build_info_honesty.py runs)."""
    info = json.loads((REPO / "BUILD_INFO.json").read_text(encoding="utf-8"))
    count = info["suite_count"]
    assert isinstance(count, int) and count > 0
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    real = None
    for line in reversed(collected.splitlines()):
        match = re.match(r"^(\d+) tests? collected", line.strip())
        if match:
            real = int(match.group(1))
            break
    assert real is not None, "collection probe must produce a count line"
    assert count <= real, f"suite_count {count} must not exceed collected reality {real}"
    assert real - count <= 200, (
        f"suite_count {count} lags collected reality {real} — the declared "
        "BUILD_INFO re-freeze ritual re-fires (UM-DR-24 precedent)"
    )
    # UM-DR-28 strengthening: the original assertion pinned the literal
    # string 'UM-DR-24' — prose of ONE window — so every legitimate
    # later re-freeze (UM-DR-25/26/27...) broke the gate unless it
    # gratuitously mentioned UM-DR-24 (the UM-DR-27 re-freeze did not,
    # and its own suite run preceded the re-freeze commit, so the
    # regression escaped that window's evidence). The actual INVARIANT
    # is: the evidence statement names its drift-register window AND
    # that window exists in DRIFT_REGISTER.md. This is strictly
    # STRONGER in the meaningful dimension (existence verified against
    # the ledger, not a hardcoded name).
    import re as _re

    window_names = sorted(set(_re.findall(r"UM-DR-\d+", info["suite_evidence"])))
    assert window_names, (
        "the re-freeze evidence statement must name its drift-register window"
    )
    drift_text = (REPO / "DRIFT_REGISTER.md").read_text(encoding="utf-8")
    for window in window_names:
        assert window in drift_text, (
            f"the evidence statement names window {window}, which does NOT "
            "exist in DRIFT_REGISTER.md — the ritual's provenance is broken"
        )


def test_refreeze_script_declares_exactly_state_py() -> None:
    """The DR-009 discipline: the declared change set is pinned, not prose."""
    script = (REPO / "scripts" / "refreeze_manifest_umdr24_release_gates.py").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"WINDOW_CHANGED_FILES\s*=\s*\[(?P<body>[^\]]*)\]", script, re.DOTALL
    )
    assert match is not None, "refreeze script must declare WINDOW_CHANGED_FILES"
    declared = re.findall(r'"([^"]+)"', match.group("body"))
    assert declared == ["src/webpent/state/state.py"], (
        f"UM-DR-24 declares exactly one frozen change, got {declared}"
    )
