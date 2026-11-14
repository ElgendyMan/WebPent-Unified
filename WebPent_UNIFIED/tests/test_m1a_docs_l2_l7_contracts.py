"""M1-A (L-2 + L-7) regression: documentation-backed contracts.

L-2: SMART_AUTO_APPROVE is an ActionAuthority shortcut ONLY — it must
     never remove the graph-level HITL interrupts (scope_review +
     execution_sandbox). Only the separate auto_approve compile flag
     does that, and it must stay orthogonal to SMART_AUTO_APPROVE.

L-7: WEBPENT_ALLOWED_EXECUTABLES governance is basename-based and the
     spawn resolves executables via PATH where the FIRST match wins —
     documented in .env.example and SECURITY.md.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_smart_auto_approve_keeps_hitl_interrupts(monkeypatch):
    """SMART_AUTO_APPROVE=true must NOT compile away interrupt_before."""
    import webpent.config.settings as settings_module
    from types import SimpleNamespace

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(smart_auto_approve=True),
    )
    from webpent.graph import builder as graph_builder

    # The compile site reads auto_approve (its own parameter), never
    # settings.smart_auto_approve — the two gates are orthogonal.
    import inspect

    source = inspect.getsource(graph_builder.build_graph)
    assert "smart_auto_approve" not in source, (
        "L-2 REGRESSION: build_graph consults smart_auto_approve — the "
        "HITL interrupts must be controlled ONLY by the auto_approve flag"
    )
    assert "interrupt_before=[NODE_SCOPE_REVIEW, NODE_EXECUTION_SANDBOX]" in source


def test_smart_auto_approve_documented_in_env_example():
    content = (REPO / ".env.example").read_text(encoding="utf-8")
    assert "SMART_AUTO_APPROVE" in content
    assert "HITL" in content


def test_executables_path_nuance_documented():
    env_content = (REPO / ".env.example").read_text(encoding="utf-8")
    security_content = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    for content, name in ((env_content, ".env.example"), (security_content, "SECURITY.md")):
        assert "WEBPENT_ALLOWED_EXECUTABLES" in content, f"L-7: missing note in {name}"
        assert "PATH" in content, f"L-7: PATH-order nuance missing in {name}"


def test_basename_allowlist_semantics():
    """The allowlist registers BASENAMES (the documented L-7 semantics)."""
    from webpent.tools.utils import subprocess as subprocess_module

    # a basename in the manifest passes even with a path prefix
    subprocess_module.validate_executable("/usr/bin/python3")  # basename matches
    # an arbitrary unregistered binary is rejected
    try:
        subprocess_module.validate_executable("/tmp/definitely-not-allowed-tool")
    except PermissionError:
        pass
    else:
        raise AssertionError("unregistered executable must be refused")
