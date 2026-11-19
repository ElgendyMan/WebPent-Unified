"""M1-A (M-2) regression: katana crawl scope must be PINNED, not inherited
from katana's defaults.

Contract (M1_READINESS_REVIEW §2.2):
  * the built argv must contain an explicit ``-fs fqdn`` field-scope
    (crawl exactly the seed host);
  * no scope-widening switch (``-ns`` / ``-no-scope``) may appear;
  * the seed-host allowlist gate and the post-invocation result filter
    stay in place (their own C4 tests live in test_v10_audit_fixes.py).
"""
from __future__ import annotations

import json

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)


def test_katana_argv_pins_fqdn_field_scope(monkeypatch):
    """The argv contract pins -fs fqdn; no -ns/-no-scope widening."""
    from webpent.tools.recon import katana as katana_mod

    captured: dict[str, object] = {}

    def fake_run_command(cmd, timeout=None, **kwargs):
        captured["cmd"] = list(cmd)
        # one JSONL line: an endpoint on the seed host
        record = {"request": {"endpoint": "http://target.test/a"}, "url": "http://target.test/a"}
        return json.dumps(record)

    monkeypatch.setattr(katana_mod, "run_command", fake_run_command)
    token = set_engagement_target_hosts("http://target.test")
    try:
        endpoints = katana_mod.run_katana("http://target.test", depth=1)
    finally:
        clear_engagement_target_hosts(token)

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    argv = [str(part) for part in cmd]
    # explicit field scope == the seed FQDN only
    assert "-fs" in argv, "M-2 REGRESSION: katana argv lost the explicit -fs switch"
    fs_value = argv[argv.index("-fs") + 1]
    assert fs_value == "fqdn", (
        f"M-2 REGRESSION: katana field scope is {fs_value!r}, expected 'fqdn'"
    )
    # scope-widening switches must never appear
    assert "-ns" not in argv and "-no-scope" not in argv
    # seed gate + post filter still in the source (belt)
    import inspect

    source = inspect.getsource(katana_mod.run_katana)
    assert "is_engagement_target_host" in source
    assert endpoints == ["http://target.test/a"]
