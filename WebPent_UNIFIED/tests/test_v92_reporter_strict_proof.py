from types import SimpleNamespace

from test_v26_report_quality import _finding


def test_reporter_blocks_tool_confirmed_without_proof_bundle(monkeypatch):
    from webpent.agents.reporter import agent as reporter_agent

    monkeypatch.setattr(
        reporter_agent,
        "get_settings",
        lambda: SimpleNamespace(
            smart_require_proof_bundle=True,
            enable_report_quality_gate=False,
            enable_bug_bounty_reporter=False,
        ),
    )

    result = reporter_agent.reporter_node(
        {
            "target": {"url": "https://target.test"},
            "findings": [_finding()],
            "hypotheses": [],
            "proof_bundles": [],
        }
    )

    assert result["current_phase"] == "reporting"
    assert result["report_quality_gate"]["status"] == "blocked"
    assert "proof_bundle" in str(result["report_quality_gate"]).lower()
