from webpent.shared.capability_manifest import CapabilityRegistry


def test_capability_registry_discovers_lazily_and_returns_safe_diagnostics(monkeypatch):
    calls = []

    def fake_builder(settings=None):
        calls.append(settings)
        return {
            "profile": "safe-smart",
            "capabilities": {
                "browser": {"available": False, "status": "infrastructure_failure"},
            },
            "blockers": [{"capability": "browser", "reason": "infrastructure_failure"}],
            "fail_closed": True,
        }

    monkeypatch.setattr(
        "webpent.shared.capability_manifest._build_capability_manifest", fake_builder
    )
    registry = CapabilityRegistry()
    assert calls == []
    assert registry.available("browser") is False
    assert len(calls) == 1
    assert registry.available("browser") is False
    assert len(calls) == 1
    assert registry.diagnostics() == {
        "profile": "safe-smart",
        "capabilities": ["browser"],
        "blocker_count": 1,
        "fail_closed": True,
    }


def test_capability_registry_emits_typed_blocker_with_fallback(monkeypatch):
    monkeypatch.setattr(
        "webpent.shared.capability_manifest._build_capability_manifest",
        lambda settings=None: {
            "profile": "safe-smart",
            "capabilities": {},
            "blockers": [],
            "fail_closed": True,
        },
    )
    blocker = CapabilityRegistry().blocker("browser", reason="chromium_missing")
    assert blocker == {
        "kind": "capability_blocker",
        "capability": "browser",
        "status": "unknown_capability",
        "reason": "chromium_missing",
        "fallback": "human_review_only",
        "fail_closed": True,
    }
    assert CapabilityRegistry().get("unknown") == {
        "available": False,
        "status": "unknown_capability",
    }


def test_capability_registry_does_not_treat_malformed_manifest_as_available(monkeypatch):
    monkeypatch.setattr(
        "webpent.shared.capability_manifest._build_capability_manifest",
        lambda settings=None: {"capabilities": {"http_read": "yes"}, "fail_closed": True},
    )
    registry = CapabilityRegistry()
    assert registry.available("http_read") is False
    assert registry.blocker("http_read")["fallback"] == "safe_stop"


assert CapabilityRegistry.__name__ == "CapabilityRegistry"


def test_coverage_intelligence_exposes_report_safe_gaps_only():
    from webpent.shared.coverage_ledger import CoverageIntelligence

    state = {
        "campaign_ledger": {
            "entries": [
                {"id": 1, "key": "idor", "status": "not_scanned", "gaps": []},
                {"id": 2, "key": "xss", "status": "clean", "gaps": []},
            ]
        },
        "proof_outcomes": [],
        "campaign_task_outcomes": [],
    }
    intelligence = CoverageIntelligence()
    projection = intelligence.project(state)
    assert projection["source"] == "coverage_intelligence_projection"
    assert [item["key"] for item in intelligence.gaps(state)] == ["idor"]
    assert projection["entries"][1]["status"] == "clean"
