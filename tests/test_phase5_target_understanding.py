from webpent.graph import builder


def test_smart_mode_routes_through_target_understanding(monkeypatch):
    monkeypatch.setattr(builder, "_target_understanding_enabled", lambda: False)

    assert (
        builder.route_after_infrastructure({"smart_mode": True})
        == builder.NODE_TARGET_UNDERSTANDING
    )


def test_legacy_mode_keeps_scope_route_when_target_understanding_disabled(monkeypatch):
    monkeypatch.setattr(builder, "_target_understanding_enabled", lambda: False)

    assert builder.route_after_infrastructure({}) == builder.NODE_SCOPE_ENFORCER


def test_explicit_target_understanding_flag_still_routes_legacy_scan(monkeypatch):
    monkeypatch.setattr(builder, "_target_understanding_enabled", lambda: True)

    assert builder.route_after_infrastructure({}) == builder.NODE_TARGET_UNDERSTANDING
