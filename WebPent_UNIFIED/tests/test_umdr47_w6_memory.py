"""UM-DR-47 Phase W6 — the cross-campaign research memory store.

The 47 prompt W6: "Research Memory is loaded at the start of the
campaign and saved at its end — with negative privacy tests (no
secrets or sessions cross campaigns)."

These tests prove exactly that on real cookie-shaped input.
"""
from __future__ import annotations

import json
import os

from webpent.production.research_memory_store import (
    load_research_memory,
    research_memory_demotion_classes,
    save_research_memory,
    scrub_for_memory,
    target_memory_key,
)


class TestStore:
    def test_save_then_load_roundtrip(self, tmp_path):
        path = save_research_memory(
            "https://shop.example/api",
            demotion_classes=["idor", "auth_bypass"],
            fp_causes=["status-200-on-foreign-read"],
            lesson_summaries=["idors refuted on /api/orders"],
            store_dir=str(tmp_path),
        )
        assert path and os.path.isfile(path)
        record = load_research_memory("https://shop.example/api", str(tmp_path))
        assert record["demotion_classes"] == ["idor", "auth_bypass"]
        assert record["revision"] == 1
        assert record["fp_causes"] == ["status-200-on-foreign-read"]

    def test_merge_is_append_only_by_class(self, tmp_path):
        save_research_memory(
            "https://t.example", demotion_classes=["idor"], store_dir=str(tmp_path))
        save_research_memory(
            "https://t.example", demotion_classes=["idor", "sqli"],
            store_dir=str(tmp_path))
        record = load_research_memory("https://t.example", str(tmp_path))
        assert record["demotion_classes"] == ["idor", "sqli"]
        assert record["revision"] == 2

    def test_different_targets_do_not_cross(self, tmp_path):
        save_research_memory(
            "https://a.example", demotion_classes=["idor"], store_dir=str(tmp_path))
        other = load_research_memory("https://b.example", str(tmp_path))
        assert other == {}

    def test_missing_store_fails_closed(self, tmp_path):
        assert load_research_memory("https://none.example", str(tmp_path)) == {}
        assert research_memory_demotion_classes("https://none.example", str(tmp_path)) == frozenset()

    def test_target_key_scheme_host_normalized(self):
        assert target_memory_key("https://shop.example/") == target_memory_key("https://shop.example")
        assert target_memory_key("https://shop.example") != target_memory_key("https://other.example")


class TestPrivacyScrub:
    """The W6 negative privacy tests — real cookie-shaped input."""

    def test_no_cookie_value_survives_key_level(self):
        scrubbed = scrub_for_memory({
            "session": "SESS-A-VALUE-1234",
            "cookie": "session=SESS-A-VALUE-1234",
            "authorization": "Bearer abc.def.ghi",
            "api_key": "sk-12345",
            "password": "hunter2",
            "safe_field": "plain value",
        })
        assert "SESS-A-VALUE-1234" not in json.dumps(scrubbed)
        assert "abc.def.ghi" not in json.dumps(scrubbed)
        assert "sk-12345" not in json.dumps(scrubbed)
        assert "hunter2" not in json.dumps(scrubbed)
        assert scrubbed["safe_field"] == "plain value"

    def test_no_cookie_shaped_string_survives(self):
        scrubbed = scrub_for_memory(
            "replay with cookie header session=SESS-B-9876; other=1")
        assert "SESS-B-9876" not in scrubbed

    def test_save_scrubs_real_lab_cookies(self, tmp_path):
        # the REAL lab cookie discipline from the batteries
        save_research_memory(
            "https://shop.example",
            lesson_summaries=[
                "foreign replay used Cookie: session=SESS-A-7f3d1 "
                "and Authorization: Bearer tok-982",
            ],
            patterns={"session_cookie": "session=SESS-A-7f3d1",
                      "headers": {"Authorization": "Bearer tok-982"}},
            store_dir=str(tmp_path),
        )
        raw = open(
            os.path.join(str(tmp_path), target_memory_key("https://shop.example") + ".json"),
            encoding="utf-8",
        ).read()
        assert "SESS-A-7f3d1" not in raw
        assert "tok-982" not in raw


class TestLearnedContextSeam:
    """W6 load: the demotion classes reach the strategist's seam."""

    def test_retrieve_merges_w6_classes_when_flag_on(self, tmp_path, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.shared.learned_context import (
            negative_outcome_classes,
            retrieve_learned_strategy,
        )

        save_research_memory(
            "https://shop.example", demotion_classes=["idor"],
            store_dir=str(tmp_path))
        monkeypatch.setenv("WEBPENT_RESEARCH_MEMORY_DIR", str(tmp_path))
        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)

        class _Stub:
            def search_lessons(self, *a, **k):
                return []

            def get_structured_hypotheses(self, *a, **k):
                return []

        learned = retrieve_learned_strategy(
            target_url="https://shop.example",
            client_id="c1", engagement_id="e1", manager=_Stub(),
        )
        assert learned is not None
        assert "idor" in negative_outcome_classes(learned)
        assert learned["research_memory"]["source"] == "umdr47-w6"

    def test_flag_off_keeps_the_46_behavior(self, tmp_path, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.shared.learned_context import (
            negative_outcome_classes,
            retrieve_learned_strategy,
        )

        save_research_memory(
            "https://shop.example", demotion_classes=["idor"],
            store_dir=str(tmp_path))
        monkeypatch.setenv("WEBPENT_RESEARCH_MEMORY_DIR", str(tmp_path))
        monkeypatch.setattr(get_settings(), "enable_brain_engine", False)

        class _Stub:
            def search_lessons(self, *a, **k):
                return []

            def get_structured_hypotheses(self, *a, **k):
                return []

        learned = retrieve_learned_strategy(
            target_url="https://shop.example",
            client_id="c1", engagement_id="e1", manager=_Stub(),
        )
        assert learned is not None
        assert "idor" not in negative_outcome_classes(learned)
        assert "research_memory" not in learned
