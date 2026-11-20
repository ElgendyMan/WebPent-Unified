# tests/test_cross_campaign.py
"""PROPOSALS_ULTIMATE_V2 §11 (2026-10-31) test suite: cross-campaign learning.

Covers the technique library (fail-closed load refusals: unreadable,
invalid encoding, invalid JSON, schema violations; flag-gated atomic
save; deterministic beta-style outcome recording; the remembering cap;
Laplace-smoothed success rates; deterministic top-k ordering; the
fail-soft flag-gated prompt hint consumed by the payload optimizer) and
the cross-campaign dedupe (tokenization with the weighted class token,
weighted Jaccard, registry check/annotate semantics that never drop,
merge or downgrade a finding, and fail-closed inventory load).
"""

from __future__ import annotations

import json

import pytest

from webpent.learning.technique_library import (
    LIBRARY_SCHEMA_VERSION,
    REMEMBERING_CAP,
    TechniqueLibraryError,
    empty_library,
    load_library,
    prompt_hint_for_finding,
    record_outcome,
    save_library,
    success_rate,
    top_payloads,
)
from webpent.learning.campaign_dedupe import (
    CLASS_TOKEN_WEIGHT,
    DEFAULT_THRESHOLD,
    InventoryError,
    CrossCampaignRegistry,
    annotate_finding,
    load_inventory,
    save_inventory,
    tokenize,
    weighted_jaccard,
)

# ---------------------------------------------------------------------------
# Technique library: load / save.
# ---------------------------------------------------------------------------


class TestLibraryLoadSave:
    def _write(self, tmp_path, doc, name="library.json"):
        p = tmp_path / name
        p.write_text(json.dumps(doc))
        return p

    def test_loads_valid_library(self, tmp_path):
        p = self._write(
            tmp_path,
            {
                "schema_version": LIBRARY_SCHEMA_VERSION,
                "entries": {
                    "xss|cloudflare|php": {
                        "payloads": {"<svg onload=alert(1)>": {"successes": 3, "failures": 1}}
                    }
                },
            },
        )
        lib = load_library(p)
        assert lib["schema_version"] == LIBRARY_SCHEMA_VERSION

    def test_empty_library_shape(self):
        lib = empty_library()
        assert lib["schema_version"] == LIBRARY_SCHEMA_VERSION
        assert lib["entries"] == {}

    def test_unreadable_refused(self, tmp_path):
        with pytest.raises(TechniqueLibraryError, match="technique_library_unreadable"):
            load_library(tmp_path / "missing.json")

    def test_invalid_json_refused(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{nope")
        with pytest.raises(TechniqueLibraryError, match="technique_library_invalid_json"):
            load_library(p)

    def test_invalid_encoding_refused(self, tmp_path):
        p = tmp_path / "bad.bin"
        p.write_bytes(b"\xff\xfe\x00broken")
        with pytest.raises(TechniqueLibraryError, match="technique_library_invalid_encoding"):
            load_library(p)

    def test_wrong_schema_version_refused(self, tmp_path):
        p = self._write(tmp_path, {"schema_version": 99, "entries": {}})
        with pytest.raises(TechniqueLibraryError, match="technique_library_schema"):
            load_library(p)

    def test_schema_violations_refused(self, tmp_path):
        bad_docs = (
            ["not", "an", "object"],
            {"schema_version": LIBRARY_SCHEMA_VERSION, "entries": []},
            {"schema_version": LIBRARY_SCHEMA_VERSION, "entries": {"bad": 7}},
            {"schema_version": LIBRARY_SCHEMA_VERSION, "entries": {"a|b": {"payloads": {}}}},
            {"schema_version": LIBRARY_SCHEMA_VERSION, "entries": {"a|b|c": {"payloads": []}}},
            {
                "schema_version": LIBRARY_SCHEMA_VERSION,
                "entries": {"a|b|c": {"payloads": {"p": {"successes": -1, "failures": 0}}}},
            },
            {
                "schema_version": LIBRARY_SCHEMA_VERSION,
                "entries": {"a|b|c": {"payloads": {"p": {"successes": True, "failures": 0}}}},
            },
        )
        for i, doc in enumerate(bad_docs):
            p = self._write(tmp_path, doc, name=f"lib{i}.json")
            with pytest.raises(TechniqueLibraryError, match="technique_library_schema"):
                load_library(p)

    def test_save_disabled_refused(self, tmp_path):
        with pytest.raises(TechniqueLibraryError, match="technique_library_write_disabled"):
            save_library(tmp_path / "lib.json", empty_library(), write_enabled=False)
        assert not (tmp_path / "lib.json").exists()

    def test_save_enabled_roundtrip(self, tmp_path):
        target = tmp_path / "sub" / "lib.json"
        (tmp_path / "sub").mkdir()
        lib = empty_library()
        record_outcome(lib, "xss", "cloudflare", "php", "<svg onload=alert(1)>", True)
        save_library(target, lib, write_enabled=True)
        reloaded = load_library(target)
        assert reloaded["entries"]["xss|cloudflare|php"]["payloads"]["<svg onload=alert(1)>"] == {
            "successes": 1,
            "failures": 0,
        }


# ---------------------------------------------------------------------------
# Outcome recording / rates / ranking.
# ---------------------------------------------------------------------------


class TestOutcomes:
    def test_record_outcome_deterministic(self):
        lib_a = empty_library()
        lib_b = empty_library()
        seq = [("xss", "none", "php", "p1", True), ("xss", "none", "php", "p1", True),
               ("xss", "none", "php", "p1", False), ("xss", "none", "php", "p2", False)]
        for args in seq:
            record_outcome(lib_a, *args)
        import random
        rng = random.Random(0)
        shuffled = seq[:]
        rng.shuffle(shuffled)
        for args in shuffled:
            record_outcome(lib_b, *args)
        # same multiset of outcomes -> same counters, however ordered
        assert (
            lib_a["entries"]["xss|none|php"]["payloads"]["p1"] == {"successes": 2, "failures": 1}
        )
        assert (
            lib_b["entries"]["xss|none|php"]["payloads"]["p1"] == {"successes": 2, "failures": 1}
        )

    def test_remembering_cap_halves(self):
        lib = empty_library()
        for _ in range(REMEMBERING_CAP - 1):
            record_outcome(lib, "xss", "none", "php", "p", True)
        # one before the cap boundary: 99 successes, no halving yet
        assert lib["entries"]["xss|none|php"]["payloads"]["p"] == {
            "successes": 99, "failures": 0,
        }
        record_outcome(lib, "xss", "none", "php", "p", False)
        assert lib["entries"]["xss|none|php"]["payloads"]["p"] == {
            "successes": 99, "failures": 1,
        }
        # total is now exactly the cap: the next update halves FIRST
        record_outcome(lib, "xss", "none", "php", "p", True)
        stats = lib["entries"]["xss|none|php"]["payloads"]["p"]
        assert stats == {"successes": 50, "failures": 0}

    def test_success_rate_laplace(self):
        assert success_rate({"successes": 0, "failures": 0}) == 0.5
        assert success_rate({"successes": 3, "failures": 1}) == 4 / 6
        assert success_rate({"successes": 0, "failures": 10}) == 1 / 12

    def test_top_payloads_orders_by_rate_then_text(self):
        lib = empty_library()
        for _ in range(9):
            record_outcome(lib, "xss", "none", "php", "winner", True)
        for _ in range(9):
            record_outcome(lib, "xss", "none", "php", "loser", False)
        tops = top_payloads(lib, "xss")
        assert [t[0] for t in tops] == ["winner", "loser"]
        assert tops[0][1] == pytest.approx(10 / 11)
        assert tops[1][1] == pytest.approx(1 / 11)

    def test_top_payloads_only_same_class(self):
        lib = empty_library()
        for _ in range(5):
            record_outcome(lib, "sqli", "none", "php", "' OR 1=1", True)
        assert top_payloads(lib, "xss") == []

    def test_top_payloads_exact_key_beats_aggregate_ties(self):
        lib = empty_library()
        # aggregate rate for "shared": 1 success 1 failure -> 0.5 via keys
        record_outcome(lib, "xss", "none", "php", "shared", True)
        record_outcome(lib, "xss", "cloudflare", "php", "shared", False)
        # exact key rate for "shared": 1/0 -> 2/3; top_payloads with the
        # exact key must use the better rate for the same payload.
        exact = top_payloads(lib, "xss", waf_category="none", tech="php")
        assert exact[0][1] == pytest.approx(2 / 3)
        agg = top_payloads(lib, "xss")
        assert agg[0][1] == pytest.approx(2 / 3)  # max over the keys' rates

    def test_top_payloads_tie_broken_by_payload_text(self):
        lib = empty_library()
        record_outcome(lib, "xss", "none", "php", "zzz", True)
        record_outcome(lib, "xss", "none", "php", "aaa", True)
        assert [t[0] for t in top_payloads(lib, "xss")] == ["aaa", "zzz"]

    def test_top_k_limit(self):
        lib = empty_library()
        for i in range(8):
            record_outcome(lib, "xss", "none", "php", f"p{i}", True)
        assert len(top_payloads(lib, "xss", k=3)) == 3


# ---------------------------------------------------------------------------
# Consumption hook: prompt_hint_for_finding (fail-soft, flag-gated).
# ---------------------------------------------------------------------------


class TestPromptHint:
    @staticmethod
    def _seed_library(tmp_path):
        lib = empty_library()
        for _ in range(5):
            record_outcome(lib, "xss", "none", "php", "p", True)
        p = tmp_path / "lib.json"
        save_library(p, lib, write_enabled=True)
        return str(p)

    def test_flag_off_returns_empty(self, tmp_path):
        path = self._seed_library(tmp_path)
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_cross_campaign_learning=False, technique_library_path=path)):
            assert prompt_hint_for_finding("xss") == ""

    def test_flag_on_returns_hint(self, tmp_path):
        path = self._seed_library(tmp_path)
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_cross_campaign_learning=True, technique_library_path=path)):
            hint = prompt_hint_for_finding("xss")
            assert "HISTORICALLY SUCCESSFUL PAYLOADS" in hint
            assert "p" in hint

    def test_flag_on_no_path_returns_empty(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_cross_campaign_learning=True, technique_library_path="")):
            assert prompt_hint_for_finding("xss") == ""

    def test_library_problem_fails_soft(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(
            Settings(
                enable_cross_campaign_learning=True,
                technique_library_path=str(tmp_path / "nope.json"),
            )
        ):
            assert prompt_hint_for_finding("xss") == ""

    def test_unknown_class_returns_empty(self, tmp_path):
        path = self._seed_library(tmp_path)
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_cross_campaign_learning=True, technique_library_path=path)):
            assert prompt_hint_for_finding("never-seen-class") == ""


# ---------------------------------------------------------------------------
# Cross-campaign dedupe.
# ---------------------------------------------------------------------------


class TestTokenize:
    def test_class_token_carries_weight(self):
        tokens = tokenize("SQLi", "https://t.example.com/api/users?id=3")
        assert tokens["sqli"] == CLASS_TOKEN_WEIGHT

    def test_path_segments_and_param_names_weight_one(self):
        tokens = tokenize("sqli", "/api/users?id=3")
        assert tokens["api"] == 1
        assert tokens["users"] == 1
        assert tokens["id"] == 1

    def test_values_excluded(self):
        tokens = tokenize("sqli", "/api/users?id=3&name=admin")
        assert "3" not in tokens
        assert "admin" not in tokens

    def test_empty_inputs(self):
        assert tokenize("", "") == {}


class TestWeightedJaccard:
    def test_identical_maps_full(self):
        m = {"sqli": 3, "users": 1}
        assert weighted_jaccard(m, m) == 1.0

    def test_disjoint_maps_zero(self):
        assert weighted_jaccard({"a": 1}, {"b": 1}) == 0.0

    def test_empty_maps_zero(self):
        assert weighted_jaccard({}, {}) == 0.0

    def test_partial_overlap(self):
        a = {"sqli": 3, "api": 1}
        b = {"sqli": 3}
        # intersection 3, union 4
        assert weighted_jaccard(a, b) == pytest.approx(0.75)


class TestRegistry:
    def test_empty_inventory_no_duplicate(self):
        reg = CrossCampaignRegistry()
        verdict = reg.check("sqli", "/api/users?id=1")
        assert verdict["possible_duplicate"] is False
        assert verdict["best_match"] is None

    def test_same_bug_flags_duplicate(self):
        reg = CrossCampaignRegistry()
        reg.register("sqli", "/api/users?id=1", campaign_id="c2")
        verdict = reg.check("sqli", "/api/users?id=2")
        assert verdict["possible_duplicate"] is True
        assert verdict["best_match"]["campaign_id"] == "c2"
        assert verdict["similarity"] >= DEFAULT_THRESHOLD

    def test_different_class_not_duplicate(self):
        reg = CrossCampaignRegistry()
        reg.register("sqli", "/api/users?id=1", campaign_id="c2")
        verdict = reg.check("xss", "/api/users?id=1")
        # path tokens overlap but the weighted class token dominates
        assert verdict["possible_duplicate"] is False

    def test_check_does_not_register(self):
        reg = CrossCampaignRegistry()
        reg.check("sqli", "/api/users?id=1")
        assert reg.findings == []

    def test_annotate_adds_flag(self):
        reg = CrossCampaignRegistry()
        reg.register("sqli", "/api/users", campaign_id="c2")
        finding = {"vuln_class": "sqli", "endpoint": "/api/users"}
        out = annotate_finding(finding, reg)
        assert out["possible_duplicate"]["similarity"] >= DEFAULT_THRESHOLD

    def test_annotate_leaves_clean_finding_unchanged(self):
        reg = CrossCampaignRegistry()
        reg.register("sqli", "/api/users", campaign_id="c2")
        finding = {"vuln_class": "xss", "endpoint": "/admin/login"}
        out = annotate_finding(finding, reg)
        assert "possible_duplicate" not in out
        assert out == {"vuln_class": "xss", "endpoint": "/admin/login"}

    def test_inventory_roundtrip(self, tmp_path):
        reg = CrossCampaignRegistry()
        reg.register("sqli", "/api/users", campaign_id="c2", detail="error-based")
        p = tmp_path / "inv.json"
        save_inventory(p, reg, write_enabled=True)
        reloaded = load_inventory(p)
        assert reloaded.findings[0]["vuln_class"] == "sqli"
        assert reloaded.findings[0]["campaign_id"] == "c2"

    def test_save_disabled_refused(self, tmp_path):
        with pytest.raises(InventoryError, match="inventory_write_disabled"):
            save_inventory(tmp_path / "inv.json", CrossCampaignRegistry(), write_enabled=False)

    def test_inventory_unreadable_refused(self, tmp_path):
        with pytest.raises(InventoryError, match="inventory_unreadable"):
            load_inventory(tmp_path / "missing.json")

    def test_inventory_invalid_json_refused(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{oops")
        with pytest.raises(InventoryError, match="inventory_invalid_json"):
            load_inventory(p)

    def test_inventory_schema_refused(self, tmp_path):
        for i, doc in enumerate(("[]", '{"findings": 3}', '{"findings": [1, 2]}')):
            p = tmp_path / f"bad{i}.json"
            p.write_text(json.dumps(doc))
            with pytest.raises(InventoryError, match="inventory_schema"):
                load_inventory(p)
