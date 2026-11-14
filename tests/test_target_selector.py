# tests/test_target_selector.py
"""PROPOSALS_ULTIMATE_V2 §10 (2026-10-30) test suite: target selection.

Covers program-brief loading (JSON and Markdown, fail-closed refusals:
unreadable, invalid JSON, no scope, schema violations), scope matching
with wildcards and out-of-scope override, bounty lookup with the
program default, and the deterministic UCB1 selector: flag-off refusal,
explore-first fairness (every target played once before any repeat),
determinism under a declared seed, exploitation of known reward,
out-of-program filtering with an explicit refusal when nothing is left
in scope, and the status-snapshot record with its reason.
"""

from __future__ import annotations

import json

import pytest

from webpent.targeting.program_brief import (
    ProgramBrief,
    ProgramBriefError,
    expected_bounty,
    load_program_brief,
    matches_scope,
)
from webpent.targeting.selector import (
    SelectorError,
    TargetSelector,
    TargetStats,
    last_selection,
    update_stats,
)


# ---------------------------------------------------------------------------
# Program brief loading.
# ---------------------------------------------------------------------------


class TestProgramBriefJSON:
    def _write(self, tmp_path, doc, name="brief.json"):
        p = tmp_path / name
        p.write_text(json.dumps(doc))
        return p

    def test_loads_scope_bounties_notes(self, tmp_path):
        p = self._write(
            tmp_path,
            {
                "name": "Acme",
                "scope": ["*.acme.com", "acme.com"],
                "out_of_scope": ["blog.acme.com"],
                "bounties": {"sqli": 500, "xss": 200},
                "default_bounty": 50,
                "notes": ["no automated scanning"],
            },
        )
        brief = load_program_brief(p)
        assert brief.name == "Acme"
        assert brief.scope == ["*.acme.com", "acme.com"]
        assert brief.out_of_scope == ["blog.acme.com"]
        assert brief.bounties == {"sqli": 500.0, "xss": 200.0}
        assert brief.default_bounty == 50.0
        assert brief.notes == ["no automated scanning"]

    def test_unreadable_refused(self, tmp_path):
        with pytest.raises(ProgramBriefError, match="program_brief_unreadable"):
            load_program_brief(tmp_path / "missing.json")

    def test_invalid_json_refused(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        with pytest.raises(ProgramBriefError, match="program_brief_invalid_json"):
            load_program_brief(p)

    def test_no_scope_refused(self, tmp_path):
        p = self._write(tmp_path, {"name": "Acme", "scope": []})
        with pytest.raises(ProgramBriefError, match="program_brief_no_scope"):
            load_program_brief(p)

    def test_missing_scope_refused(self, tmp_path):
        p = self._write(tmp_path, {"name": "Acme"})
        with pytest.raises(ProgramBriefError, match="program_brief_no_scope"):
            load_program_brief(p)

    def test_schema_violations_refused(self, tmp_path):
        for bad in (
            {"scope": ["a.com"], "bounties": {"xss": "lots"}},
            {"scope": ["a.com"], "default_bounty": "high"},
            {"scope": ["a.com"], "notes": "one string"},
            {"scope": ["a.com"], "out_of_scope": "x.com"},
        ):
            with pytest.raises(ProgramBriefError, match="program_brief_schema"):
                load_program_brief(self._write(tmp_path, bad, name="brief.json"))


class TestProgramBriefMarkdown:
    MD = """# Acme Program

## In scope
- *.acme.com
- `api.acme.io`

## Out of scope
- blog.acme.com

## Bounty table
- sqli: $500
- xss: 200
- idor: $1,000

## Notes
- no automated scanning
"""

    def test_loads_markdown(self, tmp_path):
        p = tmp_path / "brief.md"
        p.write_text(self.MD)
        brief = load_program_brief(p)
        assert brief.name == "Acme Program"
        assert brief.scope == ["*.acme.com", "api.acme.io"]
        assert brief.out_of_scope == ["blog.acme.com"]
        assert brief.bounties == {"sqli": 500.0, "xss": 200.0, "idor": 1000.0}
        assert brief.notes == ["no automated scanning"]

    def test_markdown_without_scope_refused(self, tmp_path):
        p = tmp_path / "brief.md"
        p.write_text("# Acme\n\n## Notes\n- hello\n")
        with pytest.raises(ProgramBriefError, match="program_brief_no_scope"):
            load_program_brief(p)


# ---------------------------------------------------------------------------
# Scope matching + bounty lookup (selection-level pre-filter only).
# ---------------------------------------------------------------------------


class TestScopeMatch:
    BRIEF = ProgramBrief(
        name="t",
        scope=["*.acme.com", "acme.com"],
        out_of_scope=["blog.acme.com"],
    )

    def test_wildcard_subdomain_matches(self):
        assert matches_scope("api.acme.com", self.BRIEF)
        assert matches_scope("https://api.acme.com/x", self.BRIEF)

    def test_bare_domain_matches_when_listed(self):
        assert matches_scope("acme.com", self.BRIEF)

    def test_wildcard_does_not_match_bare_domain(self):
        brief = ProgramBrief(name="t", scope=["*.acme.com"])
        assert not matches_scope("acme.com", brief)

    def test_out_of_scope_overrides(self):
        assert not matches_scope("blog.acme.com", self.BRIEF)

    def test_unlisted_host_refused(self):
        assert not matches_scope("evil.com", self.BRIEF)


class TestBounty:
    def test_known_class(self):
        brief = ProgramBrief(name="t", bounties={"sqli": 500})
        assert expected_bounty(brief, "sqli") == 500.0
        assert expected_bounty(brief, "SQLI") == 500.0

    def test_unknown_class_uses_default(self):
        brief = ProgramBrief(name="t", bounties={"sqli": 500}, default_bounty=75)
        assert expected_bounty(brief, "nomad-class") == 75.0


# ---------------------------------------------------------------------------
# The UCB1 selector.
# ---------------------------------------------------------------------------


class TestSelector:
    def test_flag_off_refused(self):
        with pytest.raises(SelectorError, match="target_selector_flag_off"):
            TargetSelector(enable_target_selector=False)

    def test_no_candidates_refused(self):
        sel = TargetSelector(enable_target_selector=True)
        with pytest.raises(SelectorError, match="target_selector_no_candidates"):
            sel.select([])

    def test_explore_first_fairness(self):
        # Every target is played once before ANY target is played twice.
        sel = TargetSelector(enable_target_selector=True, seed=7)
        cands = ["a.example.com", "b.example.com", "c.example.com"]
        stats: dict[str, TargetStats] = {}
        seen: list[str] = []
        for _ in cands:  # exactly len(cands) rounds
            rec = sel.select(cands, stats)
            assert rec.reason == "ucb1_explore_first_play"
            seen.append(rec.target)
            update_stats(stats, rec.target, 0.0)
        assert sorted(seen) == sorted(cands)

    def test_deterministic_with_seed(self):
        cands = ["x.com", "y.com", "z.com"]
        stats = {"x.com": TargetStats(plays=4, reward_sum=10.0)}
        for _ in range(5):
            rec = TargetSelector(enable_target_selector=True, seed=42).select(
                cands, stats
            )
            assert rec.target == "y.com"  # tie between y and z broken by seed
        other = TargetSelector(enable_target_selector=True, seed=43).select(
            cands, stats
        )
        assert other.seed == 43

    def test_exploits_known_reward_after_exploration(self):
        sel = TargetSelector(enable_target_selector=True, seed=1)
        cands = ["rich.com", "poor.com"]
        stats: dict[str, TargetStats] = {}
        # round 1: explore one (seeded tiebreak); then play it.
        first = sel.select(cands, stats)
        update_stats(stats, first.target, 100.0 if first.target == "rich.com" else 1.0)
        second = sel.select(cands, stats)
        update_stats(stats, second.target, 100.0 if second.target == "rich.com" else 1.0)
        # Now rich.com (mean 100) dominates poor.com (mean 1 or 0).
        third = sel.select(cands, stats)
        assert third.target == "rich.com"
        assert third.reason.startswith("ucb1_exploit")
        assert not third.explored_first

    def test_out_of_program_filtered_and_reported(self):
        brief = ProgramBrief(name="t", scope=["*.acme.com"])
        sel = TargetSelector(enable_target_selector=True, seed=0, brief=brief)
        rec = sel.select(["api.acme.com", "evil.com"], {})
        assert rec.target == "api.acme.com"
        assert rec.filtered_out == ("evil.com",)
        entry = rec.snapshot_entry()
        assert entry["filtered_out_of_scope"] == ["evil.com"]
        assert entry["reason"] == "ucb1_explore_first_play"

    def test_all_out_of_program_refused(self):
        brief = ProgramBrief(name="t", scope=["*.acme.com"])
        sel = TargetSelector(enable_target_selector=True, seed=0, brief=brief)
        with pytest.raises(SelectorError, match="no_candidates_in_scope"):
            sel.select(["evil.com", "worse.com"], {})

    def test_last_selection_recorded_for_snapshot(self):
        sel = TargetSelector(enable_target_selector=True, seed=9)
        rec = sel.select(["only.com"], {})
        assert last_selection() is rec
        entry = last_selection().snapshot_entry()
        assert entry["recommended_target"] == "only.com"
        assert entry["seed"] == 9
        assert "reason" in entry and "plays" in entry
