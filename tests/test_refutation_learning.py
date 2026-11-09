# tests/test_refutation_learning.py
"""Proposals 1+2 (2026-10-25): refutation ledger + coverage scheduling.

Covers the full contract stack:

  * RefutationLedger lifecycle: record -> threshold -> suppress ->
    CONFIRMED resets (delay-not-delete).
  * Fail-open reads (broken storage == "do not suppress") and
    fail-soft writes (capture never perturbs validation).
  * Flag-off inertness: the run_validator capture hook and both probe
    suppressors are byte-inert with ``enable_refutation_learning`` off.
  * Coverage cells: URL generalization, param-name-only identity,
    dedup across findings/ledger sources.
  * CoverageScheduler: deterministic ordering, ledger-informed prior,
    novelty decay, plateau detection, stats.
  * Planner integration: flag off -> prompt byte-identical; flag on ->
    advisory appended as an untrusted data block and exposed on the
    result; empty state -> advisory absent even with the flag on.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.config.settings import get_settings
from webpent.coverage.cell_model import CoverageCell, build_cells, generalize_url
from webpent.coverage.scheduler import CoverageScheduler, build_coverage_advisory
from webpent.learning.refutation_ledger import (
    DEFAULT_SUPPRESSION_THRESHOLD,
    RefutationLedger,
    get_ledger,
    set_ledger,
    target_fingerprint_from_url,
)
from webpent.production import validators as validators_mod
from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
    run_validator,
)

FP_A = "fp-target-a"
FP_B = "fp-target-b"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_ledger():
    """Install a clean in-memory ledger; restore the singleton after."""
    ledger = RefutationLedger(":memory:")
    set_ledger(ledger)
    yield ledger
    set_ledger(None)


@pytest.fixture()
def clean_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _record(ledger: RefutationLedger, *, vuln_class: str = "CACHE_POISONING",
            fingerprint: str = FP_A, path: str = "no_marker", count: int = 1) -> None:
    for _ in range(count):
        ledger.record_refutation(
            vuln_class=vuln_class, target_fingerprint=fingerprint,
            refutation_path=path, probe_signature="/probe",
        )


# ---------------------------------------------------------------------------
# RefutationLedger lifecycle (delay-not-delete)
# ---------------------------------------------------------------------------

class TestLedgerLifecycle:
    def test_refutations_accumulate_and_cross_threshold(self, fresh_ledger):
        _record(fresh_ledger, path="no_marker", count=2)
        assert fresh_ledger.refutation_count(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A) == 2
        assert not fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)
        _record(fresh_ledger, path="missing_header", count=1)
        assert fresh_ledger.refutation_count(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A) == 3
        assert fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)

    def test_default_threshold_is_three(self):
        assert DEFAULT_SUPPRESSION_THRESHOLD == 3

    def test_counts_sum_across_refutation_paths(self, fresh_ledger):
        _record(fresh_ledger, path="p1", count=2)
        _record(fresh_ledger, path="p2", count=1)
        assert fresh_ledger.refutation_count(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A) == 3

    def test_confirmation_resets_the_pair_only(self, fresh_ledger):
        _record(fresh_ledger, fingerprint=FP_A, path="p1", count=2)
        _record(fresh_ledger, fingerprint=FP_B, path="p1", count=3)
        fresh_ledger.reset_for_confirmation(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)
        assert fresh_ledger.refutation_count(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A) == 0
        # Sibling pair is untouched.
        assert fresh_ledger.refutation_count(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_B) == 3
        assert fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_B)
        assert not fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)

    def test_pairs_are_class_scoped(self, fresh_ledger):
        _record(fresh_ledger, vuln_class="SSRF", fingerprint=FP_A, count=3)
        assert not fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)

    def test_suppressed_family_is_delayed_not_deleted(self, fresh_ledger):
        """Suppression is advisory state; the ledger itself keeps history."""
        _record(fresh_ledger, count=4)
        assert fresh_ledger.should_suppress(
            vuln_class="CACHE_POISONING", target_fingerprint=FP_A)
        top = fresh_ledger.top_refutations()
        assert top and top[0]["total"] == 4
        summary = fresh_ledger.summarize()
        assert "delayed, not deleted" in summary
        # Redaction safety: no URL, host, or payload value in any output.
        for blob in (summary, str(top)):
            for leak in ("http", "example", "/probe"):
                assert leak not in blob


class TestFingerprintRedactionSafety:
    def test_fingerprint_is_hash_of_netloc_and_path(self):
        fp = target_fingerprint_from_url("https://Target.example:8443/a/b?q=1")
        assert len(fp) == 16
        # Query values never contribute (payload data stays out of keys).
        assert fp == target_fingerprint_from_url("https://target.example:8443/a/b?x=other")
        # Netloc case-insensitive.
        assert fp == target_fingerprint_from_url("https://TARGET.example:8443/a/b")
        # Path changes identity.
        assert fp != target_fingerprint_from_url("https://target.example:8443/a/c")

    def test_scheme_is_not_part_of_identity(self):
        assert (target_fingerprint_from_url("http://h.example/x")
                == target_fingerprint_from_url("https://h.example/x"))


# ---------------------------------------------------------------------------
# fail-open reads / fail-soft writes
# ---------------------------------------------------------------------------

class TestFailureContracts:
    def _broken_ledger(self) -> RefutationLedger:
        ledger = RefutationLedger(":memory:")
        ledger._conn.close()  # any operation now raises underneath
        return ledger

    def test_reads_fail_open(self):
        ledger = self._broken_ledger()
        assert ledger.refutation_count(
            vuln_class="X", target_fingerprint=FP_A) == 0
        assert ledger.should_suppress(vuln_class="X", target_fingerprint=FP_A) is False
        assert ledger.top_refutations() == []
        assert ledger.summarize() == ""

    def test_writes_fail_soft(self):
        ledger = self._broken_ledger()
        # Neither write may raise.
        ledger.record_refutation(
            vuln_class="X", target_fingerprint=FP_A, refutation_path="p")
        ledger.reset_for_confirmation(vuln_class="X", target_fingerprint=FP_A)


# ---------------------------------------------------------------------------
# run_validator capture hook (Proposal 1 integration)
# ---------------------------------------------------------------------------

def _stub_result(outcome: ValidationOutcome, refutation_path: str = "stub_path") -> ValidationResult:
    return ValidationResult(
        vulnerability_class="TESTFAM",
        outcome=outcome,
        evidence_quality=EvidenceQuality.OBSERVED_DIFFERENTIAL,
        discriminating_signal="stub",
        baseline_evidence={"url": "https://t.example/x"},
        candidate_evidence={"url": "https://t.example/x"},
        negative_control_evidence={"url": "https://t.example/control"},
        refutation_path=refutation_path,
    )


@pytest.fixture()
def stub_family(monkeypatch):
    """Register a TESTFAM validator whose outcome the test controls."""
    holder: dict[str, ValidationOutcome] = {"outcome": ValidationOutcome.REFUTED}

    def _vf(*, baseline, candidate, negative_control, **kwargs):
        return _stub_result(holder["outcome"])

    monkeypatch.setitem(validators_mod.VALIDATORS, "TESTFAM", _vf)
    return holder


class TestCaptureHook:
    def test_flag_off_records_nothing(self, fresh_ledger, stub_family, clean_settings):
        run_validator("TESTFAM", baseline={}, candidate={"url": "https://t.example/x"},
                      negative_control={})
        assert fresh_ledger.refutation_count(
            vuln_class="TESTFAM", target_fingerprint=target_fingerprint_from_url(
                "https://t.example/x")) == 0

    def test_refuted_outcome_is_recorded(self, fresh_ledger, stub_family, clean_settings,
                                         monkeypatch):
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        candidate = {"url": "https://t.example/x"}
        run_validator("TESTFAM", baseline={}, candidate=candidate, negative_control={})
        fp = target_fingerprint_from_url("https://t.example/x")
        assert fresh_ledger.refutation_count(
            vuln_class="TESTFAM", target_fingerprint=fp) == 1
        paths = [row["refutation_path"] for row in fresh_ledger.top_refutations()]
        assert "stub_path" in paths

    def test_confirmed_outcome_resets_pair(self, fresh_ledger, stub_family, clean_settings,
                                           monkeypatch):
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        candidate = {"url": "https://t.example/x"}
        fp = target_fingerprint_from_url("https://t.example/x")
        _record(fresh_ledger, vuln_class="TESTFAM", fingerprint=fp, count=3)
        assert fresh_ledger.should_suppress(vuln_class="TESTFAM", target_fingerprint=fp)
        stub_family["outcome"] = ValidationOutcome.CONFIRMED
        run_validator("TESTFAM", baseline={}, candidate=candidate, negative_control={})
        assert fresh_ledger.refutation_count(
            vuln_class="TESTFAM", target_fingerprint=fp) == 0
        assert not fresh_ledger.should_suppress(vuln_class="TESTFAM", target_fingerprint=fp)

    def test_broken_ledger_never_perturbs_validation(self, stub_family, clean_settings,
                                                     monkeypatch):
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        broken = RefutationLedger(":memory:")
        broken._conn.close()
        set_ledger(broken)
        try:
            result = run_validator("TESTFAM", baseline={}, candidate={"url": "https://t.example/x"},
                                   negative_control={})
            assert result.outcome == ValidationOutcome.REFUTED
        finally:
            set_ledger(None)

    def test_inconclusive_outcome_records_nothing(self, fresh_ledger, stub_family,
                                                  clean_settings, monkeypatch):
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        stub_family["outcome"] = ValidationOutcome.INCONCLUSIVE
        run_validator("TESTFAM", baseline={}, candidate={"url": "https://t.example/x"},
                      negative_control={})
        assert fresh_ledger.top_refutations() == []

    def test_candidate_without_url_records_nothing(self, fresh_ledger, stub_family,
                                                   clean_settings, monkeypatch):
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        run_validator("TESTFAM", baseline={}, candidate={}, negative_control={})
        assert fresh_ledger.top_refutations() == []


# ---------------------------------------------------------------------------
# probe suppressor (fail-open gate in the probe agents)
# ---------------------------------------------------------------------------

def _probe_state(url: str = "https://t.example/path") -> dict:
    return {"target": SimpleNamespace(url=url)}


class TestProbeSuppressor:
    def test_flag_off_is_never_suppressed(self, fresh_ledger, clean_settings):
        from webpent.agents.advanced_web_vulns.agent import _probe_refutation_suppressed
        _record(fresh_ledger, count=5)
        assert _probe_refutation_suppressed(
            _probe_state(), "CACHE_POISONING") is False

    def test_threshold_reached_suppresses(self, fresh_ledger, clean_settings, monkeypatch):
        from webpent.agents.advanced_web_vulns.agent import _probe_refutation_suppressed
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        url = "https://t.example/path"
        fp = target_fingerprint_from_url(url)
        assert not _probe_refutation_suppressed(_probe_state(url), "CACHE_POISONING")
        _record(fresh_ledger, fingerprint=fp, count=3)
        assert _probe_refutation_suppressed(_probe_state(url), "CACHE_POISONING")
        # Different class on the same target: not suppressed.
        assert not _probe_refutation_suppressed(_probe_state(url), "SSRF")

    def test_broken_ledger_fails_open(self, clean_settings, monkeypatch):
        from webpent.agents.advanced_web_vulns.agent import _probe_refutation_suppressed
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        broken = RefutationLedger(":memory:")
        broken._conn.close()
        set_ledger(broken)
        try:
            assert _probe_refutation_suppressed(
                _probe_state(), "CACHE_POISONING") is False
        finally:
            set_ledger(None)

    def test_state_without_target_fails_open(self, fresh_ledger, clean_settings, monkeypatch):
        from webpent.agents.advanced_web_vulns.agent import _probe_refutation_suppressed
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        get_settings.cache_clear()
        assert _probe_refutation_suppressed({}, "CACHE_POISONING") is False


# ---------------------------------------------------------------------------
# coverage cell model (Proposal 2)
# ---------------------------------------------------------------------------

class TestCellModel:
    def test_identifier_segments_generalize_to_id(self):
        assert generalize_url("https://h.example/api/users/42") == \
            "https://h.example/api/users/{id}"
        assert generalize_url(
            "https://h.example/api/items"
            "/123e4567-e89b-12d3-a456-426614174000") == \
            "https://h.example/api/items/{id}"
        assert generalize_url("https://h.example/f/deadbeef1234") == \
            "https://h.example/f/{id}"
        # Meaningful segments never collapse.
        assert generalize_url("https://h.example/api/users") == \
            "https://h.example/api/users"

    def test_param_values_never_become_identity(self):
        cell = CoverageCell(
            url_template="/api/search", method="GET",
            param_names=frozenset({"q", "page"}))
        other = CoverageCell(
            url_template="/api/search", method="GET",
            param_names=frozenset({"q", "page"}))
        assert cell.key == other.key

    def test_build_cells_from_endpoints_and_findings(self):
        finding_vuln = SimpleNamespace(value="CACHE_POISONING")  # enum-like
        state = {
            "crawled_data": {"endpoints": [
                "https://h.example/api/users/1?tab=a",
                "https://h.example/api/users/2?tab=a",  # same cell after {id}
                "https://h.example/api/search?q=x",
            ]},
            "findings": [
                {"url": "https://h.example/api/users/1", "vuln_class": finding_vuln,
                 "method": "GET"},
            ],
        }
        cells = build_cells(state)
        keys = [c.key for c in cells]
        # 2 endpoint cells (users/1 + users/2 dedupe to one {id} cell)
        # plus 1 class-scoped finding cell.
        assert len(cells) == 3
        assert len(keys) == len(set(keys))  # deduped
        # The finding cell is class-scoped: distinct from the bare endpoint cell.
        assert any(c.vuln_class == "CACHE_POISONING" for c in cells)
        # Deterministic order.
        assert keys == sorted(keys)

    def test_build_cells_from_campaign_ledger(self):
        state = {
            "campaign_ledger": {"entries": [
                {"campaign_key": "POST /api/login", "vulnerability_class": "AUTH_BYPASS"},
            ]},
            "campaign_task_outcomes": [
                {"campaign_key": "GET /items/7", "vulnerability_class": "IDOR"},
            ],
        }
        cells = build_cells(state)
        assert len(cells) == 2
        by_key = {c.key: c for c in cells}
        assert "POST /api/login [] {AUTH_BYPASS}" in by_key
        assert "GET /items/{id} [] {IDOR}" in by_key

    def test_empty_state_yields_no_cells(self):
        assert build_cells({}) == ()
        assert build_cells({"crawled_data": {}, "findings": []}) == ()


# ---------------------------------------------------------------------------
# coverage scheduler (Proposal 2)
# ---------------------------------------------------------------------------

def _cells(*urls: str, vuln_class: str = "SSRF") -> tuple[CoverageCell, ...]:
    return tuple(
        CoverageCell(url_template=u, method="GET", vuln_class=vuln_class)
        for u in urls
    )


class TestScheduler:
    def test_ordering_is_deterministic(self, fresh_ledger):
        cells = _cells("/a", "/b", "/c")
        s1 = CoverageScheduler(cells=cells).score(now=0.0)
        s2 = CoverageScheduler(cells=cells).score(now=0.0)
        assert [c.key for c in s1] == [c.key for c in s2]

    def test_refutation_history_lowers_prior(self, fresh_ledger):
        from webpent.learning.refutation_ledger import target_fingerprint_from_url as fp_of
        url = "https://h.example/a"
        fp = fp_of(url)
        _record(fresh_ledger, vuln_class="SSRF", fingerprint=fp, count=3)
        cells = _cells(url, "https://h.example/b")
        scores = CoverageScheduler(cells=cells).score(ledger=fresh_ledger, now=0.0)
        # Same novelty/diversity: the refuted pair must rank last.
        assert scores[-1].cell.url_template == url
        assert scores[-1].prior < 1.0
        assert scores[0].prior == 1.0

    def test_confirmation_keeps_full_prior(self, fresh_ledger):
        from webpent.learning.refutation_ledger import target_fingerprint_from_url as fp_of
        url = "https://h.example/a"
        _record(fresh_ledger, vuln_class="SSRF", fingerprint=fp_of(url), count=3)
        fresh_ledger.reset_for_confirmation(
            vuln_class="SSRF", target_fingerprint=fp_of(url))
        cells = _cells(url, "https://h.example/b")
        scores = CoverageScheduler(cells=cells).score(ledger=fresh_ledger, now=0.0)
        assert all(s.prior == 1.0 for s in scores)

    def test_novelty_decay_revisit_is_never_free(self):
        cell = _cells("/a")[0]
        sched = CoverageScheduler(cells=(cell,))
        never = sched.score(now=0.0)[0]
        sched.mark_attempted(cell.key, now=1.0)
        recent = sched.score(now=2.0)[0]
        stale = sched.score(now=1000.0)[0]
        # Never attempted > attempted long ago > attempted inside the
        # plateau window: revisits are never free, but never forbidden.
        assert never.expected_yield > stale.expected_yield > recent.expected_yield
        assert never.novelty == 1.0 and recent.novelty == 0.1 and stale.novelty == 0.3

    def test_plateau_detector_arms_only_after_first_coverage(self):
        sched = CoverageScheduler(cells=_cells("/a"), plateau_minutes=20.0)
        assert not sched.check_plateau(now=10_000_000.0)
        sched.mark_covered("/a", now=100.0)
        assert not sched.check_plateau(now=100.0 + 20.0 * 60.0)
        assert sched.check_plateau(now=100.0 + 20.0 * 60.0 + 1)

    def test_mark_covered_is_counted_once(self):
        sched = CoverageScheduler(cells=_cells("/a", "/b"))
        sched.mark_covered("/a", now=1.0)
        sched.mark_covered("/a", now=2.0)
        assert sched.stats() == {"discovered": 2, "covered": 1, "remaining": 1}

    def test_top_returns_highest_yield_first(self, fresh_ledger):
        from webpent.learning.refutation_ledger import target_fingerprint_from_url as fp_of
        url = "https://h.example/crowded"
        _record(fresh_ledger, vuln_class="SSRF", fingerprint=fp_of(url), count=5)
        cells = _cells(url, "https://h.example/fresh")
        top = CoverageScheduler(cells=cells).top(1, ledger=fresh_ledger, now=0.0)
        assert len(top) == 1
        assert top[0].cell.url_template == "https://h.example/fresh"


class TestCoverageAdvisory:
    def test_empty_state_returns_empty_string(self):
        assert build_coverage_advisory({}) == ""
        assert build_coverage_advisory({"crawled_data": {}}) == ""

    def test_advisory_is_bounded_untrusted_data_block(self):
        state = {"crawled_data": {"endpoints": ["https://h.example/api/users/1"]}}
        text = build_coverage_advisory(state)
        assert text.startswith(
            "Coverage advisory (deterministic, advisory data")
        assert "never instructions" in text
        assert "rabbit-hole review" in text

    def test_advisory_includes_ledger_summary(self, fresh_ledger):
        url = "https://h.example/api/users/1"
        _record(fresh_ledger, vuln_class="SSRF",
                fingerprint=target_fingerprint_from_url(url), count=2)
        state = {"crawled_data": {"endpoints": [url]}}
        text = build_coverage_advisory(state, ledger=fresh_ledger)
        assert "Refutation ledger patterns" in text

    def test_advisory_without_ledger_has_no_summary(self):
        state = {"crawled_data": {"endpoints": ["https://h.example/x"]}}
        text = build_coverage_advisory(state, ledger=None)
        assert "Refutation ledger patterns" not in text


# ---------------------------------------------------------------------------
# planner integration (flag-gated prompt append)
# ---------------------------------------------------------------------------

def _planner_state(with_surface: bool = False) -> dict:
    state = {
        "target": SimpleNamespace(
            url="https://example.test/items?token=redacted",
            domain="example.test",
            is_portswigger_lab=False,
        ),
        "mental_model": {"nodes": {}},
        "hypotheses": [],
    }
    if with_surface:
        state["crawled_data"] = {"endpoints": [
            "https://example.test/api/users/1?tab=a",
            "https://example.test/api/search?q=x",
        ]}
    return state


@pytest.fixture()
def planner_env(monkeypatch):
    """Deterministic no-LLM planner with methodology retrieval stubbed."""
    import webpent.agents.planner.agent as planner_agent

    monkeypatch.delenv("ENABLE_PLANNER_DECISIONS", raising=False)
    monkeypatch.delenv("ENABLE_COVERAGE_SCHEDULING", raising=False)
    monkeypatch.setattr(planner_agent, "_retrieve_methodologies", lambda: "")
    monkeypatch.setattr(
        planner_agent,
        "get_llm",
        lambda _task: SimpleNamespace(
            invoke=lambda _messages: SimpleNamespace(content="1. plan")),
    )
    return planner_agent


class TestPlannerAdvisory:
    def test_flag_off_prompt_is_byte_identical(self, planner_env, clean_settings,
                                               fresh_ledger):
        result = planner_env.planner_node(_planner_state(with_surface=True))
        content = result["messages"][0].content
        assert "Coverage advisory" not in content
        assert "coverage_advisory" not in result

    def test_flag_on_with_surface_appends_advisory(self, planner_env, clean_settings,
                                                   fresh_ledger, monkeypatch):
        monkeypatch.setenv("ENABLE_COVERAGE_SCHEDULING", "true")
        get_settings.cache_clear()
        result = planner_env.planner_node(_planner_state(with_surface=True))
        content = result["messages"][0].content
        assert "Coverage advisory (deterministic, advisory data" in content
        assert result["coverage_advisory"] in content

    def test_flag_on_without_surface_prompt_unchanged(self, planner_env, clean_settings,
                                                      fresh_ledger, monkeypatch):
        monkeypatch.setenv("ENABLE_COVERAGE_SCHEDULING", "true")
        get_settings.cache_clear()
        baseline = planner_env.planner_node(_planner_state(with_surface=False))
        baseline_content = baseline["messages"][0].content
        assert "Coverage advisory" not in baseline_content
        assert "coverage_advisory" not in baseline

    def test_advisory_failure_never_breaks_planning(self, planner_env, clean_settings,
                                                    fresh_ledger, monkeypatch):
        monkeypatch.setenv("ENABLE_COVERAGE_SCHEDULING", "true")
        get_settings.cache_clear()
        # A broken ledger singleton must degrade to a no-advisory plan.
        broken = RefutationLedger(":memory:")
        broken._conn.close()
        set_ledger(broken)
        try:
            result = planner_env.planner_node(_planner_state(with_surface=True))
            assert "messages" in result
            assert "1. plan" in result["messages"][0].content
        finally:
            set_ledger(None)


# ---------------------------------------------------------------------------
# ledger persistence via refutation_ledger_db
# ---------------------------------------------------------------------------

class TestLedgerPersistence:
    def test_file_backed_singleton_persists(self, tmp_path, clean_settings, monkeypatch):
        db = tmp_path / "ledger.sqlite3"
        monkeypatch.setenv("ENABLE_REFUTATION_LEARNING", "true")
        monkeypatch.setenv("REFUTATION_LEDGER_DB", str(db))
        get_settings.cache_clear()
        set_ledger(None)  # force rebuild from the configured path
        try:
            ledger = get_ledger()
            _record(ledger, count=1)
            ledger.close()
            assert db.exists() and db.stat().st_size > 0
            # Reopening the same path restores the history.
            reopened = RefutationLedger(str(db))
            assert reopened.refutation_count(
                vuln_class="CACHE_POISONING", target_fingerprint=FP_A) == 1
            reopened.close()
        finally:
            set_ledger(None)
