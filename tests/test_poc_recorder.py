"""Unit tests for the video POC recorder (FINAL PREP SPRINT 2026-10-05).

Hermetic by construction: the Playwright browser is replaced by an injectable
fake factory exercising the exact surface ``record_poc`` uses (route handler,
goto, inner_text, video path). No network, no chromium, no artifacts leaks.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from webpent.reporter.poc_export import (
    build_curl_commands,
    export_all_promoted,
    export_finding_evidence,
    steps_to_reproduce,
)
from webpent.reporter.poc_recorder import (
    MAX_VIDEO_BYTES,
    POCError,
    POCPlan,
    build_poc_plan,
    enrich_report_with_poc,
    finding_is_promoted,
    maybe_record_poc,
    record_poc,
)

FINDING = {
    "id": "11111111-1111-4111-8111-111111111111",
    "title": "IDOR on invoice endpoint",
    "severity": "high",
    "url": "https://lab.example/api/invoices/42",
    "request_method": "GET",
    "vuln_class": "IDOR",
    "evidence": {"promotion": {"decision": "PROMOTED"}},
}


# ---------------------------------------------------------------------------
# fake browser (mirrors the playwright surface record_poc touches)
# ---------------------------------------------------------------------------
class FakeRoute:
    def __init__(self, headers: dict[str, str], url: str = "") -> None:
        self.request = types.SimpleNamespace(headers=headers, url=url)
        self.continued: dict[str, str] | None = None

    def continue_(self, headers=None) -> None:
        self.continued = headers


class FakeVideo:
    def __init__(self, path: Path) -> None:
        self._path = path

    def path(self) -> str:
        return str(self._path)


class FakePage:
    def __init__(self, workdir: Path, bodies: list[str], video_size: int = 2048, nav_url: str = "") -> None:
        self._bodies = bodies
        self._goto_count = 0
        self._route_handler = None
        self._nav_url = nav_url
        self.captured_headers: list[dict[str, str] | None] = []
        video_file = workdir / "fake_recording.webm"
        video_file.write_bytes(b"0" * video_size)
        self.video = FakeVideo(video_file)

    def route(self, pattern, handler) -> None:
        self._route_handler = handler

    def set_default_timeout(self, ms) -> None:
        self.timeout_ms = ms

    def goto(self, url, wait_until=None):
        self._goto_count += 1
        if self._route_handler is not None:
            route = FakeRoute({"authorization": "phase-token"}, url=self._nav_url or url)
            self._route_handler(route)
            self.captured_headers.append(route.continued)
        return types.SimpleNamespace(status=200)

    def inner_text(self, selector: str) -> str:
        return self._bodies[min(self._goto_count - 1, len(self._bodies) - 1)]


class FakeContext:
    def __init__(self, workdir: Path, bodies: list[str], video_size: int = 2048, nav_url: str = "") -> None:
        self._workdir = Path(workdir)
        self._bodies = bodies
        self._video_size = video_size
        self._nav_url = nav_url
        self.pages: list[FakePage] = []
        self.closed = False

    def new_page(self) -> FakePage:
        page = FakePage(self._workdir, self._bodies, self._video_size, nav_url=self._nav_url)
        self.pages.append(page)
        return page

    def close(self) -> None:
        self.closed = True


def _factory(bodies: list[str]):
    def factory(record_dir: Path) -> FakeContext:
        ctx = FakeContext(Path(record_dir), bodies)
        ctx._bodies = bodies
        return ctx

    return factory


def _plan(**overrides) -> POCPlan:
    kwargs = dict(
        finding_id=FINDING["id"],
        url=FINDING["url"],
        owner_token="owner-token",
        foreign_token="foreign-token",
    )
    kwargs.update(overrides)
    return POCPlan(**kwargs)


# ---------------------------------------------------------------------------
# plan builder
# ---------------------------------------------------------------------------
def test_build_poc_plan_derives_url_and_method_from_finding() -> None:
    plan = build_poc_plan(FINDING, owner_token="o", foreign_token="f")
    assert plan.url == FINDING["url"]
    assert plan.method == "GET"
    assert plan.token_header == "Authorization"


def test_build_poc_plan_requires_both_tokens() -> None:
    with pytest.raises(POCError):
        build_poc_plan(FINDING, owner_token="only-owner")
    with pytest.raises(POCError):
        build_poc_plan({**FINDING, "url": "ftp://not-http"} , owner_token="o", foreign_token="f")


def test_plan_public_dict_redacts_tokens() -> None:
    view = _plan().public_dict()
    assert view["owner_token"] == "***redacted***"
    assert view["foreign_token"] == "***redacted***"
    assert "owner-token" not in json.dumps(view)


# ---------------------------------------------------------------------------
# recording (fake browser)
# ---------------------------------------------------------------------------
def test_record_poc_writes_video_and_metadata(tmp_path: Path) -> None:
    result = record_poc(
        _plan(),
        output_dir=tmp_path,
        browser_factory=_factory(["OWNER SECRET DATA", "OWNER SECRET DATA"]),
    )
    video = tmp_path / f"poc_{FINDING['id']}.webm"
    meta = tmp_path / f"poc_{FINDING['id']}.json"
    assert video.exists() and video.stat().st_size <= MAX_VIDEO_BYTES
    assert meta.exists()
    data = json.loads(meta.read_text())
    assert data["finding_id"] == FINDING["id"]
    assert [s["step"] for s in data["steps"]] == ["b", "c", "d", "e"]
    assert data["comparison"]["identical_body_detected"] is True
    assert result["metadata_path"] == str(meta)
    assert result["video_path"] == str(video)
    # tokens never reach metadata
    assert "owner-token" not in meta.read_text()


def test_record_poc_route_switches_owner_to_foreign(tmp_path: Path) -> None:
    captured: list[dict] = []

    def factory(record_dir: Path) -> FakeContext:
        ctx = FakeContext(Path(record_dir), ["A", "B"])
        original_new_page = ctx.new_page

        def new_page():
            page = original_new_page()
            real_goto = page.goto

            def goto(url, wait_until=None):
                real_goto(url, wait_until=wait_until)
                if page.captured_headers:
                    captured.append(dict(page.captured_headers[-1] or {}))
                return types.SimpleNamespace(status=200)

            page.goto = goto
            return page

        ctx.new_page = new_page
        return ctx

    record_poc(_plan(), output_dir=tmp_path, browser_factory=factory)
    assert len(captured) == 2
    assert captured[0]["authorization"] == "owner-token"
    assert captured[1]["authorization"] == "foreign-token"


def test_record_poc_over_size_cap_fails_and_flags(tmp_path: Path) -> None:
    def fat_factory(record_dir: Path) -> FakeContext:
        return FakeContext(Path(record_dir), ["A", "B"], video_size=MAX_VIDEO_BYTES + 1)

    with pytest.raises(POCError, match="exceeds cap"):
        record_poc(_plan(), output_dir=tmp_path, browser_factory=fat_factory)
    assert not (tmp_path / f"poc_{FINDING['id']}.webm").exists()
    assert (tmp_path / f"poc_{FINDING['id']}.webm.oversize").exists()


# ---------------------------------------------------------------------------
# promotion recognition + fail-soft integration entry
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "evidence,confidence,expected",
    [
        ({"promotion": {"decision": "PROMOTED"}}, None, True),
        ({"promotion_decision": {"status": "TOOL-CONFIRMED"}}, None, True),
        ({}, "tool-confirmed", True),
        ({"promotion": {"decision": "REFUTED"}}, None, False),
        ({}, None, False),
    ],
)
def test_finding_is_promoted(evidence, confidence, expected) -> None:
    finding = {**FINDING, "evidence": evidence}
    if confidence:
        finding["confidence_level"] = confidence
    assert finding_is_promoted(finding) is expected


def test_maybe_record_poc_failure_never_raises(tmp_path: Path) -> None:
    def exploding_factory(record_dir: Path) -> FakeContext:
        raise RuntimeError("chromium exploded")

    result = maybe_record_poc(
        FINDING,
        output_dir=tmp_path,
        owner_token="o",
        foreign_token="f",
        browser_factory=exploding_factory,
    )
    assert result["status"] == "failed"
    assert "RuntimeError" in result["reason"]


def test_maybe_record_poc_skips_when_disabled_or_not_promoted(tmp_path: Path) -> None:
    assert maybe_record_poc(FINDING, output_dir=tmp_path, enabled=False)["status"] == "skipped"
    unpromoted = {**FINDING, "evidence": {"promotion": {"decision": "REFUTED"}}}
    assert maybe_record_poc(unpromoted, output_dir=tmp_path, owner_token="o", foreign_token="f")[
        "status"
    ] == "skipped"


def test_maybe_record_poc_records_audit_event_best_effort(tmp_path: Path) -> None:
    class FlakyAudit:
        def __init__(self) -> None:
            self.events: list[tuple] = []

        def append_event(self, *, event_type, details) -> None:
            self.events.append((event_type, details))

    audit = FlakyAudit()
    result = maybe_record_poc(
        FINDING,
        output_dir=tmp_path,
        owner_token="o",
        foreign_token="f",
        browser_factory=_factory(["D", "D"]),
        audit_chain=audit,
    )
    assert result["status"] == "recorded"
    assert audit.events and audit.events[0][0] == "poc.recorded"


# ---------------------------------------------------------------------------
# report enrichment (post-render)
# ---------------------------------------------------------------------------
def test_enrich_report_embeds_video_and_is_idempotent(tmp_path: Path) -> None:
    report = tmp_path / "report.html"
    report.write_text("<html><body><h1>Report</h1></body></html>")
    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / f"poc_{FINDING['id']}.webm").write_bytes(b"v" * 128)
    (poc_dir / f"poc_{FINDING['id']}.json").write_text("{}")

    assert enrich_report_with_poc(report, poc_dir) is True
    html = report.read_text()
    assert "webpent-poc-embed" in html
    assert f"poc_{FINDING['id']}.webm" in html
    # idempotent
    assert enrich_report_with_poc(report, poc_dir) is False
    # no videos -> no change
    other = tmp_path / "other.html"
    other.write_text("<html><body></body></html>")
    assert enrich_report_with_poc(other, tmp_path / "empty_poc") is False


# ---------------------------------------------------------------------------
# evidence export
# ---------------------------------------------------------------------------
def test_curl_commands_use_placeholders_never_literal_tokens() -> None:
    commands = build_curl_commands(FINDING)
    text = "\n".join(commands)
    assert "$OWNER_TOKEN" in text and "$FOREIGN_TOKEN" in text
    assert "owner-token" not in text and "foreign-token" not in text
    assert FINDING["url"] in text


def test_steps_are_numbered_and_ordered() -> None:
    steps = steps_to_reproduce(FINDING)
    assert steps[0].startswith("Authenticate as the resource OWNER")
    assert any("FOREIGN" in s for s in steps)


def test_export_finding_evidence_writes_md_and_json(tmp_path: Path) -> None:
    result = export_finding_evidence(FINDING, output_dir=tmp_path)
    md = Path(result["markdown"]).read_text()
    data = json.loads(Path(result["json"]).read_text())
    for section in ("## Steps to reproduce", "## Reproduction commands", "## Impact", "## Remediation"):
        assert section in md
    assert "object-level authorization" in data["remediation"].lower()
    assert data["cvss_score"] == "high"  # falls back to severity bucket when no CVSS
    assert data["proof_bundle"]["bundle_id"] == ""


def test_export_all_promoted_skips_unpromoted(tmp_path: Path) -> None:
    findings = [
        FINDING,
        {**FINDING, "id": "22222222-2222-4222-8222-222222222222",
         "evidence": {"promotion": {"decision": "REFUTED"}}},
    ]
    summary = export_all_promoted(findings, output_dir=tmp_path)
    assert summary["count"] == 1
    assert summary["skipped"] == [
        {"finding_id": "22222222-2222-4222-8222-222222222222", "reason": "not_promoted"}
    ]


# ---------------------------------------------------------------------------
# v5: scratch-dir leak regressions (surfaced by scripts/poc_smoke_real_browser.py
# with a REAL chromium: a factory failure or a mid-recording failure used to
# skip the cleanup finally and leak _poc_tmp_* dirs into the artifact tree)
# ---------------------------------------------------------------------------
def test_record_poc_cleans_scratch_dir_on_factory_failure(tmp_path: Path) -> None:
    def exploding_factory(record_dir: Path) -> FakeContext:
        raise RuntimeError("chromium exploded")

    with pytest.raises(RuntimeError, match="chromium exploded"):
        record_poc(_plan(), output_dir=tmp_path, browser_factory=exploding_factory)
    leftovers = list(tmp_path.glob("_poc_tmp_*"))
    assert leftovers == [], f"scratch dir leaked on factory failure: {leftovers}"


def test_record_poc_cleans_scratch_dir_on_mid_recording_failure(tmp_path: Path) -> None:
    class DyingPage(FakePage):
        def goto(self, url, wait_until=None):
            raise RuntimeError("net::ERR_UNSAFE_PORT at target")  # real smoke Phase D shape

    class DyingContext(FakeContext):
        def new_page(self) -> FakePage:
            page = DyingPage(self._workdir, self._bodies)
            self.pages.append(page)
            return page

    def dying_factory(record_dir: Path) -> FakeContext:
        return DyingContext(Path(record_dir), ["body"])

    with pytest.raises(RuntimeError, match="ERR_UNSAFE_PORT"):
        record_poc(_plan(), output_dir=tmp_path, browser_factory=dying_factory)
    leftovers = list(tmp_path.glob("_poc_tmp_*"))
    assert leftovers == [], f"scratch dir leaked on mid-recording failure: {leftovers}"


def test_record_poc_browser_errors_propagate_raw(tmp_path: Path) -> None:
    """Pins the honest error contract: record_poc does NOT wrap browser errors
    into POCError (maybe_record_poc is the absorbing entry point)."""
    def exploding_factory(record_dir: Path) -> FakeContext:
        raise RuntimeError("chromium exploded")

    with pytest.raises(RuntimeError):  # NOT POCError
        record_poc(_plan(), output_dir=tmp_path, browser_factory=exploding_factory)
