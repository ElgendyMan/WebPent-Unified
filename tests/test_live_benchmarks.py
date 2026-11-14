# tests/test_live_benchmarks.py
"""PROPOSALS_ULTIMATE_V2 §8 (2026-10-30) test suite: live benchmarks.

Covers the fail-closed guarantees (flag off, empty target, ANY non-local
host refused — including userinfo and subdomain tricks, unsupported
schemes), the ground-truth loader (schema violations are hard refusals),
the scoreboard engine (strict exact (class, endpoint) matching, per-class
detection rates, false-positive accounting, deterministic bytes,
regression comparison), and an end-to-end run against a REAL localhost
HTTP fixture server driven through the runner's campaign seam.

The opt-in container test (local Juice Shop) is excluded from the
default run: it activates only with WEBPENT_BENCHMARK_LIVE=1 in the
environment AND a WEBPENT_BENCHMARK_TARGET pointing at the locally
started container. (The repo's pytest config uses --strict-markers with
no registered marker list, so opt-in gating is done by environment
rather than by an unregistered custom marker.)
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from webpent.benchmark.ground_truth import (
    GroundTruthError,
    TargetGroundTruth,
    GroundTruthVuln,
    load_ground_truth,
)
from webpent.benchmark.live_runner import (
    CampaignResult,
    LiveBenchmarkError,
    assert_local_target,
    run_live_benchmark,
)
from webpent.benchmark.scoreboard import (
    PredictedFinding,
    ScoreboardError,
    build_scoreboard,
    compare_scoreboards,
    load_scoreboard,
    write_scoreboard,
)


def _gt(target: str = "juice-shop-local", vulns: Any = None) -> TargetGroundTruth:
    if vulns is None:
        vulns = (
            GroundTruthVuln("xss", "/search"),
            GroundTruthVuln("path_traversal", "/ftp"),
        )
    return TargetGroundTruth(target=target, vulns=vulns)


# ---------------------------------------------------------------------------
# Fail-closed target gating.
# ---------------------------------------------------------------------------


class TestLocalTargetRefusal:
    def test_flag_off_refused(self) -> None:
        with pytest.raises(LiveBenchmarkError, match="enable_live_benchmarks_flag_off"):
            run_live_benchmark(
                enable_live_benchmarks=False,
                benchmark_target="http://127.0.0.1:3000",
                ground_truth=_gt(),
                campaign=lambda url: CampaignResult(()),
            )

    def test_empty_target_refused(self) -> None:
        with pytest.raises(LiveBenchmarkError, match="benchmark_target_required"):
            assert_local_target("")

    def test_remote_host_refused(self) -> None:
        with pytest.raises(LiveBenchmarkError, match="benchmark_target_not_localhost"):
            assert_local_target("http://example.com")

    def test_subdomain_trick_refused(self) -> None:
        with pytest.raises(LiveBenchmarkError, match="benchmark_target_not_localhost"):
            assert_local_target("http://127.0.0.1.evil.com:3000")

    def test_userinfo_trick_refused(self) -> None:
        # urlsplit().hostname strips credentials: the HOST is evil.com.
        with pytest.raises(LiveBenchmarkError, match="benchmark_target_not_localhost"):
            assert_local_target("http://127.0.0.1@evil.com")

    def test_unsupported_scheme_refused(self) -> None:
        with pytest.raises(LiveBenchmarkError, match="benchmark_target_unsupported_scheme"):
            assert_local_target("ftp://127.0.0.1")

    @pytest.mark.parametrize(
        "target",
        [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
            "https://localhost:8443",
            "http://user@127.0.0.1:8080",
        ],
    )
    def test_local_variants_allowed(self, target: str) -> None:
        assert assert_local_target(target) == target


# ---------------------------------------------------------------------------
# Ground-truth loader: fail-closed on every schema defect.
# ---------------------------------------------------------------------------


class TestGroundTruthLoader:
    def _write(self, tmp_path: Path, doc: Any) -> Path:
        p = tmp_path / "gt.json"
        p.write_text(
            json.dumps(doc) if not isinstance(doc, str) else doc,
            encoding="utf-8",
        )
        return p

    def test_valid_load(self, tmp_path: Path) -> None:
        p = self._write(
            tmp_path,
            {
                "schema_version": 1,
                "target": "juice-shop-local",
                "vulns": [
                    {"vuln_class": "xss", "endpoint": "/search"},
                    {"vuln_class": "sqli", "endpoint": "/rest/products/search", "notes": "UNION-based"},
                ],
            },
        )
        gt = load_ground_truth(p)
        assert gt.target == "juice-shop-local"
        assert [v.vuln_class for v in gt.vulns] == ["xss", "sqli"]
        assert gt.vulns[1].notes == "UNION-based"

    def test_unreadable_refused(self, tmp_path: Path) -> None:
        with pytest.raises(GroundTruthError, match="ground_truth_unreadable"):
            load_ground_truth(tmp_path / "missing.json")

    def test_invalid_json_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, "{not json")
        with pytest.raises(GroundTruthError, match="ground_truth_invalid_json"):
            load_ground_truth(p)

    def test_missing_class_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, {"target": "t", "vulns": [{"endpoint": "/x"}]})
        with pytest.raises(GroundTruthError, match="vuln_class"):
            load_ground_truth(p)

    def test_missing_endpoint_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, {"target": "t", "vulns": [{"vuln_class": "xss"}]})
        with pytest.raises(GroundTruthError, match="endpoint"):
            load_ground_truth(p)

    def test_bad_schema_version_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, {"schema_version": 99, "target": "t", "vulns": []})
        with pytest.raises(GroundTruthError, match="schema_version"):
            load_ground_truth(p)

    def test_non_list_vulns_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, {"target": "t", "vulns": {"xss": "/search"}})
        with pytest.raises(GroundTruthError, match="must be a list"):
            load_ground_truth(p)

    def test_empty_target_refused(self, tmp_path: Path) -> None:
        p = self._write(tmp_path, {"target": "  ", "vulns": []})
        with pytest.raises(GroundTruthError, match="target"):
            load_ground_truth(p)


# ---------------------------------------------------------------------------
# Scoreboard engine: strict matching, honest accounting, regression diff.
# ---------------------------------------------------------------------------


class TestScoreboardEngine:
    def test_perfect_detection(self) -> None:
        board = build_scoreboard(
            _gt(),
            [PredictedFinding("xss", "/search"), PredictedFinding("path_traversal", "/ftp")],
            elapsed_seconds=1.5,
            llm_tokens=420,
        )
        assert board["overall"]["detection_rate"] == 1.0
        assert board["overall"]["false_positive_count"] == 0
        assert board["overall"]["llm_tokens"] == 420
        assert board["overall"]["elapsed_seconds"] == 1.5
        assert all(c["detection_rate"] == 1.0 for c in board["classes"].values())

    def test_partial_detection_and_misses_listed(self) -> None:
        board = build_scoreboard(
            _gt(),
            [PredictedFinding("xss", "/search")],
            elapsed_seconds=0.2,
            llm_tokens=10,
        )
        assert board["classes"]["xss"]["detection_rate"] == 1.0
        assert board["classes"]["path_traversal"]["detection_rate"] == 0.0
        assert board["classes"]["path_traversal"]["missed_endpoints"] == ["/ftp"]
        assert board["overall"]["detection_rate"] == 0.5

    def test_wrong_endpoint_is_false_positive(self) -> None:
        # Right class, undeclared endpoint: NOT a detection.
        board = build_scoreboard(
            _gt(),
            [PredictedFinding("xss", "/elsewhere")],
            elapsed_seconds=0.0,
            llm_tokens=0,
        )
        assert board["overall"]["detection_rate"] == 0.0
        assert board["overall"]["false_positives"] == [
            {"vuln_class": "xss", "endpoint": "/elsewhere"}
        ]

    def test_declared_vuln_counted_once(self) -> None:
        board = build_scoreboard(
            _gt(),
            [
                PredictedFinding("xss", "/search"),
                PredictedFinding("xss", "/search"),
            ],
            elapsed_seconds=0.0,
            llm_tokens=0,
        )
        assert board["overall"]["detected_count"] == 1

    def test_board_is_deterministic(self) -> None:
        findings = [PredictedFinding("xss", "/search")]
        a = build_scoreboard(_gt(), findings, elapsed_seconds=1.0, llm_tokens=5)
        b = build_scoreboard(_gt(), findings, elapsed_seconds=1.0, llm_tokens=5)
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_write_load_roundtrip(self, tmp_path: Path) -> None:
        board = build_scoreboard(_gt(), [], elapsed_seconds=0.1, llm_tokens=1)
        p = tmp_path / "benchmark_scoreboard.json"
        write_scoreboard(p, board)
        assert load_scoreboard(p) == board

    def test_load_rejects_bad_version(self, tmp_path: Path) -> None:
        p = tmp_path / "board.json"
        p.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
        with pytest.raises(ScoreboardError, match="scoreboard_schema"):
            load_scoreboard(p)

    def test_regression_flagged_on_rate_drop(self) -> None:
        before = build_scoreboard(
            _gt(),
            [
                PredictedFinding("xss", "/search"),
                PredictedFinding("path_traversal", "/ftp"),
            ],
            elapsed_seconds=1.0,
            llm_tokens=0,
        )
        after = build_scoreboard(
            _gt(),
            [PredictedFinding("xss", "/search")],
            elapsed_seconds=1.0,
            llm_tokens=0,
        )
        report = compare_scoreboards(before, after)
        assert report["has_regressions"] is True
        assert report["regressions"][0]["vuln_class"] == "path_traversal"
        assert report["overall_delta"] < 0

    def test_no_regression_when_equal_or_better(self) -> None:
        before = build_scoreboard(
            _gt(), [PredictedFinding("xss", "/search")], elapsed_seconds=1.0, llm_tokens=0
        )
        after = build_scoreboard(
            _gt(),
            [
                PredictedFinding("xss", "/search"),
                PredictedFinding("path_traversal", "/ftp"),
            ],
            elapsed_seconds=1.0,
            llm_tokens=0,
        )
        report = compare_scoreboards(before, after)
        assert report["has_regressions"] is False
        assert report["overall_delta"] > 0

    def test_compare_rejects_schema_mismatch(self) -> None:
        with pytest.raises(ScoreboardError, match="scoreboard_compare_schema"):
            compare_scoreboards({"schema_version": 99}, {"schema_version": 1})


# ---------------------------------------------------------------------------
# End-to-end through the runner (campaign seam; no network).
# ---------------------------------------------------------------------------


class TestRunnerEndToEnd:
    def test_full_run_scores_against_ground_truth(self) -> None:
        calls: list[str] = []

        def campaign(url: str) -> CampaignResult:
            calls.append(url)
            return CampaignResult(
                findings=(
                    PredictedFinding("xss", "/search", evidence="reflected marker"),
                    PredictedFinding("sqli", "/undeclared", evidence="invented"),
                ),
                llm_tokens=77,
            )

        result = run_live_benchmark(
            enable_live_benchmarks=True,
            benchmark_target="http://127.0.0.1:3000",
            ground_truth=_gt(),
            campaign=campaign,
        )
        assert calls == ["http://127.0.0.1:3000"]
        assert result.target == "http://127.0.0.1:3000"
        assert result.elapsed_seconds >= 0.0
        assert result.llm_tokens == 77
        board = result.scoreboard
        assert board["target"] == "juice-shop-local"
        assert board["classes"]["xss"]["detection_rate"] == 1.0
        assert board["classes"]["path_traversal"]["detection_rate"] == 0.0
        assert board["overall"]["false_positive_count"] == 1
        assert board["overall"]["llm_tokens"] == 77

    def test_settings_gate_sweep(self) -> None:
        from webpent.config.settings import Settings, activate_settings, get_settings

        with activate_settings(Settings(enable_live_benchmarks=False)):
            assert get_settings().enable_live_benchmarks is False
            assert get_settings().benchmark_target == ""
        with activate_settings(
            Settings(
                enable_live_benchmarks=True,
                benchmark_target="http://127.0.0.1:3000",
            )
        ):
            assert get_settings().enable_live_benchmarks is True
            assert get_settings().benchmark_target == "http://127.0.0.1:3000"


# ---------------------------------------------------------------------------
# LIVE localhost fixture server (stdlib only, runs in the default suite —
# it is a loopback target, exactly what the runner exists for).
# ---------------------------------------------------------------------------


class _FixtureHandler(BaseHTTPRequestHandler):
    server_version = "benchfixture/1"

    def do_GET(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        if path == "/search":
            q = query.removeprefix("q=") if query else ""
            body = f"results for <b>{urllib.parse.unquote(q)}</b>".encode()
        elif path == "/ftp":
            body = b"directory listing: accounts.xml, purchaes.pdf (SOLVE_ME)"
        else:
            body = b"clean page"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: Any) -> None:
        pass


class TestLiveFixtureServer:
    @pytest.fixture()
    def server(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield httpd
        finally:
            httpd.shutdown()
            httpd.server_close()

    @staticmethod
    def _detector_campaign(base_url: str) -> CampaignResult:
        findings: list[PredictedFinding] = []
        marker = "webpent-bench-xss"
        with urllib.request.urlopen(f"{base_url}/search?q={marker}") as resp:
            if marker in resp.read().decode("utf-8", "replace"):
                findings.append(PredictedFinding("xss", "/search", evidence="reflected marker"))
        with urllib.request.urlopen(f"{base_url}/ftp") as resp:
            if "accounts.xml" in resp.read().decode("utf-8", "replace"):
                findings.append(
                    PredictedFinding("path_traversal", "/ftp", evidence="listing exposed")
                )
        return CampaignResult(findings=tuple(findings), llm_tokens=123)

    def test_loopback_run_detected_against_ground_truth(self, server, tmp_path: Path) -> None:
        target = f"http://127.0.0.1:{server.server_address[1]}"
        result = run_live_benchmark(
            enable_live_benchmarks=True,
            benchmark_target=target,
            ground_truth=_gt(),
            campaign=self._detector_campaign,
        )
        board = result.scoreboard
        assert board["overall"]["detection_rate"] == 1.0
        assert board["overall"]["false_positive_count"] == 0
        assert board["overall"]["llm_tokens"] == 123
        out = tmp_path / "benchmark_scoreboard.json"
        write_scoreboard(out, board)
        assert load_scoreboard(out)["target"] == "juice-shop-local"


# ---------------------------------------------------------------------------
# OPT-IN container test: a real local Juice Shop. Excluded from the
# default run; activate with WEBPENT_BENCHMARK_LIVE=1 AND
# WEBPENT_BENCHMARK_TARGET=http://127.0.0.1:3000 (container started
# locally by the operator).
# ---------------------------------------------------------------------------


class TestOptInJuiceShopContainer:
    @pytest.mark.skipif(
        os.environ.get("WEBPENT_BENCHMARK_LIVE") != "1"
        or not os.environ.get("WEBPENT_BENCHMARK_TARGET"),
        reason="opt-in: set WEBPENT_BENCHMARK_LIVE=1 and WEBPENT_BENCHMARK_TARGET to a local Juice Shop",
    )
    def test_container_ground_truth_scoring(self) -> None:
        import urllib.parse

        target = os.environ["WEBPENT_BENCHMARK_TARGET"]
        assert_local_target(target)  # fail-closed even in the opt-in path
        gt_path = os.environ.get("WEBPENT_BENCHMARK_GROUND_TRUTH")
        gt = load_ground_truth(gt_path) if gt_path else _gt()

        def probe(base_url: str) -> CampaignResult:
            findings: list[PredictedFinding] = []
            marker = "webpent-bench-xss"
            with urllib.request.urlopen(
                f"{base_url}/search?q={urllib.parse.quote(marker)}"
            ) as resp:
                if marker in resp.read().decode("utf-8", "replace"):
                    findings.append(
                        PredictedFinding("xss", "/search", evidence="reflected marker")
                    )
            return CampaignResult(findings=tuple(findings), llm_tokens=0)

        result = run_live_benchmark(
            enable_live_benchmarks=True,
            benchmark_target=target,
            ground_truth=gt,
            campaign=probe,
        )
        write_scoreboard(Path("benchmark_scoreboard.json"), result.scoreboard)
        print(json.dumps(result.scoreboard["overall"], indent=2))
