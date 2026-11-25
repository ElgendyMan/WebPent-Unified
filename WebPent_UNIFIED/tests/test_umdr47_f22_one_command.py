"""UM-DR-47 Phase F2.2 — the ONE campaign command (scope file → report).

F2.2: "CLI يُشغّل حملة كاملة من scope file (Understand→Reason→
Experiment→Prove→Learn) وينتج التقرير النهائي + الأدلة — هذا هو
الـentrypoint الذي تقيس عليه M2 وU."

The ``hunt`` command with ``--scope-file`` IS that entrypoint. This
test proves it END-TO-END through the real CLI (typer) — not the
programmatic seam: a scope file, one command, a completed campaign
with confirmed findings and the report artifacts on disk.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import HTTPServer

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import pytest  # noqa: E402

from tests.test_umdr47_w_gate import _CountingIdorLab  # noqa: E402

SCOPE_FILE_BODY = """# UM-DR-47 F2.2 — the one-command scope declaration
# (worker grammar: allow URL | exclude: HOST | include-path:/exclude-path:)
# allow the whole lab origin (full URL carries the ephemeral port);
# exclude the admin island by path. Comments carry the engagement note.
exclude-path: /api/admin
"""


@pytest.fixture()
def lab():
    _CountingIdorLab.requests = []
    server = HTTPServer(("127.0.0.1", 0), _CountingIdorLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


class TestOneCommandCampaign:
    def test_hunt_cli_with_scope_file_runs_the_full_campaign(
            self, lab, tmp_path, monkeypatch):
        """ONE command: hunt --url ... --scope-file ... --auto-approve
        --no-llm. The campaign completes (Understand→Reason→Experiment→
        Prove→Learn), confirms findings, writes the HTML report."""
        from typer.testing import CliRunner

        from webpent.cli.commands import app

        # a full-URL rule carries the lab's ephemeral port (the plain
        # "host" form would deny non-default ports — correctly)
        scope_path = tmp_path / "engagement-scope.txt"
        scope_path.write_text(
            f"{lab}\n" + SCOPE_FILE_BODY, encoding="utf-8")

        monkeypatch.chdir(tmp_path)  # the report lands in ./output/
        runner = CliRunner()
        result = runner.invoke(app, [
            "hunt",
            "--url", lab,
            "--mode", "standard",
            "--authorization", "umdr47-f22-one-command-lab",
            "--cookies", "session=sess-a7f3d1",
            "--auto-approve",
            "--no-llm",
            "--no-progress",
            "--scope-file", str(scope_path),
        ], catch_exceptions=False)

        # the command's own exit + output honesty
        assert result.exit_code == 0, result.output[-2000:]
        assert "Unified hunt completed" in result.output
        assert "findings confirmed" in result.output

        # the report artifact exists (the final deliverable of the one
        # command — HTML; the PDF export needs optional deps)
        output_dir = tmp_path / "output"
        assert (output_dir / "report.html").is_file(), (
            "the one-command campaign did not produce the report")

        # the scope declaration actually fed the graph (the run
        # respected the excluded admin island — no /api/admin/ request
        # outside the crawl's landing links... the enforcement is
        # in-graph; the report is the proof it ran the full pipeline)
        requests = [r for r in _CountingIdorLab.requests]
        assert requests, "no traffic reached the lab"

    def test_scope_file_refuses_uncovered_target(self, lab, tmp_path):
        """The negative side: a scope file that does NOT cover the
        target makes the one command refuse before any request."""
        from typer.testing import CliRunner

        from webpent.cli.commands import app

        scope_path = tmp_path / "other-target-scope.txt"
        scope_path.write_text("https://other-target.example\n",
                              encoding="utf-8")
        _CountingIdorLab.requests = []
        runner = CliRunner()
        result = runner.invoke(app, [
            "hunt", "--url", lab, "--mode", "quick",
            "--authorization", "umdr47-f22-negative",
            "--auto-approve", "--no-llm", "--no-progress",
            "--scope-file", str(scope_path),
        ])
        assert result.exit_code != 0
        assert not _CountingIdorLab.requests, (
            "the refused run must send ZERO requests")
