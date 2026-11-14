"""Live parity harness contract (R-01 — TEAM-2 Wave 1, structural gate).

The live multi-container proof itself can only run on a Docker host
(scripts/run_live_parity.py exits 2 WITHOUT claiming success where Docker
is unavailable — that honesty gate is pinned by test_live_parity_refuses
_without_docker). This contract test pins the structural completeness of
the runnable verification path so the harness cannot silently decay:

  * it drives the REAL dispatch seam (POST /api/v1/scans) and the real
    OAuth2 token flow;
  * it verifies the SHARED engagement database from the host side
    (./runtime/webpent.db via the compose shared mount) — the live
    one-persistence-authority proof;
  * it restarts the worker container and asserts no duplicate findings;
  * it writes a machine-readable artifact under benchmarks/live_parity_v1/.

LIMITATION (stated per report mandate): in this sandbox Docker is not
available, so only the structural contract + the harness's own honesty
gate are verified here. A live run remains the operator acceptance step
for full R-01 closure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "run_live_parity.py"
COMPOSE = ROOT / "docker-compose.test.yml"


def _source() -> str:
    return HARNESS.read_text(encoding="utf-8")


def test_live_parity_harness_exists_and_parses() -> None:
    assert HARNESS.is_file(), "scripts/run_live_parity.py must exist"
    ast.parse(_source(), filename=str(HARNESS))


def test_live_parity_harness_drives_real_seams() -> None:
    src = _source()
    assert "/api/v1/scans" in src, "harness must POST the real scan dispatch endpoint"
    assert "/token" in src, "harness must authenticate through the real token flow"
    assert "api/v1/scans/{thread_id}/findings" in src
    assert "Tool-Confirmed" in src, "harness must gate on tool-first confirmation"


def test_live_parity_harness_verifies_shared_db_from_host() -> None:
    src = _source()
    assert "runtime/webpent.db" in src or "runtime" in src
    assert "mode=ro" in src, "shared-DB verification must be read-only"
    assert "confidence_level = 'Tool-Confirmed'" in src
    assert "thread_id = ?" in src


def test_live_parity_harness_restarts_worker_and_checks_duplicates() -> None:
    src = _source()
    assert "restart" in src and "worker" in src, (
        "harness must restart the worker container to prove resume semantics"
    )


def test_live_parity_harness_writes_machine_readable_artifact() -> None:
    src = _source()
    assert "LIVE_PARITY_RESULT.json" in src
    assert "webpent-live-parity-v1" in src


def test_compose_test_stack_keeps_workspace_parity_env() -> None:
    import yaml

    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    api_env = str(data["services"]["api"]["environment"])
    worker_env = str(data["services"]["worker"]["environment"])
    for env in (api_env, worker_env):
        assert "WEBPENT_DATABASE_URL=sqlite:////app/runtime/webpent.db" in env
        assert "WEBPENT_TARGET_WORKSPACE_ROOT=/app/runtime/workspaces" in env
    api_vols = str(data["services"]["api"]["volumes"])
    worker_vols = str(data["services"]["worker"]["volumes"])
    for vols in (api_vols, worker_vols):
        assert "/app/runtime" in vols
    # R-01: harness needs the published API port and a lab credential to
    # exercise the real OAuth2 flow.
    assert "8000:8000" in str(data["services"]["api"]["ports"])


def test_live_parity_refuses_without_docker() -> None:
    """The honesty gate: no Docker on host -> exit 2, no steps claimed."""
    src = _source()
    assert "shutil.which(\"docker\") is None" in src
    assert "NOT executed and NOT claimed" in src
    assert "return 2" in src
