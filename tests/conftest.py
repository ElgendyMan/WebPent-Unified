"""Shared pytest fixtures for the WebPent test suite.

Added during the v10/v61 -> GOED v1.8.4 canonical merge (see
RECONCILIATION_REPORT.md). Somewhere in the GOED line, several secret-key
settings (``celery_payload_key``, ``jwt_secret_key``, ...) had their
defaults tightened from an old publicly-known placeholder string to an
explicit empty string, and the code paths that use them were correspondingly
changed to fail closed (refuse to encrypt/sign, and do not retain the
secret) whenever no key is configured at all, rather than silently using a
key any attacker already knows. That is a correct hardening — a well-known
default key provides no real confidentiality — but it means any test
written against the old "insecure-but-functional" default now needs an
explicit key configured, exactly as a real deployment would need to set one.

These fixtures supply those keys by default so the large majority of tests
(which are not specifically about key configuration) keep exercising the
encrypt/decrypt or sign/verify round trip they were written to test. Tests
that specifically exercise the "no key configured" fail-closed path (e.g.
``TestCeleryPayloadKeyEnvAlias`` in test_v10_exhaustive_audit.py) delete the
env vars themselves via the same ``monkeypatch`` fixture instance, which
overrides these fixtures' ``setenv`` within that test.
"""

from __future__ import annotations

import contextlib
import os

import pytest

# R3 E-4 (Ruling R3-002 §3.4, mechanism (b)): the production graph node
# derives its entrypoint TRUTHFULLY and fails closed when the surface is
# underivable. The test harness invokes nodes/graphs directly in-process —
# for THIS process the truthful label is the KNOWN_ENTRYPOINTS member
# "direct_invoke" — so the harness declares it explicitly at session start.
# Production surfaces never import conftest: worker.py/server.py/webpent-cli.sh
# set their own true labels, `python -m webpent.cli` is derived from
# __main__, and a bare underivable production process still fails closed.
os.environ.setdefault("WEBPENT_ENTRYPOINT", "direct_invoke")


@pytest.fixture(autouse=True)
def _reset_concurrency_governor_singleton():
    """Track 12 hygiene (v0.25.0): the process-wide concurrency-governor
    singleton (0.18.0 facade tickets) must not leak ACTIVE admissions
    across tests — a campaign left RUNNING by one test otherwise
    consumes the next test's global/per-target admission slots and the
    failure surfaces far from its cause. ``reset_concurrency_governor()``
    drops the singleton; the next ``get_concurrency_governor()`` call
    rebuilds it from the CURRENT settings (env flips in a test are
    therefore honored — same contract the lease-backend tests rely on).
    This does not weaken production admission: within one test the
    governor still enforces its caps exactly as designed (see
    tests/test_concurrency_governor.py).
    """
    from webpent.production.concurrency_governor import reset_concurrency_governor

    reset_concurrency_governor()
    yield
    reset_concurrency_governor()


@pytest.fixture(autouse=True)
def _reset_production_spine_registry():
    """Sprint R1 FIX 1 hygiene: resolve_production_spine()'s module-level
    configuration-drift registry (_SPINE_REGISTRY) is now exercised by many
    more tests than before (via modern_spine_recon_node / campaign_worker
    routing through the factory), and those tests use ad-hoc engagement_id
    strings for unrelated purposes. Without a reset, two unrelated tests
    that happen to reuse the same engagement_id with a different target_url
    would trip drift-detection as if they were the same production run.
    This does not weaken the real check: within a single test, calling
    resolve_production_spine twice for the same engagement_id with
    different configs still fails closed exactly as designed — see
    tests/team1_acceptance/test_half2_production_dataflow.py::
    TestEntrypointParity.
    """
    from webpent.production.production_spine import _SPINE_REGISTRY
    _SPINE_REGISTRY.clear()
    yield
    _SPINE_REGISTRY.clear()


@pytest.fixture(autouse=True)
def _allow_direct_orchestrator_construction_in_tests(monkeypatch: pytest.MonkeyPatch):
    """Sprint R1 FIX 1: ModernOrchestrator.__init__ now refuses direct
    construction outside webpent.production.production_spine.
    resolve_production_spine(), the single authoritative factory (see
    modern_spine.py). The large majority of existing unit tests construct
    ModernOrchestrator directly to exercise it in isolation — a legitimate
    test-only pattern, not a production path. This is the one explicit,
    clearly-named test-only escape hatch, applied for the whole test
    session rather than threading a factory token through every test file
    that constructs ModernOrchestrator directly.
    """
    monkeypatch.setenv("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")


@pytest.fixture(autouse=True)
def _global_memory_to_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path_factory):
    """R-09 (TEAM-2 residual): keep global memory out of the repo checkout.

    The decision-log, lessons, session-checkpoint, and vector-store managers
    fall back to CWD-anchored ``./memory/global/...`` defaults when no explicit
    database URL is passed. Under pytest the CWD is the repo root, so any test
    that touched those managers silently created/mutated
    ``memory/global/*.db`` inside the checkout. Redirect every default to a
    per-test temporary directory instead; tests that pass an explicit
    ``database_url`` (the majority) are unaffected.
    """
    base = tmp_path_factory.mktemp("global_memory") / "memory" / "global"
    base.mkdir(parents=True, exist_ok=True)
    import webpent.graph.checkpoints as _checkpoints
    import webpent.memory.decision_log as _decision_log
    import webpent.memory.lessons as _lessons
    import webpent.memory.vectorstore as _vectorstore

    monkeypatch.setattr(
        _decision_log, "_DEFAULT_DECISION_LOG_DB_PATH", str(base / "decision_log.db")
    )
    monkeypatch.setattr(_lessons, "_DEFAULT_LESSONS_DB_PATH", str(base / "lessons.db"))
    monkeypatch.setattr(
        _vectorstore, "_DEFAULT_CHROMA_PATH", str(base / "chroma_db")
    )
    monkeypatch.setattr(
        _checkpoints, "_DEFAULT_SESSIONS_DB_PATH", str(base / "sessions.db")
    )
    yield


@pytest.fixture(autouse=True)
def _hermetic_database_url(monkeypatch: pytest.MonkeyPatch):
    """R-04 (TEAM-2 residual): make the suite hermetic against ambient DB env.

    A stray generic ``DATABASE_URL`` exported in the operator shell (common in
    CI images and dev containers that also host other frameworks) used to leak
    into ``Settings`` and redirect the OOB-parity and persistence tests to a
    foreign database. Every test starts from the namespaced-variable-free,
    generic-variable-free state; tests that specifically exercise env-var
    precedence set their own variables via ``monkeypatch.setenv`` inside the
    test body, which runs after this fixture.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("WEBPENT_DATABASE_URL", raising=False)
    yield


@pytest.fixture(autouse=True)
def _default_secret_keys(monkeypatch: pytest.MonkeyPatch):
    from webpent.config.settings import get_settings

    monkeypatch.setenv(
        "CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use"
    )
    monkeypatch.setenv(
        "JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000"
    )
    # Fix-sprint 2026-10-05 (hermetic-suite fix): AUDIT_SECRET_KEY is the
    # third fail-closed key (ProofBundle seal HMAC via
    # webpent/models/proof_bundle.py::_compute_authenticity_tag). Without a
    # default here, tests that seal a ProofBundle (e.g.
    # test_v26_report_quality.py) only pass when an alphabetically-earlier
    # test module leaks WEBPENT_AUDIT_SECRET_KEY into the process (known
    # leaker: test_half2_production_dataflow.py os.environ.setdefault at
    # import time) — order-dependent, masked in full-tree runs. Tests that
    # specifically exercise the no-key fail-closed path delenv these vars
    # themselves (e.g. test_sprint_i1b_part2_secrets_gate._clean_env),
    # which overrides this fixture by design.
    monkeypatch.setenv(
        "AUDIT_SECRET_KEY", "test-only-audit-secret-key-not-for-production-0000000000"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _m2_isolated_audit_root(tmp_path, monkeypatch):
    """M2-impl WP-A/WP-B (Dispatch #009): isolate the seam's engagement
    audit/campaign-state root per test.

    The seam writes REAL hash-chained audit files and DURABLE CampaignState
    (dedupe keys + registered candidates) under WEBPENT_AUDIT_ROOT. Without
    per-test isolation: (a) repo-root ``artifacts/`` residue leaks into the
    delivery tree (hygiene-gate class), and (b) tests reusing engagement ids
    would read each other's durable dedupe memory — cross-test contamination
    of a durable store. Production behavior is unchanged (the env var is the
    documented deployment override; default remains the hunter_runner
    convention).
    """
    monkeypatch.setenv("WEBPENT_AUDIT_ROOT", str(tmp_path / "m2_audit_root"))

@pytest.fixture(autouse=True)
def _hermetic_persistent_ledgers(monkeypatch: pytest.MonkeyPatch, tmp_path_factory):
    """Isolate the on-disk finding/action ledgers per test.

    ``PersistentFindingLedger`` and the action ledger default to a shared
    ``~/.webpent/*.sqlite3`` path that survives across test runs. Because the
    OOB confirmation path is deliberately one-way (a finding can only be
    upgraded to ``Tool-Confirmed`` once), a row written by an earlier test or
    an earlier run made a later test's confirmation get refused by the
    persistence authority — an isolation defect, not a product bug.

    Point both ledgers at a per-test temporary directory so every test starts
    from an empty, private store. Tests that specifically exercise ledger
    persistence set their own path inside the test body, which runs after this
    fixture and therefore wins.
    """
    base = tmp_path_factory.mktemp("persistent-ledgers")
    monkeypatch.setenv("WEBPENT_FINDINGS_LEDGER_PATH", str(base / "findings_ledger.sqlite3"))
    monkeypatch.setenv("WEBPENT_ACTION_LEDGER_PATH", str(base / "action_ledger.sqlite3"))
    monkeypatch.setenv(
        "WEBPENT_TARGET_PACKAGE_LEASE_PATH", str(base / "target_package_leases.sqlite3")
    )
    from webpent.config.settings import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_db_manager_singletons():
    """Reset the process-global DB manager cache between tests.

    ``webpent.memory.db.get_db_manager`` caches one manager per resolved
    database URL in module-level globals (``_db_manager_singleton`` and
    ``_db_manager_singletons``). Those globals survive across tests in a
    single process, so a manager bound to an earlier test's temporary
    workspace database was reused by a later test — the later test's
    finding was written to the wrong database and its OOB confirmation was
    refused. Clearing the cache before and after each test restores real
    per-test isolation without changing production behaviour.
    """
    from webpent.memory import db as _db

    def _clear() -> None:
        _db._db_manager_singleton = None
        _db._db_manager_singletons.clear()

    _clear()
    yield
    _clear()


@pytest.fixture(autouse=True)
def _teardown_leaked_playwright_loops():
    """Stop Playwright's sync driver if a test left one running.

    ``playwright.sync_api.sync_playwright().start()`` (used by
    ``BrowserFarm._start``) creates its own asyncio event loop and runs it
    from a greenlet; the loop stays "running" for the rest of the process
    until the driver's ``__exit__``/``stop`` is called. ``BrowserFarm``
    exposes ``close_all()`` for exactly this, but a test that builds a farm
    and does not close it (e.g. the crawler test in
    ``tests/test_browser_hunter.py``) leaked the loop into every later
    test. The next ``async`` test then died with
    ``RuntimeError: Runner.run() cannot be called from a running event
    loop`` — a test-isolation defect that had nothing to do with the code
    under test.

    This fixture tracks every ``BrowserFarm`` constructed during the test
    and closes any that the test did not close itself, so each test starts
    with no running loop. It is a no-op when no farm was created.
    """
    try:
        from webpent.recon import browser_farm as _bf
    except Exception:
        yield
        return

    created: list = []
    original_init = _bf.BrowserFarm.__init__

    def _tracking_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self)

    _bf.BrowserFarm.__init__ = _tracking_init
    try:
        yield
    finally:
        _bf.BrowserFarm.__init__ = original_init
        for farm in created:
            if getattr(farm, "_closed", True):
                continue
            with contextlib.suppress(Exception):
                farm.close_all()

@pytest.fixture(scope="session", autouse=True)
def _verdict_test_workspace(tmp_path_factory):
    """MERGE 2026-10-26: session default verdict workspace (initialized AND
    pre-registered).

    Why: the absorbed donorC-lineage acceptance tests (fabric dispatch) drive
    the production spine against non-loopback lab targets; the Round-4
    verdict bridge (absorbed from the l6 lineage) fail-closes those runs when
    the default workspace is uninitialized. Production behavior is unchanged
    (conftest is never imported by production surfaces); the strict verdict
    tests manage their own workspace via _set_workspace_env / monkeypatch and
    override this default per-test, so their gate strictness is untouched.
    Promoted findings from the inherited tests register into this isolated
    per-session workspace, never the shipped default.
    """
    import pathlib
    import subprocess

    root = pathlib.Path(__file__).resolve().parents[1]
    ws = tmp_path_factory.mktemp("verdict-ws")
    cli = ["python3", "-m", "verdict_tool.cli", "--path", str(ws)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src")
    cwd = str(root / "verdict")
    steps = [
        cli + ["init"],
        cli + ["pre-registration", "predict", "--findings", "5", "15",
               "--acceptance", "0.2", "0.5"],
    ]
    for step in steps:
        subprocess.run(step, check=True, cwd=cwd, env=env,
                       capture_output=True, text=True)
    template = root / "verdict" / "verdict_tool" / "templates" / "pre_registration.md"
    (ws / "pre_registration.md").write_text(
        template.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(cli + ["pre-registration", "done"], check=True, cwd=cwd,
                   env=env, capture_output=True, text=True)
    os.environ.setdefault("WEBPENT_VERDICT_WORKSPACE", str(ws))
    yield
    os.environ.pop("WEBPENT_VERDICT_WORKSPACE", None)
