# tests/team1_acceptance/test_sprint_i1_part2_s2_composition.py
"""Sprint I-1, item 2.3 — S-2 composition test (M3 v1.1 §5.2.2 / F-02).

Spawns _s2_composition_subprocess_body.py in a fresh subprocess (clean
sys.modules) and asserts on its JSON result.

See that script's own docstring and config/isolation_denylist.yaml for
the documented D-01/A-01 gap: this test does NOT (and cannot, without
fabricating a contract this sprint was never given) assert "no
denylisted name in sys.modules" or "no module outside webpent/stdlib/
A-01" — it asserts everything that IS fully specified: successful
composition-root imports (including the pinned uvicorn string target),
a successful resolve_production_spine() call, the F-02 lazy-load
trigger actually resolving names, the OQ-2 bbscout-absence check, and a
"strix" substring absence check (justified directly by M3's own stated
audit objective).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SUBPROCESS_BODY = Path(__file__).parent / "_s2_composition_subprocess_body.py"


@pytest.fixture(scope="module")
def s2_result():
    proc = subprocess.run(
        [sys.executable, str(SUBPROCESS_BODY)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"S-2 subprocess exited {proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
    )
    # The subprocess prints exactly one JSON line to stdout.
    return json.loads(proc.stdout.strip().splitlines()[-1])


class TestS2Composition:
    def test_no_import_errors(self, s2_result):
        assert s2_result["errors"] == [], f"composition-root import errors: {s2_result['errors']}"

    def test_resolve_production_spine_succeeded(self, s2_result):
        assert s2_result["resolve_production_spine_ok"] is True

    def test_pinned_uvicorn_target_imported(self, s2_result):
        assert "webpent.api.app" in s2_result["sys_modules_keys"]

    def test_all_composition_roots_present(self, s2_result):
        for root in (
            "webpent.cli", "webpent.cli.ingest", "webpent.workers.pentest_worker",
            "webpent.production.production_spine", "webpent.production.modern_spine_integration",
        ):
            assert root in s2_result["sys_modules_keys"], f"{root} not in sys.modules"

    def test_lazy_load_trigger_resolved_names(self, s2_result):
        """F-02: the lazy-load trigger must have actually resolved at
        least one name per composition root that has a lazy __getattr__
        surface — an empty resolved-list everywhere would mean the
        trigger silently did nothing."""
        total_resolved = sum(len(v) for v in s2_result["lazy_loaded"].values())
        assert total_resolved > 0, "lazy-load trigger resolved zero names across all composition roots"

    def test_research_engine_lazy_loads_triggered(self, s2_result):
        """F-02 explicitly requires importing webpent.research_engine
        directly and triggering its lazy loads, since it may not be
        reached by every entrypoint import chain."""
        assert "webpent.research_engine" in s2_result["lazy_loaded"]
        # research_engine/__init__.py defines 18 __getattr__ branches
        # (verified this sprint) plus its eagerly-imported names, all
        # listed in its own __all__ — every one must resolve.
        assert len(s2_result["lazy_loaded"]["webpent.research_engine"]) >= 18

    def test_bbscout_absent_when_signed_package_path_not_exercised(self, s2_result):
        """OQ-2: the actual third-party bbscout package must not appear
        in sys.modules when the signed-package intake path is not
        exercised — which it isn't here.

        Matches the real package only (top-level "bbscout" or
        "bbscout.<submodule>"), NOT webpent.shared.bbscout_bridge —
        WebPent's own isolation-boundary module, whose docstring states
        it "deliberately does not import or execute bbscout code". A
        naive substring match against "bbscout" anywhere in the module
        name would false-positive on that legitimate boundary module;
        verified against this real tree before fixing this test.
        """
        real_bbscout_hits = [
            mod for mod in s2_result["sys_modules_keys"]
            if mod == "bbscout" or mod.startswith("bbscout.")
        ]
        assert real_bbscout_hits == [], f"unexpected bbscout import(s): {real_bbscout_hits}"

    def test_strix_absent_from_sys_modules(self, s2_result):
        """Justified directly by M3's own stated audit objective ("no
        capability of the external reference codebase (Strix) is
        reachable") — this does not require D-01's actual pattern list,
        since "strix" is the audited codebase's own name, not one of
        its internal module names. Matches the real package only (top-
        level "strix" or "strix.<submodule>"), same precision fix as
        the bbscout check above — verified no legitimate webpent module
        name contains "strix" as a substring before relying on this."""
        real_strix_hits = [
            mod for mod in s2_result["sys_modules_keys"]
            if mod == "strix" or mod.startswith("strix.")
        ]
        assert real_strix_hits == [], f"unexpected strix import(s): {real_strix_hits}"

    def test_no_denylisted_top_level_name_in_sys_modules(self, s2_result):
        """D-01, now buildable: Sprint I-1 Continuation 03 supplied the
        genuine M3 v1.0 document with D-01's full pattern list."""
        assert s2_result["d01_hits"] == [], f"D-01 hits found: {s2_result['d01_hits']}"

    def test_no_module_outside_webpent_stdlib_or_a01(self, s2_result):
        """A-01, now buildable. See
        _s2_composition_subprocess_body.py::compute_a01_transitive_closure
        for why this checks A-01's transitive dependency closure rather
        than exact-name membership: A-01's 33 direct entries pull in 41
        real, legitimate transitive dependencies at runtime (anyio,
        starlette, click, six, requests, ... — verified this sprint) plus
        2 non-package interpreter artifacts (cython_runtime,
        sitecustomize) that carry no pip metadata at all. A literal
        exact-name check would false-positive on every one of them."""
        assert s2_result["a01_unaccounted_top_level"] == [], (
            f"modules outside webpent/stdlib/A-01(+closure): "
            f"{s2_result['a01_unaccounted_top_level']}"
        )
