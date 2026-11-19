"""C2(b) TC-2 — resurrect.py is residue-aware.

The prior lineage's resurrection scripts ran their import-origin proof
OUTSIDE pytest's conftest redirection and shipped runtime residue
(``memory/global/chroma_db/chroma.sqlite3``) inside the v14.1 delivery.
The canonical ``scripts/resurrect.py`` must therefore satisfy, as a
tested contract:

  * running it NEVER leaves residue in the delivery tree (the same env
    redirection pytest's conftest applies is performed pre-import, the
    conftest-patched default path constants are re-pointed into a temp
    sandbox, and a self-sweep runs afterwards);
  * the import-origin proof stays green (brain + spine modules resolve
    from ``src/``, never site-packages);
  * the repo's own extended hygiene gate is green after a run.

DoD (C2): "run resurrect.py → the hygiene gate stays green".
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESURRECT = ROOT / "scripts" / "resurrect.py"
HYGIENE = ROOT / "scripts" / "hygiene_gate_extended.py"


def _run(script: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # emulate the operator shell: NO conftest redirection present
    env.pop("WEBPENT_AUDIT_ROOT", None)
    return subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True,
        cwd=str(ROOT), env=env, timeout=300,
    )


def test_resurrect_passes_and_leaves_tree_clean():
    """Run resurrect.py exactly as an operator would (outside pytest's
    redirection) — the script must pass and leave zero residue.

    A dirty starting tree is the OPERATOR's reality: residue from other
    runs may already exist, and the script's sweep intercepting + purging
    it IS the designed behavior.  The contract is therefore idempotent:

      run 1: PASS, and the probe is either clean or intercepted+purged;
             the hygiene gate is green afterwards.
      run 2: the probe MUST be clean (the redirection holds on an
             already-clean tree — proof the script itself deposits
             nothing).
    """
    first = _run(RESURRECT)
    assert first.returncode == 0, (
        f"resurrect.py failed rc={first.returncode}\n{first.stdout}\n{first.stderr}"
    )
    assert "RESURRECT: PASS" in first.stdout
    assert ("residue probe clean" in first.stdout
            or "residue intercepted + purged" in first.stdout), first.stdout
    gate_after_first = _run(HYGIENE)
    assert gate_after_first.returncode == 0, gate_after_first.stdout + gate_after_first.stderr

    second = _run(RESURRECT)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "RESURRECT: PASS" in second.stdout
    assert "residue probe clean" in second.stdout, (
        "residue-awareness redirection did not hold on an already-clean "
        f"tree — the script itself deposits residue:\n{second.stdout}"
    )


def test_hygiene_gate_stays_green_after_resurrect():
    """C2 DoD: the extended hygiene gate is green AFTER resurrect.py runs
    (the delivery tree carries zero runtime residue).
    """
    first = _run(RESURRECT)
    assert first.returncode == 0, first.stdout + first.stderr
    gate = _run(HYGIENE)
    assert gate.returncode == 0, (
        f"hygiene gate FAILED after resurrect run:\n{gate.stdout}\n{gate.stderr}"
    )
    assert "HYGIENE GATE: PASS" in gate.stdout
    # and no chroma residue can exist, ever again
    assert not (ROOT / "memory" / "global" / "chroma_db" / "chroma.sqlite3").exists()


def test_import_origin_proof_covers_six_brain_modules():
    """The resurrect script's proof list covers all remaining brain modules
    (the U-0 import-origin contract) plus the memory/spine defaults that
    conftest redirects.

    G-1 (v0.29.0): the retired ``webpent.brain.lessons`` ledger was DELETED
    from the tree in its declared removal window
    (docs/learning_source_of_truth.md), so the contract is now SIX brain
    modules, not seven. The live lessons source of truth remains
    ``webpent.memory.lessons`` (pinned in the script's SPINE_MODULES).
    """
    script = RESURRECT.read_text()
    for mod in (
        "webpent.brain.ev_scheduler", "webpent.brain.blocked_path",
        "webpent.brain.curiosity", "webpent.brain.adaptation",
        "webpent.brain.payload_selector", "webpent.brain.scorecard",
    ):
        assert f'"{mod}"' in script, f"brain module missing from proof list: {mod}"
    # The deleted module must NOT be resurrected by anything.
    assert '"webpent.brain.lessons"' not in script, (
        "webpent.brain.lessons was deleted in G-1 (v0.29.0) — it must not "
        "reappear in the resurrect proof list"
    )
    for attr in (
        "_DEFAULT_CHROMA_PATH", "_DEFAULT_LESSONS_DB_PATH",
        "_DEFAULT_DECISION_LOG_DB_PATH", "_DEFAULT_SESSIONS_DB_PATH",
    ):
        assert attr in script, f"conftest default not redirected: {attr}"
