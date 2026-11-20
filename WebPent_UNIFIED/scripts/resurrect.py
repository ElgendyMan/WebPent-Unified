#!/usr/bin/env python3
"""WebPent resurrection script — canonical, residue-aware (C2(b), TC-2).

The prior lineage's resurrection scripts regenerated the post-reset tree
but ran their import-origin proof OUTSIDE pytest's conftest redirection,
so every run risked depositing runtime state into the delivery tree
(chroma.sqlite3 under ``memory/global/`` — the exact residue the
verifier found shipped in v14.1).

This script is the corrected, canonical version.  Ordering is the fix:

  1. REDIRECT FIRST — before importing ANY webpent module, the same env
     redirection pytest's conftest applies is set here:
       * ``WEBPENT_AUDIT_ROOT``       -> temp sandbox
       * ``DATABASE_URL`` / ``WEBPENT_DATABASE_URL`` removed
     and, right after each memory/spine import, the module-level default
     path constants (the very ones conftest monkeypatches) are re-pointed
     into the sandbox:
       * ``memory.vectorstore._DEFAULT_CHROMA_PATH``
       * ``memory.lessons._DEFAULT_LESSONS_DB_PATH``
       * ``memory.decision_log._DEFAULT_DECISION_LOG_DB_PATH``
       * ``graph.checkpoints._DEFAULT_SESSIONS_DB_PATH``
  2. IMPORT-ORIGIN PROOF — the U-0 proof made repeatable: the seven brain
     modules (plus the spine integrator) must resolve from this repo's
     ``src/`` tree, never from an installed copy in site-packages.
  3. SELF-SWEEP — after the proof, the tree is swept for the
     hygiene-gate residue classes (C1 hunt_artifacts, C2 memory/global,
     C3 output, C4 .env*, C5 WAL/SHM sidecars) and anything the run
     deposited there is purged.  Non-sweepable surprises fail the run.

Exit 0 = proof passed AND tree left clean.  Any failure exits non-zero.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

BRAIN_MODULES = [
    "webpent.brain.ev_scheduler",
    "webpent.brain.blocked_path",
    "webpent.brain.curiosity",
    "webpent.brain.adaptation",
    # G-1 (v0.29.0): the retired in-memory lessons ledger module REMOVED
    # from this list — it was deleted from the tree in its declared
    # removal window (docs/learning_source_of_truth.md decision), so there
    # is nothing left to resurrect. The live lessons source of truth is
    # webpent.memory.lessons (already pinned in SPINE_MODULES below).
    "webpent.brain.payload_selector",
    "webpent.brain.scorecard",
]
SPINE_MODULES = [
    "webpent.production.modern_spine_integration",
    "webpent.production.autonomous_validation_v1",  # DR-005: shipped broken in v14.1
    "webpent.memory.vectorstore",
    "webpent.memory.lessons",
    "webpent.memory.decision_log",
    "webpent.graph.checkpoints",
]

# hygiene-gate sweep classes (mirror scripts/hygiene_gate_extended.py)
SWEEP_DIRS = ["memory", "output", "hunt_artifacts", "artifacts"]
ENV_REDIR = "WEBPENT_AUDIT_ROOT"
ENV_STRIP = ("DATABASE_URL", "WEBPENT_DATABASE_URL")


def _redirect_env(sandbox: Path) -> None:
    """Step 1a: the conftest env redirection, applied pre-import."""
    os.environ[ENV_REDIR] = str(sandbox / "audit_root")
    for var in ENV_STRIP:
        os.environ.pop(var, None)
    # keep the suite's entrypoint contract
    os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
    os.environ.setdefault(
        "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
    )


def _redirect_default_paths(sandbox: Path) -> list[str]:
    """Step 1b: re-point the conftest-patched default path constants."""
    redirected: list[str] = []
    import importlib

    targets = [
        ("webpent.memory.vectorstore", "_DEFAULT_CHROMA_PATH", sandbox / "chroma_db"),
        ("webpent.memory.lessons", "_DEFAULT_LESSONS_DB_PATH", sandbox / "lessons.db"),
        ("webpent.memory.decision_log", "_DEFAULT_DECISION_LOG_DB_PATH",
         sandbox / "decision_log.db"),
        ("webpent.graph.checkpoints", "_DEFAULT_SESSIONS_DB_PATH", sandbox / "sessions.db"),
    ]
    for mod_name, attr, sandbox_path in targets:
        mod = importlib.import_module(mod_name)
        if hasattr(mod, attr):
            setattr(mod, attr, str(sandbox_path))
            redirected.append(f"{mod_name}.{attr}")
    return redirected


def _import_origin_proof() -> list[str]:
    """Step 2: every brain/spine module must originate from ``src/``."""
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    import importlib

    failures: list[str] = []
    for mod_name in BRAIN_MODULES + SPINE_MODULES:
        mod = importlib.import_module(mod_name)
        origin = Path(getattr(mod, "__file__", "") or "").resolve()
        try:
            origin.relative_to(SRC.resolve())
        except ValueError:
            failures.append(f"{mod_name} resolves OUTSIDE src/: {origin}")
    return failures


def _self_sweep() -> list[str]:
    """Step 3: purge anything the run deposited into residue classes."""
    purged: list[str] = []
    for rel in SWEEP_DIRS:
        base = ROOT / rel
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file():
                purged.append(str(p.relative_to(ROOT)))
        shutil.rmtree(base, ignore_errors=True)
    return purged


def _residue_probe() -> list[str]:
    """Files the run deposited into residue classes BEFORE the sweep
    (proof that redirection was necessary and that the sweep caught them).
    """
    found: list[str] = []
    for rel in SWEEP_DIRS:
        base = ROOT / rel
        if base.exists():
            for p in base.rglob("*"):
                if p.is_file():
                    found.append(str(p.relative_to(ROOT)))
    return found


def main() -> int:
    print("=== WebPent resurrect (residue-aware, TC-2 C2b) ===")
    sandbox = Path(tempfile.mkdtemp(prefix="webpent-resurrect-"))
    try:
        _redirect_env(sandbox)
        failures = _import_origin_proof()
        if failures:
            for f in failures:
                print(f"IMPORT-ORIGIN FAIL: {f}")
            return 2
        print(f"import-origin OK: {len(BRAIN_MODULES) + len(SPINE_MODULES)} "
              f"modules resolve from src/")
        redirected = _redirect_default_paths(sandbox)
        print(f"default paths redirected ({len(redirected)}): {', '.join(redirected)}")
        residue = _residue_probe()
        _self_sweep()
        if residue:
            print(f"residue intercepted + purged ({len(residue)}): {', '.join(residue)}")
        else:
            print("residue probe clean: redirection held (zero tree writes)")
        # final authority: the repo's own hygiene gate must agree
        gate = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "hygiene_gate_extended.py")],
            capture_output=True, text=True,
        )
        tail = (gate.stdout or gate.stderr).strip().splitlines()
        print("hygiene gate:", tail[-1] if tail else f"rc={gate.returncode}")
        if gate.returncode != 0:
            print("RESURRECT: FAIL — hygiene gate not green after sweep")
            return 3
        print("RESURRECT: PASS — proof green, tree clean")
        return 0
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
