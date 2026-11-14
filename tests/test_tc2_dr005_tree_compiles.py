"""TC-2 DR-005 regression gate — every shipped src file must compile.

The v14.1 inheritance shipped ``src/webpent/production/
autonomous_validation_v1.py`` syntactically broken (a resurrection
script inserted a try/except block INSIDE a call's argument list), making
the module unimportable and every lazily-importing test fail — while the
delivery still claimed "all gates green" (the claim was collection-based;
collection never imports this module at scope).

DR-005 closes the class, not just the instance: this gate compiles EVERY
``src/`` and ``scripts/`` Python file with ``py_compile`` and fails on
any syntax error, so no future resurrection can ship an unimportable
tree behind a collection-only green claim.
"""
from __future__ import annotations

import os
import py_compile
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _python_files(rel: str) -> list[Path]:
    base = ROOT / rel
    if not base.exists():
        return []
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def test_every_src_file_compiles():
    """DR-005: every file under src/ compiles (no syntax corruption)."""
    broken: list[str] = []
    for p in _python_files("src"):
        try:
            py_compile.compile(str(p), doraise=True, cfile=str(p.with_suffix(".pyc")) + ".gate")
        except py_compile.PyCompileError as exc:
            broken.append(f"{p.relative_to(ROOT)}: {exc}")
        finally:
            cache = p.with_suffix(".pyc")
            for stray in (cache, Path(str(cache) + ".gate")):
                stray.unlink(missing_ok=True)
    assert not broken, "syntactically broken src files shipped:\n" + "\n".join(broken)


def test_every_scripts_file_compiles():
    """The same gate over scripts/ (build/gate tooling must stay importable)."""
    broken: list[str] = []
    for p in _python_files("scripts"):
        try:
            py_compile.compile(str(p), doraise=True, cfile=str(p.with_suffix(".pyc")) + ".gate")
        except py_compile.PyCompileError as exc:
            broken.append(f"{p.relative_to(ROOT)}: {exc}")
        finally:
            cache = p.with_suffix(".pyc")
            for stray in (cache, Path(str(cache) + ".gate")):
                stray.unlink(missing_ok=True)
    assert not broken, "syntactically broken script files:\n" + "\n".join(broken)


def test_dr005_module_imports_and_reports_confidence_path():
    """The DR-005 module imports AND its promotion path carries the
    reconstructed confidence plumbing (compute-before-decide, None on
    failure — never a faked number).
    """
    import importlib

    mod = importlib.import_module("webpent.production.autonomous_validation_v1")
    source = Path(mod.__file__).read_text()
    assert "confidence_score=_confidence_score," in source
    # P-1 hygiene: the handler is NARROWED (no broad except in critical
    # modules) and never fakes a number on failure.
    assert ("except (ImportError, TypeError, ValueError, KeyError):\n"
            "            # P-1 exception hygiene") in source
    # the call site passes the confidence kwarg INSIDE evaluate(...)'s
    # argument list, directly after the verdict authority — the broken
    # pattern (an assignment interrupting the arg list) is structurally
    # impossible now, which the compile gate above already proves; this
    # pins the intended call shape.
    assert (
        'verdict_authority="CausalGuard_deterministic_engine",\n'
        "            confidence_score=_confidence_score,"
    ) in source
