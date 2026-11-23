#!/usr/bin/env python3
"""Generate the per-run CycloneDX SBOM and adjudicate it with the audited allowlist.

UM-DR-45 R1 (CI root 4) — why this wrapper exists
------------------------------------------------
``pip-audit`` writes the formatted SBOM to ``--output`` and THEN exits 1
whenever the audited dependency closure lists any known vulnerability
(``pip_audit/_cli.py``: output first, ``sys.exit(1)`` after). The CI step
called it bare, so one exit code conflated two different outcomes:

* the SBOM could not be produced (network / advisory DB / resolution), and
* the SBOM was produced and lists advisories that the dependency CVE gate
  had already adjudicated through ``scripts/quality/cve_allowlist.json``.

The second outcome stopped the ``tests`` job before the regression suite on
every run after the chromadb advisories were published. Dropping the exit code
(``|| true``) hides the first outcome — that was the UM-DR-44 A0 finding — so
this script separates the two instead:

  exit 0  the SBOM was written, parses, and every advisory it lists is covered
          by an allowlist entry with the SAME id AND the SAME package
  exit 1  the SBOM was written but lists an advisory that is not waived — a
          new advisory, or a waived id affecting a different package
  exit 2  no parseable SBOM was produced (generation failure) — fail closed

The SBOM file itself is pip-audit's output, unmodified: waived advisories stay
listed in it. The allowlist is imported from ``check_deps_gate`` so the SBOM
step and the CVE gate cannot drift apart.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from check_deps_gate import ALLOWLIST, load_allowlist

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "sbom.cdx.json"


def _norm(name: str) -> str:
    """PEP 503 normalisation: PyPI names are case- and ``-/_``-insensitive."""
    return re.sub(r"[-_.]+", "-", name).lower()


def run_pip_audit(requirements: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--format",
            "cyclonedx-json",
            "--output",
            str(output),
            "-r",
            str(requirements),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def evaluate(sbom_path: Path, allow: dict[str, dict]) -> tuple[int, list[str]]:
    """Adjudicate a written SBOM. Returns ``(exit_code, report_lines)``."""
    if not sbom_path.is_file():
        return 2, [f"ABORT: pip-audit produced no SBOM at {sbom_path}"]
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return 2, [f"ABORT: SBOM at {sbom_path} is not parseable JSON ({exc})"]
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        return 2, [f"ABORT: {sbom_path} is not a CycloneDX document"]
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        return 2, [f"ABORT: SBOM at {sbom_path} lists no components"]

    by_ref: dict[str, tuple[str, str]] = {}
    for comp in components:
        if isinstance(comp, dict) and comp.get("bom-ref"):
            by_ref[str(comp["bom-ref"])] = (
                str(comp.get("name", "")),
                str(comp.get("version", "?")),
            )

    lines: list[str] = []
    blocked: list[str] = []
    waived: list[str] = []
    for vuln in sbom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            blocked.append("UNKNOWN (malformed vulnerability entry)")
            continue
        vuln_id = str(vuln.get("id", "UNKNOWN")).upper()
        affects = vuln.get("affects") or []
        if not affects:
            blocked.append(f"{vuln_id} (no affected component recorded)")
            continue
        for affected in affects:
            ref = str((affected or {}).get("ref", ""))
            comp = by_ref.get(ref)
            if comp is None:
                blocked.append(f"{vuln_id} (affected component ref unresolvable: {ref})")
                continue
            name, version = comp
            entry = allow.get(vuln_id)
            if entry is not None and _norm(str(entry.get("package", ""))) == _norm(name):
                reason = entry.get("reason", "no reason recorded")
                waived.append(f"{vuln_id} ({name} {version}) — {reason}")
            else:
                blocked.append(
                    f"{vuln_id} ({name} {version}) — not covered by the audited allowlist"
                )

    lines.append(
        f"sbom gate: {len(components)} components, "
        f"{len(waived) + len(blocked)} advisory listing(s) in {sbom_path.name}"
    )
    lines.extend(f"  WAIVED {item}" for item in waived)
    lines.extend(f"  BLOCK  {item}" for item in blocked)
    if blocked:
        lines.append(
            f"\nFAIL: {len(blocked)} SBOM advisory listing(s) are not waived by "
            f"{ALLOWLIST.relative_to(ROOT)}.\n"
            "  Preferred: upgrade the affected package (locked dep bump + "
            "integration tests). Only with an approved\n  risk decision add "
            "an entry with id/package/reason/added — the same file the CVE "
            "gate reads."
        )
        return 1, lines
    lines.append(
        "PASS: SBOM generated and every listed advisory is covered by the "
        "audited allowlist (the advisories remain listed in the SBOM)."
    )
    return 0, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--requirements",
        type=Path,
        default=None,
        help="locked requirements file to audit (uv export --locked --no-emit-project)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"SBOM destination (default: {DEFAULT_OUTPUT.relative_to(ROOT)})",
    )
    parser.add_argument(
        "--evaluate",
        type=Path,
        default=None,
        help="adjudicate an already-written SBOM instead of running pip-audit",
    )
    args = parser.parse_args(argv)

    allow = load_allowlist()

    if args.evaluate is None:
        if args.requirements is None:
            parser.error("--requirements is required unless --evaluate is used")
        # A committed SBOM exists at the default destination. Remove it first
        # so that its presence after the run can only mean THIS run wrote it.
        if args.output.is_file():
            args.output.unlink()
        proc = run_pip_audit(args.requirements, args.output)
        summary = next(
            (
                line.strip()
                for line in proc.stderr.splitlines()
                if "known vulnerabilities" in line
            ),
            f"pip-audit exited rc={proc.returncode} without a summary line",
        )
        print(summary)
        if not args.output.is_file():
            print(
                "ABORT: pip-audit produced no SBOM (generation failure).\n"
                f"  rc={proc.returncode}\n{proc.stderr[-1500:]}",
                file=sys.stderr,
            )
            return 2
        target = args.output
    else:
        target = args.evaluate

    code, lines = evaluate(target, allow)
    print("\n".join(lines), file=sys.stderr if code == 2 else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
