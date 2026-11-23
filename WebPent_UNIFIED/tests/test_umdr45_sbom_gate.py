"""UM-DR-45 R1 (CI root 4) — the SBOM step's allowlist-aware generator.

On 2026-11-23 the ``tests`` job was red on a663e37 for a reason unrelated to
the suite: the ``Generate SBOM (CycloneDX)`` step ran ``pip-audit`` bare, and
``pip-audit`` exits 1 whenever the audited closure lists ANY known
vulnerability — after writing the SBOM — including the chromadb advisories the
dependency CVE gate had just waived through ``scripts/quality/cve_allowlist.json``
(CI log run 45135833672: "deps gate: 5 vulnerability/vulnerabilities found …
PASS: no un-allow-listed vulnerabilities", then "Found 5 known vulnerabilities
in 1 package … exit code 1"). The job stopped there, so the regression suite
never ran and the evidence checks reported a missing evidence file.

``scripts/generate_sbom.py`` separates "the SBOM could not be produced" from
"the SBOM lists advisories": only the audited allowlist can turn the second
outcome into a pass. These tests pin the decision table and the workflow
contract so neither the bare invocation nor ``|| true`` can come back.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

CHROMADB_REF = "BomRef.034847877018232554.07578989713507434"
REQUESTS_REF = "BomRef.requests"


def _load(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(f"umdr45_{name}", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sbom(vulnerabilities: list[dict] | None) -> dict:
    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"bom-ref": CHROMADB_REF, "type": "library", "name": "chromadb", "version": "1.5.9"},
            {"bom-ref": REQUESTS_REF, "type": "library", "name": "requests", "version": "2.32.0"},
        ],
    }
    if vulnerabilities is not None:
        doc["vulnerabilities"] = vulnerabilities
    return doc


def _affects(vuln_id: str, ref: str) -> dict:
    return {"bom-ref": f"VulnRef.{vuln_id}", "id": vuln_id, "affects": [{"ref": ref}]}


WAIVED_LISTINGS = [
    _affects("PYSEC-2026-311", CHROMADB_REF),
    _affects("PYSEC-2026-3813", CHROMADB_REF),
]


@pytest.fixture()
def gen() -> types.ModuleType:
    return _load("generate_sbom")


def _write(path: Path, doc: object) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# decision table
# ---------------------------------------------------------------------------


def test_only_audited_waivers_pass_and_sbom_is_left_unmodified(gen, tmp_path) -> None:
    """The CI state: every listed advisory carries an allowlist entry with
    the same id AND package. The SBOM keeps listing them — a waiver is an
    adjudication, not a deletion."""
    listings = [_affects("PYSEC-2026-311", CHROMADB_REF), _affects("PYSEC-2026-3815", CHROMADB_REF)]
    sbom = _write(tmp_path / "sbom.json", _sbom(listings))
    before = sbom.read_bytes()
    code, lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 0, lines
    assert sum(line.startswith("  WAIVED") for line in lines) == 2
    assert not any(line.startswith("  BLOCK") for line in lines)
    assert sbom.read_bytes() == before


def test_no_advisories_passes(gen, tmp_path) -> None:
    code, lines = gen.evaluate(_write(tmp_path / "sbom.json", _sbom([])), gen.load_allowlist())
    assert code == 0, lines
    # the CycloneDX writer omits the key entirely when there is nothing to list
    code, lines = gen.evaluate(_write(tmp_path / "sbom2.json", _sbom(None)), gen.load_allowlist())
    assert code == 0, lines


def test_a_new_advisory_blocks(gen, tmp_path) -> None:
    """A vulnerability absent from the audited allowlist fails the SBOM step
    even though the SBOM itself was produced fine."""
    listings = [_affects("PYSEC-2026-9999", REQUESTS_REF), _affects("PYSEC-2026-311", CHROMADB_REF)]
    sbom = _write(tmp_path / "sbom.json", _sbom(listings))
    code, lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 1, lines
    assert any("BLOCK  PYSEC-2026-9999 (requests 2.32.0)" in line for line in lines)


def test_a_waived_id_on_a_different_package_blocks(gen, tmp_path) -> None:
    """The allowlist is per (id, package): the chromadb waiver never covers
    the same advisory id reported against another component."""
    sbom = _write(tmp_path / "sbom.json", _sbom([_affects("PYSEC-2026-311", REQUESTS_REF)]))
    code, lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 1, lines


def test_an_unresolvable_component_ref_blocks(gen, tmp_path) -> None:
    sbom = _write(tmp_path / "sbom.json", _sbom([_affects("PYSEC-2026-311", "BomRef.gone")]))
    code, lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 1, lines
    assert any("unresolvable" in line for line in lines)


def test_a_vulnerability_without_an_affected_component_blocks(gen, tmp_path) -> None:
    sbom = _write(tmp_path / "sbom.json", _sbom([{"id": "PYSEC-2026-311"}]))
    code, lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 1, lines


def test_no_sbom_is_a_generation_failure_not_a_pass(gen, tmp_path) -> None:
    """pip-audit could not run (network / advisory DB / resolution): there is
    nothing to adjudicate, so the step must fail closed with the harness
    exit code — this is the outcome ``|| true`` used to hide."""
    code, lines = gen.evaluate(tmp_path / "missing.json", gen.load_allowlist())
    assert code == 2, lines


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"bomFormat": "SPDX", "components": [{"name": "x"}]}),
        json.dumps({"bomFormat": "CycloneDX", "components": []}),
    ],
)
def test_an_unusable_sbom_is_a_generation_failure(gen, tmp_path, content) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(content, encoding="utf-8")
    code, _lines = gen.evaluate(sbom, gen.load_allowlist())
    assert code == 2


def test_package_names_are_compared_pep503_normalised(gen, tmp_path) -> None:
    """Case and ``-``/``_``/``.`` runs are one name; a different name is a
    different package and never inherits the waiver."""
    listings = [
        _affects("PYSEC-2026-311", "BomRef.cased"),
        _affects("PYSEC-2026-3813", "BomRef.other"),
    ]
    doc = _sbom(listings)
    doc["components"].extend(
        [
            {"bom-ref": "BomRef.cased", "type": "library", "name": "ChromaDB", "version": "1.5.9"},
            {"bom-ref": "BomRef.other", "type": "library", "name": "chroma-db", "version": "1.5.9"},
        ]
    )
    code, lines = gen.evaluate(_write(tmp_path / "sbom.json", doc), gen.load_allowlist())
    assert code == 1, lines
    assert any("WAIVED PYSEC-2026-311 (ChromaDB 1.5.9)" in line for line in lines)
    assert any("BLOCK  PYSEC-2026-3813 (chroma-db 1.5.9)" in line for line in lines)


# ---------------------------------------------------------------------------
# end-to-end main(): the stale committed SBOM can never stand in for this run
# ---------------------------------------------------------------------------


def test_main_passes_end_to_end_when_every_listing_is_waived(gen, tmp_path, monkeypatch) -> None:
    output = tmp_path / "docs" / "sbom.cdx.json"
    output.parent.mkdir()
    proc = subprocess.CompletedProcess(
        args=["pip_audit"], returncode=1, stdout="",
        stderr="Found 2 known vulnerabilities in 1 package\n",
    )

    def fake_run(requirements: Path, out: Path) -> subprocess.CompletedProcess:
        _write(out, _sbom(WAIVED_LISTINGS))
        return proc

    monkeypatch.setattr(gen, "run_pip_audit", fake_run)
    assert gen.main(["--requirements", str(tmp_path / "locked.txt"), "--output", str(output)]) == 0


def test_main_removes_the_previous_sbom_before_running_so_a_dead_run_cannot_pass(
    gen, tmp_path, monkeypatch
) -> None:
    """docs/sbom.cdx.json is a tracked file: without the removal, a pip-audit
    that dies before writing would leave the committed SBOM behind and the
    gate would adjudicate last release's document as if it were this run."""
    output = _write(tmp_path / "sbom.cdx.json", _sbom([_affects("PYSEC-2026-311", CHROMADB_REF)]))

    def dead_run(requirements: Path, out: Path) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["pip_audit"], returncode=2, stdout="",
            stderr="ERROR:pip_audit._cli:Failed to install packages: [...]",
        )

    monkeypatch.setattr(gen, "run_pip_audit", dead_run)
    code = gen.main(["--requirements", str(tmp_path / "locked.txt"), "--output", str(output)])
    assert code == 2
    assert not output.exists()


def test_main_fails_when_a_new_advisory_is_listed(gen, tmp_path, monkeypatch) -> None:
    output = tmp_path / "sbom.cdx.json"
    proc = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="Found 1 known vulnerability in 1 package\n"
    )

    def fake_run(requirements: Path, out: Path) -> subprocess.CompletedProcess:
        _write(out, _sbom([_affects("PYSEC-2026-4242", REQUESTS_REF)]))
        return proc

    monkeypatch.setattr(gen, "run_pip_audit", fake_run)
    assert gen.main(["--requirements", str(tmp_path / "locked.txt"), "--output", str(output)]) == 1


def test_run_pip_audit_targets_a_file_and_never_filters(gen, tmp_path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def capture(cmd, **kwargs) -> subprocess.CompletedProcess:
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gen.subprocess, "run", capture)
    gen.run_pip_audit(Path("/tmp/locked-requirements.txt"), Path("/tmp/out.json"))
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[1:3] == ["-m", "pip_audit"]
    assert cmd[cmd.index("--format") + 1] == "cyclonedx-json"
    assert cmd[cmd.index("--output") + 1] == "/tmp/out.json"
    assert cmd[cmd.index("-r") + 1] == "/tmp/locked-requirements.txt"
    assert "--fix" not in cmd and "--ignore-vuln" not in cmd, (
        "the SBOM must be the unfiltered audit output; adjudication is the "
        "wrapper's job, never a silent exclusion inside the audit"
    )


# ---------------------------------------------------------------------------
# single source of truth + workflow contract
# ---------------------------------------------------------------------------


def test_the_allowlist_is_the_cve_gate_s_file_not_a_second_list(gen) -> None:
    # the wrapper's `from check_deps_gate import …` is what registered it
    gate = sys.modules["check_deps_gate"]
    assert Path(gen.ALLOWLIST) == Path(gate.ALLOWLIST)
    assert gen.ALLOWLIST.name == "cve_allowlist.json"
    assert gen.load_allowlist is gate.load_allowlist


def _executable_lines(text: str) -> str:
    """Workflow text without comment lines (the header DOCUMENTS the old
    `|| true` and must keep doing so)."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_ci_sbom_step_runs_the_gated_generator_and_never_a_bare_pip_audit() -> None:
    workflow = REPO.parent / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():  # standalone project-directory checkout
        pytest.skip("canonical root-level ci.yml is not part of this checkout")
    text = _executable_lines(workflow.read_text(encoding="utf-8"))
    step_start = text.index("name: Generate SBOM (CycloneDX)")
    step = text[step_start : text.index("- name: ", step_start + 1)]
    assert "scripts/generate_sbom.py" in step
    assert "--requirements /tmp/locked-requirements.txt" in step
    assert "|| true" not in step
    assert "pip-audit --format cyclonedx-json" not in text, (
        "a bare pip-audit exits 1 on any advisory — waived or not — and stops "
        "the job before the regression suite"
    )
    assert "|| true" not in text


def test_recorded_release_scan_still_passes_the_cve_gate() -> None:
    """Both gates read one allowlist: the recorded scan the CVE gate is
    tested against must adjudicate the same way here."""
    gate = _load("check_deps_gate")
    report = json.loads((REPO / "docs" / "pip_audit_release.json").read_text(encoding="utf-8"))
    allow = gate.load_allowlist()
    vulns = gate.extract_vulns(report)
    assert vulns, "the recorded scan is expected to carry the waived chromadb advisories"
    assert all(v["id"] in allow for v in vulns)
