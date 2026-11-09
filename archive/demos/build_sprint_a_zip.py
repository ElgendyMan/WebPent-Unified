"""Build the updated Sprint-A delivery ZIP (writes to E: - C: is full)."""

import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = Path("E:/webpent-lab/webpent-vuln-arsenal-sprint-a-final.zip")

EXCLUDE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
    "artifacts",
    ".tools",
    ".zwork",
    ".git",
    ".idea",
    ".vscode",
    "webpent.egg-info",
    "htmlcov",
    ".mypy_cache",
    ".ruff_cache",
}
EXCLUDE_SUFFIXES = (".db", ".log", ".pyc")
EXCLUDE_FILES = {"webpent.db", "juice_shop_runtime.log"}

INCLUDE_TOP_DIRS = [
    ".github",
    "alembic",
    "benchmarks",
    "config",
    "docs",
    "goed_v1_8",
    "goed_v1_8_1",
    "goed_v1_8_2",
    "goed_v1_8_3",
    "goed_v1_8_4",
    "knowledge_pack",
    "memory",
    "production",
    "release",
    "reports",
    "scripts",
    "src",
    "tests",
    "verification",
]


def is_excluded(path: Path) -> bool:
    if path.name in EXCLUDE_FILES:
        return True
    if path.suffix in EXCLUDE_SUFFIXES:
        return True
    return False


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        OUT.unlink()
    count = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for entry in sorted(ROOT.iterdir()):
            if entry.is_file() and not is_excluded(entry):
                zf.write(entry, entry.name)
                count += 1
        for top in INCLUDE_TOP_DIRS:
            base = ROOT / top
            if not base.exists():
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
                for filename in sorted(filenames):
                    full = Path(dirpath) / filename
                    if is_excluded(full):
                        continue
                    rel = full.relative_to(ROOT)
                    zf.write(full, str(rel))
                    count += 1
    print(f"built {OUT.name}: {count} files, {OUT.stat().st_size / 1024 / 1024:.2f} MiB")

    with zipfile.ZipFile(OUT) as zf:
        names = set(zf.namelist())
        for must in (
            "src/webpent/vulns/__init__.py",
            "src/webpent/vulns/race_condition.py",
            "src/webpent/vulns/business_logic.py",
            "src/webpent/vulns/file_upload.py",
            "src/webpent/vulns/jwt_analyzer.py",
            "src/webpent/vulns/mass_assignment.py",
            "tests/team1_acceptance/test_vuln_arsenal_sprint_a.py",
            "scripts/run_sprint_a_juice_campaign.py",
            "scripts/run_sprint_a_juice_round2.py",
            "scripts/regen_direct_io_inventory_sprint_a.py",
            "docs/VULN_ARSENAL_SPRINT_A_REPORT.md",
            ".env.example",
            "src/webpent/production/validators.py",
            "src/webpent/production/autonomous_validation_v1.py",
            "src/webpent/shared/capability_manifest.py",
            "src/webpent/tools/utils/subprocess.py",
            "src/webpent/tools/recon/nuclei.py",
            "src/webpent/shared/engagement_audit.py",
            "scripts/verify_frozen_manifest.py",
            "docs/integration/WEBPENT_AUTHORITY_MANIFEST.json",
        ):
            assert must in names, f"missing from archive: {must}"
        for banned in ("webpent.db", "juice_shop_runtime.log"):
            assert banned not in names, f"unexpected in archive: {banned}"
        assert not any(n.startswith("artifacts/") for n in names), "artifacts leaked"
        assert not any("__pycache__" in n for n in names), "pycache leaked"
        assert not any(n.startswith(".tools/") for n in names), ".tools leaked"
        assert not any(n.startswith(".zwork/") for n in names), ".zwork leaked"
    print("archive verification: OK")


if __name__ == "__main__":
    main()
