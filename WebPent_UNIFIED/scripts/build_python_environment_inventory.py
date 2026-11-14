"""Create a dependency inventory without claiming a full SBOM standard."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packages = [
        {"name": distribution.metadata["Name"], "version": distribution.version}
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name")
    ]
    packages.sort(key=lambda item: (item["name"].lower(), item["version"]))
    inventory = {
        "schema_version": "python-environment-inventory-v1",
        "format": "package-name-version-list",
        "project": "WebPent v60",
        "source": "active virtual environment importlib.metadata",
        "standard_sbom": False,
        "strict_release_gate": False,
        "tooling_note": (
            "syft/grype unavailable; this is an inventory artifact, not a CycloneDX or SPDX SBOM."
        ),
        "packages": packages,
    }
    args.output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"packages": len(packages), "standard_sbom": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
