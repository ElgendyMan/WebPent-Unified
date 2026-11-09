"""Compare mock matrix runs while ignoring volatile timestamps."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _stable(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("generated_at", None)
    return data


def main() -> int:
    paths = [Path(value) for value in sys.argv[1:]]
    if len(paths) < 2:
        raise SystemExit("usage: compare_waptlab_matrix_runs.py RUN1 RUN2 [RUN3 ...]")
    baseline = _stable(paths[0])
    mismatches: list[str] = []
    for path in paths[1:]:
        if _stable(path) != baseline:
            mismatches.append(str(path))
    summary = baseline.get("summary", {})
    print(
        json.dumps(
            {
                "runs": [str(path) for path in paths],
                "stable": not mismatches,
                "mismatches": mismatches,
                "summary": summary,
            },
            sort_keys=True,
        )
    )
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
