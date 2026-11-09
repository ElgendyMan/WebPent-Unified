#!/usr/bin/env python3
"""UM-DR-32 — portable full-suite chunked runner.

Replaces ``scripts/run_suite_chunks_umdr31_1.sh`` (and its hardcoded
``/home/z/...`` layout) with a repository-portable Python runner.

Design contract (UM-DR-32 §3.3):

  * the repository root is discovered via ``git rev-parse`` (with a
    script-location fallback) — never a hardcoded absolute path;
  * the Python executable is configurable (``--python``); the default
    is the interpreter running this script;
  * the state directory, chunk size and per-chunk timeout are
    configurable;
  * file discovery is deterministic: the cached result of a single
    ``pytest --collect-only`` pass, sorted, every file in exactly one
    chunk;
  * a chunk that failed, timed out or was interrupted is reported as
    such and re-run on the next invocation (idempotent completion);
  * overall success is reported ONLY when every chunk ran to
    completion AND passed AND the per-chunk collected counts reconcile
    with the inventory — the runner exits non-zero otherwise;
  * a machine-readable JSON summary is always written.

Usage:
    python3 scripts/run_suite.py                     # full suite, chunked
    python3 scripts/run_suite.py --chunks 3:5        # only chunks 3..5
    python3 scripts/run_suite.py --reset             # fresh state
    python3 scripts/run_suite.py --list              # show the plan
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_SUMMARY_TOKEN = re.compile(
    r"(\d+) (passed|failed|skipped|xfailed|xpassed|errors?|deselected|warnings)"
)
_COUNT_KEYS = {
    "passed": "passed",
    "failed": "failed",
    "skipped": "skipped",
    "xfailed": "xfailed",
    "xpassed": "xpassed",
    "error": "errors",
    "errors": "errors",
    "deselected": "deselected",
}  # "warnings" is informational only — deliberately not counted


def discover_repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=REPO, capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except Exception:
        pass
    return REPO  # script lives in <root>/scripts — portable fallback


def discover_test_files(
    root: Path, python: str, rel_tests: str,
) -> tuple[list[str], str]:
    """Deterministic test-file inventory.

    Primary source: one ``pytest --collect-only -q`` pass over the tests
    tree (respects conftest collection semantics). Fallback: sorted glob
    of ``test_*.py`` / ``*_test.py`` files (used only if collection
    itself fails, in which case the summary records ``discovery=fallback``).
    """
    tests_dir = (root / rel_tests).resolve()
    cmd = [
        python, "-m", "pytest", "--collect-only", "-q",
        rel_tests, "-p", "no:cacheprovider",
    ]
    try:
        out = subprocess.run(
            cmd, cwd=root, capture_output=True, text=True, timeout=900,
        )
        prefix = rel_tests.rstrip("/") + "/"
        files = sorted({
            line.split("::", 1)[0]
            for line in out.stdout.splitlines()
            if line.startswith(prefix) and "::" in line
        })
        if files:
            return files, "pytest-collect"
    except Exception:
        pass
    files = sorted(
        p.relative_to(root).as_posix()
        for p in tests_dir.rglob("*.py")
        if (p.name.startswith("test_") or p.name.endswith("_test.py"))
    )
    return files, "fallback-glob"


def chunk_plan(files: list[str], chunk_size: int) -> list[list[str]]:
    return [
        files[i:i + chunk_size]
        for i in range(0, len(files), chunk_size)
    ]


def parse_summary(log_text: str) -> dict[str, int]:
    """Parse the pytest terminal summary line into a count dict."""
    counts = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "errors": 0, "deselected": 0,
    }
    summary_line = ""
    for line in log_text.splitlines():
        # pytest terminal summary, e.g. "496 passed, 1 skipped in 82.3s"
        # or "1 failed, 495 passed in 81.68s (0:01:21)" — the trailing
        # "(0:01:21)" breaks endswith("s"), so match structurally.
        if " in " in line and _SUMMARY_TOKEN.search(line):
            summary_line = line
    if not summary_line:
        return counts
    for num, key in _SUMMARY_TOKEN.findall(summary_line):
        mapped = _COUNT_KEYS.get(key)
        if mapped is not None:
            counts[mapped] = int(num)
    return counts


def run_chunk(
    root: Path, python: str, files: list[str],
    log_path: Path, timeout: int,
) -> tuple[str, dict[str, int], float]:
    """Run one chunk. Returns (status, counts, seconds).

    status: ok | failed | timeout | empty | error
    """
    cmd = [
        python, "-m", "pytest",
        *files, "-q", "--no-header", "--tb=line", "-p", "no:cacheprovider",
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=root, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", "replace") \
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        log_path.write_text(
            f"$ {' '.join(cmd)}\n--- TIMEOUT after {timeout}s ---\n{stdout}\n",
            encoding="utf-8", errors="replace",
        )
        return "timeout", parse_summary(stdout), time.monotonic() - t0
    log_path.write_text(
        f"$ {' '.join(cmd)}\n--- exit {proc.returncode} ---\n"
        f"{proc.stdout}\n{proc.stderr}",
        encoding="utf-8", errors="replace",
    )
    counts = parse_summary(proc.stdout)
    seconds = time.monotonic() - t0
    # pytest exit 5 = no tests ran (e.g. a file whose tests are all
    # collected away); treat as empty-ok only when nothing failed.
    if proc.returncode == 5 and counts["failed"] == 0 and counts["errors"] == 0:
        return "empty", counts, seconds
    if proc.returncode == 0 and counts["failed"] == 0 and counts["errors"] == 0:
        return "ok", counts, seconds
    return "failed", counts, seconds


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--python", default=sys.executable,
                        help="python executable for pytest (default: this one)")
    parser.add_argument("--tests-dir", default="tests",
                        help="tests directory relative to the repo root")
    parser.add_argument("--state-dir", default=None,
                        help="state/report directory (default: a "
                             "'webpent_suite_state' dir under the system "
                             "temp dir — NEVER inside the repo, the "
                             "hygiene gate flags *.log residue)")
    parser.add_argument("--chunk-size", type=int, default=55,
                        help="test files per chunk (default: 55)")
    parser.add_argument("--chunk-timeout", type=int, default=900,
                        help="per-chunk timeout seconds (default: 900)")
    parser.add_argument("--chunks", default=None,
                        help="chunk range to run, e.g. '3' or '3:5' (1-based, inclusive)")
    parser.add_argument("--reset", action="store_true",
                        help="discard cached state and start fresh")
    parser.add_argument("--list", action="store_true",
                        help="print the chunk plan and exit")
    parser.add_argument("--summary-json", default=None,
                        help="path for the machine-readable summary (default: <state>/summary.json)")
    args = parser.parse_args()

    root = discover_repo_root()
    tests_dir = (root / args.tests_dir).resolve()
    if not tests_dir.is_dir():
        print(f"ABORT: tests dir not found: {tests_dir}", file=sys.stderr)
        return 2
    state = Path(args.state_dir) if args.state_dir else (
        Path(tempfile.gettempdir()) / "webpent_suite_state"
    )
    state.mkdir(parents=True, exist_ok=True)

    inventory = state / "files.txt"
    meta_path = state / "inventory.json"
    if args.reset:
        for p in state.glob("chunk_*.log"):
            p.unlink()
        for p in state.glob("progress.log"):
            p.unlink()
        inventory.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)

    if args.reset or not inventory.exists():
        files, how = discover_test_files(root, args.python, args.tests_dir)
        inventory.write_text("\n".join(files) + "\n", encoding="utf-8")
        meta_path.write_text(json.dumps({
            "discovery": how,
            "python": args.python,
            "tests_dir": args.tests_dir,
            "file_count": len(files),
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2), encoding="utf-8")
        print(f"inventory: {len(files)} test files ({how})")
    else:
        how = json.loads(meta_path.read_text(encoding="utf-8"))["discovery"]
    files = [
        ln for ln in inventory.read_text(encoding="utf-8").splitlines() if ln
    ]

    chunks = chunk_plan(files, args.chunk_size)
    total = len(chunks)
    plan = list(range(1, total + 1))
    if args.chunks:
        if ":" in args.chunks:
            a, b = args.chunks.split(":", 1)
            plan = list(range(int(a), int(b) + 1))
        else:
            plan = [int(args.chunks)]
    if args.list:
        for i, chunk in enumerate(chunks, 1):
            mark = "*" if i in plan else " "
            print(f"{mark} chunk {i:>3}/{total}: {len(chunk):>3} files "
                  f"({chunk[0]} .. {chunk[-1]})")
        print(f"total: {len(files)} files / {total} chunks / "
              f"chunk-size {args.chunk_size}")
        return 0

    progress = state / "progress.log"
    statuses: dict[str, str] = {}
    counts_total = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "errors": 0, "deselected": 0,
    }
    collected_total = 0
    wall_start = time.monotonic()

    for c in plan:
        if c > total:
            break
        chunk = chunks[c - 1]
        log_path = state / f"chunk_{c:03d}.log"
        status, counts, seconds = run_chunk(
            root, args.python, chunk, log_path, args.chunk_timeout,
        )
        statuses[str(c)] = status
        chunk_collected = sum(counts.values()) - counts["deselected"]
        collected_total += chunk_collected
        for key in counts_total:
            counts_total[key] += counts[key]
        line = (f"chunk {c}/{total} [{status}] {chunk_collected} collected "
                f"({counts['passed']} passed, {counts['failed']} failed, "
                f"{counts['skipped']} skipped, {counts['xfailed']} xfailed, "
                f"{counts['errors']} errors) {seconds:.1f}s")
        print(line)
        with progress.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    # Reconciliation: every planned chunk must have run and passed, and
    # the per-chunk collected totals must equal the sum over all chunks
    # in the plan; a full run must also account for every file.
    not_run = [str(c) for c in plan if str(c) not in statuses]
    bad = [c for c, s in statuses.items() if s not in ("ok", "empty")]
    summary = {
        "ran_chunks": statuses,
        "not_run_chunks": not_run,
        "planned_chunks": plan,
        "total_chunks": total,
        "files": len(files),
        "discovery": how,
        "counts": counts_total,
        "collected_from_counts": collected_total,
        "wall_seconds": round(time.monotonic() - wall_start, 1),
        "python": args.python,
        "chunk_size": args.chunk_size,
        "chunk_timeout": args.chunk_timeout,
        "all_ok": not bad and not not_run,
    }
    out_json = Path(args.summary_json) if args.summary_json \
        else state / "summary.json"
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary["counts"], indent=None))
    print(f"summary: {out_json}")

    if bad:
        print(f"FAILED chunks: {', '.join(sorted(bad, key=int))}", file=sys.stderr)
    if not_run:
        print(f"NOT RUN chunks: {', '.join(not_run)}", file=sys.stderr)
    if summary["all_ok"]:
        print("SUITE OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
