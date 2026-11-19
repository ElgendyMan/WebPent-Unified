#!/usr/bin/env python3
"""POC promotion watcher — the non-invasive PromotionPipeline integration.

The frozen trust chain (PromotionPipeline + its callers) cannot be edited to
emit POC hooks, so this watcher provides the sanctioned "after promotion"
trigger: it polls the persistent findings ledger for PROMOTED findings that
do not yet have POC artifacts and records them via the fail-soft
``maybe_record_poc`` entry point.

Contract (sprint constraints):
* POC failure NEVER affects findings, promotion, or exit code of the
  campaign — the watcher logs and continues.
* Opt-in via env ``WEBPENT_POC_ENABLED=1`` (default off; "optional, can be
  disabled via flag").
* No target-specific code: replay plans derive from the findings themselves;
  tokens come from ``WEBPENT_POC_OWNER_TOKEN`` / ``WEBPENT_POC_FOREIGN_TOKEN``.

v4 (TEAM-RED remediations):
* R-11: single-instance via flock; per-finding failure memory (>= 3
  consecutive failures -> finding is parked and skipped, ending the v3
  endless re-record loop that generated unbudgeted traffic to the TARGET
  every cycle); artifacts are attempted once per cycle, not per finding
  storm.
* R-09: POC audit events are actually wired — the watcher appends
  ``poc.recorded`` / ``poc.failed`` to the engagement's EXISTING
  ``EngagementAuditChain`` (same file the product writes; constructed per
  append so the hash chain resumes correctly). Construction/append failures
  are swallowed by the recorder's registered best-effort audit boundary.

Usage:
    WEBPENT_POC_ENABLED=1 python scripts/poc_watcher.py \
        --engagement eng_20261005_demo [--interval 30] [--once]
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from webpent.reporter.poc_recorder import finding_is_promoted, maybe_record_poc
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger

MAX_CONSECUTIVE_FAILURES = 3
LOCK_NAME = ".poc_watcher.lock"
FAILURES_NAME = ".poc_failures.json"


def _has_poc(poc_dir: Path, finding_id: str) -> bool:
    return (poc_dir / f"poc_{finding_id}.webm").exists() or (
        poc_dir / f"poc_{finding_id}.json"
    ).exists()


def _load_failures(poc_dir: Path) -> dict[str, int]:
    path = poc_dir / FAILURES_NAME
    try:
        data = json.loads(path.read_text())
        return {str(k): int(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_failures(poc_dir: Path, failures: dict[str, int]) -> None:
    try:
        (poc_dir / FAILURES_NAME).write_text(json.dumps(failures, indent=2) + "\n")
    except OSError:
        pass


def _parked(failures: dict[str, int], fid: str) -> bool:
    return failures.get(fid, 0) >= MAX_CONSECUTIVE_FAILURES


def _audit_chain_for(engagement_id: str, artifact_root: Path):
    """Best-effort construction of the engagement's EXISTING audit chain.

    Single-writer authority: this appends to the SAME hash-chained file the
    product writes (``<artifact_root>/audit/<engagement>.audit.jsonl``).
    Constructed per append so the frozen resume logic picks up the latest
    seq/hash. Any failure is absorbed by the recorder's registered
    best-effort audit boundary (never affects recording or promotion).
    """
    from webpent.shared.engagement_audit import EngagementAuditChain

    return EngagementAuditChain(
        engagement_id=engagement_id,
        audit_dir=artifact_root / "audit",
        workspace_dir=artifact_root / "audit_workspace",
    )


def watch(
    engagement_id: str,
    *,
    interval: int = 30,
    once: bool = False,
    poc_dir: Path | None = None,
    ledger: PersistentFindingLedger | None = None,
    artifact_root: Path | None = None,
    lock_file: Path | None = None,
) -> int:
    poc_dir = poc_dir or PROJECT_ROOT / "hunt_artifacts" / "poc"
    ledger = ledger or PersistentFindingLedger()
    artifact_root = artifact_root or PROJECT_ROOT / "hunt_artifacts" / engagement_id
    poc_dir.mkdir(parents=True, exist_ok=True)
    failures = _load_failures(poc_dir)
    lock_path = lock_file or (poc_dir / LOCK_NAME)

    # v4 (R-11): single instance. run_campaign.sh's background watcher and
    # its final --once sweep previously raced the same finding (double
    # recording, artifact overwrite). The flock makes the loser exit quietly.
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("[poc_watcher] another watcher holds the lock — exiting quietly")
            os.close(lock_fd)
            return 0
    except OSError:  # lock bookkeeping must never abort setup
        lock_fd = -1

    print(f"[poc_watcher] engagement={engagement_id} poc_dir={poc_dir} interval={interval}s")
    try:
        while True:
            try:
                promoted = [
                    dict(f) for f in ledger.get(engagement_id)
                    if finding_is_promoted(dict(f))
                ]
                pending = [
                    f for f in promoted
                    if not _has_poc(poc_dir, str(f.get("id")))
                    and not _parked(failures, str(f.get("id")))
                ]
                parked_count = sum(
                    1 for f in promoted
                    if _parked(failures, str(f.get("id")))
                    and not _has_poc(poc_dir, str(f.get("id")))
                )
                if parked_count:
                    print(f"[poc_watcher] {parked_count} finding(s) parked after "
                          f"{MAX_CONSECUTIVE_FAILURES} consecutive failures")
                if pending:
                    print(f"[poc_watcher] {len(pending)} promoted finding(s) pending POC")
                for finding in pending:
                    fid = str(finding.get("id"))
                    try:
                        chain = _audit_chain_for(engagement_id, artifact_root)
                    except (OSError, TypeError, ValueError, ImportError):
                        chain = None  # audit is best-effort (registered boundary)
                    result = maybe_record_poc(
                        finding,
                        engagement_id=engagement_id,
                        output_dir=poc_dir,
                        audit_chain=chain,
                    )
                    status = result.get("status")
                    print(f"[poc_watcher] finding={fid} status={status}"
                          + (f" reason={result.get('reason')}" if status != "recorded" else ""))
                    if status == "recorded":
                        failures.pop(fid, None)
                    else:
                        failures[fid] = failures.get(fid, 0) + 1
                    _save_failures(poc_dir, failures)
            except KeyboardInterrupt:
                print("[poc_watcher] stopped by operator")
                return 0
            except Exception as exc:  # noqa: BLE001 — watcher must survive any cycle
                print(f"[poc_watcher] cycle failed (continuing): {type(exc).__name__}: {exc}")
            if once:
                return 0
            time.sleep(max(5, interval))
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engagement", required=True)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true", help="Single sweep, then exit.")
    parser.add_argument("--poc-dir", default=None)
    parser.add_argument(
        "--artifact-root", default=None,
        help="Engagement artifact root holding the product audit chain "
             "(default: hunt_artifacts/<engagement>). POC audit events append "
             "to the existing chain there.",
    )
    args = parser.parse_args()
    if os.environ.get("WEBPENT_POC_ENABLED", "").lower() not in {"1", "true", "yes"}:
        print("[poc_watcher] WEBPENT_POC_ENABLED is not set — POC recording is "
              "opt-in; nothing to do (promotion is unaffected).")
        return 0
    return watch(
        args.engagement,
        interval=args.interval,
        once=args.once,
        poc_dir=Path(args.poc_dir) if args.poc_dir else None,
        artifact_root=Path(args.artifact_root) if args.artifact_root else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
