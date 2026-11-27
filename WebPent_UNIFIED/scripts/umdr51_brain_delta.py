#!/usr/bin/env python3
"""UM-DR-51 Phase 1 — the brain OFF/ON decision delta (gate G5).

Design (the honest-measurement contract, fixed after the ceiling
root-cause): ONE campaign per SUBPROCESS — the settings singleton is
lru-cached per process, so flipping WEBPENT_ENABLE_BRAIN_ENGINE
inside one process would be a no-op (measured: the flag never reached
the graph). Each arm/run pair launches `uv run` fresh, exactly like
CI and like window 49's launcher.

The lab rate ceiling (900/min process-wide — 222 requests/campaign)
is operator-configured UP for the measurement window
(WEBPENT_GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE=10000, local lab
target, owner-authorized) so the rate ceiling cannot contaminate the
OFF/ON comparison; the governor snapshot is recorded per run as the
proof (requests_last_minute, denials visible).

Usage:
  uv run --extra dev python scripts/umdr51_brain_delta.py \
      --app juiceshop --url http://127.0.0.1:3000 --runs 3   # orchestrate
  uv run --extra dev python scripts/umdr51_brain_delta.py \
      --child --arm on --run 1 --app juiceshop --url ...     # one campaign
Writes: deliverables/umdr51/run_files/brain_{off,on}_run<n>.json
        deliverables/umdr51/PHASE1_BRAIN_DELTA.json (the verdict record)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

LAB_CEILING = "10000"  # operator-configured for the measurement window


def _rank_fingerprint(hypotheses: list[dict]) -> list[str]:
    """The ranked decision surface: what the campaign would test next.

    Only stable fields enter the fingerprint (status + target + class)
    so the comparison is about ORDER/SELECTION, not incidental text.
    A different order = a different research decision.
    """
    out: list[str] = []
    for h in hypotheses[:24]:
        status = str(h.get("status") or "")
        tgt = str(h.get("target") or h.get("target_url") or "")
        cls = str(h.get("vuln_class") or h.get("hypothesis_class") or "")
        out.append(f"{status}|{tgt}|{cls}")
    return out


def run_child(app: str, url: str, run: int, arm: str,
              keep_memory: bool = False) -> dict:
    """One campaign in a fresh subprocess (settings cache honored)."""
    os.environ["LLM_ENABLED"] = "false"
    os.environ["ENABLE_UMDR48_LANES"] = "true"
    os.environ["EMBEDDINGS_OFFLINE"] = "true"
    os.environ["DISABLE_RAG"] = "true"
    os.environ["WEBPENT_GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE"] = LAB_CEILING
    os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
    if arm == "on":
        os.environ["WEBPENT_ENABLE_BRAIN_ENGINE"] = "true"
    else:
        os.environ.pop("WEBPENT_ENABLE_BRAIN_ENGINE", None)

    campaign_id = f"umdr51-{app}-brain{arm}-run{run}-{uuid.uuid4().hex[:6]}"
    started = time.monotonic()

    from webpent.cli.unified_hunt import run_unified_hunt
    from webpent.production.brain_engine import brain_engine_enabled
    from webpent.shared.global_rate_governor import get_global_rate_governor

    flag_verified = brain_engine_enabled()

    if not keep_memory:
        # zero-prior-knowledge posture (law 1): every campaign starts
        # with a clean research-memory slate for its target
        from webpent.production.research_memory_store import _memory_path
        try:
            mem = _memory_path(url, None)
            if os.path.isfile(mem):
                os.remove(mem)
        except OSError:
            pass

    if not keep_memory:
        # zero-prior-knowledge posture (law 1): every campaign starts
        # with a clean research-memory slate for its target
        from webpent.production.research_memory_store import _memory_path
        try:
            mem = _memory_path(url, None)
            if os.path.isfile(mem):
                os.remove(mem)
        except OSError:
            pass
    from webpent.production.research_memory_store import (
        load_research_memory,
    )
    mem_before = load_research_memory(url) or {}

    summary = run_unified_hunt(
        url=url, mode="standard",
        authorization="umdr51-owner-approved-local-lab",
        engagement_id=campaign_id,
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True,
    )
    elapsed = round(time.monotonic() - started, 3)
    gov = get_global_rate_governor().snapshot()

    hyps = summary.get("hypotheses_dump") or []
    findings = summary.get("findings_detail") or []
    confirmed = [f for f in findings
                 if str(f.get("confidence_level") or "") == "Tool-Confirmed"]
    rank = _rank_fingerprint(hyps)
    mem_after = load_research_memory(url) or {}
    return {
        "schema": "umdr51-brain-delta-run/1.1.0",
        "app": app,
        "target_url": url,
        "run": run,
        "campaign_id": campaign_id,
        "brain": "ON" if arm == "on" else "OFF",
        "brain_flag_verified_in_process": flag_verified,
        "llm": "OFF",
        "lanes": "ON",
        "lab_rate_ceiling_config": int(LAB_CEILING),
        "zero_prior_knowledge": True,
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": elapsed,
        "findings_total": len(findings),
        "findings_confirmed": len(confirmed),
        "hypotheses_total": len(hyps),
        "hypotheses_confirmed": sum(
            1 for h in hyps if str(h.get("status") or "") == "confirmed"),
        "hypotheses_status_counts": {
            s: sum(1 for h in hyps if str(h.get("status") or "") == s)
            for s in sorted({str(h.get("status") or "") for h in hyps})
        },
        "hypotheses_rank_fingerprint": rank,
        "rank_fingerprint_sha256": hashlib.sha256(
            "\n".join(rank).encode()).hexdigest()[:16],
        "governor_snapshot": gov,
        "research_memory": {
            "existed_before": bool(mem_before),
            "revision_before": int(mem_before.get("revision") or 0),
            "revision_after": int(mem_after.get("revision") or 0),
            "saved": bool(summary.get("research_memory_saved")),
            "demotion_classes_after": list(
                mem_after.get("demotion_classes") or []),
            "lesson_count_after": len(
                mem_after.get("lesson_summaries") or []),
        },
        "findings_detail": [
            {"vuln_class": f.get("vuln_class"),
             "url": f.get("url"),
             "confidence_level": f.get("confidence_level")}
            for f in findings],
        "summary_keys": {
            k: v for k, v in summary.items()
            if isinstance(v, (int, float, str, bool))},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", default="deliverables/umdr51/run_files")
    ap.add_argument("--child", action="store_true",
                    help="internal: run ONE campaign in this process")
    ap.add_argument("--keep-memory", action="store_true",
                    help="child: keep the target's research memory (W6 "
                         "chain experiment — consult what the previous "
                         "campaign saved)")
    ap.add_argument("--arm", choices=("off", "on"))
    ap.add_argument("--run", type=int)
    args = ap.parse_args()

    if args.child:
        assert args.arm and args.run, "child mode needs --arm and --run"
        rec = run_child(args.app, args.url, args.run, args.arm,
                        keep_memory=args.keep_memory)
        outdir = REPO / args.out
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / f"brain_{args.arm}_run{args.run}.json").write_text(
            json.dumps(rec, indent=2) + "\n")
        print(
            f"[brain {args.arm.upper()}] run{args.run}: findings="
            f"{rec['findings_total']} confirmed="
            f"{rec['findings_confirmed']} hyps={rec['hypotheses_total']} "
            f"flag_verified={rec['brain_flag_verified_in_process']} "
            f"rankFP={rec['rank_fingerprint_sha256']} "
            f"gov_req={rec['governor_snapshot']['requests_last_minute']}"
            f"/{rec['governor_snapshot']['requests_per_minute']} "
            f"elapsed={rec['elapsed_s']}s")
        return 0

    # orchestrator: one subprocess per campaign (fresh settings cache)
    env = {**os.environ,
           "EMBEDDINGS_OFFLINE": "true", "DISABLE_RAG": "true"}
    py = [sys.executable, str(Path(__file__).resolve())]
    outdir = REPO / args.out
    outdir.mkdir(parents=True, exist_ok=True)
    runs: list[dict] = []
    for arm in ("off", "on"):
        for n in range(1, args.runs + 1):
            r = subprocess.run(
                py + ["--child", "--arm", arm, "--run", str(n),
                      "--app", args.app, "--url", args.url],
                env=env, cwd=str(REPO), timeout=600,
                capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if line.startswith("[brain"):
                    print(line, flush=True)
            path = outdir / f"brain_{arm}_run{n}.json"
            if not path.is_file():
                print(f"CHILD FAILED (arm={arm} run={n}):\n{r.stdout[-800:]}\n{r.stderr[-2000:]}")
                return 1
            runs.append(json.loads(path.read_text()))

    off = [r for r in runs if r["brain"] == "OFF"]
    on = [r for r in runs if r["brain"] == "ON"]
    assert all(r["brain_flag_verified_in_process"] is False for r in off), \
        "OFF arm contaminated: flag verified ON in an OFF run"
    assert all(r["brain_flag_verified_in_process"] is True for r in on), \
        "ON arm invalid: flag not honored in process"

    def arm_stats(arm_runs: list[dict]) -> dict:
        return {
            "runs": len(arm_runs),
            "findings_total_mean": round(statistics.mean(
                r["findings_total"] for r in arm_runs), 3),
            "findings_confirmed_mean": round(statistics.mean(
                r["findings_confirmed"] for r in arm_runs), 3),
            "hypotheses_total_mean": round(statistics.mean(
                r["hypotheses_total"] for r in arm_runs), 3),
            "hypotheses_confirmed_mean": round(statistics.mean(
                r["hypotheses_confirmed"] for r in arm_runs), 3),
            "elapsed_s_mean": round(statistics.mean(
                r["elapsed_s"] for r in arm_runs), 3),
            "rank_fingerprints": [r["rank_fingerprint_sha256"]
                                  for r in arm_runs],
            "deterministic_within_arm": len(
                {r["rank_fingerprint_sha256"] for r in arm_runs}) == 1,
            "governor_requests_last_minute": [
                r["governor_snapshot"]["requests_last_minute"]
                for r in arm_runs],
        }

    off_stats = arm_stats(off)
    on_stats = arm_stats(on)
    off_fps = set(off_stats["rank_fingerprints"])
    on_fps = set(on_stats["rank_fingerprints"])
    ceiling_clean = all(
        r["governor_snapshot"]["requests_last_minute"]
        < r["governor_snapshot"]["requests_per_minute"] for r in runs)
    decision_delta = {
        "off_fingerprints": sorted(off_fps),
        "on_fingerprints": sorted(on_fps),
        "on_rank_changed_vs_off": bool(on_fps - off_fps),
        "hypotheses_confirmed_delta": round(
            on_stats["hypotheses_confirmed_mean"]
            - off_stats["hypotheses_confirmed_mean"], 3),
        "findings_confirmed_delta": round(
            on_stats["findings_confirmed_mean"]
            - off_stats["findings_confirmed_mean"], 3),
        "findings_total_delta": round(
            on_stats["findings_total_mean"]
            - off_stats["findings_total_mean"], 3),
        "elapsed_delta_s": round(
            on_stats["elapsed_s_mean"] - off_stats["elapsed_s_mean"], 3),
        "rate_ceiling_never_hit": ceiling_clean,
    }
    rank_changed = bool(on_fps - off_fps)
    counts_changed = (
        decision_delta["hypotheses_confirmed_delta"] != 0
        or decision_delta["findings_total_delta"] != 0)
    hyps_delta = round(
        on_stats["hypotheses_total_mean"]
        - off_stats["hypotheses_total_mean"], 3)
    decision_delta["hypotheses_total_delta"] = hyps_delta
    # The honest verdict per the mandatory status language: the brain
    # measurably changes the research POOL (+N injected W4/W5
    # hypotheses, deterministic) = PARTIALLY VERIFIED; full VERIFIED
    # additionally needs a rank-order or outcome change ON the field.
    pool_changed = hyps_delta != 0
    verdict = {
        "schema": "umdr51-phase1-brain-delta/1.1.0",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "app": args.app,
        "target_url": args.url,
        "runs_per_arm": args.runs,
        "isolation": "one campaign per subprocess (settings cache + "
                     "process-wide rate ceiling cannot contaminate)",
        "lab_ceiling_operator_config": {
            "env": "WEBPENT_GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE",
            "value": int(LAB_CEILING),
            "reason": "measurement window over the local owner-authorized "
                      "lab target; the 900/min default would deny the 5th "
                      "campaign's requests inside one window (root-caused: "
                      "222 requests/campaign, proven by governor snapshots)",
        },
        "off_stats": off_stats,
        "on_stats": on_stats,
        "decision_delta": decision_delta,
        "gate_g5": {
            "question": "does the brain change REAL research decisions "
                        "OFF/ON, measured on the field, without touching "
                        "scope/execution/confirmation authority?",
            "rank_order_changed": rank_changed,
            "outcome_counts_changed": counts_changed,
            "hypothesis_pool_changed": pool_changed,
            "hypotheses_total_delta": hyps_delta,
            "arms_deterministic": (
                off_stats["deterministic_within_arm"]
                and on_stats["deterministic_within_arm"]),
            "rate_ceiling_clean": ceiling_clean,
            "status": (
                "VERIFIED" if (rank_changed or counts_changed) and ceiling_clean
                else "PARTIALLY VERIFIED — the brain measurably changes the "
                     "research pool (+N injected hypotheses, deterministic) "
                     "but not the rank order or promoted outcomes on this "
                     "target shape in standard mode"
                if pool_changed and ceiling_clean
                else "FAILED — no measured decision delta"),
        },
    }
    # W6 chain experiment: the cross-campaign learning loop — ON run A
    # (fresh memory) writes, ON run B (memory kept) must consult it and
    # measurably change its decisions vs the zero-knowledge ON arm.
    for arm, n, keep in (("on", 4, False), ("on", 5, True)):
        r = subprocess.run(
            py + ["--child", "--arm", arm, "--run", str(n),
                  "--app", args.app, "--url", args.url,
                  *(["--keep-memory"] if keep else [])],
            env=env, cwd=str(REPO), timeout=600,
            capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("[brain"):
                print(line, flush=True)
        wpath = outdir / f"brain_{arm}_run{n}.json"
        if not wpath.is_file():
            print(f"W6 CHILD FAILED (run {n}):\n{r.stdout[-500:]}\n{r.stderr[-1500:]}")
            return 1
    w6_a = json.loads((outdir / "brain_on_run4.json").read_text())
    w6_b = json.loads((outdir / "brain_on_run5.json").read_text())
    w6 = {
        "schema": "umdr51-phase1-w6-chain/1.0.0",
        "question": "does the W6 research memory measurably change the "
                    "next campaign's decisions (cross-campaign learning)?",
        "run_a_fresh_memory": {
            "rank_fp": w6_a["rank_fingerprint_sha256"],
            "mem": w6_a["research_memory"],
        },
        "run_b_consulting": {
            "rank_fp": w6_b["rank_fingerprint_sha256"],
            "mem": w6_b["research_memory"],
        },
        "memory_persisted": w6_b["research_memory"]["existed_before"]
        and w6_b["research_memory"]["revision_before"] >= 1,
        "decisions_changed": (
            w6_b["rank_fingerprint_sha256"]
            != w6_a["rank_fingerprint_sha256"]
            or w6_b["hypotheses_total"] != w6_a["hypotheses_total"]
            or w6_b["findings_total"] != w6_a["findings_total"]),
        "status": "VERIFIED" if (
            w6_b["research_memory"]["existed_before"]
            and (w6_b["rank_fingerprint_sha256"]
                 != w6_a["rank_fingerprint_sha256"]
                 or w6_b["hypotheses_total"] != w6_a["hypotheses_total"]
                 or w6_b["findings_total"] != w6_a["findings_total"])
        ) else "INCONCLUSIVE — memory did not measurably change decisions",
    }
    verdict["w6_chain"] = w6

    (REPO / "deliverables/umdr51/PHASE1_BRAIN_DELTA.json").write_text(
        json.dumps(verdict, indent=2) + "\n")
    print(json.dumps(verdict["gate_g5"], indent=1))
    print(json.dumps(w6, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
