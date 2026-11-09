"""Fix-sprint performance benchmarks (PHASE 7, 2026-10-05).

Measures the critical paths named in the sprint brief:
  1. hypothesis generation (HypothesisGenerator.generate, with and without
     enriched_context)
  2. validation dispatch (production/validators on synthetic evidence)
  3. session-recovery wrapper overhead (RecoveringExploiter passthrough vs
     raw exploiter - the zero-FP hot path)
  4. checkpoint write/read roundtrip (get_checkpointer + SqliteSaver)
  5. report quality evaluation (report_quality.evaluate_report_quality)

Run from repo root: python3 scripts/perf_benchmarks_20261005.py
Outputs absolute numbers; no network, no LLM (deterministic paths only).
"""
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

RESULTS: list[tuple[str, float, str]] = []


def bench(name: str, fn, repeats: int = 50, unit: str = "ms") -> None:
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    med = statistics.median(times)
    p95 = sorted(times)[int(len(times) * 0.95) - 1]
    RESULTS.append((name, med, f"median {med:.2f} {unit} | p95 {p95:.2f} {unit} | n={repeats}"))
    print(f"{name:55s} median {med:8.2f} {unit}   p95 {p95:8.2f} {unit}")


def bench_hypothesis_generation() -> None:
    from webpent.recon.hypothesis_generator import HypothesisGenerator
    from webpent.recon.autonomous_crawler import RouteSurface, SurfaceMap, SurfaceParameter

    gen = HypothesisGenerator()
    parameter = SurfaceParameter(name="id", location="path", value_shape="int",
                                 observed_length=3, source_route="/api/invoices/{id}")
    route = RouteSurface(
        route="/api/invoices/{id}", method="GET", status_code=200,
        content_type="application/json", response_digest="d" * 8,
        response_length=128, depth=1, auth_required=True, login_signal=False,
        api_signal=True, parameters=(parameter,),
    )
    surface = SurfaceMap(
        target_url="https://lab.example", target_fingerprint="fp" * 16,
        scope_fingerprint="sc" * 16, routes={route.route: route},
    )
    bench("hypothesis.generate (no enrichment)", lambda: gen.generate(surface), repeats=30)

    class _Enriched:
        tech_stack = ("php", "mysql")
        auth_type = "session"
        payload_suggestions = ("../etc/passwd",)

    bench("hypothesis.generate (enriched_context)",
          lambda: gen.generate(surface, enriched_context=_Enriched()), repeats=30)


def bench_validators() -> None:
    from webpent.production.validators import validate_xss

    base = {"status": 200, "body": "invoice total 100", "headers": {"content-type": "text/html"}}
    cand = {"status": 200, "body": "invoice total 100 <script>alert(1)</script>",
            "headers": {"content-type": "text/html"}}
    nc = {"status": 403, "body": "denied", "headers": {"content-type": "text/html"}}
    bench("validators.validate_xss (reflection path)",
          lambda: validate_xss(baseline=base, candidate=cand, negative_control=nc), repeats=200)


def bench_recovery_wrapper_overhead() -> None:
    from webpent.recon.session_recovery import SessionRecoveryManager
    from webpent.integration.session_recovery_bridge import RecoveringExploiter

    def _login_ok():
        return True

    mgr = SessionRecoveryManager(campaign_id="bench-engagement", login=_login_ok)

    def _inner(hypothesis, hunter_dict):
        return {"status_code": 200, "headers": {"x-ok": "1"}, "body": "fine"}

    wrapped = RecoveringExploiter(_inner, recovery_manager=mgr, hypothesis_id=lambda h: "bench-hyp")
    hyp = {"hypothesis_id": "bench-hyp"}
    bench("RecoveringExploiter passthrough (healthy 200)",
          lambda: wrapped(hyp, {}), repeats=300)
    bench("raw exploiter passthrough", lambda: _inner(hyp, {}), repeats=300)


def bench_checkpoint_roundtrip(tmp: Path) -> None:
    import os

    from langgraph.checkpoint.base import empty_checkpoint

    from webpent.graph.checkpoints import get_checkpointer

    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        with get_checkpointer() as cp:
            cfg = {"configurable": {"thread_id": "bench-thread", "checkpoint_ns": "", "checkpoint_id": None}}
            chk = empty_checkpoint()
            metadata = {"source": "input", "step": 1, "writes": None, "parents": {}}
            bench("checkpoint write",
                  lambda: cp.put(cfg, chk, {"node": {"k": "v" * 512}}, metadata), repeats=50)
            read_cfg = {"configurable": {"thread_id": "bench-thread", "checkpoint_ns": ""}}
            bench("checkpoint read", lambda: cp.get_tuple(read_cfg), repeats=50)
    finally:
        os.chdir(cwd)


def bench_report_quality() -> None:
    from webpent.shared.report_quality import evaluate_report_quality

    finding = {
        "id": "f-bench", "title": "t", "severity": "high",
        "confidence": "high", "confidence_level": "Tool-Confirmed",
        "evidence": {"causal_signal": True, "negative_control_complete": True},
        "evidence_bundle": {"request": {"method": "GET", "url": "https://t/x"},
                            "response": {"status": 200, "body": "b"}},
        "hypothesis_id": "h-bench",
    }
    bench("evaluate_report_quality (1 finding)", lambda: evaluate_report_quality([finding]), repeats=100)


def main() -> None:
    import tempfile

    print("WebPent fix-sprint performance benchmarks (2026-10-05)")
    print("=" * 78)
    bench_hypothesis_generation()
    bench_validators()
    bench_recovery_wrapper_overhead()
    bench_report_quality()
    with tempfile.TemporaryDirectory() as td:
        bench_checkpoint_roundtrip(Path(td))
    print("=" * 78)
    print("Note: medians over repeated identical calls; deterministic paths only.")


if __name__ == "__main__":
    main()
