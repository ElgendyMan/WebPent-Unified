#!/usr/bin/env python3
"""E-4 PROBE (Dispatch #005 §3.2, phase 3.2) — commit-free artifact D3.

Empirical questions (ruling 3.4(i)):
  P1. What entrypoint value do REAL graph runs record today?
  P2. Every double-resolution path for the same engagement_id — does the
      in-process drift registry raise on each?
  P3. Cross-process drift visibility (known limitation to document).
  P4. Surface detectability for mechanism (b): can each production surface
      be labeled truthfully (env var at editable launch surfaces / process
      derivation), and what happens when neither is available?

Zero external-target interaction: the graph run targets a loopback HTTP
stub (127.0.0.1, ephemeral port) that serves an empty site.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESULTS: dict = {}


def _loopback_site() -> tuple[ThreadingHTTPServer, str]:
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def probe_p1_real_graph_run() -> dict:
    """Compile the REAL production graph via build_graph and stream exactly
    one node (the combined recon node, which hosts the modern-spine node),
    capturing the _production_trace it records today."""
    import webpent.graph.builder as gb

    srv, url = _loopback_site()
    state = {
        "engagement_id": f"e4probe_{uuid.uuid4().hex[:10]}",
        "target_url": url,
        "scan_id": f"e4probe_{uuid.uuid4().hex[:6]}",
        "objective": "E-4 probe (loopback stub, bounded to first node)",
    }
    graph = gb.build_graph(auto_approve=True)
    recorded = {}
    try:
        for chunk in graph.stream(state, stream_mode="updates"):
            for node_name, update in chunk.items():
                upd = update if isinstance(update, dict) else {}
                if "_production_trace" in upd:
                    recorded["node"] = node_name
                    recorded["trace"] = upd["_production_trace"]
                # bounded: stop after the first node that produced state
                if recorded:
                    break
            if recorded:
                break
    finally:
        srv.shutdown()
    return recorded


def probe_p2_double_resolution() -> dict:
    """Same engagement_id resolved twice IN-PROCESS via different
    entrypoints -> drift registry must raise (R2-V NF-08 confirmed/denied)."""
    from webpent.production.production_spine import (
        ProductionSpineConfig,
        ProductionSpineError,
        resolve_production_spine,
    )
    eng = f"e4double_{uuid.uuid4().hex[:8]}"
    out = {}
    cfg1 = ProductionSpineConfig(
        engagement_id=eng, target_url="http://127.0.0.1:9/",
        entrypoint="api", auto_approve=True)
    orch1, trace1 = resolve_production_spine(cfg1)
    out["first_resolution"] = {"entrypoint": trace1.summary()["entrypoint"],
                               "digest": trace1.summary()["config_digest"]}
    cfg2 = ProductionSpineConfig(
        engagement_id=eng, target_url="http://127.0.0.1:9/",
        entrypoint="direct_invoke", auto_approve=True)
    try:
        resolve_production_spine(cfg2)
        out["second_resolution_raise"] = False
    except ProductionSpineError as exc:
        out["second_resolution_raise"] = True
        out["second_resolution_error"] = str(exc)[:180]
    # same-entrypoint re-resolution (identical digest) must NOT raise
    try:
        resolve_production_spine(cfg1)
        out["identical_reresolution_raise"] = False
    except ProductionSpineError as exc:
        out["identical_reresolution_raise"] = True
        out["identical_reresolution_error"] = str(exc)[:180]
    return out


def probe_p3_cross_process() -> dict:
    """Same engagement resolved in TWO separate processes -> no in-process
    registry can see it (documented limitation, ruling 3.4(iii))."""
    code = (
        "from webpent.production.production_spine import ProductionSpineConfig,"
        " resolve_production_spine;"
        " resolve_production_spine(ProductionSpineConfig(engagement_id='%s',"
        " target_url='http://127.0.0.1:9/', entrypoint='%s', auto_approve=True))"
    )
    eng = f"e4cross_{uuid.uuid4().hex[:8]}"
    env = dict(os.environ)
    r1 = subprocess.run([sys.executable, "-c", code % (eng, "cli")],
                        capture_output=True, text=True, env=env, timeout=120)
    r2 = subprocess.run([sys.executable, "-c", code % (eng, "direct_invoke")],
                        capture_output=True, text=True, env=env, timeout=120)
    return {
        "proc1_rc": r1.returncode, "proc2_rc": r2.returncode,
        "proc2_stderr_tail": r2.stderr.strip().splitlines()[-1][:160] if r2.stderr.strip() else "",
        "cross_process_raise": r1.returncode != 0 or r2.returncode != 0,
    }


def probe_p4_surface_detectability() -> dict:
    """Mechanism (b) evidence: which surfaces can be labeled truthfully?"""
    out = {}
    # (1) CLI: `python -m webpent.cli` -> __main__.__file__ points inside
    #     webpent/cli/ -> derivable without touching frozen files.
    #     Probe with a tiny -m module to pin the interpreter semantics.
    probe_dir = os.path.dirname(os.path.abspath(__file__))
    mdir = os.path.join("/home/z/my-project/work/r3_wt", "e4probe_mod")
    os.makedirs(mdir, exist_ok=True)
    with open(os.path.join(mdir, "__main__.py"), "w") as f:
        f.write("import __main__;print(__main__.__file__)\n")
    r = subprocess.run([sys.executable, "-m", "e4probe_mod"],
                       capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "/home/z/my-project/work/r3_wt"})
    out["m_main_dunder_file"] = r.stdout.strip()
    out["m_main_dunder_file_is_module_path"] = r.stdout.strip().endswith("e4probe_mod/__main__.py")
    # (2) worker/api: launched through EDITABLE root surfaces (worker.py,
    #     server.py) -> explicit env var set at those surfaces (option b).
    out["editable_launch_surfaces"] = {
        "worker.py": "EDITABLE (root, not in 695 manifest)",
        "server.py": "EDITABLE (root, not in 695 manifest)",
        "webpent-cli.sh": "EDITABLE (root, not in 695 manifest)",
        "cli/commands.py": "FROZEN (cannot set env; covered by -m derivation)",
        "workers/pentest_worker.py": "FROZEN (launched via editable worker.py)",
    }
    # (3) underivable process (this pytest-less probe itself): main module is
    #     this script -> no env var, no known-surface derivation -> the
    #     node's derivation must FAIL CLOSED (reject), never label wrongly.
    out["underivable_main_here"] = __file__
    return out


def main() -> None:
    print("== E-4 PROBE (D3) ==")
    print("\n[P1] real graph run — recorded trace entrypoint TODAY:")
    try:
        r1 = probe_p1_real_graph_run()
        RESULTS["P1"] = r1
        print(json.dumps(r1, indent=1, default=str)[:800])
    except Exception as exc:  # probe must record, not crash silently
        RESULTS["P1"] = {"error": repr(exc)[:300]}
        print("  probe error:", repr(exc)[:300])

    print("\n[P2] in-process double resolution (same engagement, different entrypoint):")
    RESULTS["P2"] = probe_p2_double_resolution()
    print(json.dumps(RESULTS["P2"], indent=1)[:600])

    print("\n[P3] cross-process same-engagement resolution:")
    RESULTS["P3"] = probe_p3_cross_process()
    print(json.dumps(RESULTS["P3"], indent=1)[:400])

    print("\n[P4] surface detectability for mechanism (b):")
    RESULTS["P4"] = probe_p4_surface_detectability()
    print(json.dumps(RESULTS["P4"], indent=1)[:900])

    with open("/home/z/my-project/work/r3_evidence/D3_E4_probe_results.json", "w") as f:
        json.dump(RESULTS, f, indent=1, default=str)
    print("\nrecorded -> work/r3_evidence/D3_E4_probe_results.json")


if __name__ == "__main__":
    main()
