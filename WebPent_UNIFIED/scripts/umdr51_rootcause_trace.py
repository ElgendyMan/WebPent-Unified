#!/usr/bin/env python3
"""UM-DR-51 P1 root-cause: capture full final state per run (6 OFF runs)."""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

os.environ["LLM_ENABLED"] = "false"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["EMBEDDINGS_OFFLINE"] = "true"
os.environ["DISABLE_RAG"] = "true"
os.environ.pop("WEBPENT_ENABLE_BRAIN_ENGINE", None)
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import webpent.cli.unified_hunt as uh  # noqa: E402

FINALS: dict[int, dict] = {}
_orig = uh._invoke_with_progress


def _capturing(*a, **k):
    r = _orig(*a, **k)
    if isinstance(r, dict):
        FINALS[len(FINALS) + 1] = r
    return r


uh._invoke_with_progress = _capturing

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

URL = "http://127.0.0.1:3000"
for n in range(1, 7):
    t0 = time.monotonic()
    s = run_unified_hunt(
        url=URL, mode="standard",
        authorization="umdr51-owner-approved-local-lab",
        engagement_id=f"umdr51-rc-off-run{n}-{uuid.uuid4().hex[:6]}",
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True,
    )
    el = round(time.monotonic() - t0, 2)
    fin = FINALS.get(n, {})
    trace = fin.get("node_step_trace") or []
    crawl = fin.get("crawled_data") or {}
    urls = crawl.get("urls") or crawl.get("discovered_urls") or []
    nodes_seq = [t.get("node") for t in trace]
    from collections import Counter
    cnt = Counter(nodes_seq)
    print(f"off-run{n}: elapsed={el}s hyps={len(s.get('hypotheses_dump') or [])} "
          f"findings={len(s.get('findings_detail') or [])} "
          f"budget={s.get('dynamic_step_budget')} "
          f"| final_state_keys={len(fin)} trace_len={len(trace)} "
          f"crawl_urls={len(urls)}", flush=True)
    if n in (4, 5):
        print(f"  run{n} nodes: {nodes_seq[:40]}", flush=True)
        print(f"  run{n} node counts: {dict(cnt)}", flush=True)
