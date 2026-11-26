#!/usr/bin/env python3
"""UM-DR-51 P1: PROVE the 5th-run collapse is the 900/min rate ceiling.

Prints the GlobalRateGovernor snapshot after each campaign run — the
denial counters and the window state are the evidence."""
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

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402
from webpent.shared.global_rate_governor import get_global_rate_governor  # noqa: E402

URL = "http://127.0.0.1:3000"
for n in range(1, 7):
    t0 = time.monotonic()
    s = run_unified_hunt(
        url=URL, mode="standard",
        authorization="umdr51-owner-approved-local-lab",
        engagement_id=f"umdr51-ceiling-run{n}-{uuid.uuid4().hex[:6]}",
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True,
    )
    el = round(time.monotonic() - t0, 2)
    gov = get_global_rate_governor().snapshot()
    print(f"run{n}: elapsed={el}s hyps={len(s.get('hypotheses_dump') or [])} "
          f"budget={s.get('dynamic_step_budget')}", flush=True)
    print(f"  governor: {gov}", flush=True)
