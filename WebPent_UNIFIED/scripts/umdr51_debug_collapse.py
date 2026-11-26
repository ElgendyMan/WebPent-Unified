#!/usr/bin/env python3
"""UM-DR-51 P1 debug: reproduce the ON-run-2 collapse with visibility."""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

os.environ["LLM_ENABLED"] = "false"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["EMBEDDINGS_OFFLINE"] = "true"
os.environ["DISABLE_RAG"] = "true"
os.environ["WEBPENT_ENABLE_BRAIN_ENGINE"] = "true"
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

URL = "http://127.0.0.1:3000"
for n in (1, 2):
    cid = f"umdr51-debug-on-run{n}-{uuid.uuid4().hex[:6]}"
    t0 = time.monotonic()
    s = run_unified_hunt(
        url=URL, mode="standard",
        authorization="umdr51-owner-approved-local-lab",
        engagement_id=cid, auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True,
    )
    el = round(time.monotonic() - t0, 2)
    hyps = s.get("hypotheses_dump") or []
    fnd = s.get("findings_detail") or []
    print(f"run{n}: elapsed={el}s hyps={len(hyps)} findings={len(fnd)} "
          f"safe_stop={s.get('safe_stop_reason', '')!r} "
          f"consulted={s.get('consulted_lessons')!r} "
          f"steps={s.get('steps_done', s.get('step_count', '?'))}")
    print("  summary_keys:", json.dumps(
        {k: v for k, v in s.items() if isinstance(v, (int, float, str, bool))},
        sort_keys=True)[:600])
    mem = s.get("research_memory_saved")
    print("  memory_saved:", mem)
