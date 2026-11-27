#!/usr/bin/env python3
"""UM-DR-51 P1 decisive experiment: 6 all-OFF runs in ONE process.

If runs 5-6 collapse (budget 50, 0 hyps) the trigger is process-level
accumulation, NOT the brain flag. Pure honest bisection."""
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

URL = "http://127.0.0.1:3000"
for n in range(1, 7):
    cid = f"umdr51-bisect-off-run{n}-{uuid.uuid4().hex[:6]}"
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
    print(f"off-run{n}: elapsed={el}s hyps={len(hyps)} findings={len(fnd)} "
          f"budget={s.get('dynamic_step_budget')}",
          flush=True)
