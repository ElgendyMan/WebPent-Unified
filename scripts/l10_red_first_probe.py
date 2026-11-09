"""L10 Phase 1 red-first probe (evidence record, not a gate).

Runs the CURRENT engine stack -- the L8/L9 discovery engine and both
L9 planner configurations (full prerequisite reasoning and the
prerequisite-ablated variant) -- against the generation-3 dev block
(consign, permit) at budget 32, BEFORE any L10 engine work begins.

The expected shape of the record this produces is the phase's
red-first evidence:

- every CLEAN variant (secured, transition_no_vuln,
  unavailable_prereq) is FP-free for every strategy: the corpus
  offers no benign open transition (funding is consignor-reserved on
  every consign variant), so a confirmation there would be a corpus
  manufacturing defect, not an engine finding;
- every DEFECTIVE instance shows fn 1 for every strategy: the
  generation-3 prerequisite shapes (a consignor-reserved funding
  record; a three-item conjunctive checklist) are not yet reachable
  by the unmodified engine, which is precisely the work the later L10
  phases must generalize to.

Run: python3 scripts/l10_red_first_probe.py
Writes: docs/l10_red_first_probe.json
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "scripts")
from l9_planner_matrix import run_one  # noqa: E402

from webpent.appsuite import corpus  # noqa: E402


def main() -> None:
    block = corpus.l10_dev_block()
    out = []
    for entry in block:
        for strat in ("l8-engine", "planner", "planner-no-prereq"):
            rec = run_one(strat, entry, 32)
            out.append(rec)
            print(strat, entry.instance_id, entry.variant,
                  "tp", rec["tp"], "fp", rec["fp"], "fn", rec["fn"],
                  "req", rec["requests"], "status", rec["status_tally"],
                  flush=True)
    json.dump(out, open("docs/l10_red_first_probe.json", "w"),
              indent=1)


if __name__ == "__main__":
    main()
