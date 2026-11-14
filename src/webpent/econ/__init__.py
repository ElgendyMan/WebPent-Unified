"""WebPent Economist — the business brain (NC-ECON-1).

Four brains, one tool: the technical brain (EV scheduler, curiosity,
adaptation), the temporal brain (CEM), and now the business brain
(the Economist): what is worth working on, when, and in what order.

Governing laws (NC-ECON-1 §7), binding on every module in this package:

L-1  ADVISORY-ONLY: nothing here submits, sends or executes anything.
     Every output is a suggestion; the operator decides.
L-2  ZERO NETWORK FROM CORE: no module under ``webpent.econ`` performs
     network I/O. Ingestion reads local snapshots produced by offline,
     operator-run scripts only.
L-3  DETERMINISTIC: every formula is deterministic. No randomness, no
     LLM in any economic decision.
L-4  TRANSPARENCY: every decision carries {value, components, rationale,
     confidence, timestamp}. No black boxes.
L-8  HUMAN-IN-THE-LOOP: every recommendation requires explicit operator
     confirmation before any (operator-performed) action.
"""

from __future__ import annotations

ADVISORY_ONLY = True

__all__ = ["ADVISORY_ONLY"]
