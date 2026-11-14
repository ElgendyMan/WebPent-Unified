"""EGAIE deterministic state persistence.

save_state / load_state write the full InvestigationState as JSON so an
interrupted investigation resumes exactly where it stopped. No dynamic
resolution, no pickles: plain data through schemas.to_dict/from_dict.
"""
from __future__ import annotations

import json
import pathlib

from webpent.egaie.schemas import InvestigationState


def save_state(state: InvestigationState, path: pathlib.Path) -> None:
    path.write_text(
        json.dumps(state.to_dict(), sort_keys=True), encoding="utf-8"
    )


def load_state(path: pathlib.Path) -> InvestigationState:
    data = json.loads(path.read_text(encoding="utf-8"))
    return InvestigationState.from_dict(data)
