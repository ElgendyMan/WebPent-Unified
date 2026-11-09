"""U-DOJO-11: the operator trainer — step-by-step drill sessions.

Laws honored here:
- L-2 ISOLATED STATE: session state, when persisted, lives only inside the
  Dojo directory (WEBPENT_DOJO_DIR or an explicitly given folder).
- L-3 GROUND TRUTH: the trainee sees surface information only; answers are
  judged against the scenario's ground truth on the trainer side.
- L-4 DETERMINISTIC: the present -> answer -> evaluate -> advance cycle is
  a pure function of the session state; no clocks, no randomness.
- L-8 PREAMBLE BEFORE: every session opens with the advisory preamble,
  before any training content is shown.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from webpent.dojo.scenario_library import ScenarioLibrary

#: hints cost 10 points of a step's 100, deterministically
HINT_COST = 10.0

_PREAMBLE = (
    "advisory: Dojo training session. Every target here is a simulated lab "
    "built from a fixed seed; nothing you answer touches a real host, and "
    "nothing in this session sends a request anywhere. Ground truth stays on "
    "the trainer side; you are evaluated on what you can justify."
)

#: deterministic final answer once the hint ladder is exhausted
_NO_MORE_HINTS = "advisory: no more hints for this step; commit to an answer."


@dataclass(frozen=True)
class StepView:
    """What the trainee may see for the current step (L-3: no truth)."""

    scenario_id: str
    title: str
    description: str
    difficulty: int
    request_budget: int
    hints_used: int


@dataclass(frozen=True)
class StepResult:
    """The verdict on one answer, with the reason stated (L-7)."""

    correct: bool
    detail: str


class TrainingSession:
    """A deterministic step-by-step drill over a list of scenarios."""

    def __init__(
        self,
        library: ScenarioLibrary,
        scenario_ids: list[str],
        dojo_dir: str | Path | None = None,
    ) -> None:
        self._library = library
        self.scenario_ids: tuple[str, ...] = tuple(scenario_ids)
        self.current_index = 0
        self.correct_count = 0
        self.hints_used = 0
        self._answers: list[bool] = []
        self._hints_per_step: list[int] = []
        self.dojo_dir = Path(dojo_dir) if dojo_dir is not None else None

    # -- L-8 ----------------------------------------------------------------

    @staticmethod
    def preamble() -> str:
        return _PREAMBLE

    # -- the deterministic cycle ---------------------------------------------

    @property
    def finished(self) -> bool:
        return self.current_index >= len(self.scenario_ids)

    @property
    def _current_id(self) -> str:
        return self.scenario_ids[self.current_index]

    def present(self) -> StepView:
        if self.finished:
            raise IndexError("session already finished")
        scenario = self._library.get(self._current_id)
        return StepView(
            scenario_id=scenario.scenario_id,
            title=scenario.title,
            description=scenario.description,
            difficulty=scenario.difficulty,
            request_budget=scenario.request_budget,
            hints_used=self.hints_used,
        )

    def request_hint(self) -> str:
        if self.finished:
            raise IndexError("session already finished")
        scenario = self._library.get(self._current_id)
        if self.hints_used >= len(scenario.hints):
            return _NO_MORE_HINTS
        hint = scenario.hints[self.hints_used]
        self.hints_used += 1
        return hint

    def answer(self, answer: dict) -> StepResult:
        if self.finished:
            raise IndexError("session already finished")
        scenario = self._library.get(self._current_id)
        matches = {
            key: str(answer.get(key, "")) == getattr(scenario, key)
            for key in ("vuln_class", "location", "signature")
        }
        correct = all(matches.values())
        self._answers.append(correct)
        self._hints_per_step.append(self.hints_used)
        if correct:
            self.correct_count += 1
            self.current_index += 1
            self.hints_used = 0
        missing = [key for key, ok in matches.items() if not ok]
        detail = (
            "advisory: answer accepted; advancing to the next step"
            if correct
            else f"advisory: answer rejected; mismatched: {', '.join(missing)}"
        )
        return StepResult(correct=correct, detail=detail)

    # -- scoring ---------------------------------------------------------------

    def score(self) -> float:
        if not self.scenario_ids:
            return 0.0
        total = 0.0
        # R2-dojo-01: only CORRECT attempts earn step points. The old
        # loop scored every recorded attempt (including rejected answers,
        # worth up to 100 each) while dividing by len(scenario_ids), so
        # five wrong answers then one correct scored 600.0.
        for correct, hints in zip(self._answers, self._hints_per_step,
                                  strict=False):
            if correct:
                total += max(0.0, 100.0 - HINT_COST * hints)
        return round(total / len(self.scenario_ids), 2)

    # -- L-2 isolated state ------------------------------------------------------

    def _default_dojo_dir(self) -> Path:
        env = os.environ.get("WEBPENT_DOJO_DIR")
        return Path(env) if env else Path("download") / "dojo"

    def save(self) -> Path:
        base = self.dojo_dir if self.dojo_dir is not None else self._default_dojo_dir()
        base.mkdir(parents=True, exist_ok=True)
        path = base / "trainer_session.json"
        state = {
            "scenario_ids": list(self.scenario_ids),
            "current_index": self.current_index,
            "correct_count": self.correct_count,
            "answers": self._answers,
            "hints_per_step": self._hints_per_step,
            # hint economics (HINT_COST) must survive a reload: a trainee
            # who burned a hint cannot get it back by saving and loading
            "hints_used": self.hints_used,
        }
        payload = json.dumps(state, indent=2, sort_keys=True)
        # R2-dojo-10: a plain write_text is not atomic; a crash mid-write
        # tears trainer_session.json and load() then fails forever. Mirror
        # the progress ledger: write to a temp file in the same directory,
        # then os.replace it into place, unlinking the temp on failure.
        handle, tmp_name = tempfile.mkstemp(
            dir=str(base), prefix=path.name, suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as tmp:
                tmp.write(payload)
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        return path

    @classmethod
    def load(
        cls, path: str | Path, library: ScenarioLibrary
    ) -> TrainingSession:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
        session = cls(library, scenario_ids=list(state["scenario_ids"]))
        session.current_index = int(state["current_index"])
        session.correct_count = int(state["correct_count"])
        session._answers = [bool(a) for a in state.get("answers", [])]
        session._hints_per_step = [int(h) for h in state.get("hints_per_step", [])]
        # older state files may not carry hints_used; default keeps them working
        session.hints_used = max(0, int(state.get("hints_used", 0)))
        return session
