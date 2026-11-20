"""U-DOJO-2: the Scenario Library.

Laws honored here:
- L-3 GROUND TRUTH: every scenario must carry a full ground truth block
  (vuln_class, location, signature) plus graduated hints; loading refuses
  anything less.
- L-4 DETERMINISTIC: loading is ordered lexicographically by file name and
  then by scenario order inside each file; two loads return identical data.
- L-7 LESSON FEEDBACK: each scenario carries lesson_tags and skill_families
  so outcomes can flow back into the skill matrix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Scenario:
    """One trainable exercise with its ground truth and lesson metadata."""

    scenario_id: str
    family: str
    title: str
    description: str
    difficulty: int
    template_id: str
    seed: int
    ground_truth: dict
    hints: tuple[str, ...]
    lesson_tags: tuple[str, ...]
    skill_families: tuple[str, ...]
    request_budget: int

    @property
    def vuln_class(self) -> str:
        return str(self.ground_truth["vuln_class"])

    @property
    def location(self) -> str:
        return str(self.ground_truth["location"])

    @property
    def signature(self) -> str:
        return str(self.ground_truth["signature"])


_REQUIRED_GROUND_TRUTH_KEYS = ("vuln_class", "location", "signature")
_REQUIRED_FIELDS = (
    "scenario_id",
    "title",
    "description",
    "difficulty",
    "template_id",
    "seed",
    "ground_truth",
    "hints",
    "lesson_tags",
    "skill_families",
    "request_budget",
)


def _scenario_from_mapping(data: dict, family: str) -> Scenario:
    """Build a Scenario from one YAML mapping, refusing anything incomplete (L-3)."""
    missing = [key for key in _REQUIRED_FIELDS if key not in data]
    if missing:
        raise ValueError(
            f"scenario in family {family!r} missing fields: {', '.join(missing)}"
        )
    ground_truth = data["ground_truth"]
    if not isinstance(ground_truth, dict):
        raise ValueError(
            f"scenario {data['scenario_id']!r}: ground_truth must be a mapping"
        )
    for key in _REQUIRED_GROUND_TRUTH_KEYS:
        if not ground_truth.get(key):
            raise ValueError(
                f"scenario {data['scenario_id']!r}: ground_truth.{key} is required (L-3)"
            )
    difficulty = int(data["difficulty"])
    if not 1 <= difficulty <= 5:
        raise ValueError(
            f"scenario {data['scenario_id']!r}: difficulty {difficulty} outside 1..5"
        )
    budget = int(data["request_budget"])
    if budget <= 0:
        raise ValueError(f"scenario {data['scenario_id']!r}: request_budget must be > 0")
    hints = tuple(str(h) for h in data["hints"])
    if len(hints) < 2:
        raise ValueError(
            f"scenario {data['scenario_id']!r}: needs at least 2 graduated hints (L-3)"
        )
    return Scenario(
        scenario_id=str(data["scenario_id"]),
        family=str(family),
        title=str(data["title"]),
        description=str(data["description"]),
        difficulty=difficulty,
        template_id=str(data["template_id"]),
        seed=int(data["seed"]),
        ground_truth=dict(ground_truth),
        hints=hints,
        lesson_tags=tuple(str(t) for t in data["lesson_tags"]),
        skill_families=tuple(str(f) for f in data["skill_families"]),
        request_budget=budget,
    )


@dataclass
class ScenarioLibrary:
    """An ordered, deterministic collection of training scenarios."""

    scenarios: tuple[Scenario, ...] = field(default_factory=tuple)
    _by_id: dict[str, Scenario] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._by_id = {s.scenario_id: s for s in self.scenarios}
        if len(self._by_id) != len(self.scenarios):
            raise ValueError("duplicate scenario_id in library")

    @classmethod
    def load_dir(cls, directory: Path) -> ScenarioLibrary:
        """Load every YAML file in the directory, deterministically (L-4).

        Files are read in lexicographic order and scenarios in file order;
        the resulting tuple is therefore stable across loads.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise FileNotFoundError(f"scenario directory not found: {directory}")
        loaded: list[Scenario] = []
        # R2-dojo-09: the docstring promises every YAML file; globbing only
        # *.yaml silently skipped *.yml. Collect both patterns, deduped by
        # path, then sort for the same deterministic order as before (L-4).
        paths: set[Path] = set()
        for pattern in ("*.yaml", "*.yml"):
            paths.update(directory.glob(pattern))
        for path in sorted(paths):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or "scenarios" not in raw:
                raise ValueError(f"{path.name}: expected a mapping with a 'scenarios' list")
            family = raw.get("family", path.stem)
            for item in raw["scenarios"]:
                loaded.append(_scenario_from_mapping(item, family))
        return cls(scenarios=tuple(loaded))

    def all(self) -> tuple[Scenario, ...]:
        return self.scenarios

    def families(self) -> set[str]:
        return {s.family for s in self.scenarios}

    def by_family(self, family: str) -> tuple[Scenario, ...]:
        return tuple(s for s in self.scenarios if s.family == family)

    def filter(
        self,
        *,
        family: str | None = None,
        max_difficulty: int | None = None,
        min_difficulty: int | None = None,
        skill_family: str | None = None,
    ) -> tuple[Scenario, ...]:
        selected = self.scenarios
        if family is not None:
            selected = tuple(s for s in selected if s.family == family)
        if min_difficulty is not None:
            selected = tuple(s for s in selected if s.difficulty >= min_difficulty)
        if max_difficulty is not None:
            selected = tuple(s for s in selected if s.difficulty <= max_difficulty)
        if skill_family is not None:
            selected = tuple(s for s in selected if skill_family in s.skill_families)
        return selected

    def get(self, scenario_id: str) -> Scenario:
        return self._by_id[scenario_id]
