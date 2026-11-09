"""The Dojo operator commands (v85, U-DOJO-12).

``webpent dojo`` is the console of the self-training environment: every
command runs against the deterministic simulated labs only — zero network,
zero real targets, zero campaign state (L-1, L-10). Each command prints the
preamble line first (L-8), appends to the capped audit log (L-2), and
reports measured numbers only (L-5, L-6).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated

import typer

from webpent.dojo.case_study import CaseStudyWriter
from webpent.dojo.defender import DEFENSE_PATTERNS
from webpent.dojo.engine import SimulatedTarget
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_generator import PracticeGenerator
from webpent.dojo.practice_runner import PracticeRunner
from webpent.dojo.progress import ProgressTracker
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.skill_assessor import SkillAssessor
from webpent.dojo.sparring import SparringMatch
from webpent.dojo.tournament import BUILTIN_AGENTS, TournamentRunner
from webpent.dojo.trainer import TrainingSession
from webpent.dojo.weakness_identifier import WeaknessIdentifier

dojo_app = typer.Typer(help="The Dojo: the self-training environment (advisory).")

DojoDir = Annotated[Path | None, typer.Option("--dojo-dir", help="Dojo state directory.")]
Family = Annotated[str | None, typer.Option("--family", help="Filter by scenario family.")]
AgentName = Annotated[str, typer.Option("--agent", help="Built-in agent name.")]
ScenarioId = Annotated[str, typer.Argument(help="Scenario identifier.")]

PREAMBLE_LINE = (
    "advisory: Dojo commands run against simulated labs only — no network, "
    "no real targets, no campaign state."
)

_CONFIG_DIR_CANDIDATES = (
    Path("config/dojo/scenarios"),
    Path(__file__).resolve().parents[2] / "config" / "dojo" / "scenarios",
)


def _library() -> ScenarioLibrary:
    for candidate in _CONFIG_DIR_CANDIDATES:
        if candidate.is_dir():
            return ScenarioLibrary.load_dir(candidate)
    raise RuntimeError("dojo scenarios directory not found")


def _tracker(dojo_dir: Path | None) -> ProgressTracker:
    return ProgressTracker(dojo_dir)


def _rehydrate(entries: list[dict]):
    """PracticeResults from ledger entries, honoring every recorded metric.

    Old-format entries (RT-06) carry only scenario_id/score/success; those
    load with zeroed efficiency metrics rather than being dropped (L-7).
    """
    from webpent.dojo.practice_runner import PracticeResult

    return [
        PracticeResult(
            scenario_id=entry["scenario_id"],
            success=entry["success"],
            score=entry["score"],
            requests_used=int(entry.get("requests_used", 0)),
            false_positives=int(entry.get("false_positives", 0)),
            time_steps=int(entry.get("time_steps", 0)),
            budget=int(entry.get("budget", 0)),
        )
        for entry in entries
    ]


def _emit(message: str) -> None:
    typer.echo(PREAMBLE_LINE)
    typer.echo(message)


def _record_and_audit(
    tracker: ProgressTracker, command: str, entry: dict, detail: str = ""
) -> None:
    tracker.record({"command": command, "ts": time.time(), **entry})
    tracker.audit(command, detail)


@dojo_app.command("labs")
def labs_cmd(dojo_dir: DojoDir = None) -> None:
    """List the deterministic lab templates (L-1/L-4)."""
    generator = LabGenerator()
    templates = [
        {"template_id": t.template_id, "family": t.family}
        for t in generator.list_available()
    ]
    _emit(json.dumps({"templates": templates}, indent=2, sort_keys=True))
    _tracker(dojo_dir).audit("labs")


@dojo_app.command("scenarios")
def scenarios_cmd(
    family: Family = None,
    dojo_dir: DojoDir = None,
) -> None:
    """List the training scenarios, optionally by family (L-3 surface only)."""
    library = _library()
    chosen = library.by_family(family) if family else library.all()
    payload = [
        {
            "scenario_id": s.scenario_id,
            "family": s.family,
            "difficulty": s.difficulty,
            "request_budget": s.request_budget,
        }
        for s in chosen
    ]
    _emit(json.dumps({"scenarios": payload}, indent=2, sort_keys=True))
    _tracker(dojo_dir).audit("scenarios", family or "")


@dojo_app.command("practice")
def practice_cmd(
    scenario_id: ScenarioId,
    agent: AgentName = "adaptive",
    dojo_dir: DojoDir = None,
) -> None:
    """Run one practice session of a built-in agent on a scenario (L-3/L-6)."""
    library = _library()
    runner = PracticeRunner()
    result = runner.run(BUILTIN_AGENTS[agent], library.get(scenario_id))
    payload = result.as_dict()
    _emit(json.dumps(payload, indent=2, sort_keys=True))
    _record_and_audit(
        _tracker(dojo_dir), "practice",
        result.as_dict(),
        detail=agent,
    )


@dojo_app.command("spar")
def spar_cmd(
    scenario_id: ScenarioId,
    agent: AgentName = "adaptive",
    dojo_dir: DojoDir = None,
) -> None:
    """Run one red-vs-blue match on a scenario (L-6, L-7)."""
    library = _library()
    match = SparringMatch().run(
        BUILTIN_AGENTS[agent], library.get(scenario_id), DEFENSE_PATTERNS
    )
    payload = match.as_dict()
    _emit(json.dumps(payload, indent=2, sort_keys=True))
    _record_and_audit(
        _tracker(dojo_dir), "spar",
        {"scenario_id": match.scenario_id, "winner": match.winner,
         "red_score": match.red_score, "blue_score": match.blue_score},
        detail=agent,
    )


@dojo_app.command("tournament")
def tournament_cmd(family: Family = None, dojo_dir: DojoDir = None) -> None:
    """Run the built-in agents round-robin on same-seed scenarios (L-4)."""
    library = _library()
    chosen = list(library.by_family(family)) if family else list(library.all())
    result = TournamentRunner().round_robin(chosen)
    _emit(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    _record_and_audit(
        _tracker(dojo_dir), "tournament",
        {"scenarios": len(chosen)}, detail=family or "all",
    )


@dojo_app.command("skill")
def skill_cmd(family: Family = None, dojo_dir: DojoDir = None) -> None:
    """Assess skill families from the recorded ledger (L-5)."""
    library = _library()
    tracker = _tracker(dojo_dir)
    results = [
        entry for entry in tracker.history() if entry.get("command") == "practice"
    ]
    practice_results = _rehydrate(results)
    scenarios = list(library.all())
    # R2-dojo-05: SkillAssessor.assess matches scenario.skill_families, so
    # the enumeration must cover those, not scenario.family values, or
    # shipped skill families are silently unsampleable. A user-supplied
    # family override still passes through untouched.
    families = (
        sorted({f for s in scenarios for f in s.skill_families})
        if family is None
        else [family]
    )
    profiles = [
        SkillAssessor().assess(f, practice_results, scenarios).as_dict()
        for f in families
    ]
    _emit(json.dumps({"profiles": profiles}, indent=2, sort_keys=True))
    tracker.audit("skill", family or "")


@dojo_app.command("weaknesses")
def weaknesses_cmd(dojo_dir: DojoDir = None) -> None:
    """Identify weaknesses from the recorded ledger (L-7)."""
    library = _library()
    tracker = _tracker(dojo_dir)
    entries = [
        entry for entry in tracker.history() if entry.get("command") == "practice"
    ]
    practice_results = _rehydrate(entries)
    weaknesses = WeaknessIdentifier().identify(practice_results, list(library.all()))
    _emit(json.dumps(
        {"weaknesses": [w.as_dict() for w in weaknesses]}, indent=2, sort_keys=True
    ))
    tracker.audit("weaknesses")


@dojo_app.command("plan")
def plan_cmd(seed: int = 0, dojo_dir: DojoDir = None) -> None:
    """Generate a training plan from the identified weaknesses (L-7/L-4)."""
    library = _library()
    tracker = _tracker(dojo_dir)
    entries = [
        entry for entry in tracker.history() if entry.get("command") == "practice"
    ]
    practice_results = _rehydrate(entries)
    weaknesses = WeaknessIdentifier().identify(practice_results, list(library.all()))
    plan = PracticeGenerator().generate(weaknesses, library, seed=seed)
    _emit(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
    tracker.audit("plan", str(seed))


@dojo_app.command("case-study")
def case_study_cmd(scenario_id: ScenarioId, dojo_dir: DojoDir = None) -> None:
    """Run a match and export its sanitized case study (L-10)."""
    library = _library()
    tracker = _tracker(dojo_dir)
    scenario = library.get(scenario_id)
    match = SparringMatch().run(
        BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS
    )
    study = CaseStudyWriter.from_match(match, scenario)
    out_path = tracker.dojo_dir / f"case_study_{scenario_id}.md"
    out_path.write_text(study, encoding="utf-8")
    _emit(f"case study written: {out_path}")
    _record_and_audit(
        tracker, "case-study",
        {"scenario_id": scenario_id, "winner": match.winner},
    )


@dojo_app.command("train")
def train_cmd(
    family: Family = None,
    dojo_dir: DojoDir = None,
) -> None:
    """Start a step-by-step training session on a family (L-8, L-3)."""
    library = _library()
    tracker = _tracker(dojo_dir)
    chosen = (
        list(library.by_family(family)) if family
        else list(library.by_family(sorted(library.families())[0]))
    )
    session = TrainingSession(
        library, scenario_ids=[s.scenario_id for s in chosen], dojo_dir=dojo_dir
    )
    typer.echo(session.preamble())
    view = session.present()
    typer.echo(json.dumps({
        "scenario_id": view.scenario_id,
        "title": view.title,
        "difficulty": view.difficulty,
        "request_budget": view.request_budget,
    }, indent=2, sort_keys=True))
    state = session.save()
    typer.echo(f"session state: {state}")
    tracker.audit("train", family or "")


@dojo_app.command("progress")
def progress_cmd(dojo_dir: DojoDir = None) -> None:
    """Report the ledger summary and the measured trend (L-5)."""
    tracker = _tracker(dojo_dir)
    _emit(json.dumps(tracker.summary(), indent=2, sort_keys=True))
    tracker.audit("progress")


@dojo_app.command("status")
def status_cmd(dojo_dir: DojoDir = None) -> None:
    """JSON status of the Dojo: scenarios, ledger, trend, defense set."""
    tracker = _tracker(dojo_dir)
    library = _library()
    status = {
        "advisory": True,
        "offline": True,
        "scenarios": len(library.all()),
        "families": sorted(library.families()),
        "defense_patterns": len(DEFENSE_PATTERNS),
        "agents": sorted(BUILTIN_AGENTS),
        "ledger": tracker.summary(),
        "simulated_target": SimulatedTarget().__class__.__name__,
    }
    _emit(json.dumps(status, indent=2, sort_keys=True))
    tracker.audit("status")


if __name__ == "__main__":  # pragma: no cover
    dojo_app()
