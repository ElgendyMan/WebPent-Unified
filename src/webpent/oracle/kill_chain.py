"""THE ORACLE — U-ORACLE-7, the Kill Chain Simulator (v88).

Walks a chain proposal through seven simulated phases. The simulation
runs entirely against evidence already gathered: it issues no requests,
executes nothing, and exists to tell the operator where a hypothesis
would stand or fall (ORACLE-L-1/L-2/L-10). Abort points come from
config/oracle/kill_chain.yaml, not from code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.chain_composer import ChainProposal
from webpent.oracle.graph_builder import AttackGraph
from webpent.oracle.models import OracleLawError


@dataclass
class PhaseOutcome:
    phase_id: str
    name: str
    status: str                     # "passed" | "aborted"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class SimulationTrace:
    proposal_id: str
    phases: list[PhaseOutcome] = field(default_factory=list)
    completed: bool = False
    abort_phase: str = ""
    abort_reason: str = ""
    executed: bool = False          # ORACLE-L-10: always False, by design

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "phases": [p.to_dict() for p in self.phases],
            "completed": self.completed,
            "abort_phase": self.abort_phase,
            "abort_reason": self.abort_reason,
            "executed": self.executed,
        }


class KillChainSimulator:
    def __init__(self, kill_chain_path: Path) -> None:
        data = yaml.safe_load(
            Path(kill_chain_path).read_text(encoding="utf-8")
        ) or {}
        phases = data.get("phases")
        if not phases or not isinstance(phases, list):
            raise OracleLawError(
                "kill_chain.yaml missing a non-empty 'phases' list"
            )
        self._phases: list[dict] = []
        for phase in phases:
            for key in ("phase_id", "name", "min_confidence", "abort_reason"):
                if key not in phase:
                    raise OracleLawError(
                        f"kill-chain phase missing {key!r}"
                    )
            conf = float(phase["min_confidence"])
            if not 0.0 <= conf <= 1.0:
                raise OracleLawError(
                    f"phase {phase['phase_id']}: min_confidence must be "
                    f"within [0, 1]"
                )
            self._phases.append(phase)
        if len(self._phases) != 7:
            raise OracleLawError(
                f"kill chain must define exactly 7 phases, got "
                f"{len(self._phases)}"
            )
        self._halt_on_first = bool(
            data.get("abort_policy", {}).get("halt_on_first", True)
        )

    # -- evidence helpers -------------------------------------------------------

    def _evidence_confidence(
        self, graph: AttackGraph, proposal: ChainProposal
    ) -> float:
        nodes = [
            graph.nodes[n] for n in proposal.nodes if n in graph.nodes
        ]
        if not nodes:
            return 0.0
        return sum(n.confidence for n in nodes) / len(nodes)

    def _phase_confidence(self, index: int, base: float) -> float:
        """Later phases demand more of the same evidence: the base
        confidence decays as the chain stretches beyond what the graph
        actually holds."""
        decay = 1.0 - 0.03 * index
        return base * max(decay, 0.5)

    # -- public surface ----------------------------------------------------------

    def simulate(
        self, graph: AttackGraph, proposal: ChainProposal
    ) -> SimulationTrace:
        trace = SimulationTrace(proposal_id=proposal.proposal_id)
        base = self._evidence_confidence(graph, proposal)
        for index, phase in enumerate(self._phases):
            floor = float(phase["min_confidence"])
            confidence = self._phase_confidence(index, base)
            if confidence >= floor:
                trace.phases.append(
                    PhaseOutcome(
                        phase_id=phase["phase_id"],
                        name=phase["name"],
                        status="passed",
                        detail=(
                            f"evidence confidence {confidence:.2f} clears "
                            f"the {floor:.2f} floor"
                        ),
                    )
                )
                continue
            trace.phases.append(
                PhaseOutcome(
                    phase_id=phase["phase_id"],
                    name=phase["name"],
                    status="aborted",
                    detail=phase["abort_reason"],
                )
            )
            trace.abort_phase = phase["phase_id"]
            trace.abort_reason = phase["abort_reason"]
            if self._halt_on_first:
                return trace
        trace.completed = True
        return trace


__all__ = ["KillChainSimulator", "PhaseOutcome", "SimulationTrace"]
