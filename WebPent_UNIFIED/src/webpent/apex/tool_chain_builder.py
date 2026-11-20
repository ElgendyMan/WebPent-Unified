"""The Apex Predator — U-APEX-4, the Tool Chain Builder (v87).

Turns a hypothesis type into an ordered, dependency-linked chain of
registered vetted tools (APEX-L-1, APEX-L-2). Chains are frozen plans:
deterministic for identical inputs, advisory in nature (APEX-L-9), and
their dependency graph is exactly what the parallel runner exploits
(APEX-L-5). Unknown hypothesis types fall back to a declared recon chain
with a stated reason — never a silent guess.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from webpent.apex.tool_registry import ToolRegistry

PREAMBLE_LINE = (
    "advisory: chains are executable plans for vetted tools, gated by scope "
    "and operator approval; nothing here runs on its own."
)

#: deterministic per-speed tier estimates used for planning metrics only
SPEED_SECONDS = {"fast": 30.0, "medium": 120.0, "slow": 600.0}
SPEED_REQUESTS = {"fast": 500, "medium": 2000, "slow": 10000}




@dataclass
class ChainStep:
    """One tool invocation inside a chain."""

    tool_id: str
    capability: str
    after: list[str] = field(default_factory=list)
    step_id: str = ""


@dataclass
class ToolChain:
    """A frozen, deterministic plan of tool steps for one hypothesis."""

    chain_id: str
    hypothesis_type: str
    target: str
    steps: list[ChainStep] = field(default_factory=list)
    advisory_note: str = PREAMBLE_LINE
    fallback_reason: str = ""
    registry: ToolRegistry | None = None

    def independent_steps(self) -> list[ChainStep]:
        """Steps with no dependency — the parallel runner's starting set."""
        return [s for s in self.steps if not s.after]

    def optimize(self) -> ToolChain:
        """Drop duplicate tool steps and orphaned dependents (steps whose
        parents no longer exist). Deterministic; keeps first occurrences."""
        seen: set[str] = set()
        kept: list[ChainStep] = []
        for step in self.steps:
            if step.tool_id in seen:
                continue
            seen.add(step.tool_id)
            kept.append(step)
        known_ids = {s.step_id for s in kept}
        live = [
            s for s in kept
            if all(parent in known_ids for parent in s.after)
        ]
        # one more pass: re-check with the surviving set until stable
        while True:
            known_ids = {s.step_id for s in live}
            pruned = [
                s for s in live
                if all(parent in known_ids for parent in s.after)
            ]
            if len(pruned) == len(live):
                break
            live = pruned
        return ToolChain(
            chain_id=self.chain_id,
            hypothesis_type=self.hypothesis_type,
            target=self.target,
            steps=live,
            advisory_note=self.advisory_note,
            fallback_reason=self.fallback_reason,
            registry=self.registry,
        )

    def estimated_duration_seconds(
        self, registry: ToolRegistry | None = None
    ) -> float:
        reg = registry or self.registry
        if reg is None:
            raise ValueError("chain estimates need a registry")
        total = 0.0
        for step in self.steps:
            spec = reg.get(step.tool_id)
            total += SPEED_SECONDS.get(spec.speed, 120.0)
        return total

    def estimated_requests(self, registry: ToolRegistry | None = None) -> int:
        reg = registry or self.registry
        if reg is None:
            raise ValueError("chain estimates need a registry")
        total = 0
        for step in self.steps:
            spec = reg.get(step.tool_id)
            total += SPEED_REQUESTS.get(spec.speed, 2000)
        return total

    def to_dict(self, registry: ToolRegistry | None = None) -> dict:
        data = {
            "chain_id": self.chain_id,
            "hypothesis_type": self.hypothesis_type,
            "target": self.target,
            "fallback_reason": self.fallback_reason,
            "advisory_note": self.advisory_note,
            "steps": [
                {
                    "step_id": s.step_id,
                    "tool_id": s.tool_id,
                    "capability": s.capability,
                    "after": list(s.after),
                }
                for s in self.steps
            ],
            "estimated_duration_seconds": self.estimated_duration_seconds(
                registry
            ),
            "estimated_requests": self.estimated_requests(registry),
        }
        return data


class ToolChainBuilder:
    """Instantiate chain templates from config per hypothesis + target."""

    def __init__(
        self,
        templates: dict,
        registry: ToolRegistry,
        config_digest: str = "",
    ) -> None:
        self._templates = templates
        self._registry = registry
        self._config_digest = config_digest

    @classmethod
    def load(cls, chains_path: Path, registry: ToolRegistry) -> ToolChainBuilder:
        if not chains_path.is_file():
            raise FileNotFoundError(f"chains file not found: {chains_path}")
        try:
            raw = yaml.safe_load(chains_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"broken chains yaml: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("chains"), dict):
            raise ValueError("chains yaml must map 'chains' to a mapping")
        templates = dict(raw["chains"])
        if isinstance(raw.get("fallback"), dict):
            templates["fallback"] = raw["fallback"]
        # RT-04: the fingerprint covers the config source bytes, so any
        # edit to the chains file moves every derived chain id.
        config_digest = hashlib.sha256(chains_path.read_bytes()).hexdigest()
        return cls(templates, registry, config_digest=config_digest)

    def list_hypothesis_types(self) -> list[str]:
        return sorted(self._templates)

    def build(self, hypothesis_type: str, target: str) -> ToolChain:
        template = self._templates.get(hypothesis_type)
        fallback_reason = ""
        effective_type = hypothesis_type
        if template is None:
            template = self._templates.get(
                "fallback",
                {"steps": [{"tool_id": "subfinder", "capability": "subdomain_enum"}]},
            )
            effective_type = "fallback"
            fallback_reason = (
                f"no chain template for hypothesis type {hypothesis_type!r}; "
                "using the declared recon fallback"
            )
        steps = []
        for index, s in enumerate(template["steps"], start=1):
            steps.append(
                ChainStep(
                    tool_id=s["tool_id"],
                    capability=s["capability"],
                    after=list(s.get("after", [])),
                    step_id=f"{s['tool_id']}-{index}",
                )
            )
        # validate every step's tool is registered (APEX-L-2: vetted only)
        for step in steps:
            if not self._registry.has(step.tool_id):
                raise ValueError(
                    f"chain step references unregistered tool {step.tool_id!r}"
                )
        # RT-04: the id must move when the config moves, so a rebuilt plan
        # can never silently replace the plan behind an existing run record.
        # Determinism is preserved: same inputs → same id (RT-04 test 1).
        config_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "hyp": hypothesis_type,
                    "steps": template["steps"],
                    "cfg": self._config_digest,
                    "tools": sorted(
                        t.id for t in self._registry.list_tools()
                    ),
                },
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:8]
        chain_seed = f"{hypothesis_type}|{target}|{config_fingerprint}"
        chain_id = "chain-" + hashlib.sha256(
            chain_seed.encode("utf-8")
        ).hexdigest()[:12]
        return ToolChain(
            chain_id=chain_id,
            hypothesis_type=effective_type,
            target=target,
            steps=steps,
            fallback_reason=fallback_reason,
            registry=self._registry,
        )
