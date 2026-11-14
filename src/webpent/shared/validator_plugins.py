"""Validator plugin contracts and bounded capability accounting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

from webpent.agents.validator.registry import validator_id_for
from webpent.shared.campaigns import GENERIC_CAMPAIGNS

PluginStage = Literal[
    "discover",
    "prepare_state",
    "execute_probe",
    "collect_oracle",
    "classify_evidence",
    "cleanup",
    "render_finding",
]

PLUGIN_STAGES: Final[tuple[PluginStage, ...]] = (
    "discover",
    "prepare_state",
    "execute_probe",
    "collect_oracle",
    "classify_evidence",
    "cleanup",
    "render_finding",
)


@dataclass(frozen=True)
class ValidatorPluginSpec:
    """Declarative plugin capability; it does not execute a probe."""

    plugin_id: str
    campaign_key: str
    vuln_class: str
    validator_id: str | None
    stages: tuple[PluginStage, ...]
    evidence_schema: str
    report_renderer: str
    evidence_mode: str = "deterministic"
    preconditions: tuple[str, ...] = ()
    action_plan: tuple[str, ...] = ()
    baseline: str = ""
    negative_control: str = ""
    causal_oracle: str = ""
    cleanup: str = ""
    proof_schema: str = ""
    replay_function: str = ""
    confidence_policy: str = ""

    @property
    def complete(self) -> bool:
        return (
            bool(self.plugin_id)
            and bool(self.campaign_key)
            and bool(self.vuln_class)
            and self.stages == PLUGIN_STAGES
            and bool(self.evidence_schema)
            and bool(self.report_renderer)
            and bool(self.preconditions)
            and bool(self.action_plan)
            and bool(self.baseline)
            and bool(self.negative_control)
            and bool(self.causal_oracle)
            and bool(self.cleanup)
            and bool(self.proof_schema)
            and bool(self.replay_function)
            and bool(self.confidence_policy)
        )


def build_validator_plugin_registry(
    campaigns: Iterable[Mapping[str, Any]] | None = None,
) -> tuple[ValidatorPluginSpec, ...]:
    """Build plugin contracts for the selected inventory.

    The default is target-neutral. Vertical inventories must be supplied
    explicitly so a planner cannot silently inherit target-specific metadata.
    """
    selected_campaigns = GENERIC_CAMPAIGNS if campaigns is None else campaigns
    plugins: list[ValidatorPluginSpec] = []
    for campaign in selected_campaigns:
        campaign_key = str(campaign.get("key", "")).strip()
        if not campaign_key:
            continue
        validator_value = campaign.get("validator")
        vuln_class = str(validator_value or campaign_key)
        injected_validator_id = campaign.get("validator_id")
        if validator_value is None:
            registered_id = None
        elif injected_validator_id:
            registered_id = str(injected_validator_id)
        else:
            registered_id = validator_id_for(vuln_class)
        plugins.append(
            ValidatorPluginSpec(
                plugin_id=f"campaign:{campaign_key}",
                campaign_key=campaign_key,
                vuln_class=vuln_class,
                validator_id=registered_id,
                stages=PLUGIN_STAGES,
                evidence_schema="EvidenceLedgerEntry:v1",
                report_renderer="finding_renderer:v1",
                evidence_mode="deterministic" if registered_id else "human-review",
                preconditions=("in_scope_target", "authorized_execution"),
                action_plan=("baseline", "negative_control", "causal_probe", "replay"),
                baseline="paired_baseline_observation",
                negative_control="paired_negative_control_observation",
                causal_oracle="deterministic_validator_oracle",
                cleanup="bounded_cleanup_or_explicit_not_applicable",
                proof_schema="ProofBundle:v1",
                replay_function="replay_from_sealed_bundle",
                confidence_policy=(
                    "tool_confirmed_only_with_causal_signal_negative_control_sealed_proof_and_replay"
                ),
            )
        )
    return tuple(plugins)


def plugin_capability_gaps(
    plugins: tuple[ValidatorPluginSpec, ...] | None = None,
) -> list[dict[str, str]]:
    """Return explicit gaps; never silently route incomplete classes."""
    selected_plugins = build_validator_plugin_registry() if plugins is None else plugins
    gaps: list[dict[str, str]] = []
    for plugin in selected_plugins:
        if not plugin.complete:
            gaps.append({"plugin_id": plugin.plugin_id, "reason": "incomplete-contract"})
        if plugin.evidence_mode == "human-review":
            gaps.append(
                {
                    "plugin_id": plugin.plugin_id,
                    "reason": "missing-deterministic-validator",
                }
            )
    return gaps


__all__ = [
    "PLUGIN_STAGES",
    "ValidatorPluginSpec",
    "build_validator_plugin_registry",
    "plugin_capability_gaps",
]
