"""Advisory coverage packs for vulnerability classes without validators (v80, Task 2).

Every pack stays honestly labelled ``missing-validator`` until a real
proof bundle exists for that class on a real engagement. Packs describe
what to probe for and what oracle would count as proof; they never ship
executable payloads and never let the engine promote their output to
findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.hunt_contracts import redact

MAX_PACK_SEEDS = 4
# Zero-evidence advisory seeds must not outrank proof-history intel seeds
# (0.5-0.75) or real hypotheses; they rank at or below 0.5 (critique CR-1).
SEED_PRIORITY_CAP = 0.5


@dataclass(frozen=True)
class CoveragePack:
    """An advisory probe agenda for one uncovered class."""

    class_label: str
    probes: tuple[str, ...]
    required_oracles: tuple[str, ...]
    status: str = "missing-validator"
    notes: str = ""
    hypotheses: tuple[str, ...] = field(default_factory=tuple)


PACKS: dict[str, CoveragePack] = {
    "ssti": CoveragePack(
        class_label="ssti",
        probes=(
            "template-context markers reflected on error pages and rendered fields",
            "engine fingerprint strings in responses to malformed template input",
        ),
        required_oracles=(
            "engine-specific fingerprint response reproduced on replay",
            "rendered output distinct from the input string under a controlled probe",
        ),
        notes="Template engines differ; a class oracle must pin the engine first.",
        hypotheses=(
            "user-controlled text reaches a template render context",
            "error pages render raw user input through the template engine",
        ),
    ),
    "xxe": CoveragePack(
        class_label="xxe",
        probes=(
            "XML-accepting endpoints (SOAP, RSS, SVG upload, SAML) and their content types",
            "parser error messages that echo document structure",
        ),
        required_oracles=(
            "out-of-band callback or file-content oracle reproduced on replay",
            "parser behaviour difference between controlled documents",
        ),
        notes=(
            "Blind variants need an out-of-band oracle; "
            "local file read alone is not a claim."
        ),
        hypotheses=(
            "XML parsers resolve external entities on user-supplied documents",
            "DTD processing is enabled on an XML-accepting endpoint",
        ),
    ),
    "ssrf": CoveragePack(
        class_label="ssrf",
        probes=(
            "URL-accepting parameters (importers, webhooks, fetchers, avatar loaders)",
            "endpoints that report fetch results or errors from a server-side request",
        ),
        required_oracles=(
            "out-of-band callback from the target's network position",
            "differential response between an internal and an external destination",
        ),
        notes=(
            "DNS rebinding and redirect tricks belong to a later pack; "
            "this pack only finds the surface."
        ),
        hypotheses=(
            "a server-side fetch uses a user-controlled destination",
            "metadata or internal services are reachable from a fetch endpoint",
        ),
    ),
    "backup_files": CoveragePack(
        class_label="backup_files",
        probes=(
            "predictable backup/editor artefact paths next to known application files",
            "directory listings and error differentials on candidate paths",
        ),
        required_oracles=(
            "fetched artefact with recognizable source content, reproduced on replay",
            "response that confirms the artefact exists and returns readable content",
        ),
        notes=(
            "Probe lists stay advisory; the oracle must return real source bytes, "
            "not a 404/403 differential alone."
        ),
        hypotheses=(
            "deployed backups or editor swap files are publicly fetchable",
            "vcs metadata directories are exposed on the web root",
        ),
    ),
}


def pack_ledger_entries(seen_classes: set[str] | None = None) -> list[dict[str, Any]]:
    """Coverage-ledger rows for the packed classes, honest by construction.

    A class only leaves ``missing-validator`` status through a real proof
    bundle recorded elsewhere in the state; the ledger rows here never
    upgrade themselves.
    """
    seen = {redact(str(item or "")).strip().lower() for item in (seen_classes or set())}
    rows: list[dict[str, Any]] = []
    for label in sorted(PACKS):
        pack = PACKS[label]
        covered = label in seen
        rows.append(
            {
                "class": pack.class_label,
                "status": "missing-validator" if not covered else "validated-by-bundle",
                "probes_advisory": list(pack.probes),
                "required_oracles": list(pack.required_oracles),
                "notes": pack.notes,
            }
        )
    return rows


def pack_hypothesis_seeds(cap: int = MAX_PACK_SEEDS) -> list[dict[str, Any]]:
    """Advisory seeds reminding the planner of the uncovered surface."""
    seeds: list[dict[str, Any]] = []
    for label in sorted(PACKS):
        pack = PACKS[label]
        if len(seeds) >= cap:
            break
        seeds.append(
            {
                "vuln_class": pack.class_label,
                "priority": SEED_PRIORITY_CAP,
                "rationale": (
                    "no validator coverage yet for this class; "
                    f"pack probes: {pack.probes[0]}"
                ),
                "source": "coverage_pack",
                "advisory": True,
            }
        )
    return seeds
