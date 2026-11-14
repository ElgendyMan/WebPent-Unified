"""THE ORACLE — U-ORACLE-2, the Stack Inferrer (v88).

Turns gathered OSINT evidence into a technology-stack profile and a
candidate attack-vector list, using only static signature rules
(ORACLE-L-6: the graph is built from confirmed data — here, from
confirmed evidence). No request is ever made: CVE enrichment comes from
the static `config/oracle/attack_signatures.yaml` map.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport


@dataclass
class Component:
    name: str
    version: str | None
    confidence: float
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "confidence": round(self.confidence, 3),
            "evidence_sources": sorted(set(self.evidence_sources)),
        }


@dataclass
class ComponentCVE:
    cve: str
    severity: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "severity": self.severity,
            "summary": self.summary,
        }


@dataclass
class AttackVector:
    component: str
    vector: str
    basis: str  # which evidence suggested this component

    def to_dict(self) -> dict[str, Any]:
        return {"component": self.component, "vector": self.vector,
                "basis": self.basis}


@dataclass
class TechStackProfile:
    target_id: str
    components: list[Component] = field(default_factory=list)
    inference_sources: list[str] = field(default_factory=list)
    cves: dict[str, list[ComponentCVE]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "components": [c.to_dict() for c in self.components],
            "inference_sources": sorted(set(self.inference_sources)),
            "cves": {k: [c.to_dict() for c in v]
                     for k, v in self.cves.items()},
        }


def _load(path: Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for key in ("inference_rules", "cve_map", "attack_vectors"):
        if key not in data:
            raise OracleLawError(
                f"attack_signatures.yaml missing section {key!r}"
            )
    return data


class StackInferrer:
    def __init__(self, signatures_path: Path) -> None:
        self._sig = _load(Path(signatures_path))
        self._rules = self._sig["inference_rules"]
        self._cve_map = self._sig["cve_map"]
        self._vectors = self._sig["attack_vectors"]

    # -- inference ---------------------------------------------------------

    def infer(self, report: OsintReport) -> TechStackProfile:
        profile = TechStackProfile(target_id=report.target_id)
        candidates: dict[tuple[str, str | None], Component] = {}
        for finding in report.findings:
            haystack = json.dumps(finding.raw_data, default=str).lower()
            for rule in self._rules:
                if rule.get("category") != finding.category:
                    continue
                if not any(
                    str(k).lower() in haystack for k in rule.get("keywords", [])
                ):
                    continue
                name = str(rule["infers"])
                version = self._extract_version(name, haystack)
                key = (name, version)
                rule_conf = float(rule.get("confidence", 0.5))
                contrib = rule_conf * finding.confidence
                comp = candidates.get(key)
                if comp is None:
                    candidates[key] = Component(
                        name=name,
                        version=version,
                        confidence=contrib,
                        evidence_sources=[finding.source],
                    )
                else:
                    comp.confidence = min(0.95, comp.confidence + contrib / 2)
                    comp.evidence_sources.append(finding.source)
        profile.components = sorted(
            candidates.values(),
            key=lambda c: (-c.confidence, c.name, c.version or ""),
        )
        profile.inference_sources = [
            f.source for f in report.findings
        ]
        return profile

    @staticmethod
    def _extract_version(name: str, haystack: str) -> str | None:
        import re

        pattern = re.escape(name) + r"[ /:=]*v?(\d+(?:\.\d+){0,2})"
        match = re.search(pattern, haystack)
        return match.group(1) if match else None

    # -- CVE enrichment (static map only, ORACLE-L-1) --------------------------

    def enrich_with_cves(self, profile: TechStackProfile) -> TechStackProfile:
        for comp in profile.components:
            entries: list[dict] = []
            versions = [comp.version, "*"] if comp.version else ["*"]
            for version in versions:
                by_name = self._cve_map.get(comp.name, {})
                entries.extend(by_name.get(version, []) or [])
            if entries:
                profile.cves[comp.name] = [
                    ComponentCVE(
                        cve=str(e["cve"]),
                        severity=str(e.get("severity", "unknown")),
                        summary=str(e.get("summary", "")),
                    )
                    for e in entries
                ]
        return profile

    # -- cross reference ----------------------------------------------------------

    def cross_reference(
        self, profile: TechStackProfile, evidence_basis: str = "stack profile"
    ) -> list[AttackVector]:
        vectors: list[AttackVector] = []
        for comp in profile.components:
            for vector in self._vectors.get(comp.name, []):
                vectors.append(
                    AttackVector(
                        component=comp.name,
                        vector=str(vector),
                        basis=evidence_basis,
                    )
                )
        return vectors


__all__ = [
    "AttackVector",
    "Component",
    "ComponentCVE",
    "StackInferrer",
    "TechStackProfile",
    "OsintFinding",
]
