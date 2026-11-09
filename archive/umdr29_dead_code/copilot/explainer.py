"""Read-only explanation boundary for optional LLM assistance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class LLMExplainer:
    """Produce a deterministic report-safe explanation from local artifacts."""

    def explain(self, artifact: Mapping[str, Any]) -> dict[str, Any]:
        evidence = (
            list(artifact.get("evidence_refs") or [])
            if isinstance(artifact, Mapping)
            else []
        )
        gaps = (
            list(artifact.get("coverage_gaps") or [])
            if isinstance(artifact, Mapping)
            else []
        )
        status = (
            str(artifact.get("status", "unknown"))
            if isinstance(artifact, Mapping)
            else "unknown"
        )
        return {
            "status": status,
            "evidence_refs": [str(item)[:200] for item in evidence[:20]],
            "coverage_gaps": [str(item)[:200] for item in gaps[:20]],
            "claims": [],
            "finding_authority": False,
            "proof_authority": False,
            "execution_authority": False,
        }


__all__ = ["LLMExplainer"]
