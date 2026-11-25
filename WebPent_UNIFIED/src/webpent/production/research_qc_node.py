"""UM-DR-46 Phase I — the research-QC production node.

Deterministic deficiency reports over the research artifacts (the
hypothesis pool, the lesson records, the experiment plans). QC never
deletes or modifies an artifact — it flags.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["research_qc_node"]


def research_qc_node(state: Any) -> dict[str, Any]:
    """Run the deterministic QC over the research channels."""
    try:
        from webpent.researcher.qc import qc_channel_report

        report = qc_channel_report(state)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("research QC failed (advisory node): %s", exc)
        return {
            "research_qc": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
            },
        }
    report["built"] = True
    report["influence_contract"] = (
        "QC records are deficiency reports for the operator — QC never "
        "deletes, never modifies, never authorizes"
    )
    return {"research_qc": report}
