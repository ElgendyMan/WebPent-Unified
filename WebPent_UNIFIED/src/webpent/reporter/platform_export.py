# src/webpent/reporter/platform_export.py
"""Platform report export (PROPOSALS_ULTIMATE_V3 §6, 2026-11-01).

Renders a Finding as paste-ready Markdown in the section structure the
three bounty platforms expect (HackerOne, Bugcrowd, Intigriti), and
optionally wraps that report plus the finding's existing evidence-bundle
ZIP into one deliverable ZIP.

Honesty contracts, stated up front:
- NO platform API calls, ever. This module owns no network transport:
  it produces text (and a zip of text/bytes it was handed). The operator
  pastes the report into the platform themselves — no access tokens for
  any third party exist in this path.
- A field the finding does not carry is rendered as an explicit
  ``missing: <field>`` marker. It is NEVER invented, estimated or
  defaulted: a missing CVSS vector is reported as missing, not guessed
  from the severity bucket.
- Every step in "Steps to Reproduce" is derived from data the finding
  actually carries (URL, method, form data, target parameter, payload).
  Nothing narrative is added.
- Unknown platforms fail closed: ``platform_export_unsupported``.

Flag-gated via ``enable_platform_export`` (default False) — read-only,
but it keeps one uniform gate pattern across every §-module.

All functions are deterministic for the same inputs: same finding + same
platform → byte-identical markdown.
"""

from __future__ import annotations

import io
import zipfile
from typing import Any, Mapping

__all__ = [
    "PLATFORMS",
    "PlatformExportError",
    "export_bundle_zip",
    "export_finding",
    "platform_export_refusal",
]

PLATFORMS = ("hackerone", "bugcrowd", "intigriti")

# Per-platform section vocabulary. Values are the exact headers each
# platform's report form expects; title heading is h1, sections h2.
_TEMPLATES: dict[str, dict[str, str]] = {
    "hackerone": {
        "steps": "Steps To Reproduce",
        "impact": "Impact",
        "attachments": "Attachments",
        "description": "Description",
    },
    "bugcrowd": {
        "steps": "Steps to Reproduce",
        "impact": "Impact",
        "attachments": "Attachments",
        "description": "Description",
    },
    "intigriti": {
        "steps": "Steps to reproduce",
        "impact": "Impact",
        "attachments": "Attachments",
        "description": "Description",
    },
}

_MISSING = "missing: {}"


class PlatformExportError(ValueError):
    """Raised when an export cannot be produced within its contracts."""


def platform_export_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_platform_export:
        return "platform_export_flag_off"
    return None


def _finding_mapping(finding: Any) -> Mapping[str, Any]:
    if isinstance(finding, Mapping):
        return finding
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    raise PlatformExportError("platform_export_input_type_invalid")


def _template(platform: str) -> dict[str, str]:
    if platform not in _TEMPLATES:
        raise PlatformExportError("platform_export_unsupported")
    return _TEMPLATES[platform]


def _missing(value: Any) -> str:
    text = str(value).strip() if value is not None else ""
    return text if text else _MISSING.format("unknown")


def _steps(data: Mapping[str, Any]) -> list[str]:
    """Numbered steps derived ONLY from fields the finding carries."""
    steps: list[str] = []
    url = str(data.get("url") or "").strip()
    method = str(data.get("request_method") or "GET").strip()
    if url:
        steps.append(f"Navigate to `{url}`.")
    else:
        steps.append(_MISSING.format("url"))

    target_param = str(data.get("target_param") or "").strip()
    if target_param:
        steps.append(f"Locate the affected parameter `{target_param}`.")

    request_data = data.get("request_data") or {}
    if isinstance(request_data, Mapping) and request_data:
        rendered = ", ".join(f"`{k}`" for k in sorted(request_data))
        steps.append(f"Submit the request with fields: {rendered}.")

    payload = str(data.get("payload") or "").strip()
    if payload:
        steps.append(
            "Send the payload:\n\n"
            "```\n"
            f"{payload}\n"
            "```\n"
        )
    else:
        steps.append(_MISSING.format("payload"))
    return steps


def _cvss_cell(data: Mapping[str, Any]) -> str:
    cvss = str(data.get("cvss_score") or "").strip()
    if not cvss:
        return _MISSING.format("cvss_vector")
    return cvss


def export_finding(finding: Any, platform: str) -> str:
    """Render one Finding as platform-native paste-ready Markdown.

    Deterministic; contains no invented values — anything the finding
    does not carry is rendered as ``missing: <field>``.

    M1-B (E-3, 2026-11-05): a ``Tool-Confirmed`` finding is a VERIFIED
    claim shipped to a third-party platform triager — the strict report
    quality gate is enforced for exactly that class before export
    (hypothesis, evidence, reproduction, business impact, CVSS must all
    be present; the sealed bundle was already enforced at confirmation
    time by verify_replay_evidence + the model-level provenance rule).
    Non-confirmed findings keep the honest-marker contract (``missing:``
    fields are rendered, never invented) — they are not confirmed claims.
    """
    if platform_export_refusal() is not None:
        raise PlatformExportError("platform_export_flag_off")
    tpl = _template(platform)
    data = _finding_mapping(finding)

    title = str(data.get("title") or "").strip()
    if not title:
        raise PlatformExportError("platform_export_missing_title")

    if str(data.get("confidence_level") or "") == "Tool-Confirmed":
        from webpent.shared.report_quality import (
            ReportQualityGateError,
            enforce_report_quality,
        )

        try:
            enforce_report_quality([finding], require_proof_bundle=False)
        except ReportQualityGateError as exc:
            raise PlatformExportError(
                "platform_export_quality_gate: "
                + "; ".join(
                    f"{item.finding_id or '<unknown>'}: "
                    + ", ".join(item.blocking_issues)
                    for item in exc.result.findings
                    if item.blocking_issues
                )
            ) from exc

    lines: list[str] = [f"# {title}", ""]
    lines.append(f"**Severity:** {data.get('severity', _MISSING.format('severity'))}")
    lines.append(f"**CVSS:** {_cvss_cell(data)}")
    url = str(data.get("url") or "").strip()
    lines.append(f"**URL:** {_missing(url)}")
    vuln_class = data.get("vuln_class")
    lines.append(f"**Vulnerability class:** {_missing(vuln_class)}")
    lines.append("")
    lines.append(f"## {tpl['description']}")
    lines.append("")
    lines.append(str(data.get("description") or _MISSING.format("description")).strip())
    lines.append("")
    lines.append(f"## {tpl['steps']}")
    lines.append("")
    for i, step in enumerate(_steps(data), start=1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append(f"## {tpl['impact']}")
    lines.append("")
    impact = str(data.get("business_impact") or "").strip()
    if not impact:
        # fall back to the finding's own description-based impact ONLY if
        # explicitly present; otherwise the marker — never prose we wrote
        impact = str(data.get("reasoning") or "").strip() or _MISSING.format(
            "business_impact"
        )
    lines.append(impact)
    lines.append("")
    lines.append(f"## {tpl['attachments']}")
    lines.append("")
    lines.append(
        "evidence-bundle.zip (HAR reconstruction, browser-proof digests, "
        "poc.sh, cvss.json) — assembled by `webpent.reporter."
        "evidence_bundle`; attached as a file, no platform API used."
    )
    lines.append("")
    return "\n".join(lines)


def export_bundle_zip(finding: Any, bundle_zip_bytes: bytes, platform: str) -> bytes:
    """Wrap the export report and an existing evidence ZIP into one ZIP.

    The bundle bytes are copied entry-for-entry unchanged; the report is
    added as ``report.md``. No platform API call occurs here either.
    """
    report = export_finding(finding, platform)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("report.md", report)
        with zipfile.ZipFile(io.BytesIO(bundle_zip_bytes)) as inner:
            for name in inner.namelist():
                out.writestr(name, inner.read(name))
    return buf.getvalue()
