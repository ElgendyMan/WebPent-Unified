# src/webpent/reporter/evidence_bundle.py
"""Per-finding evidence bundle assembly (PROPOSALS_ULTIMATE_V2 §7, 2026-10-29).

Turns the framework's existing proof surfaces into one deliverable ZIP per
finding: a HAR reconstructed from the bounded request ledger, browser-proof
digest attestations from ``webpent.shared.browser_proof_runner``, a secret-
free ``poc.sh`` from the chain-v3 reproduction steps, and a ``cvss.json``
carrying the cvss_engine's v3.1 vector.

Honesty contracts, stated up front:
- The HAR is NOT a full capture. The ledger records ``(ts, method, url)``
  only, so every entry carries empty headers/body and a zero status; the
  bundle manifest records this incompleteness explicitly rather than
  dressing the file up as a capture.
- Screenshots are stored by this framework as DIGESTS (fingerprint-before-
  evidence), so the bundle carries the attestations, never image binaries.
- CVSS v4 is not produced by the cvss_engine; ``cvss.json`` records the
  v3.1 vector as-is and says so.
- ``submit_bundle`` implements the human-approval GATE only: it produces a
  platform-neutral JSON payload after both the flag and a recorded human
  approval pass. It performs no network transport itself.

Everything is bounded, deterministic (byte-identical rebuilds for the same
inputs) and fail-closed on the size budget. Flag-gated via
``enable_evidence_bundle`` (default False); the submission path additionally
requires ``enable_external_submission`` AND a recorded human approval.
"""

from __future__ import annotations

import hashlib
import io
import json
import shlex
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

__all__ = [
    "EvidenceBundleError",
    "EvidenceBundleResult",
    "SubmissionRefused",
    "build_cvss_json",
    "build_evidence_bundle",
    "build_poc_sh",
    "build_requests_har",
    "dedupe_findings",
    "maybe_build_evidence_bundle",
    "platform_submission_payload",
    "root_endpoint_of",
    "submit_bundle",
]

HAR_VERSION = "1.2"
BUNDLE_SCHEMA = "webpent.evidence-bundle.v1"
# Ledger rows the HAR can honestly reconstruct from.
_LEDGER_FIELDS = ("ts", "method", "url")
_LEDGER_MISSING = (
    "request headers",
    "request body",
    "response status",
    "response headers",
    "response body",
)
_MAX_LEDGER_ENTRIES = 5_000
_MAX_OBSERVATIONS = 200
_MAX_STEPS = 100
_MAX_CHAINS = 50

# Browser-proof observation fields that may enter the bundle: digest and
# count attestations only, mirroring the runner's own projection allowlist.
_OBSERVATION_FIELDS = (
    "handler_id",
    "handler_version",
    "observation_role",
    "target_fingerprint",
    "request_digest",
    "response_digest",
    "status_code",
    "dom_digest",
    "screenshot_digest",
    "dialog_count",
    "network_event_count",
    "replayable",
)


class EvidenceBundleError(ValueError):
    """Raised when a bundle cannot be assembled within its contracts."""


class SubmissionRefused(PermissionError):
    """Raised when the human-approval gate refuses an external submission."""


@dataclass(frozen=True)
class EvidenceBundleResult:
    """One assembled bundle: ZIP bytes plus the manifest that describes it."""

    zip_bytes: bytes
    manifest: Mapping[str, Any]
    warnings: tuple[str, ...]
    root_endpoint: str


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def _as_mapping(item: Any) -> Mapping[str, Any]:
    if isinstance(item, Mapping):
        return item
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if hasattr(item, "__dict__"):
        return dict(vars(item))
    raise EvidenceBundleError("bundle_input_type_invalid")


def build_requests_har(
    ledger_entries: Sequence[Mapping[str, Any]], *, engagement_id: str = ""
) -> dict[str, Any]:
    """Reconstruct a HAR 1.2 document from bounded request-ledger rows.

    Entries are chronological (the ledger is newest-first). Every entry is
    minimal and honestly marked: no headers, no bodies, no response status
    exist in the ledger, and ``_meta`` says so.
    """
    rows = sorted(
        (_as_mapping(e) for e in ledger_entries),
        key=lambda e: float(e.get("ts") or 0.0),
    )
    entries: list[dict[str, Any]] = []
    for row in rows:
        method = str(row.get("method") or "").upper()
        url = str(row.get("url") or "")
        if not method or not url:
            continue
        entries.append(
            {
                "startedDateTime": _iso(float(row.get("ts") or 0.0)),
                "time": 0,
                "_webpent": {"source": "request_ledger", "complete": False},
                "request": {
                    "method": method,
                    "url": url,
                    "httpVersion": "",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 0,
                    "statusText": "not recorded by request ledger",
                    "httpVersion": "",
                    "headers": [],
                    "cookies": [],
                    "content": {"size": 0, "mimeType": ""},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )
    return {
        "log": {
            "version": HAR_VERSION,
            "creator": {"name": "webpent evidence bundle", "version": BUNDLE_SCHEMA},
            "entries": entries,
            "_meta": {
                "engagement_id": str(engagement_id or ""),
                "ledger_completeness": {
                    "fields_recorded": list(_LEDGER_FIELDS),
                    "fields_missing": list(_LEDGER_MISSING),
                    "warning": (
                        "Reconstructed from the bounded request ledger: "
                        "statistically complete request inventory, NOT a "
                        "full capture. Incomplete by design."
                    ),
                },
            },
        }
    }


def build_poc_sh(steps: Sequence[Any]) -> str:
    """Render chain-v3 reproduction steps as a secret-free shell script."""
    lines = [
        "#!/bin/sh",
        "set -eu",
        "# Secret-free reproduction script (digests only; generated by",
        "# webpent evidence bundle). Review before running.",
        "",
    ]
    for step in steps:
        data = _as_mapping(step)
        number = data.get("number")
        method = str(data.get("method") or "GET").upper()
        url = str(data.get("url") or "")
        description = str(data.get("description") or "")
        if not url:
            continue
        if description:
            lines.append(f"# Step {number or '?'}: {description[:300]}")
        else:
            lines.append(f"# Step {number or '?'}")
        lines.append(
            "curl -sS -o /dev/null -w '%{http_code}\\n' "
            f"-X {shlex.quote(method)} {shlex.quote(url)}"
        )
        lines.append("")
    if len(lines) == 5:
        lines.append("# (no reproduction steps available)")
        lines.append("")
    return "\n".join(lines)


def build_cvss_json(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Carry the cvss_engine's CVSS v3.1 vector; document that v4 is absent."""
    raw = str(finding.get("cvss_score") or "").strip()
    vector = raw.split("|")[0].strip() if raw else ""
    score = raw.split("|")[1].strip() if "|" in raw else ""
    doc: dict[str, Any] = {
        "cvss_version": "3.1",
        "vector": vector or None,
        "base_score": score or None,
        "note": (
            "CVSS v4 is not produced by webpent's cvss_engine; the v3.1 "
            "vector is recorded as-is without reinterpretation."
        ),
    }
    if not vector:
        doc["warning"] = "no CVSS vector available for this finding"
    return doc


def root_endpoint_of(
    finding: Mapping[str, Any],
    chains: Sequence[Sequence[Mapping[str, Any]]] = (),
) -> str:
    """The chain's first inbound endpoint, falling back to the finding URL."""
    for chain in chains:
        for member in chain:
            data = _as_mapping(member)
            url = str(data.get("url") or "")
            if url:
                return url
    return str(finding.get("url") or "")


def dedupe_findings(
    items: Sequence[Any],
) -> list[dict[str, Any]]:
    """Merge findings sharing (vuln_class, root endpoint) into one record.

    The root endpoint is the first inbound endpoint across the finding's
    chains; two findings of the same class hitting the same root are one
    vulnerability with several chains, not two reports.
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for item in items:
        data = _as_mapping(item)
        chains = [
            [_as_mapping(m) for m in chain]
            for chain in (data.get("chains") or ())
        ][:_MAX_CHAINS]
        vuln_class = str(data.get("vuln_class") or "unknown")
        root = root_endpoint_of(data, chains)
        key = (vuln_class, root)
        if key not in groups:
            groups[key] = {
                "vuln_class": vuln_class,
                "root_endpoint": root,
                "finding_ids": [],
                "chains": [],
            }
            order.append(key)
        record = groups[key]
        finding_id = str(data.get("finding_id") or data.get("id") or "")
        if finding_id and finding_id not in record["finding_ids"]:
            record["finding_ids"].append(finding_id)
        if chains and chains not in record["chains"]:
            record["chains"].append(chains)
    return [groups[key] for key in order]


def platform_submission_payload(report: Any) -> dict[str, Any]:
    """Project a BountyReport into a platform-neutral JSON payload."""
    data = report.to_json() if hasattr(report, "to_json") else _as_mapping(report)
    if not str(data.get("report_id") or ""):
        raise EvidenceBundleError("submission_payload_requires_report_id")
    return dict(data)


def submit_bundle(
    report: Any,
    *,
    enable_external_submission: bool,
    approval_recorded: bool,
    engagement_id: str | None,
) -> dict[str, Any]:
    """Human-approval gate for external submission; transport-free by design.

    Passes only when the flag is on AND a human approval is recorded on the
    engagement AND an engagement id is present. Refusals are fail-closed.
    The returned payload is what a human would submit; this module never
    sends anything anywhere.
    """
    if not enable_external_submission:
        raise SubmissionRefused("external_submission_flag_off")
    if not approval_recorded:
        raise SubmissionRefused("human_approval_not_recorded")
    if not str(engagement_id or ""):
        raise SubmissionRefused("engagement_id_required")
    return platform_submission_payload(report)


def maybe_build_evidence_bundle(
    finding: Mapping[str, Any],
    *,
    settings: Any,
    ledger_entries: Sequence[Mapping[str, Any]] = (),
    browser_observations: Sequence[Mapping[str, Any]] = (),
    reproduction_steps: Sequence[Any] = (),
    chains: Sequence[Sequence[Mapping[str, Any]]] = (),
    engagement_id: str = "",
    generated_at: datetime | None = None,
) -> EvidenceBundleResult | None:
    """Flag-gated entry point: None when ``enable_evidence_bundle`` is off."""
    if not bool(getattr(settings, "enable_evidence_bundle", False)):
        return None
    return build_evidence_bundle(
        finding,
        ledger_entries=ledger_entries,
        browser_observations=browser_observations,
        reproduction_steps=reproduction_steps,
        chains=chains,
        engagement_id=engagement_id,
        max_bytes=int(getattr(settings, "evidence_bundle_max_bytes", 10_000_000)),
        generated_at=generated_at,
    )


def build_evidence_bundle(
    finding: Mapping[str, Any],
    *,
    ledger_entries: Sequence[Mapping[str, Any]] = (),
    browser_observations: Sequence[Mapping[str, Any]] = (),
    reproduction_steps: Sequence[Any] = (),
    chains: Sequence[Sequence[Mapping[str, Any]]] = (),
    engagement_id: str = "",
    max_bytes: int = 10_000_000,
    generated_at: datetime | None = None,
) -> EvidenceBundleResult:
    """Assemble one bounded, deterministic evidence ZIP for a finding."""
    if max_bytes < 1:
        raise EvidenceBundleError("evidence_bundle_budget_must_be_positive")
    data = _as_mapping(finding)
    when = generated_at or datetime.now(timezone.utc)
    warnings: list[str] = []

    rows = list(ledger_entries)
    if len(rows) > _MAX_LEDGER_ENTRIES:
        warnings.append(
            f"request ledger truncated from {len(rows)} to {_MAX_LEDGER_ENTRIES} rows"
        )
        rows = rows[:_MAX_LEDGER_ENTRIES]
    har = build_requests_har(rows, engagement_id=engagement_id)
    if not rows:
        warnings.append("requests.har has zero entries: ledger returned no rows")

    observations: list[dict[str, Any]] = []
    for obs in list(browser_observations)[:_MAX_OBSERVATIONS]:
        mapped = _as_mapping(obs)
        observations.append(
            {key: mapped[key] for key in _OBSERVATION_FIELDS if key in mapped}
        )
    screenshots_doc: dict[str, Any] = {
        "note": (
            "This framework stores browser evidence as digests "
            "(fingerprint-before-evidence); no image binaries exist."
        ),
        "observations": observations,
    }
    if not observations:
        warnings.append("screenshots/browser_proof.json carries no observations")

    steps = list(reproduction_steps)[:_MAX_STEPS]
    poc = build_poc_sh(steps)
    if not steps:
        warnings.append("poc.sh has no reproduction steps")

    cvss = build_cvss_json(data)
    if cvss.get("warning"):
        warnings.append("cvss.json: no CVSS vector available")

    chain_view = [
        [_as_mapping(m) for m in chain] for chain in list(chains)[:_MAX_CHAINS]
    ]
    root = root_endpoint_of(data, chain_view)
    if not root:
        warnings.append("no root endpoint determinable for this finding")

    files: list[tuple[str, bytes]] = [
        ("requests.har", json.dumps(har, indent=2, sort_keys=True).encode("utf-8")),
        (
            "screenshots/browser_proof.json",
            json.dumps(screenshots_doc, indent=2, sort_keys=True).encode("utf-8"),
        ),
        ("poc.sh", poc.encode("utf-8")),
        ("cvss.json", json.dumps(cvss, indent=2, sort_keys=True).encode("utf-8")),
    ]
    manifest: dict[str, Any] = {
        "schema_version": BUNDLE_SCHEMA,
        "finding_id": str(data.get("finding_id") or data.get("id") or ""),
        "vuln_class": str(data.get("vuln_class") or "unknown"),
        "root_endpoint": root,
        "engagement_id": str(engagement_id or ""),
        "generated_at": when.isoformat(),
        "warnings": warnings,
        "entries": [
            {
                "path": path,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for path, payload in files
        ],
        "completeness_notes": {
            "requests.har": "ledger-reconstructed; incomplete by design",
            "screenshots/browser_proof.json": "digest attestations only",
            "cvss.json": "v3.1 only; v4 not produced",
        },
    }
    files.insert(
        0,
        ("bundle.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")),
    )

    buffer = io.BytesIO()
    stamp = when.timetuple()[:6]
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, payload in files:
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, payload)
    zip_bytes = buffer.getvalue()
    if len(zip_bytes) > max_bytes:
        raise EvidenceBundleError("evidence_bundle_exceeds_budget")

    return EvidenceBundleResult(
        zip_bytes=zip_bytes,
        manifest=manifest,
        warnings=tuple(warnings),
        root_endpoint=root,
    )
