"""File-upload vulnerability probes: SVG XSS, traversal, MIME confusion.

PURE LOGIC ONLY. No I/O. This module generates the test payloads (as data) and
the multipart request specs; AVI executes them through the governed boundary.

Scenarios from the sprint brief:

a. SVG with embedded script  — if it renders, stored XSS
b. Path traversal filename   — ../../etc/passwd style names
c. MIME confusion            — Content-Type says image/png, content is script
d. Null byte in filename     — file.php%00.jpg
e. Double extension          — file.php.jpg

The canonical validator ``validate_file_upload`` lives in
``webpent.production.validators``. It never confirms from an upload success
message alone: it requires the uploaded artifact to be *reachable* and to
demonstrate the specific impact (rendered script / execution output / a written
path outside the upload directory) with a clean negative control.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FILE_UPLOAD_EXPERIMENT_ID = "exp_file_upload_v1"
FILE_UPLOAD_FAMILY = "FILE_UPLOAD"

# Marker embedded in every probe so a confirmation can prove OUR file was
# uploaded and served, not a coincidental static resource.
UPLOAD_MARKER = "webpent_upload_probe_9c31"

# A benign SVG carrying a script sink that a correct implementation neutralizes
# (by serving it as an inert attachment or refusing it). Deliberately minimal.
SVG_XSS_PAYLOAD = (
    '<?xml version="1.0" standalone="no"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
    f'<!--{UPLOAD_MARKER}-->'
    '<script type="text/javascript">document.title="webpent_upload_probe_9c31"</script>'
    '</svg>'
).strip()

# A harmless script body used for MIME-confusion / execution checks. It echoes a
# static marker instead of executing anything on the target: a target that
# *executes* uploaded PHP will return the marker in its output, which is the
# evidence; a target that stores the file as opaque data will not.
SCRIPT_MARKER_PAYLOAD = f"<?php echo '{UPLOAD_MARKER}'; ?>"

FILE_UPLOAD_SCENARIOS: tuple[str, ...] = (
    "svg_xss",
    "path_traversal",
    "mime_confusion",
    "null_byte",
    "double_extension",
)

# Filename templates per scenario, with the marker inside so the stored name is
# traceable in the probe response/listing.
SCENARIO_FILENAMES: dict[str, str] = {
    "svg_xss": f"{UPLOAD_MARKER}.svg",
    "path_traversal": f"../../../../tmp/{UPLOAD_MARKER}.txt",
    "mime_confusion": f"{UPLOAD_MARKER}.png",
    "null_byte": f"{UPLOAD_MARKER}.php%00.jpg",
    "double_extension": f"{UPLOAD_MARKER}.php.jpg",
}

SCENARIO_CONTENT_TYPES: dict[str, str] = {
    "svg_xss": "image/svg+xml",
    # MIME confusion declares an image while the bytes are a script.
    "mime_confusion": "image/png",
    "path_traversal": "text/plain",
    "null_byte": "image/jpeg",
    "double_extension": "image/jpeg",
}


@dataclass(frozen=True)
class UploadProbe:
    """One multipart upload probe plus its expected access path."""

    scenario: str
    endpoint_path: str
    method: str
    filename: str
    content_type: str
    file_content: str
    field_name: str = "file"
    access_path: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)

    def as_hypothesis(self, *, target_url: str, hypothesis_id: str) -> dict[str, Any]:
        """Project to the AVI hypothesis shape (advisory input, no credentials)."""
        candidate: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.endpoint_path,
            "content_type": "multipart/form-data",
            "upload_field": self.field_name,
            "upload_filename": self.filename,
            "upload_part_content_type": self.content_type,
            "upload_body": self.file_content,
            "extra_fields": dict(self.extra_fields),
        }
        baseline: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.endpoint_path,
            "content_type": "multipart/form-data",
            "upload_field": self.field_name,
            "upload_filename": f"benign_{UPLOAD_MARKER}.txt",
            "upload_part_content_type": "text/plain",
            "upload_body": "benign baseline upload",
            "extra_fields": dict(self.extra_fields),
        }
        control: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.endpoint_path,
            "content_type": "multipart/form-data",
            "upload_field": self.field_name,
            "upload_filename": f"control_{UPLOAD_MARKER}.txt",
            "upload_part_content_type": "text/plain",
            "upload_body": "control upload with no script sink",
            "extra_fields": dict(self.extra_fields),
        }
        return {
            "id": hypothesis_id,
            "hypothesis_id": hypothesis_id,
            "vulnerability_class": FILE_UPLOAD_FAMILY,
            "api_type": "rest",
            "path": self.endpoint_path,
            "method": str(self.method).upper(),
            "information_value": 0.9,
            "requests": {
                "baseline": baseline,
                "candidate": candidate,
                "negative_control": control,
            },
            "family_contract_version": "v1",
        "executable": True,
            "hypothesis_template": (
                "a file-upload endpoint may accept and serve a dangerous artifact "
                f"({self.scenario}) that is then reachable by an attacker"
            ),
            "expected_evidence": [
                "candidate_artifact_reachable",
                "candidate_impact_demonstrated",
                "baseline_control_no_impact",
            ],
            "target_url": str(target_url),
            "metadata": {
                "experiment_id": FILE_UPLOAD_EXPERIMENT_ID,
                "scenario": self.scenario,
                "marker": UPLOAD_MARKER,
                "access_path": self.access_path,
                "upload_filename": self.filename,
                "stored_basename": self.filename.replace("\\", "/").split("/")[-1],
            },
        }


def build_upload_probe(
    *,
    endpoint_path: str,
    scenario: str = "svg_xss",
    method: str = "POST",
    field_name: str = "file",
    filename: str | None = None,
    content_type: str | None = None,
    file_content: str | None = None,
    access_path: str | None = None,
    extra_fields: dict[str, str] | None = None,
) -> UploadProbe:
    """Build one upload probe for a named scenario (fail-closed on unknown)."""
    key = str(scenario or "").strip().lower()
    if key not in FILE_UPLOAD_SCENARIOS:
        raise ValueError(f"unknown_file_upload_scenario:{key}")
    default_content = SVG_XSS_PAYLOAD if key == "svg_xss" else SCRIPT_MARKER_PAYLOAD
    return UploadProbe(
        scenario=key,
        endpoint_path=str(endpoint_path),
        method=str(method or "POST").upper(),
        filename=str(filename or SCENARIO_FILENAMES[key]),
        content_type=str(content_type or SCENARIO_CONTENT_TYPES[key]),
        file_content=str(file_content if file_content is not None else default_content),
        field_name=str(field_name or "file"),
        access_path=str(access_path) if access_path else None,
        extra_fields={str(k): str(v) for k, v in (extra_fields or {}).items()},
    )


def analyze_upload_response(evidence: dict[str, Any], *, scenario: str,
                            marker: str = UPLOAD_MARKER) -> dict[str, Any]:
    """Extract validator-readable signals from one redacted observation.

    A "reachable" artifact means the response either served the marker content
    directly, or exposed a retrievable artifact location for it. An "executed"
    artifact means the target returned the script's own output marker rather than
    the raw script source.
    """
    status = _status_code(evidence)
    body = str(evidence.get("response_body", evidence.get("body", "")))
    lowered = body.lower()
    served_marker = marker.lower() in lowered
    # Executed vs stored: our PHP payload echoes the marker; its raw source
    # contains the marker inside a `<?php` tag. If the marker appears WITHOUT
    # the surrounding script tag, the server executed it.
    executed = served_marker and "<?php" not in lowered and "<script" not in lowered
    traversal_written = any(
        token in lowered
        for token in ("/tmp/", "/etc/", "/var/www", "root:", "www-data")
    ) and served_marker
    return {
        "_upload_status": status,
        "_upload_accepted": 200 <= status < 300,
        "_upload_marker_served": served_marker,
        "_upload_executed": executed,
        "_upload_traversal_written": traversal_written,
        "_upload_scenario": str(scenario),
        "_upload_reflected_source": served_marker and not executed,
    }


def _status_code(evidence: dict[str, Any]) -> int:
    raw = evidence.get("status_code", evidence.get("status", 0))
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


__all__ = [
    "FILE_UPLOAD_EXPERIMENT_ID",
    "FILE_UPLOAD_FAMILY",
    "FILE_UPLOAD_SCENARIOS",
    "SCENARIO_FILENAMES",
    "SCENARIO_CONTENT_TYPES",
    "UPLOAD_MARKER",
    "SVG_XSS_PAYLOAD",
    "SCRIPT_MARKER_PAYLOAD",
    "UploadProbe",
    "analyze_upload_response",
    "build_upload_probe",
]
