# src/webpent/shared/mobile_app_indicators.py
"""webpent.shared.mobile_app_indicators — Track 10.7 (0.26.0).

Roadmap contract (المسار 10 — تطبيقات الجوال وواجهات API):

    دراسة adapters تحليلية واستخراج مؤشرات، مع منع إرسال طلبات أو فحص
    أصول خارج النطاق.

    ("Study ANALYTICAL adapters and extract indicators, while preventing
    requests or inspection of assets outside the scope.")

Until 0.25.0 mobile coverage was the weakest Track-10 signal: keyword
lists in unrelated modules and an OAuth scenario *description* — no
extraction module existed at all. This closes the gap with the repo's
advisory-indicator posture:

* **No execution, no decompilation, no network.** An APK/IPA artifact
  is opened as a ZIP ARCHIVE ONLY (stdlib ``zipfile``); indicator
  extraction is byte/regex analysis of its entries. No dex parsing, no
  manifest XML parsing (binary AXML is out of scope on purpose — the
  honest output is shape-level indicators, not a reverse-engineering
  claim), and never a request.
* **Scope-gated by construction.** The caller supplies the authorized
  origins for the engagement; every extracted indicator is classified
  in_scope / out_of_scope / unattributed against them, and OUT-OF-SCOPE
  indicators are dropped from the returned surface (they are counted,
  never carried). No request is ever sent to anything.
* **Secrets are report-only, redacted.** Credential-shaped strings are
  fingerprinted (sha256 prefix + redaction marker) exactly like
  ``javascript_intelligence`` — values are never returned, stored, or
  used. The roadmap line: "التعامل مع مؤشرات الأسرار كتقرير يحتاج
  مراجعة ولا يحاول استخدام أي بيانات اعتماد".

Output schema (deterministic; same input bytes -> same dict)::

    {
      "artifact": "<path>", "artifact_sha256": "...", "entries_scanned": N,
      "package_hints": [...], "api_base_urls": {"in_scope": [...],
      "out_of_scope_count": K}, "secret_indicators": [{"kind": ...,
      "entry": ..., "fingerprint": ...}], "advisory_only": True,
      "does_not_confirm": True
    }
"""

from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

__all__ = ["analyze_mobile_artifact", "classify_origin"]

_MAX_FILE_BYTES = 400_000_000  # hard cap on artifact size considered
_MAX_ENTRY_BYTES = 8_000_000  # per-entry read cap (dex/resources can be huge)
_MAX_ENTRIES_SCANNED = 4_000
_MAX_URLS = 400
_MAX_SECRET_INDICATORS = 50
_MAX_PACKAGE_HINTS = 12

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
_PACKAGE_HINT_RE = re.compile(rb"^(?:[a-z][a-z0-9_]{1,30}\.){2,}[a-z][a-z0-9_]{1,60}$")
_SECRET_SHAPES: tuple[tuple[str, Any], ...] = (
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("firebase_url", re.compile(rb"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("generic_bearer", re.compile(rb"(?i)bearer\s+[a-z0-9._\-]{20,}")),
    ("api_key_assignment",
     re.compile(rb"(?i)[\"']?(?:api[_-]?key|api[_-]?secret|token)[\"']?\s*[:=]\s*[\"'][^\"']{16,64}[\"']")),
)


def _origin_of(url: str) -> str:
    try:
        parts = urlsplit(url)
        if not parts.netloc:
            return ""
        origin = f"{parts.scheme.lower()}://{parts.netloc.lower()}"
        return origin
    except ValueError:
        return ""


def classify_origin(url: str, authorized_origins: Iterable[str]) -> str:
    """in_scope | out_of_scope — by exact origin membership (normalized).

    ``unattributed`` does not exist at URL level here: a URL without a
    parseable origin is treated as out_of_scope (fail-closed posture).
    """
    origin = _origin_of(url)
    if not origin:
        return "out_of_scope"
    allowed = {o.strip().lower().rstrip("/") for o in authorized_origins if o}
    if not allowed:
        return "out_of_scope"  # no authorized origins declared -> nothing is in scope
    return "in_scope" if origin.rstrip("/") in allowed else "out_of_scope"


def analyze_mobile_artifact(
    artifact_path: str | Path,
    *,
    authorized_origins: Iterable[str] = (),
) -> dict[str, Any]:
    """Extract static indicators from an APK/IPA ZIP artifact (read-only).

    Advisory-only triage support for mobile/API coverage: the result
    feeds the operator's review queue (routes, API bases, credential
    INDICATORS as redacted fingerprints) — it never creates a finding,
    never sends a request, and never inspects anything outside the
    artifact itself.
    """
    path = Path(artifact_path)
    result: dict[str, Any] = {
        "artifact": str(path.name),
        "artifact_sha256": "",
        "entries_scanned": 0,
        "package_hints": [],
        "api_base_urls": {"in_scope": [], "out_of_scope_count": 0},
        "secret_indicators": [],
        "advisory_only": True,
        "does_not_confirm": True,
    }
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            result["error"] = "artifact missing or too large"
            return result
        data = path.read_bytes()
        result["artifact_sha256"] = hashlib.sha256(data).hexdigest()
    except OSError as exc:
        result["error"] = f"unreadable artifact: {type(exc).__name__}"
        return result

    origins = [o for o in authorized_origins if o]
    in_scope_urls: list[str] = []
    seen_urls: set[str] = set()
    out_of_scope_count = 0
    package_hints: list[str] = []
    secret_indicators: list[dict[str, Any]] = []
    entries_scanned = 0

    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        result["error"] = "not a zip-archive artifact (apk/ipa expected)"
        return result

    try:
        for info in archive.infolist()[:_MAX_ENTRIES_SCANNED]:
            if info.file_size > _MAX_ENTRY_BYTES:
                continue
            try:
                with archive.open(info) as handle:
                    blob = handle.read(_MAX_ENTRY_BYTES)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            entries_scanned += 1
            entry_name = info.filename

            for match in _URL_RE.finditer(blob):
                url = match.group(0).decode("utf-8", errors="replace").rstrip(".,;)")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                verdict = classify_origin(url, origins)
                if verdict == "in_scope" and len(in_scope_urls) < _MAX_URLS:
                    in_scope_urls.append(url)
                elif verdict == "out_of_scope":
                    out_of_scope_count += 1  # counted, never carried
            for hint in _PACKAGE_HINT_RE.finditer(blob[:65536]):
                text = hint.group(0).decode("utf-8", errors="replace")
                if text not in package_hints and len(package_hints) < _MAX_PACKAGE_HINTS:
                    package_hints.append(text)
            for shape_name, pattern in _SECRET_SHAPES:
                for sm in pattern.finditer(blob):
                    if len(secret_indicators) >= _MAX_SECRET_INDICATORS:
                        break
                    value = sm.group(0)
                    secret_indicators.append(
                        {
                            "kind": shape_name,
                            "entry": entry_name[:120],
                            "fingerprint": hashlib.sha256(value).hexdigest()[:12],
                            "redacted_value": "[REDACTED]",
                        }
                    )
    finally:
        archive.close()

    result["entries_scanned"] = entries_scanned
    result["package_hints"] = package_hints
    result["api_base_urls"] = {
        "in_scope": in_scope_urls,
        "out_of_scope_count": out_of_scope_count,
    }
    result["secret_indicators"] = secret_indicators
    return result
