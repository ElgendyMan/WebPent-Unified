"""Deterministic cumulative finding aggregation.

Findings are persisted per scan thread for tenant isolation.  A logical
engagement may contain several scan threads, so reporting needs a bounded,
deterministic merge across those threads.  This module deliberately does not
change Finding IDs or database rows; it only controls the read-side projection.
"""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from webpent.models.findings import Confidence, Finding, Severity
from webpent.shared.evidence_quality import assess_finding_evidence

_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}
_CONFIDENCE_RANK = {
    Confidence.TENTATIVE.value: 0,
    Confidence.FIRM.value: 1,
    Confidence.CONFIRMED.value: 2,
}
_CONFIDENCE_LEVEL_RANK = {
    "pending": 0,
    "needs human review": 1,
    "ai-assessed": 2,
    "tool-confirmed": 3,
}


def _value(value: object) -> str:
    return str(getattr(value, "value", value) or "").strip().lower()


def _normalise_url(url: str) -> str:
    """Normalise URL without discarding query parameter names."""
    try:
        parsed = urlsplit(str(url).strip())
        query_keys = sorted(
            (key.strip().lower(), "")
            for key, _value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.strip()
        )
        query = urlencode(query_keys)
        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                query,
                "",
            )
        )
    except ValueError:
        return str(url).strip().lower().rstrip("/")


def default_engagement_id(target_url: str, client_id: str | None = None) -> str:
    """Derive a stable, non-secret scope for repeated scans of one target."""
    scope = f"{_normalise_url(target_url)}|{str(client_id or '').strip()}"
    return f"target-{sha256(scope.encode('utf-8')).hexdigest()[:24]}"


def finding_fingerprint(finding: Finding) -> str:
    """Return the stable logical identity used for cross-run deduplication.

    IDOR/BAC findings are endpoint-scoped rather than title-scoped because the
    strategist and access-control paths may use different titles for the same
    resource. Other vulnerability classes retain the existing title-sensitive
    identity so unrelated findings cannot be merged.
    """
    vuln_class = _value(finding.vuln_class) or "unknown"
    title = " ".join(str(finding.title).lower().split())
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    is_idor_claim = (
        vuln_class == "idor"
        or "idor" in title
        or _value(evidence.get("vulnerability_class")) == "idor"
        or bool(evidence.get("access_control"))
        or bool(evidence.get("idor"))
    )
    if is_idor_claim:
        return "idor|" + _normalise_url(finding.url)
    return "|".join((vuln_class, _normalise_url(finding.url), title))


def _selection_key(finding: Finding) -> tuple[object, ...]:
    """Prefer equally strong records that carry the current proof context."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    richness = (
        bool(finding.evidence_bundle),
        bool(evidence.get("proof_bundle")),
        bool(finding.business_impact),
        bool(finding.cvss_score),
        len(evidence),
    )
    return (*_strength(finding), *richness, finding.created_at.isoformat(), str(finding.id))


def _strength(finding: Finding) -> tuple[int, int, int, int, float]:
    evidence_rank = {
        "unconfirmed": 0,
        "needs_human_review": 1,
        "supported": 2,
        "confirmed": 3,
        "clean": -1,
        "not_scanned": -1,
    }
    evidence_quality = evidence_rank.get(
        assess_finding_evidence(finding).classification.value,
        0,
    )
    confidence_level = _CONFIDENCE_LEVEL_RANK.get(_value(finding.confidence_level), 0)
    confidence = _CONFIDENCE_RANK.get(_value(finding.confidence), 0)
    severity = _SEVERITY_RANK.get(_value(finding.severity), 0)
    cvss = 0.0
    if finding.cvss_score:
        try:
            cvss = float(str(finding.cvss_score).split()[0])
        except (TypeError, ValueError):
            cvss = 0.0
    return evidence_quality, confidence_level, confidence, severity, cvss


def aggregate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings across runs while preserving distinct vulnerabilities.

    When repeated runs report the same logical issue, the strongest record is
    retained.  A confirmed finding therefore cannot be replaced by a newer
    tentative candidate.  Different classes, URLs, or titles remain separate.
    Output order is deterministic by creation time and UUID.

    IMPL P0-C (terminal-state precedence): ``Refuted`` is a terminal,
    deterministically sealed status (``db.mark_refuted`` refuses un-refuting
    and requires a negative-control bundle). Projecting a newer tentative
    duplicate over a refuted record resurrects the claim on the read path,
    so a refuted member always wins its fingerprint group; among several
    refuted records the strongest one is projected deterministically.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding_fingerprint(finding), []).append(finding)

    selected: dict[str, Finding] = {}
    for key, members in grouped.items():
        refuted = [m for m in members if _value(m.confidence_level) == "refuted"]
        if refuted:
            selected[key] = max(refuted, key=_selection_key)
            continue
        # Preserve the historical first-wins-on-tie semantics exactly:
        # a later record replaces the current one only on a strictly
        # greater selection key.
        winner = members[0]
        for candidate in members[1:]:
            if _selection_key(candidate) > _selection_key(winner):
                winner = candidate
        selected[key] = winner
    return sorted(
        selected.values(),
        key=lambda item: (item.created_at.isoformat(), str(item.id)),
    )
