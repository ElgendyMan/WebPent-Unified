"""Deterministic, evidence-first authorization matrix projection.

The builder consumes already-sanitised BAC observations. It does not send
requests, infer ownership from numeric identifiers, or promote findings. Its
only output is a bounded matrix plus explicit coverage gaps for the reporter
and revisit scheduler.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from webpent.models.authorization_matrix import (
    AuthorizationComparison,
    AuthorizationMatrix,
    AuthorizationMatrixRow,
)

_SENSITIVE_QUERY_KEYS = {
    "token",
    "session",
    "cookie",
    "authorization",
    "password",
    "secret",
    "api_key",
    "apikey",
}


def _text(value: Any, default: str = "") -> str:
    return str(value).strip() if value is not None and str(value).strip() else default


def _safe_endpoint(value: Any) -> str:
    """Keep endpoint identity while removing secret-shaped query values."""
    raw = _text(value)
    if not raw:
        return "unknown://endpoint"
    try:
        parsed = urlsplit(raw)
        pairs: list[str] = []
        for part in parsed.query.split("&"):
            if not part:
                continue
            key, sep, val = part.partition("=")
            if key.lower() in _SENSITIVE_QUERY_KEYS:
                val = "[REDACTED]"
            pairs.append(key + (sep + val if sep else ""))
        query = "&".join(pairs)
        return urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", query, "")
        )
    except Exception:
        return raw[:1000]


def _observation_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        _text(
            row.get("object_id") or row.get("object_ref") or row.get("resource_url"),
            "unknown-object",
        ),
        _safe_endpoint(row.get("endpoint") or row.get("resource_url") or row.get("url")),
        _text(row.get("method"), "GET").upper(),
        _text(row.get("identity") or row.get("identity_ref"), "unknown-identity"),
    )


def _identity_relation(row: Mapping[str, Any], owner_identity: str | None) -> str:
    identity = _text(row.get("identity") or row.get("identity_ref"))
    if owner_identity and identity == owner_identity:
        return "owner"
    if owner_identity and identity and identity != "anonymous":
        return "non_owner"
    return "unknown"


def _expected_access(row: Mapping[str, Any], relation: str) -> str:
    explicit = _text(row.get("expected_access") or row.get("access_expectation"))
    if explicit in {"allow", "deny", "unknown"}:
        return explicit
    if relation == "owner":
        return "allow"
    if relation == "non_owner":
        return "deny"
    return "unknown"


def build_authorization_matrix(
    observations: Iterable[Mapping[str, Any]],
    *,
    target_url: str | None = None,
    max_rows: int = 500,
    max_comparisons: int = 1000,
) -> dict[str, Any]:
    """Build a deterministic matrix from report-safe BAC rows.

    ``observations`` must already have redacted response data. Invalid rows are
    skipped and represented by a coverage gap rather than raising from a scan.
    The target URL is used only for a conservative host coverage hint.
    """
    max_rows = max(1, min(int(max_rows), 10000))
    max_comparisons = max(1, min(int(max_comparisons), 20000))
    rows_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    gaps: set[str] = set()
    for raw in observations:
        if not isinstance(raw, Mapping):
            gaps.add("invalid_observation_shape")
            continue
        key = _observation_key(raw)
        if len(rows_by_key) >= max_rows and key not in rows_by_key:
            gaps.add("matrix_row_cap_reached")
            continue
        if key in rows_by_key:
            continue
        object_ref, endpoint, method, identity = key
        owner = _text(raw.get("owner_identity")) or None
        relation = _identity_relation(raw, owner)
        fingerprint = _text(raw.get("response_fingerprint"), "unfingerprinted")
        try:
            status_code = max(0, min(999, int(raw.get("status_code", 0))))
        except (TypeError, ValueError):
            status_code = 0
            gaps.add("invalid_status_code")
        row = AuthorizationMatrixRow(
            identity_ref=identity,
            role=_text(raw.get("role"), "unknown"),
            object_ref=object_ref,
            endpoint=endpoint,
            method=method,
            ownership_relation=relation,
            expected_access=_expected_access(raw, relation),
            observed_access=bool(raw.get("accessible")),
            status_code=status_code,
            response_fingerprint=fingerprint,
            evidence_refs=[str(item) for item in (raw.get("evidence_refs") or []) if item][:16],
            redacted=True,
        )
        rows_by_key[key] = {"model": row, "owner_identity": owner}

    rows = list(rows_by_key.values())
    by_resource: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in rows:
        model = item["model"]
        key = (model.object_ref or "unknown-object", model.endpoint, model.method)
        by_resource.setdefault(key, []).append(item)

    comparisons: list[AuthorizationComparison] = []
    for (object_ref, endpoint, method), resource_rows in sorted(by_resource.items()):
        identities = sorted(resource_rows, key=lambda item: item["model"].identity_ref)
        owner = next(
            (item["owner_identity"] for item in identities if item["owner_identity"]), None
        )
        if len(identities) < 2:
            gaps.add(f"insufficient_identity_comparison:{object_ref}:{method}")
            continue
        if not owner:
            gaps.add(f"ownership_provenance_missing:{object_ref}:{method}")
        for left_index, left in enumerate(identities):
            for right in identities[left_index + 1 :]:
                if len(comparisons) >= max_comparisons:
                    gaps.add("matrix_comparison_cap_reached")
                    break
                left_model: AuthorizationMatrixRow = left["model"]
                right_model: AuthorizationMatrixRow = right["model"]
                access_diff = left_model.observed_access != right_model.observed_access
                status_diff = left_model.status_code != right_model.status_code
                fingerprint_diff = (
                    left_model.response_fingerprint != right_model.response_fingerprint
                )
                pair = {left_model.identity_ref, right_model.identity_ref}
                if left_model.role != right_model.role:
                    kind = "vertical"
                elif owner and owner in pair:
                    kind = "ownership_differential"
                elif owner:
                    kind = "same_role"
                else:
                    kind = "horizontal"
                comparisons.append(
                    AuthorizationComparison(
                        left_identity_ref=left_model.identity_ref,
                        right_identity_ref=right_model.identity_ref,
                        left_role=left_model.role,
                        right_role=right_model.role,
                        object_ref=object_ref,
                        endpoint=endpoint,
                        method=method,
                        comparison_kind=kind,
                        access_differential=access_diff,
                        status_differential=status_diff,
                        fingerprint_differential=fingerprint_diff,
                        owner_identity_ref=owner,
                        evidence_refs=sorted(
                            set(left_model.evidence_refs + right_model.evidence_refs)
                        )[:32],
                        redacted=True,
                    )
                )
            if len(comparisons) >= max_comparisons:
                break

    identities = sorted({row["model"].identity_ref for row in rows})
    roles = sorted({row["model"].role for row in rows})
    objects = sorted({row["model"].object_ref for row in rows if row["model"].object_ref})
    endpoints = sorted({row["model"].endpoint for row in rows})
    methods = sorted({row["model"].method for row in rows})
    if len(identities) < 2:
        gaps.add("fewer_than_two_identities_observed")
    if len({role for role in roles if role != "unknown"}) < 2:
        gaps.add("fewer_than_two_roles_observed")
    if not objects:
        gaps.add("no_object_provenance")
    if target_url and endpoints:
        target_host = _text(urlsplit(target_url).hostname).lower()
        endpoint_hosts = {
            _text(urlsplit(endpoint).hostname).lower()
            for endpoint in endpoints
            if urlsplit(endpoint).hostname
        }
        if target_host and endpoint_hosts and target_host not in endpoint_hosts:
            gaps.add("matrix_endpoints_outside_target_host")

    matrix = AuthorizationMatrix(
        identities=identities,
        roles=roles,
        objects=objects,
        endpoints=endpoints,
        methods=methods,
        rows=[item["model"] for item in rows],
        comparisons=comparisons,
        coverage_gaps=sorted(gaps),
    )
    return matrix.model_dump(mode="json")


__all__ = ["build_authorization_matrix"]
