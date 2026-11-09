# tests/test_integration_surface_dossier.py
"""Surface dossier consolidation tests (capability matrix A2)."""

from __future__ import annotations

import pytest

from webpent.integration.surface_dossier import (
    EndpointRecord,
    SurfaceDossier,
    build_surface_dossier,
)


def test_empty_state_yields_empty_dossier():
    dossier = build_surface_dossier({})
    assert dossier.endpoints == ()
    assert dossier.authz_candidates == ()
    assert dossier.injection_sources == ()
    assert dossier.auth_posture == "unknown"
    assert dossier.skipped_malformed == 0


def test_state_endpoints_are_consolidated_with_evidence_refs():
    state = {
        "endpoints": [
            {"path": "/api/users", "method": "get", "evidence_ref": "obs:10"},
            {"url": "/api/admin", "method": "post", "auth_required": True},
        ]
    }
    dossier = build_surface_dossier(state)
    assert len(dossier.endpoints) == 2
    assert dossier.endpoints[0].path == "/api/users"
    assert dossier.endpoints[0].evidence_ref == "obs:10"
    assert dossier.endpoints[1].path == "/api/admin"
    assert dossier.endpoints[1].evidence_ref == "observation:1"
    assert dossier.endpoints[1].auth_required is True


def test_malformed_rows_are_skipped_and_counted_never_raised():
    state = {
        "endpoints": [
            "not-a-dict",
            {"no_path": True},
            {"path": "/ok", "method": "GET"},
            42,
        ],
        "authz_candidates": [{"path": "/x", "role": "admin"}],  # missing expected
        "injection_sources": [{"endpoint_path": "/y", "parameter": "q"}],
    }
    dossier = build_surface_dossier(state)
    assert len(dossier.endpoints) == 1
    assert dossier.skipped_malformed == 4  # non-dict, no-path, non-dict(42), bad authz row
    assert len(dossier.authz_candidates) == 0
    assert len(dossier.injection_sources) == 1


def test_authz_and_injection_signals_are_typed():
    state = {
        "authz_candidates": [
            {
                "endpoint_path": "/api/users",
                "role": "user",
                "expected": "only own records",
                "evidence_ref": "obs:authz-1",
            }
        ],
        "injection_sources": [
            {
                "endpoint_path": "/api/users",
                "param": "id",
                "kind": "query",
                "evidence_ref": "obs:inj-1",
            }
        ],
    }
    dossier = build_surface_dossier(state)
    assert dossier.authz_candidates[0].role_ref == "user"
    assert dossier.authz_candidates[0].evidence_ref == "obs:authz-1"
    assert dossier.injection_sources[0].parameter == "id"


def test_auth_posture_is_extracted_without_secrets():
    state = {
        "auth_state": {"posture": "authenticated", "cookies": ["SECRET-COOKIE-VALUE"]},
    }
    dossier = build_surface_dossier(state)
    assert dossier.auth_posture == "authenticated"
    # No cookie values leak into the dossier (only the posture string).
    assert "SECRET-COOKIE-VALUE" not in dossier.model_dump_json()


def test_dossier_never_contains_finding_fields():
    dossier = build_surface_dossier({"endpoints": [{"path": "/a", "method": "GET"}]})
    dump = dossier.model_dump()
    for forbidden in ("findings", "verdict", "confirmed", "severity", "ground_truth"):
        assert forbidden not in dump


def test_duplicate_endpoints_fail_closed():
    with pytest.raises(ValueError):
        SurfaceDossier(
            endpoints=(
                EndpointRecord(path="/a", http_method="GET", evidence_ref="obs:1"),
                EndpointRecord(path="/a", http_method="GET", evidence_ref="obs:2"),
            )
        )


def test_audit_view_is_json_safe_and_ref_only():
    dossier = build_surface_dossier(
        {
            "endpoints": [{"path": "/a", "method": "GET", "evidence_ref": "obs:1"}],
            "authz_candidates": [
                {
                    "endpoint_path": "/a",
                    "role": "admin",
                    "expected": "deny",
                    "evidence_ref": "obs:2",
                }
            ],
        }
    )
    audit = dossier.to_audit_dict()
    assert audit["endpoint_count"] == 1
    assert audit["authz_candidate_count"] == 1
    assert audit["evidence_refs"] == ["obs:1", "obs:2"]
