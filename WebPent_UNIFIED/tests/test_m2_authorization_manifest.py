# tests/test_m2_authorization_manifest.py
"""M2-A acceptance — the structured, tamper-evident Authorization Manifest.

Covers the model contract (``models/authorization.py``) and the unified
hunt CLI gate (``cli/unified_hunt.py``): digest verification, validity
window, origin coverage, the free-text reference cross-check, the H-2
placeholder echo, and the ``--scope-file`` fail-closed entry gate.
Every refusal must happen BEFORE any state is built (``run_graph=False``
preview refuses too).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webpent.models.authorization import (
    MANIFEST_SCHEMA_VERSION,
    AuthorizationManifestError,
    authorize_target,
    load_authorization_manifest,
    normalize_origin,
    require_authorization_manifest,
    sign_manifest_document,
)

FIELDS = {
    "client_id": "acme-corp",
    "engagement_id": "eng-2026-001",
    "operator": "ops@example.corp",
    "authorization_reference": "BB-2026-777",
    "authorized_origins": ["https://lab.example"],
    "not_before": "2026-01-01T00:00:00+00:00",
    "expires_at": "2027-01-01T00:00:00+00:00",
}


def _signed_manifest(tmp_path: Path, **overrides) -> Path:
    fields = {**FIELDS, **overrides}
    document = sign_manifest_document(fields)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Origin normalization
# ---------------------------------------------------------------------------


def test_origin_normalization_matches_the_documented_rules():
    assert normalize_origin("https://LAB.Example:443") == "https://lab.example"
    assert normalize_origin("http://app.example:80/x/y") == "http://app.example"
    assert normalize_origin("http://app.example:8080") == "http://app.example:8080"
    assert normalize_origin("https://user:pass@app.example") == "https://app.example"
    assert normalize_origin("ftp://x.example") == ""
    assert normalize_origin("not-a-url") == ""
    assert normalize_origin("") == ""


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_signed_manifest_loads_and_authorizes_its_origin(tmp_path):
    path = _signed_manifest(tmp_path)
    manifest, decision = require_authorization_manifest(
        "https://lab.example/a/b?x=1", path, authorization_reference="BB-2026-777"
    )
    assert decision.allowed is True
    assert decision.reason == "authorized"
    assert decision.manifest_sha256 == manifest.manifest_sha256
    assert decision.target_origin == "https://lab.example"
    assert len(manifest.manifest_sha256) == 64


def test_sign_then_load_round_trip_is_deterministic(tmp_path):
    first = _signed_manifest(tmp_path)
    second = _signed_manifest(tmp_path)
    assert first.read_bytes() == second.read_bytes(), (
        "signing must be deterministic — the same fields always produce "
        "the same canonical document and digest"
    )


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------


def test_tampered_origin_is_refused_by_the_digest(tmp_path):
    path = _signed_manifest(tmp_path)
    document = json.loads(path.read_text())
    document["authorized_origins"] = ["https://evil.example"]
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError, match="integrity"):
        load_authorization_manifest(path)


def test_tampered_expiry_is_refused_by_the_digest(tmp_path):
    path = _signed_manifest(tmp_path)
    document = json.loads(path.read_text())
    # extending the window silently is exactly what the digest must catch
    document["expires_at"] = "2099-01-01T00:00:00+00:00"
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError, match="integrity"):
        load_authorization_manifest(path)


def test_swapped_reference_is_refused_by_the_digest(tmp_path):
    path = _signed_manifest(tmp_path)
    document = json.loads(path.read_text())
    document["authorization_reference"] = "BB-2026-888"
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError, match="integrity"):
        load_authorization_manifest(path)


# ---------------------------------------------------------------------------
# Structural refusals
# ---------------------------------------------------------------------------


def test_wrong_schema_version_is_refused(tmp_path):
    # a v0 document can never be SIGNED (the signing helper refuses it by
    # design) — hand-write one and confirm the loader's version check fires
    # before any integrity comparison
    document = dict(FIELDS)
    document["schema_version"] = "webpent-authorization-manifest-v0"
    document["manifest_sha256"] = "0" * 64
    path = tmp_path / "v0.json"
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError, match="schema_version"):
        load_authorization_manifest(path)


def test_missing_required_field_is_refused(tmp_path):
    # the signing helper refuses an incomplete document (pydantic required
    # fields); the LOADER must also refuse a signed document that later
    # loses a field — pop the field but keep the digest, so the missing-
    # field check (which runs before the integrity check) is what fires
    document = sign_manifest_document(FIELDS)
    document.pop("operator")
    path = tmp_path / "m.json"
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError, match="operator"):
        load_authorization_manifest(path)


def test_empty_origins_is_refused(tmp_path):
    with pytest.raises(AuthorizationManifestError):
        sign_manifest_document({**FIELDS, "authorized_origins": []})


def test_placeholder_reference_is_refused_at_sign_and_load(tmp_path):
    with pytest.raises(AuthorizationManifestError):
        sign_manifest_document({**FIELDS, "authorization_reference": "CHANGE-ME-1"})
    # a hand-written document that skips signing still refuses at load
    document = json.loads(_signed_manifest(tmp_path).read_text())
    document["authorization_reference"] = "your-auth-here"
    document["manifest_sha256"] = "0" * 64
    path = tmp_path / "ph.json"
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError):
        load_authorization_manifest(path)


def test_missing_file_and_bad_json_are_refused(tmp_path):
    with pytest.raises(AuthorizationManifestError, match="not found"):
        load_authorization_manifest(tmp_path / "nope.json")
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(AuthorizationManifestError, match="JSON"):
        load_authorization_manifest(path)


# ---------------------------------------------------------------------------
# Authorization decisions
# ---------------------------------------------------------------------------


def test_expired_manifest_is_refused(tmp_path):
    path = _signed_manifest(tmp_path, expires_at="2020-01-01T00:00:00+00:00")
    with pytest.raises(AuthorizationManifestError, match="expired"):
        require_authorization_manifest("https://lab.example", path)


def test_not_yet_valid_manifest_is_refused(tmp_path):
    path = _signed_manifest(
        tmp_path, not_before=(datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    )
    with pytest.raises(AuthorizationManifestError, match="not valid before"):
        require_authorization_manifest("https://lab.example", path)


def test_out_of_scope_origin_is_refused_with_reason(tmp_path):
    path = _signed_manifest(tmp_path)
    with pytest.raises(AuthorizationManifestError, match="outside the manifest"):
        require_authorization_manifest("https://other.example", path)


def test_subdomain_of_an_authorized_origin_is_refused(tmp_path):
    # origin-level matching has NO wildcard semantics — a manifest for
    # lab.example never covers dev.lab.example (that requires a manifest entry)
    path = _signed_manifest(tmp_path)
    with pytest.raises(AuthorizationManifestError, match="outside the manifest"):
        require_authorization_manifest("https://dev.lab.example", path)


def test_excluded_host_wins_over_authorized_origin(tmp_path):
    path = _signed_manifest(tmp_path, excluded_hosts=["lab.example"])
    with pytest.raises(AuthorizationManifestError, match="excluded"):
        require_authorization_manifest("https://lab.example", path)


def test_reference_mismatch_is_refused(tmp_path):
    path = _signed_manifest(tmp_path)
    with pytest.raises(AuthorizationManifestError, match="reference mismatch"):
        require_authorization_manifest(
            "https://lab.example", path, authorization_reference="BB-2026-999"
        )


def test_authorize_target_decision_api_without_raising(tmp_path):
    path = _signed_manifest(tmp_path)
    manifest = load_authorization_manifest(path)
    ok = authorize_target(manifest, "https://lab.example", authorization_reference="BB-2026-777")
    assert ok.allowed
    denied = authorize_target(manifest, "https://evil.example")
    assert not denied.allowed and "outside the manifest" in denied.reason
    # decision carries the binding identity for M9 approval binding
    assert denied.engagement_id == "eng-2026-001"


# ---------------------------------------------------------------------------
# Unified hunt CLI gate (preview path — no graph, no network)
# ---------------------------------------------------------------------------


def test_hunt_preview_accepts_verified_manifest(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    path = _signed_manifest(tmp_path)
    summary = run_unified_hunt(
        url="https://lab.example",
        mode="quick",
        authorization="BB-2026-777",
        run_graph=False,
        authorization_manifest=str(path),
    )
    assert summary["authorization_manifest"]["manifest_sha256"] == json.loads(
        path.read_text()
    )["manifest_sha256"]
    assert summary["authorization_manifest"]["engagement_id"] == "eng-2026-001"


def test_hunt_preview_refuses_tampered_manifest(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    path = _signed_manifest(tmp_path)
    document = json.loads(path.read_text())
    document["authorized_origins"] = ["https://attacker.example"]
    path.write_text(json.dumps(document))
    with pytest.raises(AuthorizationManifestError):
        run_unified_hunt(
            url="https://lab.example",
            mode="quick",
            authorization="BB-2026-777",
            run_graph=False,
            authorization_manifest=str(path),
        )


def test_hunt_preview_refuses_manifest_reference_mismatch(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    path = _signed_manifest(tmp_path)
    with pytest.raises(AuthorizationManifestError, match="reference mismatch"):
        run_unified_hunt(
            url="https://lab.example",
            mode="quick",
            authorization="some-other-ref",
            run_graph=False,
            authorization_manifest=str(path),
        )


# ---------------------------------------------------------------------------
# --scope-file gate (the worker grammar, now on the CLI entry)
# ---------------------------------------------------------------------------


def test_hunt_preview_accepts_covering_scope_file(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    scope = tmp_path / "engagement.scope"
    scope.write_text(
        "# engagement scope\n"
        "lab.example\n"
        "exclude: admin.lab.example\n"
        "exclude-path: /logout\n",
        encoding="utf-8",
    )
    summary = run_unified_hunt(
        url="https://lab.example",
        mode="quick",
        authorization="BB-2026-777",
        run_graph=False,
        scope_file=str(scope),
    )
    assert summary["scope"]["source"] == "scope_file"
    assert summary["scope"]["allow_entry_count"] == 1


def test_hunt_preview_refuses_target_outside_scope_file(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    scope = tmp_path / "engagement.scope"
    scope.write_text("lab.example\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scope_file_target_url_not_in_scope"):
        run_unified_hunt(
            url="https://other.example",
            mode="quick",
            authorization="BB-2026-777",
            run_graph=False,
            scope_file=str(scope),
        )


def test_hunt_preview_refuses_missing_scope_file(tmp_path):
    from webpent.cli.unified_hunt import run_unified_hunt

    with pytest.raises(ValueError, match="scope file not found"):
        run_unified_hunt(
            url="https://lab.example",
            mode="quick",
            authorization="BB-2026-777",
            run_graph=False,
            scope_file=str(tmp_path / "missing.scope"),
        )


def test_cli_hunt_declares_the_two_new_options():
    """The documented flags exist on the hunt command surface."""
    import inspect

    from webpent.cli.commands import hunt

    params = set(inspect.signature(hunt).parameters)
    assert "authorization_manifest" in params
    assert "scope_file" in params
