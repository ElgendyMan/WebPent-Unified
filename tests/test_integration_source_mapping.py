# tests/test_integration_source_mapping.py
"""Source→runtime mapping contract tests (capability matrix A3)."""

from __future__ import annotations

import pytest

from webpent.integration.source_mapping import (
    CodeLocation,
    SourceMappingRecord,
    SourceRole,
    join_source_locations,
)


def _loc(**overrides) -> CodeLocation:
    base = dict(
        file="app/routes/admin.py",
        start_line=10,
        end_line=20,
        role=SourceRole.SINK,
        symbol="delete_user",
    )
    base.update(overrides)
    return CodeLocation(**base)


def test_code_location_accepts_relative_paths():
    loc = _loc()
    assert loc.normalized_file == "app/routes/admin.py"


def test_code_location_rejects_absolute_and_traversal_paths():
    with pytest.raises(ValueError):
        _loc(file="/etc/passwd")
    with pytest.raises(ValueError):
        _loc(file="../../etc/passwd")
    with pytest.raises(ValueError):
        _loc(file="C:\\app\\routes.py")


def test_code_location_rejects_inverted_line_range():
    with pytest.raises(ValueError):
        _loc(start_line=30, end_line=20)


def test_mapping_record_id_is_stable_and_content_derived():
    rec = SourceMappingRecord(
        code_location=_loc(),
        endpoint_path="/admin/users/{id}",
        http_method="delete",
        hypothesis_id="hyp-1",
        evidence_refs=("obs:1",),
    )
    rec2 = SourceMappingRecord(
        code_location=_loc(),
        endpoint_path="/admin/users/{id}",
        http_method="DELETE",
        hypothesis_id="hyp-1",
        evidence_refs=("obs:1",),
    )
    # Same content (method case-insensitive) → same stable id.
    assert rec.mapping_id == rec2.mapping_id
    assert rec.mapping_id.startswith("smap-")


def test_join_groups_by_endpoint_deterministically():
    recs = [
        SourceMappingRecord(
            code_location=_loc(),
            endpoint_path="/admin/users/{id}",
            http_method="DELETE",
            hypothesis_id="hyp-1",
        ),
        SourceMappingRecord(
            code_location=_loc(
                role=SourceRole.GUARD, symbol="require_admin", start_line=5, end_line=6
            ),
            endpoint_path="/admin/users/{id}",
            http_method="delete",
            hypothesis_id="hyp-1",
        ),
        SourceMappingRecord(
            code_location=_loc(symbol="search", start_line=100, end_line=110),
            endpoint_path="/search",
            http_method="GET",
        ),
    ]
    joined = join_source_locations(recs)
    assert [j.endpoint_path for j in joined] == ["/admin/users/{id}", "/search"]
    first = joined[0]
    assert first.http_method == "DELETE"
    assert len(first.locations) == 2
    assert first.hypothesis_ids == ("hyp-1",)
    # Deterministic: re-run yields identical structure.
    assert join_source_locations(recs) == joined


def test_join_collects_evidence_refs_without_duplicates():
    recs = [
        SourceMappingRecord(
            code_location=_loc(),
            endpoint_path="/x",
            evidence_refs=("obs:1", "obs:2"),
        ),
        SourceMappingRecord(
            code_location=_loc(start_line=2, end_line=3),
            endpoint_path="/x",
            evidence_refs=("obs:1",),
        ),
    ]
    joined = join_source_locations(recs)
    assert joined[0].evidence_refs == ("obs:1", "obs:2")


def test_join_output_is_ordered():
    recs = [
        SourceMappingRecord(
            code_location=_loc(symbol="b"), endpoint_path="/z", http_method="get"
        ),
        SourceMappingRecord(
            code_location=_loc(symbol="a"), endpoint_path="/a", http_method="post"
        ),
    ]
    joined = join_source_locations(recs)
    assert [j.endpoint_path for j in joined] == ["/a", "/z"]
