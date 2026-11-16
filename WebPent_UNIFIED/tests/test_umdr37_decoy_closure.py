"""UM-DR-37 §12 — the decoy closure (public resources must never
confirm as access-control violations).

The extended lab's decoy route (a public-by-design invoice lookalike)
exposed a real false-positive class: the primary-session ownership
heuristic fabricated an owner for ANY authenticated-readable resource,
so a public invoice confirmed as an IDOR. The closure records explicit
body-level ownership semantics in the crawl channel (public marker ->
no ownership semantics; owner -> evidence when represented by a probed
identity) and pins all three layers.
"""

from __future__ import annotations

from webpent.agents.access_control.agent import _extract_candidate_records
from webpent.shared.http_discovery import _bounded_ownership_markers

LAB_BASE = "http://127.0.0.1:9"


def test_ownership_markers_extract_explicit_body_semantics() -> None:
    owned = _bounded_ownership_markers(
        '{"id": "INV-A-101", "owner": "User_A", "status": "paid"}',
        "application/json")
    assert owned == {"owner_identity": "User_A"}

    public = _bounded_ownership_markers(
        '{"id": "DECOY-9999", "public": true, "notice": "sample"}',
        "application/json")
    assert public == {"public_resource": True}

    both = _bounded_ownership_markers(
        '{"owner": "User_A", "is_public": true}', "application/json")
    assert both == {"owner_identity": "User_A", "public_resource": True}


def test_ownership_markers_reject_non_evidence() -> None:
    # non-JSON content types and non-dict documents never yield markers
    assert _bounded_ownership_markers("<html>owner: x</html>",
                                      "text/html") is None
    assert _bounded_ownership_markers('["owner", "User_A"]',
                                      "application/json") is None
    # falsy/typed-wrong values never yield markers
    assert _bounded_ownership_markers(
        '{"public": "yes"}', "application/json") is None
    assert _bounded_ownership_markers(
        '{"owner": 42}', "application/json") is None
    # unparseable JSON fails closed
    assert _bounded_ownership_markers("{broken", "application/json") is None


def test_surface_records_flow_rich_first_through_dedup() -> None:
    """The surface record (dict, carrying the body-level markers) must
    win the dedup canonical against the bare-URL endpoints entry."""
    surface = {
        "surface_records": [{
            "url": f"{LAB_BASE}/api/invoices/DECOY-9999",
            "method": "GET", "status_code": 200,
            "public_resource": True,
        }],
        "endpoints": [f"{LAB_BASE}/api/invoices/DECOY-9999"],
    }
    records = _extract_candidate_records(surface)
    assert len(records) == 1
    assert records[0].get("public_resource") is True

    owned = {
        "surface_records": [{
            "url": f"{LAB_BASE}/api/invoices/INV-A-101",
            "method": "GET", "status_code": 200,
            "owner_identity": "User_A",
        }],
        "endpoints": [f"{LAB_BASE}/api/invoices/INV-A-101"],
    }
    records = _extract_candidate_records(owned)
    assert records[0].get("owner_identity") == "User_A"


def test_public_resource_record_never_becomes_a_finding(
        monkeypatch) -> None:
    """Node-level: a record carrying the explicit public marker is
    skipped as a public resource (honest gap accounting) — the
    ownership heuristic must not fabricate a differential for it."""
    from webpent.agents.access_control import agent as access_agent
    from webpent.models.targets import Target

    probed: list[str] = []

    def probe(url, cookies=None, timeout=10.0, headers=None, **_kwargs):
        probed.append(url)
        return 200, 123

    # monkeypatch restores the module function automatically — a bare
    # assignment + del deleted the MODULE'S function mid-suite and
    # contaminated every later BAC test (root-caused in the
    # verification report)
    monkeypatch.setattr(access_agent, "_probe_url", probe)
    state = {
        "target": Target(url=LAB_BASE),
        "findings": [],
        "engagement_id": "umdr37-decoy-test",
        "crawled_data": {"surface_records": [{
            "url": f"{LAB_BASE}/api/invoices/DECOY-9999",
            "method": "GET", "status_code": 200,
            "public_resource": True,
        }]},
        "identity_profiles": {
            "alice": {"role": "owner",
                      "cookies": {"session": "alice-secret"}},
            "bob": {"role": "user",
                    "cookies": {"session": "bob-secret"}},
        },
    }
    result = access_agent.access_control_node(state)

    assert result["findings"] == []
    gaps = result.get("bac_coverage_gaps") or []
    assert any(g.get("status") == "public_resource" for g in gaps), gaps
    # the public resource is never even probed as a differential
    assert not any("DECOY-9999" in url for url in probed)
