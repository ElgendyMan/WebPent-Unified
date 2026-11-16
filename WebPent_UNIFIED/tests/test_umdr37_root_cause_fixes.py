"""UM-DR-37 Phase 2 — regression tests for the zero-findings root causes.

Every test pins one measured root cause of the UM-DR-36.1 zero-findings
production run (see artifacts/umdr37_graph_trace_before.json):

  RC-1  the HTTP crawler was blind to JSON link manifests, so an
        API-first target yielded ``endpoints == [origin]`` and every
        resource-hungry family starved (RESOURCE_NOT_DISCOVERED);
  RC-2  the BAC identifier gate required >=10-char path ids and silently
        dropped structured short ids such as ``INV-A-101``
        (CANDIDATE_EXTRACTION_FAILED);
  RC-3  the no-checkpointer branch of ``run_unified_hunt`` dropped the
        operator-supplied ``identity_profiles`` so secondary principals
        never reached the graph (IDENTITY_BINDING_MISSING);
  RC-4  BAC probe rows lacked the authorization context keys CausalGuard
        reads, so complete owner/foreign/denied triples were adjudicated
        INCONCLUSIVE (GUARD_INCONCLUSIVE).

The final test is the production-path proof: a real ``run_unified_hunt``
campaign against the authorized lab reaches Tool-Confirmed IDOR findings
through the legal chain while negative controls stay unconfirmed.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

from webpent.agents.access_control.agent import (  # noqa: E402
    _ID_PATTERN,
    _authz_context_row,
    _extract_candidate_records,
)

LAB_INVOICES = {
    "INV-A-101": ("User_A", "paid", 1200),
    "INV-B-777": ("User_B", "open", 3400),
    "INV-ADMIN-9001": ("User_ADMIN", "paid", 99),
}
LAB_SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}
MISSING = "INV-MISSING-404"


class _IdorLab(BaseHTTPRequestHandler):
    """The authorized local lab (same scenario as the UM-DR-36.1/37 runs)."""

    def _principal(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "session=" in part:
                return LAB_SESSIONS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("", "/"):
            self._send(200, json.dumps({
                "app": "invoice-lab", "version": "1.5.0",
                "links": ["/api/users", "/api/session", "/api/health",
                          "/api/invoices/INV-A-101",
                          "/api/invoices/INV-B-777",
                          "/api/invoices/INV-ADMIN-9001",
                          f"/api/invoices/{MISSING}"]}).encode())
            return
        if path == "/api/health":
            self._send(200, b'{"status":"ok"}')
            return
        if path == "/api/users":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"users": [
                {"id": "u1", "name": "User_A", "role": "customer"},
                {"id": "u2", "name": "User_B", "role": "customer"}]}).encode())
            return
        if path == "/api/session":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"principal": principal,
                                        "authenticated": True}).encode())
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            inv = path.rsplit("/", 1)[1]
            if inv not in LAB_INVOICES:
                self._send(404, b'{"error":"invoice not found"}')
                return
            owner, status, amount = LAB_INVOICES[inv]
            if owner == "User_ADMIN" and principal != "User_ADMIN":
                self._send(403, json.dumps({
                    "error": "forbidden", "invoice": inv,
                    "requires": "admin"}).encode())
                return
            self._send(200, json.dumps({
                "id": inv, "owner": owner, "status": status,
                "amount": amount, "requested_by": principal}).encode())
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *_a) -> None:
        return


@pytest.fixture()
def lab():
    server = HTTPServer(("127.0.0.1", 0), _IdorLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture()
def engaged_lab(lab):
    """Declare the lab origin as the engagement target so the SSRF
    transport's operator-declared-target allowlist admits loopback (the
    same production wiring run_unified_hunt establishes internally)."""
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    token = set_engagement_target_hosts(lab)
    yield lab
    clear_engagement_target_hosts(token)


# --------------------------------------------------------------------------
# RC-1 — JSON link manifests must be crawlable
# --------------------------------------------------------------------------

def test_rc1_bounded_json_links_extracts_manifest_links() -> None:
    from webpent.shared.http_discovery import _bounded_json_links

    manifest = json.dumps({
        "app": "invoice-lab", "version": "1.5.0",
        "links": ["/api/users", "/api/invoices/INV-A-101",
                  "https://evil.example.com/x", "./api/health"],
        "location": "Cairo", "status": "ok",
    })
    links = _bounded_json_links(
        manifest, "http://127.0.0.1:9/base", limit=100)
    paths = [link.rsplit("/", 1)[-1] or link for link in links]
    assert "/api/users" or "users" in paths
    assert any("INV-A-101" in link for link in links)
    assert any("health" in link for link in links)  # ./api/health resolved
    # off-origin links are dropped by _normalise_url (same-origin rule)
    assert not any("evil.example" in link for link in links)
    # free-text values never become links
    assert not any("Cairo" in link for link in links)


def test_rc1_json_api_surface_is_discovered(engaged_lab: str) -> None:
    from webpent.shared.http_discovery import discover_http_surface

    surface = discover_http_surface(
        engaged_lab, session_cookies={"session": "sess-a7f3d1"}, max_pages=20)
    endpoints = surface["endpoints"]
    assert any("INV-A-101" in url for url in endpoints), (
        "the JSON manifest's invoice routes must be crawled "
        f"(got: {endpoints})"
    )
    assert any("INV-B-777" in url for url in endpoints)
    assert len(endpoints) >= 4, (
        "an authenticated JSON API must yield more than the origin"
    )


# --------------------------------------------------------------------------
# RC-2 — the identifier gate must accept structured short ids
# --------------------------------------------------------------------------

def test_rc2_id_pattern_accepts_structured_short_ids() -> None:
    assert _ID_PATTERN.search("/api/invoices/INV-A-101")
    assert _ID_PATTERN.search("/api/invoices/INV-B-777")
    assert _ID_PATTERN.search("/api/invoices/INV-ADMIN-9001")
    assert _ID_PATTERN.search("/api/invoices/101")


def test_rc2_id_pattern_rejects_plain_words_and_tiny_versions() -> None:
    assert not _ID_PATTERN.search("/api/session")
    assert not _ID_PATTERN.search("/api/health")
    assert not _ID_PATTERN.search("/api/settings/v2")  # 2-char version


def test_rc1_nested_traversal_bounded_and_deduplicated() -> None:
    """RC-1 sub-checks (§4): nested object traversal reaches link-named
    keys at depth, duplicates collapse, free text never becomes a
    link."""
    from webpent.shared.http_discovery import _bounded_json_links

    document = {
        "api": {"v1": {"pages": {"links": [
            "/api/x", "/api/x", {"url": "/api/y"},
        ]}}},
        "routes": [{"path": "/api/z"}, "free text", "Cairo"],
        "location": "Cairo",
        "status": "ok",
    }
    links = _bounded_json_links(
        json.dumps(document), "http://127.0.0.1:9", limit=100)
    assert sorted(links) == [
        "http://127.0.0.1:9/api/x", "http://127.0.0.1:9/api/y",
        "http://127.0.0.1:9/api/z",
    ]


def test_rc3_identity_profiles_forwarded_with_checkpointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RC-3 sub-check (§4): the CHECKPOINTER-ENABLED branch must forward
    identity_profiles too — both branches of the entrypoint carry the
    same kwargs (the no-checkpointer direction is pinned above)."""
    import webpent.cli.unified_hunt as uh
    import webpent.graph.builder as gb

    class _Ctx:
        def __enter__(self):
            return object()

        def __exit__(self, *args):
            return False

    captured: dict = {}

    def fake_invoke(graph, *args, **kwargs):
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(uh, "get_checkpointer", lambda: _Ctx())
    monkeypatch.setattr(gb, "build_graph", lambda *a, **k: object())
    monkeypatch.setattr(uh, "_invoke_with_progress", fake_invoke)

    profiles = {"user-b": {"name": "user-b", "role": "user",
                           "cookies": {"session": "sess-b9e2c4"}}}
    uh.run_unified_hunt(
        url="http://127.0.0.1:9", mode="standard",
        authorization="umdr37-authorized-test",
        cookies="session=sess-a7f3d1",
        identity_profiles=profiles,
        auto_approve=True, no_llm=True, progress=False,
        engagement_id=f"rc3cp-{uuid.uuid4().hex[:8]}",
    )
    assert captured.get("identity_profiles") == profiles, (
        "the checkpointer branch must forward identity_profiles"
    )


def test_rc2_candidate_extraction_recovers_lab_resources(lab: str) -> None:
    surface = {"endpoints": [
        f"{lab}/api/invoices/INV-A-101",
        f"{lab}/api/invoices/INV-B-777",
        f"{lab}/api/invoices/INV-ADMIN-9001",
        f"{lab}/api/session", f"{lab}/api/health", lab,
    ]}
    records = _extract_candidate_records(surface)
    object_ids = {r.get("object_id") for r in records}
    assert {"INV-A-101", "INV-B-777", "INV-ADMIN-9001"} <= object_ids, (
        f"lab invoice ids must survive candidate extraction: {object_ids}"
    )


# --------------------------------------------------------------------------
# RC-3 — identity_profiles must reach the graph without a checkpointer
# --------------------------------------------------------------------------

def test_rc3_identity_profiles_forwarded_without_checkpointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import webpent.cli.unified_hunt as uh
    import webpent.graph.builder as gb

    captured: dict = {}

    def fake_invoke(graph, *args, **kwargs):
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(uh, "get_checkpointer", None)
    monkeypatch.setattr(gb, "build_graph", lambda *a, **k: object())
    monkeypatch.setattr(uh, "_invoke_with_progress", fake_invoke)

    profiles = {"user-b": {"name": "user-b", "role": "user",
                           "cookies": {"session": "sess-b9e2c4"}}}
    uh.run_unified_hunt(
        url="http://127.0.0.1:9", mode="standard",
        authorization="umdr37-authorized-test",
        cookies="session=sess-a7f3d1",
        identity_profiles=profiles,
        auto_approve=True, no_llm=True, progress=False,
        engagement_id=f"rc3-{uuid.uuid4().hex[:8]}",
    )
    assert captured.get("identity_profiles") == profiles, (
        "the no-checkpointer branch must forward identity_profiles"
    )


# --------------------------------------------------------------------------
# RC-4 — BAC rows must carry the guard's authorization context
# --------------------------------------------------------------------------

def _lab_row(identity: str, role: str, url: str, status: int) -> dict:
    return {
        "identity": identity, "role": role, "url": url,
        "status_code": status, "content_length": 120,
        "accessible": 200 <= status < 300,
        "semantic_digest": f"digest-{url.rsplit('/', 1)[-1]}-{status}",
        "response_digest": f"resp-{status}-{identity}",
        "request_digest": f"req-GET-{url}",
    }


def test_rc4_authz_context_row_stamps_guard_contract() -> None:
    row = _lab_row("User_B", "user",
                   "http://127.0.0.1:9/api/invoices/INV-A-101", 200)
    enriched = _authz_context_row(
        row, owner="User_A", object_id="INV-A-101",
        url="http://127.0.0.1:9/api/invoices/INV-A-101")
    assert enriched["actor_id"] == "User_B"
    assert enriched["resource_owner"] == "User_A"
    assert enriched["resource_id"] == "INV-A-101"
    assert enriched["resource_type"] == "invoices"
    assert enriched["authorization_outcome"] == "granted_full"
    denied = _authz_context_row(
        _lab_row("User_B", "user",
                 "http://127.0.0.1:9/api/invoices/INV-ADMIN-9001", 403),
        owner="User_ADMIN", object_id="INV-ADMIN-9001",
        url="http://127.0.0.1:9/api/invoices/INV-ADMIN-9001")
    assert denied["authorization_outcome"] == "denied"


def test_rc4_guard_confirms_production_shaped_rows() -> None:
    from webpent.cqa_v2.causal_guard import Verdict, guarded_causal_evaluate

    url = "http://127.0.0.1:9/api/invoices/INV-A-101"
    baseline = _authz_context_row(
        _lab_row("User_A", "owner", url, 200), owner="User_A",
        object_id="INV-A-101", url=url)
    candidate = _authz_context_row(
        _lab_row("User_B", "user", url, 200), owner="User_A",
        object_id="INV-A-101", url=url)
    control = _authz_context_row(
        _lab_row("User_B", "user",
                 "http://127.0.0.1:9/api/invoices/INV-ADMIN-9001", 403),
        owner="User_ADMIN", object_id="INV-ADMIN-9001",
        url="http://127.0.0.1:9/api/invoices/INV-ADMIN-9001")

    result = guarded_causal_evaluate(baseline, candidate, control)
    assert result.verdict is Verdict.CONFIRMED, (
        f"complete production-shaped triple must confirm: {result}"
    )


def test_rc4_guard_rejects_contaminated_control() -> None:
    """The owner's own granted access re-used as the control is NOT an
    independent boundary proof (UM-DR-35 §1.5)."""
    from webpent.cqa_v2.causal_guard import Verdict, guarded_causal_evaluate

    url = "http://127.0.0.1:9/api/invoices/INV-A-101"
    baseline = _authz_context_row(
        _lab_row("User_A", "owner", url, 200), owner="User_A",
        object_id="INV-A-101", url=url)
    candidate = _authz_context_row(
        _lab_row("User_B", "user", url, 200), owner="User_A",
        object_id="INV-A-101", url=url)
    contaminated = _authz_context_row(  # owner's own access, no denial
        _lab_row("User_A", "owner", url, 200), owner="User_A",
        object_id="INV-A-101", url=url)

    result = guarded_causal_evaluate(baseline, candidate, contaminated)
    assert result.verdict is not Verdict.CONFIRMED


# --------------------------------------------------------------------------
# The production-path proof (mission Part 12 / gate G37-16)
# --------------------------------------------------------------------------

def test_production_path_discovers_and_confirms_idor(lab: str) -> None:
    """A REAL run_unified_hunt campaign against the authorized lab must
    reach at least one Tool-Confirmed IDOR finding through the legal
    chain (CausalGuard -> ProofBundle -> Replay), while the enforced
    admin boundary and the missing resource stay unconfirmed."""
    from webpent.cli.unified_hunt import run_unified_hunt

    summary = run_unified_hunt(
        url=lab, mode="standard",
        authorization="umdr37-authorized-lab-regression",
        cookies="session=sess-a7f3d1",
        identity_profiles={
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": "sess-b9e2c4"}},
        },
        auto_approve=True, no_llm=True, progress=False,
        engagement_id=f"umdr37-reg-{uuid.uuid4().hex[:8]}",
        run_graph=True,
    )

    detail = summary.get("findings_detail") or []
    confirmed = [
        f for f in detail
        if f.get("confidence_level") == "Tool-Confirmed"
    ]
    idor = [
        f for f in confirmed
        if str(f.get("vuln_class", "")).lower() in {"auth_bypass", "idor"}
    ]
    assert summary.get("findings_confirmed", 0) >= 1, (
        f"the production path must confirm the lab IDOR: {summary}"
    )
    assert idor, f"confirmed findings must include IDOR: {confirmed}"
    for finding in idor:
        assert finding.get("evidence_bundle_id"), (
            "every Tool-Confirmed finding must carry a sealed ProofBundle"
        )
        assert "INV-A-101" in finding.get("url", "") or \
            "INV-B-777" in finding.get("url", ""), (
                f"confirmed IDOR must be one of the vulnerable invoices, "
                f"got {finding.get('url')}"
            )
    # negative controls stay unconfirmed
    for finding in confirmed:
        assert "INV-ADMIN-9001" not in finding.get("url", ""), (
            "the enforced admin boundary must never confirm"
        )
        assert MISSING not in finding.get("url", ""), (
            "the missing resource must never confirm"
        )
    # non-confirmed findings on the control resource remain review-level
    for finding in detail:
        if "INV-ADMIN-9001" in finding.get("url", ""):
            assert finding.get("confidence_level") != "Tool-Confirmed"
