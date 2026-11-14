from __future__ import annotations


def test_http_surface_discovers_authenticated_links_get_forms_and_js(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/": (
            200,
            "text/html",
            """
            <a href="/vulnerabilities/sqli/?id=7">SQLi</a>
            <a href="https://outside.test/admin">outside</a>
            <script src="/static/app.js"></script>
            <form action="/transfer.php" method="POST">
              <input type="hidden" name="csrf_token" value="opaque-token">
              <input type="text" name="amount" value="1">
              <input type="password" name="password" value="secret-do-not-store">
            </form>
            <form action="/search.php" method="GET">
              <input name="q" value="hello">
              <input name="Submit" value="Search">
            </form>
            """,
        ),
        "http://lab.test/vulnerabilities/sqli/?id=7": (200, "text/html", "<h1>SQLi</h1>"),
        "http://lab.test/search.php?Submit=Search&q=hello": (200, "text/html", "<h1>Search</h1>"),
        "http://lab.test/static/app.js": (
            200,
            "application/javascript",
            "const route='/api/v1/orders';",
        ),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            status, content_type, text = pages.get(url, (404, "text/html", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface(
        "http://lab.test/",
        session_cookies={"PHPSESSID": "opaque-session"},
        max_pages=10,
    )

    assert "http://lab.test/" in result["endpoints"]
    assert "http://lab.test/vulnerabilities/sqli/?id=7" in result["endpoints"]
    assert "http://lab.test/static/app.js" in result["endpoints"]
    assert all("outside.test" not in endpoint for endpoint in result["endpoints"])
    assert any(form["method"] == "POST" for form in result["forms"])
    assert any(form["method"] == "GET" for form in result["forms"])
    post_form = next(form for form in result["forms"] if form["method"] == "POST")
    assert post_form["data"]["password"] == ""
    assert "secret-do-not-store" not in str(result)


def test_crawler_uses_http_fallback_when_katana_is_missing(monkeypatch) -> None:
    from webpent.agents.crawler import agent as crawler_agent
    from webpent.models.targets import Target
    from webpent.shared.exceptions import ToolNotFoundError

    fallback = {
        "endpoints": [
            "http://lab.test/",
            "http://lab.test/vulnerabilities/sqli/?id=1",
        ],
        "forms": [
            {
                "action": "http://lab.test/transfer.php",
                "method": "POST",
                "data": {"amount": "1"},
                "source_url": "http://lab.test/",
            }
        ],
        "pages_fetched": 2,
        "coverage_gaps": [],
        "surface_records": [
            {
                "record_id": "http:1",
                "url": "http://lab.test/",
                "method": "GET",
                "source": "http_get",
            },
        ],
    }

    monkeypatch.setattr(
        crawler_agent,
        "run_katana",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ToolNotFoundError("katana")),
    )
    monkeypatch.setattr(crawler_agent, "discover_http_surface", lambda *_args, **_kwargs: fallback)
    monkeypatch.setattr(crawler_agent, "get_llm", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(crawler_agent, "_fetch_and_analyze_js", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(crawler_agent, "_discover_html_forms", lambda *_args, **_kwargs: [])

    result = crawler_agent.crawler_node(
        {
            "target": Target(url="http://lab.test/"),
            "session_cookies": {"PHPSESSID": "opaque-session"},
            "auth_state": {"source": "operator_supplied"},
        }
    )

    crawled = result["crawled_data"]
    assert crawled["endpoints"] == fallback["endpoints"]
    assert crawled["forms"] == fallback["forms"]
    assert crawled["http_discovery"]["pages_fetched"] == 2
    assert crawled["surface_records"][0]["record_id"] == "http:1"
    assert "opaque-session" not in str(result)


def test_http_surface_invalid_target_fails_closed() -> None:
    from webpent.shared.http_discovery import discover_http_surface

    result = discover_http_surface("not-a-url")

    assert result["endpoints"] == []
    assert "invalid_target_url" in result["coverage_gaps"]


def test_rabbit_hole_read_only_source_code_is_not_lfi() -> None:
    from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
    from webpent.models.findings import EXPLOITABLE_CLASSES, VulnClass

    vuln_class = _infer_rabbit_hole_vuln_class("source_code", "read_only_parse")

    assert vuln_class == VulnClass.INFO_DISCLOSURE.value
    assert vuln_class not in EXPLOITABLE_CLASSES


def test_rabbit_hole_file_artifact_remains_lfi_candidate() -> None:
    from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
    from webpent.models.findings import VulnClass

    assert _infer_rabbit_hole_vuln_class("file", "read_only_parse") == VulnClass.LFI.value



def test_info_disclosure_path_match_is_promoted_to_validator() -> None:
    from webpent.models.findings import VulnClass
    from webpent.models.hypothesis import Hypothesis
    from webpent.shared.prioritization import (
        PrioritizationAction,
        promote_hypothesis_to_finding,
        recommend_action,
    )

    hypothesis = Hypothesis(
        target_url="http://lab.test/instructions.php",
        statement="Follow source_code via read_only_parse",
        vuln_class=VulnClass.INFO_DISCLOSURE.value,
        confidence_score=0.9,
        deterministic_match=True,
    )
    state = {"findings": [], "hypotheses": [hypothesis], "mental_model": {}}

    action, _score, rule = recommend_action(hypothesis, state)

    assert action == PrioritizationAction.PROMOTE
    assert "validator-available" in rule
    promoted = promote_hypothesis_to_finding(hypothesis, state)
    assert promoted is not None
    assert promoted.vuln_class == VulnClass.INFO_DISCLOSURE.value




def test_http_surface_skips_state_changing_get_routes(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    requested: list[str] = []
    pages = {
        "http://lab.test/": (
            200,
            "text/html",
            '<a href="/logout.php">Logout</a>'
            '<a href="/account?action=delete">Delete account</a>'
            '<a href="/profile">Profile</a>',
        ),
        "http://lab.test/profile": (200, "text/html", "<h1>Profile</h1>"),
    }

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            requested.append(url)
            status, content_type, text = pages.get(url, (404, "text/html", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=10)

    assert "http://lab.test/profile" in result["endpoints"]
    assert "http://lab.test/logout.php" not in requested
    assert "http://lab.test/account?action=delete" not in requested
    assert result["skipped_state_changing"] == 2
    assert "state_changing_gets_not_fetched" in result["coverage_gaps"]




def test_missing_validator_is_terminal_human_review() -> None:
    from webpent.agents.validator import agent as validator_agent
    from webpent.models.findings import Finding, Severity

    finding = Finding(
        title="Candidate file read",
        severity=Severity.MEDIUM,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/file.php",
        vuln_class="lfi",
        confidence_level="Pending",
    )

    updated = validator_agent._validate_with_tool(finding, "lfi", llm=None)

    assert updated.confidence_level == "Needs Human Review"
    assert updated.evidence["validation_unavailable"] is True
    assert updated.evidence["tool_infra_failure"] is True
    assert updated.evidence["missing_validator_class"] == "lfi"
    assert "not confirmation" in updated.reasoning.lower()



def test_exploit_chainer_does_not_repropose_same_pair() -> None:
    from uuid import uuid4

    from webpent.agents.exploit_chainer.agent import _find_chain_candidates
    from webpent.models.findings import Finding, Severity, VulnClass

    redirect_id = uuid4()
    xss_id = uuid4()
    redirect = Finding(
        id=redirect_id,
        title="Open redirect",
        severity=Severity.MEDIUM,
        description="redirect",
        tool_name="redirect_scanner",
        url="http://lab.test/redirect",
        vuln_class=VulnClass.OPEN_REDIRECT.value,
        confidence_level="Tool-Confirmed",
        evidence={"tool_confirmed_by": "test.fixture"},
    )
    xss = Finding(
        id=xss_id,
        title="Reflected XSS",
        severity=Severity.HIGH,
        description="xss",
        tool_name="dalfox",
        url="http://lab.test/search",
        vuln_class=VulnClass.XSS.value,
        confidence_level="Tool-Confirmed",
        evidence={"tool_confirmed_by": "test.fixture"},
    )
    chained = Finding(
        title="Chained candidate",
        severity=Severity.HIGH,
        description="candidate",
        url="http://lab.test/search",
        vuln_class=VulnClass.XSS.value,
        confidence_level="Pending",
        tool_name="exploit_chainer",
        evidence={
            "source_finding_a": str(redirect_id),
            "source_finding_b": str(xss_id),
        },
    )

    assert _find_chain_candidates([redirect, xss, chained]) == []
    assert len(_find_chain_candidates([redirect, xss])) == 1



def test_offline_payload_generation_is_deterministic_and_non_retryable() -> None:
    from webpent.agents.payload_generator.agent import _generate_payloads_for_finding
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="Reflected XSS candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/search?q=x",
        vuln_class=VulnClass.XSS.value,
    )

    # GOED made offline (LLM-disabled) payload generation deterministic-in-
    # structure for XSS specifically: a bounded canary payload is always
    # produced (so the browser sandbox still has a candidate to validate),
    # but each canary token is freshly generated and non-repeating (so a
    # captured/replayed payload can't be reused to spoof a later result).
    # Every other vuln class still returns ([], None) because their
    # validators are tool/OOB driven. See RECONCILIATION_REPORT.md.
    payloads_1, canary_1 = _generate_payloads_for_finding(finding, None)
    payloads_2, canary_2 = _generate_payloads_for_finding(finding, None)

    assert payloads_1 == [f'<svg/onload=alert("{canary_1}")>']
    assert payloads_2 == [f'<svg/onload=alert("{canary_2}")>']
    assert canary_1 != canary_2, "canary tokens must not be replayable/retryable"

    lfi_finding = finding.model_copy(update={"vuln_class": VulnClass.LFI.value})
    assert _generate_payloads_for_finding(lfi_finding, None) == ([], None)



def test_missing_validator_finding_cannot_reenter_optimizer() -> None:
    from webpent.graph.builder import NODE_DEVILS_ADVOCATE, route_after_validator
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="Candidate file read",
        severity=Severity.MEDIUM,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/file.php",
        vuln_class=VulnClass.LFI.value,
        confidence_level="Needs Human Review",
        evidence={
            "validation_unavailable": True,
            "tool_infra_failure": True,
        },
    )

    assert route_after_validator(
        {
            "findings": [finding],
            "payloads_to_test": {str(finding.id): ["stale-payload"]},
            "optimization_retries": {str(finding.id): 0},
        }
    ) == NODE_DEVILS_ADVOCATE



def test_tool_infra_failure_also_blocks_optimizer_even_if_confidence_is_pending() -> None:
    from webpent.graph.builder import NODE_DEVILS_ADVOCATE, route_after_validator
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="SQL injection candidate",
        severity=Severity.HIGH,
        description="candidate",
        tool_name="hypothesis_analyzer",
        url="http://lab.test/item?id=1",
        vuln_class=VulnClass.SQLI.value,
        confidence_level="Pending",
        evidence={"tool_infra_failure": True},
    )

    assert route_after_validator(
        {
            "findings": [finding],
            "payloads_to_test": {str(finding.id): ["__SQLMAP_TOOL_DRIVEN__"]},
            "optimization_retries": {str(finding.id): 0},
        }
    ) == NODE_DEVILS_ADVOCATE




def test_http_surface_enriches_from_sitemap_openapi_and_graphql(monkeypatch) -> None:
    from webpent.shared import http as http_module
    from webpent.shared.http_discovery import discover_http_surface

    pages = {
        "http://lab.test/robots.txt": (
            200,
            "text/plain",
            "Sitemap: http://lab.test/sitemap.xml\nDisallow: /admin",
        ),
        "http://lab.test/sitemap.xml": (
            200,
            "application/xml",
            "<urlset><url><loc>http://lab.test/from-sitemap</loc></url></urlset>",
        ),
        "http://lab.test/openapi.json": (
            200,
            "application/json",
            '{"paths":{"/api/orders":{"get":{}}}}',
        ),
        "http://lab.test/from-sitemap": (200, "text/html", "<h1>sitemap</h1>"),
        "http://lab.test/api/orders": (200, "application/json", "{}"),
        "http://lab.test/graphql": (405, "application/json", "{}"),
    }
    requested: list[str] = []

    class FakeResponse:
        def __init__(self, status_code: int, content_type: str, text: str) -> None:
            self.status_code = status_code
            self.headers = {"content-type": content_type}
            self.text = text
            self.content = text.encode("utf-8")

    class FakeClient:
        def get(self, url: str) -> FakeResponse:
            requested.append(url)
            status, content_type, text = pages.get(url, (404, "text/plain", ""))
            return FakeResponse(status, content_type, text)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(http_module, "make_safe_httpx_client", lambda **_kwargs: FakeClient())

    result = discover_http_surface("http://lab.test/", max_pages=10)

    assert "http://lab.test/from-sitemap" in result["endpoints"]
    assert "http://lab.test/api/orders" in result["endpoints"]
    assert result["discovery_metadata"]["robots_fetched"] is True
    assert result["discovery_metadata"]["sitemap_urls"] == ["http://lab.test/sitemap.xml"]
    assert result["discovery_metadata"]["openapi_urls"] == ["http://lab.test/openapi.json"]
    assert result["discovery_metadata"]["graphql_urls"] == ["http://lab.test/graphql"]
    assert all(not url.startswith("http://outside") for url in requested)



def test_f03_openapi_path_templates_materialized_not_literal_braces() -> None:
    """F-03 (RA-1): OpenAPI {param} path templates must be materialized to 1."""
    from webpent.shared.http_discovery import _openapi_discovered_urls
    payload = {"paths": {"/api/invoices/{id}": {"get": {}}, "/api/users/{userId}/posts/{postId}": {"get": {}}, "/api/orders": {"get": {}}}}
    result = _openapi_discovered_urls(payload, "http://lab.test")
    assert "http://lab.test/api/invoices/1" in result, f"F-03 FAIL: {result}"
    assert "http://lab.test/api/users/1/posts/1" in result, f"F-03 FAIL: {result}"
    assert "http://lab.test/api/orders" in result
    assert not any("{id}" in url for url in result), f"F-03 FAIL: literal braces in {result}"
    assert not any("{userId}" in url for url in result), f"F-03 FAIL: literal braces in {result}"
    assert not any("{postId}" in url for url in result), f"F-03 FAIL: literal braces in {result}"

def test_f03_openapi_multiple_templates_single_materialization() -> None:
    """F-03: a single templated path produces exactly ONE probe URL (bounded)."""
    from webpent.shared.http_discovery import _openapi_discovered_urls
    payload = {"paths": {"/api/items/{id}": {"get": {}}}}
    result = _openapi_discovered_urls(payload, "http://lab.test")
    assert result == ["http://lab.test/api/items/1"], f"F-03 FAIL: {result}"
