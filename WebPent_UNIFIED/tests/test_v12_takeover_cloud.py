from __future__ import annotations

from webpent.agents.cloud_storage import agent as cloud_agent
from webpent.agents.subdomain_takeover import agent as takeover_agent
from webpent.models.targets import Target


class _Response:
    def __init__(self, status_code: int, text: str, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _Client:
    def __init__(self, response: _Response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, *args, **kwargs):
        return self.response


def _factory(response):
    return lambda **kwargs: _Client(response)


def test_takeover_requires_cname_and_provider_fingerprint(monkeypatch):
    target = Target(
        url="https://example.com",
        in_scope_regex=[r"(?:[a-z0-9-]+\.)?example\.com"],
    )
    monkeypatch.setattr(takeover_agent, "_resolve_cname", lambda host: "orphan.github.io")
    monkeypatch.setattr(
        takeover_agent,
        "make_safe_httpx_client",
        _factory(_Response(404, "There isn't a GitHub Pages site here.", {"server": "github"})),
    )
    findings, observations, gaps = takeover_agent.verify_subdomain_takeover(
        target, ["orphan.example.com"]
    )
    assert len(findings) == 1
    assert findings[0].vuln_class == "subdomain_takeover"
    assert observations[0]["provider"] == "github-pages"
    assert gaps == []


def test_takeover_does_not_promote_cname_without_fingerprint(monkeypatch):
    target = Target(url="https://example.com", in_scope_regex=[r"example\.com"])
    monkeypatch.setattr(takeover_agent, "_resolve_cname", lambda host: "orphan.github.io")
    monkeypatch.setattr(
        takeover_agent,
        "make_safe_httpx_client",
        _factory(_Response(200, "Application is healthy", {"server": "github"})),
    )
    findings, observations, _ = takeover_agent.verify_subdomain_takeover(
        target, ["example.com"]
    )
    assert findings == []
    assert observations[0]["status"] == "provider_responded_without_takeover_fingerprint"


def test_takeover_rejects_out_of_scope_host(monkeypatch):
    target = Target(url="https://example.com")
    monkeypatch.setattr(takeover_agent, "_resolve_cname", lambda host: "orphan.github.io")
    findings, observations, _ = takeover_agent.verify_subdomain_takeover(
        target, ["evil.example.net"]
    )
    assert findings == []
    assert observations[0]["status"] == "out_of_scope"


def test_cloud_listing_requires_provider_specific_evidence(monkeypatch):
    target = Target(url="https://bucket.s3.amazonaws.com")
    body = "<ListBucketResult><Contents><Key>public.txt</Key></Contents></ListBucketResult>"
    monkeypatch.setattr(
        cloud_agent,
        "make_safe_httpx_client",
        _factory(_Response(200, body, {"x-amz-bucket-region": "us-east-1"})),
    )
    findings, observations, gaps = cloud_agent.verify_cloud_storage(target)
    assert len(findings) == 1
    assert findings[0].vuln_class == "cloud_storage_exposure"
    assert observations[0]["status"] == "public_listing_confirmed"
    assert gaps == []


def test_cloud_200_without_listing_is_not_a_finding(monkeypatch):
    target = Target(url="https://bucket.s3.amazonaws.com")
    monkeypatch.setattr(
        cloud_agent,
        "make_safe_httpx_client",
        _factory(_Response(200, "Access denied by application", {})),
    )
    findings, observations, _ = cloud_agent.verify_cloud_storage(target)
    assert findings == []
    assert observations[0]["matched_evidence"] == []
