"""UM-DR-44 B3 — 307/308 redirects must not pass via the GET fallback.

The redirect guard's second fallback allowed a redirect when the target
origin was allowed for GET, regardless of the redirect status code —
without checking it.  For 307/308, httpx re-issues the ORIGINAL method
(POST), so passing it under a "it will become a GET" justification meant
an actual POST was executed outside the method constraints.

Required semantics:

* 301/302/303 genuinely downgrade to GET — the GET fallback stays
  legitimate for those codes;
* 307/308 re-issue the original method — the target must pass under the
  ORIGINAL method itself, or the redirect is refused;
* GET/HEAD originals keep their exact previous behavior for every code.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from webpent.shared import http as http_mod
from webpent.shared.http import SSRFRedirectBlockedError


def _response(status_code: int, location: str, method: str = "POST",
              request_url: str = "https://target.example.com/submit") -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url = httpx.URL(request_url)
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = httpx.Headers({"location": location})
    resp.url = httpx.URL(request_url)
    resp.request = req
    # url.join(location) must behave like a real httpx.URL join
    resp.url.join = lambda other: httpx.URL(request_url).join(other)
    return resp


@pytest.fixture(autouse=True)
def get_only_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Target origin allowed for GET only — every POST must be denied."""

    def fake_allowed(value: str, *, method: str | None = None) -> bool:
        url = str(value)
        if "evil.example.net" in url:
            return False  # never in scope
        if "other-origin.example.com" not in url:
            return True  # same-origin/target redirect: always fine
        return (method or "GET").upper() in {"GET", "HEAD"}

    monkeypatch.setattr(http_mod, "is_engagement_origin_allowed", fake_allowed)
    # keep the SSRF blocklist from interfering with these cases
    monkeypatch.setattr(http_mod, "_is_blocked_host", lambda host: False)
    monkeypatch.setattr(http_mod, "is_engagement_target_host", lambda host: False)


class TestTemporaryAndPermanentRedirects:
    def test_308_post_to_get_only_origin_blocked(self) -> None:
        """RED on the current tree: allowed via the GET fallback."""
        resp = _response(308, "https://other-origin.example.com/x", method="POST")
        with pytest.raises(SSRFRedirectBlockedError):
            http_mod._redirect_guard_decision(resp)

    def test_307_post_to_get_only_origin_blocked(self) -> None:
        resp = _response(307, "https://other-origin.example.com/x", method="POST")
        with pytest.raises(SSRFRedirectBlockedError):
            http_mod._redirect_guard_decision(resp)

    def test_308_delete_to_get_only_origin_blocked(self) -> None:
        resp = _response(308, "https://other-origin.example.com/x", method="DELETE")
        with pytest.raises(SSRFRedirectBlockedError):
            http_mod._redirect_guard_decision(resp)


class TestGenuineDowngradesStillPass:
    def test_301_post_to_get_only_origin_allowed(self) -> None:
        """301 genuinely downgrades POST to GET — fallback stays valid."""
        resp = _response(301, "https://other-origin.example.com/x", method="POST")
        http_mod._redirect_guard_decision(resp)  # must NOT raise

    def test_302_post_to_get_only_origin_allowed(self) -> None:
        resp = _response(302, "https://other-origin.example.com/x", method="POST")
        http_mod._redirect_guard_decision(resp)

    def test_303_post_to_get_only_origin_allowed(self) -> None:
        resp = _response(303, "https://other-origin.example.com/x", method="POST")
        http_mod._redirect_guard_decision(resp)


class TestOriginalMethodStillHonored:
    def test_307_get_to_get_only_origin_allowed(self, get_only_origin) -> None:
        resp = _response(307, "https://other-origin.example.com/x", method="GET")
        http_mod._redirect_guard_decision(resp)

    def test_308_post_to_post_allowed_origin_passes(self, get_only_origin) -> None:
        """Target allows POST itself — no fallback needed, must pass."""
        resp = _response(308, "https://target.example.com/y", method="POST")
        http_mod._redirect_guard_decision(resp)

    def test_307_post_to_out_of_scope_origin_blocked(self, get_only_origin) -> None:
        resp = _response(307, "https://evil.example.net/x", method="GET")
        # origin never allowed at all -> blocked even for GET
        with pytest.raises(SSRFRedirectBlockedError):
            http_mod._redirect_guard_decision(resp)


class TestNonRedirectCodesUnaffected:
    def test_200_with_location_header_ignored(self, get_only_origin) -> None:
        resp = _response(200, "https://evil.example.net/x", method="POST")
        http_mod._redirect_guard_decision(resp)  # no redirect semantics

    def test_304_without_location_ignored(self, get_only_origin) -> None:
        resp = _response(304, "", method="POST")
        http_mod._redirect_guard_decision(resp)
