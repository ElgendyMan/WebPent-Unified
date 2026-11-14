# tests/test_cache_key_discovery.py
"""PROPOSALS_ULTIMATE_V2 §6 (2026-10-30) test suite: cache-key discovery.

Covers the fail-closed refusals (flag off, no endpoints, budget
exceeded), the strict differential taxonomy (candidate / refuted /
inconclusive / neutral, with a failed fetch never yielding a confident
verdict), end-to-end sweeps against an in-memory cache model and a LIVE
threaded HTTP fixture server that stores and reflects X-Forwarded-Host,
marker uniqueness, and the to_validator_inputs hand-off (only
``candidate`` verdicts pass; discovery never alleges poisoning itself).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.shared import cache_key_discovery as ckd
from webpent.shared.cache_key_discovery import (
    CacheKeyDiscoveryError,
    _differential,
    discover_cache_keys,
    to_validator_inputs,
)


# ---------------------------------------------------------------------------
# In-memory cache model.
#
# Behaviour switches:
#   keyed    -- candidate headers the cache DOES key on (separate entries)
#   reflect  -- candidate headers the origin echoes into the body
#   store    -- whether the cache stores responses for this path at all
#   counter  -- per-response sequence number written into every body
#               (models cache-generated noise: storage visible without
#               any marker reflection)
# ---------------------------------------------------------------------------

class _CacheModel:
    def __init__(
        self,
        *,
        keyed: frozenset[str] = frozenset(),
        reflect: frozenset[str] = frozenset(),
        store: bool = True,
        counter: bool = False,
    ) -> None:
        self.keyed = keyed
        self.reflect = reflect
        self.store = store
        self.counter = counter
        self.entries: dict[tuple, tuple[int, str]] = {}
        self._n = 0

    def fetch(
        self, url: str, headers: Any, params: Any
    ) -> "tuple[int, str]":
        key_headers = tuple(
            sorted((k, v) for k, v in dict(headers).items() if k in self.keyed)
        )
        key = (url, key_headers, tuple(sorted(dict(params).items())))
        if key in self.entries:
            return self.entries[key]
        self._n += 1
        body = "BASE"
        for name in self.reflect:
            value = dict(headers).get(name)
            if value:
                body += f" ref[{name}]={value}"
        if self.counter:
            body += f" seq={self._n}"
        response = (200, body)
        if self.store:
            self.entries[key] = response
        return response


def _run(
    model: _CacheModel,
    pools: Any,
    endpoints: Any,
    **kwargs: Any,
) -> "tuple[ckd.CacheKeyResult, ...]":
    header = (pools,) if isinstance(pools, str) else tuple(pools)
    original_h = ckd.CACHE_KEY_HEADER_CANDIDATES
    original_p = ckd.CACHE_KEY_PARAM_CANDIDATES
    ckd.CACHE_KEY_HEADER_CANDIDATES = header
    ckd.CACHE_KEY_PARAM_CANDIDATES = ()
    try:
        return discover_cache_keys(
            [endpoints] if isinstance(endpoints, str) else list(endpoints),
            fetcher=model.fetch,
            enable_cache_key_discovery=True,
            **kwargs,
        )
    finally:
        ckd.CACHE_KEY_HEADER_CANDIDATES = original_h
        ckd.CACHE_KEY_PARAM_CANDIDATES = original_p


class TestFailClosed:
    def test_flag_off_refused(self) -> None:
        with pytest.raises(CacheKeyDiscoveryError, match="cache_key_discovery_flag_off"):
            discover_cache_keys(
                ["http://t/"], fetcher=lambda *a: (200, "x"),
                enable_cache_key_discovery=False,
            )

    def test_no_endpoints_refused(self) -> None:
        with pytest.raises(
            CacheKeyDiscoveryError, match="cache_key_discovery_requires_endpoints"
        ):
            discover_cache_keys(
                [], fetcher=lambda *a: (200, "x"), enable_cache_key_discovery=True
            )

    def test_budget_exceeded_refused(self) -> None:
        with pytest.raises(CacheKeyDiscoveryError, match="cache_key_budget_exceeded"):
            discover_cache_keys(
                ["http://t/a", "http://t/b"],
                fetcher=lambda *a: (200, "x"),
                enable_cache_key_discovery=True,
                max_endpoints=1,
            )

    def test_budget_at_cap_allowed(self) -> None:
        model = _CacheModel(store=False)
        results = _run(model, "x-nope", ["http://t/a"], max_endpoints=1)
        assert len(results) == 1


class TestDifferentialTaxonomy:
    M = "webpent-ck-test-header-x-h"

    def test_reflected_and_stored_is_candidate(self) -> None:
        baseline = (200, "BASE")
        probe = (200, f"BASE ref[h]={self.M}")
        victim = (200, f"BASE ref[h]={self.M}")
        reflected, stored, verdict = _differential(baseline, probe, victim, self.M)
        assert (reflected, stored, verdict) == (True, True, "candidate")

    def test_probe_echo_without_storage_is_refuted(self) -> None:
        baseline = (200, "BASE")
        probe = (200, f"BASE ref[h]={self.M}")  # app echoes unkeyed input
        victim = (200, "BASE")  # byte-identical: nothing was stored
        reflected, stored, verdict = _differential(baseline, probe, victim, self.M)
        assert (reflected, stored, verdict) == (True, False, "refuted")

    def test_storage_without_reflection_is_inconclusive(self) -> None:
        baseline = (200, "BASE seq=0")
        probe = (200, "BASE seq=1")
        victim = (200, "BASE seq=1")
        reflected, stored, verdict = _differential(baseline, probe, victim, self.M)
        assert (reflected, stored, verdict) == (False, True, "inconclusive")

    def test_neither_is_neutral(self) -> None:
        reflected, stored, verdict = _differential(
            (200, "BASE"), (200, "BASE"), (200, "BASE"), self.M
        )
        assert (reflected, stored, verdict) == (False, False, "neutral")

    def test_marker_in_baseline_is_delivered_candidate(self) -> None:
        # Path-keyed cache: the poisoned entry is served to the baseline
        # fetch too. The marker reaching a request that carried no
        # marker-bearing input is delivery, on its own.
        reflected, stored, verdict = _differential(
            (200, f"BASE xfwd={self.M}"),  # baseline served poisoned entry
            (200, f"BASE xfwd={self.M}"),
            (200, f"BASE xfwd={self.M}"),
            self.M,
        )
        assert verdict == "candidate"

    def test_failed_fetch_never_confident(self) -> None:
        # no baseline -> cannot establish the differential
        assert _differential(None, (200, f"x{self.M}"), (200, f"x{self.M}"), self.M)[2] == "inconclusive"
        # no victim -> cannot confirm storage
        assert _differential((200, "BASE"), (200, f"x{self.M}"), None, self.M)[2] == "inconclusive"


class TestEndToEndModel:
    def test_unkeyed_store_and_reflect_is_candidate(self) -> None:
        model = _CacheModel(reflect=frozenset({"x-forwarded-host"}))
        results = _run(model, "x-forwarded-host", "http://t/page")
        cands = results[0].candidates
        assert len(cands) == 1
        assert cands[0].verdict == "candidate"
        assert cands[0].reflected and cands[0].stored

    def test_app_echo_without_cache_is_refuted(self) -> None:
        # Origin reflects the header, but nothing is ever stored.
        model = _CacheModel(reflect=frozenset({"x-forwarded-host"}), store=False)
        results = _run(model, "x-forwarded-host", "http://t/page")
        assert results[0].candidates[0].verdict == "refuted"

    def test_storage_without_reflection_is_inconclusive(self) -> None:
        # Cache stores unkeyed responses (counter advances per fetch and is
        # frozen into the stored body), but the origin reflects nothing.
        model = _CacheModel(counter=True)
        results = _run(model, "x-forwarded-host", "http://t/page")
        assert results[0].candidates[0].verdict == "inconclusive"

    def test_keyed_header_is_refuted(self) -> None:
        # Cache keys the candidate header: the probe is stored under its
        # own key and reflected, the victim misses and re-serves the
        # origin. Reflection with no shared-key storage -> refuted (the
        # input is keyed, so it is not an unkeyed primitive).
        model = _CacheModel(
            keyed=frozenset({"x-forwarded-host"}),
            reflect=frozenset({"x-forwarded-host"}),
        )
        results = _run(model, "x-forwarded-host", "http://t/page")
        assert results[0].candidates[0].verdict == "refuted"

    def test_no_reflection_no_storage_is_neutral(self) -> None:
        model = _CacheModel(reflect=frozenset(), store=False)
        results = _run(model, "x-forwarded-host", "http://t/page")
        assert results[0].candidates[0].verdict == "neutral"

    def test_markers_unique_per_candidate(self) -> None:
        model = _CacheModel(reflect=frozenset({"x-forwarded-host"}))
        results = _run(
            model, ["x-forwarded-host", "x-original-url"], "http://t/page"
        )
        markers = [c.marker for c in results[0].candidates]
        assert len(set(markers)) == len(markers)
        assert all(m.startswith("webpent-ck-") for m in markers)

    def test_marker_prefix_pinned(self, monkeypatch) -> None:
        model = _CacheModel(reflect=frozenset({"x-forwarded-host"}))
        results = discover_cache_keys(
            ["http://t/page"],
            fetcher=model.fetch,
            enable_cache_key_discovery=True,
            marker_prefix="fixed-base",
        )
        marker = results[0].candidates[0].marker
        assert marker.startswith("webpent-ck-fixed-base-")


class TestValidatorHandoff:
    def test_only_candidates_pass(self) -> None:
        results = (
            ckd.CacheKeyResult(
                endpoint="http://t/page",
                candidates=(
                    ckd.CacheKeyCandidate(
                        "header", "x-forwarded-host", "m1", True, True, "candidate"
                    ),
                    ckd.CacheKeyCandidate(
                        "header", "x-original-url", "m2", True, False, "refuted"
                    ),
                    ckd.CacheKeyCandidate(
                        "param", "utm_source", "m3", False, True, "inconclusive"
                    ),
                    ckd.CacheKeyCandidate(
                        "header", "x-cache", "m4", False, False, "neutral"
                    ),
                ),
            ),
        )
        inputs = to_validator_inputs(results)
        assert len(inputs) == 1
        assert inputs[0] == {
            "endpoint": "http://t/page",
            "kind": "header",
            "name": "x-forwarded-host",
            "marker": "m1",
        }

    def test_empty_when_no_candidates(self) -> None:
        results = (
            ckd.CacheKeyResult(
                endpoint="http://t/page",
                candidates=(
                    ckd.CacheKeyCandidate(
                        "header", "x-cache", "m4", False, False, "neutral"
                    ),
                ),
            ),
        )
        assert to_validator_inputs(results) == ()


# ---------------------------------------------------------------------------
# LIVE fixture server: real HTTP over the loopback, cache keyed on path
# only, origin reflects X-Forwarded-Host into the body. Skipped nowhere
# (stdlib only), mirrors the §5 live-server style.
# ---------------------------------------------------------------------------

class _FixtureHandler(BaseHTTPRequestHandler):
    server_version = "ckfixture/1"

    def do_GET(self) -> None:  # noqa: N802
        cache = self.server.cache  # type: ignore[attr-defined]
        path = self.path
        if path in cache:
            body = cache[path]
        else:
            body = b"BASE"
            host = self.headers.get("X-Forwarded-Host")
            if host:
                body = b"BASE xfwd=" + host.encode("ascii", "replace")
            cache[path] = body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: Any) -> None:
        pass


class TestLiveFixtureServer:
    @pytest.fixture()
    def server(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        httpd.cache = {}
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield httpd
        finally:
            httpd.shutdown()
            httpd.server_close()

    @staticmethod
    def _http_fetcher(url: str, headers: Any, params: Any) -> "tuple[int, str]":
        import http.client
        from urllib.parse import urlsplit, urlencode

        parts = urlsplit(url)
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
        path = parts.path or "/"
        if params:
            path += "?" + urlencode(dict(params))
        conn.request("GET", path, headers=dict(headers))
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        conn.close()
        return resp.status, body

    def test_x_forwarded_host_detected_as_candidate(self, server) -> None:
        url = f"http://127.0.0.1:{server.server_address[1]}/page"
        results = discover_cache_keys(
            [url],
            fetcher=self._http_fetcher,
            enable_cache_key_discovery=True,
            marker_prefix="webpent-ck-live",
        )
        verdicts = {
            c.name: c.verdict
            for c in results[0].candidates
            if c.verdict != "neutral"
        }
        # The fixture stores every response keyed on path and reflects
        # X-Forwarded-Host: the poisoned probe's body is served to the
        # unpoisoned victim -> reflected AND stored.
        assert verdicts.get("x-forwarded-host") == "candidate"
        inputs = to_validator_inputs(results)
        assert [i["name"] for i in inputs] == ["x-forwarded-host"]

    def test_sweep_settings_gate(self, server) -> None:
        from webpent.config.settings import get_settings

        with activate_settings(Settings(enable_cache_key_discovery=False)):
            assert get_settings().enable_cache_key_discovery is False
        with activate_settings(Settings(enable_cache_key_discovery=True)):
            assert get_settings().enable_cache_key_discovery is True
            assert get_settings().cache_key_max_endpoints == 15
