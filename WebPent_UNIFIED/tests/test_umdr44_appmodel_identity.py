"""UM-DR-44 A5a — endpoint identity is the canonical tuple (RED on 6f3dc7c).

The three endpoint-id construction sites (builder.ensure_endpoint ~201,
builder observation-link ~337, models.apply_observation ~356) all build
the identity from f"{host}{path}" — scheme and port are DROPPED:

* https://example.com/x and http://example.com/x collapse into ONE
  entity (evidence merged across different trust boundaries);
* https://example.com/x and https://example.com:8443/x collapse the
  same way (different origin);
* in add_entity's merge path the provenance tie keeps the EXISTING
  record, so methods_seen=['GET'] survives and ['GET','POST'] is
  discarded — methods must ACCUMULATE (set semantics) regardless of
  which record wins;
* metadata carries only host/path — scheme/port are not observable.

Required (this prompt):

* ONE SSOT: _endpoint_tuple_key(url) -> (scheme, host, effective_port,
  path) | None; _endpoint_id_of(url) builds the id from it; both build
  paths and apply_observation use them;
* effective_port = explicit port or scheme default (http→80, https→443)
  so https://h/x ≡ https://h:443/x and http://h/x ≠ https://h/x;
* URL without scheme or host → None → ABSTAIN (no invented identity);
* metadata carries scheme/port/host/path;
* methods_seen accumulates in the merge path (independent of the
  provenance winner); status_code keeps the latest (current state).
"""

from __future__ import annotations

import pytest

from webpent.appmodel.models import ApplicationModel

try:  # RED on 6f3dc7c: the SSOT does not exist on the base tree.
    from webpent.appmodel.builder import _endpoint_id_of, _endpoint_tuple_key
except ImportError:  # pragma: no cover — the RED state this file proves
    _endpoint_id_of = None
    _endpoint_tuple_key = None

EVID = {"evidence_ref": "req-1"}


def _endpoints(model: ApplicationModel) -> list[dict]:
    return [
        {"id": eid, **(e.metadata or {})}
        for eid, e in model.entities.items()
        if str(e.kind) == "endpoint"
    ]


class TestTupleKeySSOT:
    def test_scheme_change_is_different_endpoint(self) -> None:
        """RED: http and https on the same host+path must be DISTINCT."""
        m = ApplicationModel()
        m.apply_observation({"url": "https://example.com/api/orders", **EVID})
        m.apply_observation({"url": "http://example.com/api/orders",
                             "evidence_ref": "req-2"})
        assert len(_endpoints(m)) == 2

    def test_default_port_equivalence(self) -> None:
        """https://h/x ≡ https://h:443/x — same identity."""
        assert _endpoint_id_of("https://example.com/x") == \
            _endpoint_id_of("https://example.com:443/x")

    def test_explicit_port_distinct(self) -> None:
        """RED: :8443 must not merge with the implicit :443."""
        assert _endpoint_id_of("https://example.com/x") != \
            _endpoint_id_of("https://example.com:8443/x")

    def test_no_scheme_abstains(self) -> None:
        """A URL without a scheme has NO identity — the observation must
        abstain (recorded), not invent one from a bare host."""
        m = ApplicationModel()
        result = m.apply_observation({"url": "example.com/api/orders",
                                      **EVID})
        assert not [
            e for e in m.entities.values() if str(e.kind) == "endpoint"]
        assert any(
            a.get("what") == "endpoint" for a in result.get("abstained", []))

    def test_unparseable_url_abstains(self) -> None:
        m = ApplicationModel()
        result = m.apply_observation({"url": "::::not-a-url::::", **EVID})
        assert not [
            e for e in m.entities.values() if str(e.kind) == "endpoint"]
        assert any(
            a.get("what") == "endpoint" for a in result.get("abstained", []))


class TestMethodsAndMetadata:
    def test_methods_seen_accumulate_get_then_post(self) -> None:
        """RED: the tie-break currently keeps the OLD methods_seen."""
        m = ApplicationModel()
        m.apply_observation({"url": "https://example.com/api/orders",
                             "method": "GET", "evidence_ref": "req-1"})
        m.apply_observation({"url": "https://example.com/api/orders",
                             "method": "POST", "evidence_ref": "req-2"})
        endpoint = _endpoints(m)[0]
        assert set(endpoint.get("methods_seen") or []) >= {"GET", "POST"}

    def test_metadata_carries_scheme_and_port(self) -> None:
        """RED: metadata currently carries only host/path."""
        m = ApplicationModel()
        m.apply_observation({"url": "https://example.com:8443/api/orders",
                             **EVID})
        endpoint = _endpoints(m)[0]
        assert endpoint.get("scheme") == "https"
        assert int(endpoint.get("port")) == 8443
        assert endpoint.get("host") == "example.com"
        assert endpoint.get("path") == "/api/orders"


@pytest.mark.parametrize("url,expect", [
    ("https://example.com/x", ("https", "example.com", 443, "/x")),
    ("http://example.com/x", ("http", "example.com", 80, "/x")),
    ("https://example.com:8443/x", ("https", "example.com", 8443, "/x")),
    ("http://example.com:8080/x", ("http", "example.com", 8080, "/x")),
])
def test_tuple_key_values(url: str, expect: tuple) -> None:
    assert _endpoint_tuple_key(url) == expect


def test_tuple_key_none_for_bare_host() -> None:
    assert _endpoint_tuple_key("example.com/api") is None
