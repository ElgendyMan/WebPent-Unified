"""UM-DR-44 B7 — the GraphQL introspection oracle fired on REQUEST
success, not response CONTENT.

``graphql_testing_node`` Probe 1 appends an introspection-exposure
finding whenever ``baseline and candidate and negative_control`` are
all truthy — i.e. whenever the three HTTP exchanges merely RETURNED
(evidence dicts are always truthy when a response arrived, regardless
of status code or body).  A server that answers
``403 {"errors": [...]}`` "introspection disabled" to all three probes
still produced a positive finding — the finding description even
claims "Full GraphQL schema returned" while the recorded body contains
no schema at all.

Required semantics (tighten without weakening):

* the CANDIDATE response must actually look like an introspection
  result — a parsed ``__schema`` (via the framework's own
  ``parse_graphql_introspection``) or a 2xx body containing
  ``__schema``;
* the BASELINE must look like a normal GraphQL response (``__typename``
  answered or a GraphQL errors array — i.e. the endpoint is a live
  GraphQL endpoint at all);
* the NEGATIVE CONTROL (introspection on a non-GraphQL URL) must NOT
  itself contain ``__schema`` (control validity);
* when the candidate is a refusal (403/400 + errors array, no
  ``__schema`` anywhere), NO finding is emitted — the probe records
  a suppressed/no-signal outcome instead.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from webpent.agents.graphql_testing.agent import graphql_testing_node


def _resp(status: int, body: str) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = "https://target.example.com/graphql"
    return r


def _state() -> dict:
    return {
        "target": MagicMock(url="https://target.example.com"),
        "crawled_data": {
            "graphql_urls": ["https://target.example.com/graphql"],
            "graphql_operations": [{"name": "users"}],
        },
        "findings": [],
        "messages": [],
    }


def _run(client_responses: list[MagicMock]) -> dict:
    """Run the node with _post mocked to return the given responses in
    order (any request beyond the list returns a 403 refusal)."""
    state = _state()
    seq = list(client_responses)

    def fake_post(client, endpoint, payload, budget, governor, host):
        if seq:
            current = seq.pop(0)
            return {
                "status_code": current.status_code,
                "response_body": current.text,
                "headers": {},
                "elapsed_ms": 1,
                "url": endpoint,
            }
        return {
            "status_code": 403,
            "response_body": '{"errors": [{"message": "introspection disabled"}]}',
            "headers": {},
            "elapsed_ms": 1,
            "url": endpoint,
        }

    with patch(
        "webpent.agents.graphql_testing.agent.get_settings"
    ) as settings, patch(
        "webpent.agents.graphql_testing.agent._post", side_effect=fake_post
    ), patch(
        "webpent.agents.graphql_testing.agent.RequestRateGovernor"
    ) as gov, patch(
        "webpent.agents.graphql_testing.agent.make_safe_httpx_client"
    ) as mk:
        settings.return_value.enable_graphql_testing = True
        settings.return_value.enable_graphql_introspection_probe_delay = False
        mk.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mk.return_value.__exit__ = MagicMock(return_value=False)
        gov.return_value = MagicMock()
        gov.return_value.acquire.return_value.__enter__ = MagicMock(
            return_value=MagicMock(aborted=False))
        gov.return_value.acquire.return_value.__exit__ = MagicMock(
            return_value=False)
        return graphql_testing_node(state)


class TestIntrospectionOracleContentBased:
    def test_refusing_server_produces_no_finding(self) -> None:
        """RED on the current tree: 403 'introspection disabled' on all
        probes still appended a positive finding (request-success
        oracle)."""
        refusing = _resp(
            403, '{"errors": [{"message": "introspection disabled"}]}')
        out = _run([refusing, refusing, refusing, refusing, refusing,
                    refusing, refusing, refusing])
        new_findings = out.get("findings", [])
        introspection = [
            f for f in new_findings
            if "introspection" in str(getattr(f, "title", "")).lower()
        ]
        assert not introspection

    def test_real_schema_response_still_produces_finding(self) -> None:
        """A genuine introspection response keeps producing the finding
        (no weakening)."""
        typename_ok = _resp(200, '{"data": {"__typename": "Query"}}')
        schema_ok = _resp(
            200,
            '{"data": {"__schema": {"types": [{"name": "Query"}]}}}',
        )
        control = _resp(404, "Not Found")
        out = _run([typename_ok, schema_ok, control])
        new_findings = out.get("findings", [])
        introspection = [
            f for f in new_findings
            if "introspection" in str(getattr(f, "title", "")).lower()
        ]
        assert introspection, "real schema must still produce a finding"

    def test_disabled_flag_zero_probes(self) -> None:
        with patch(
            "webpent.agents.graphql_testing.agent.get_settings"
        ) as settings:
            settings.return_value.enable_graphql_testing = False
            out = graphql_testing_node(_state())
            assert not out.get("findings")
