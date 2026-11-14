"""UM-DR-28 tests — the campaign-side stateful discovery component
(production/stateful_discovery.py), unit level.

Coverage contract:
  1. mine_probe_cases — structural grouping, read-triple shape, cyclic
     control, control_alternatives, requires_state_transition from the
     directory's stateful surface, cap, determinism, no naming
     assumptions (unguessable tokens are just id-tokens).
  2. CampaignProberClient — scope refusal BEFORE any request, refusal
     accounting, translation to the executor's request_plan shape.
  3. run_stateful_discovery — budget honesty, findings only on
     CONFIRMED, fail-soft on garbage, summary shape, scope-refused
     cases never probed.
  4. The evidence-integrity contract — ordered transitions, the full
     application log (singles + pairs), nothing silently disappearing.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.production.stateful_discovery import (  # noqa: E402
    MAX_TOTAL_REQUESTS,
    CampaignProberClient,
    mine_probe_cases,
    run_stateful_discovery,
)
from webpent.production.stateful_probe import StatefulCaseProber  # noqa: E402
from webpent.production.transition_sources import ObservedSurfaceSource  # noqa: E402

INVENTORY = [
    {"method": "GET", "path": "/api/ledger/accounts/acct_1"},
    {"method": "GET", "path": "/api/ledger/accounts/acct_2"},
    {"method": "GET", "path": "/api/ledger/accounts/acct_3"},
    {"method": "GET", "path": "/api/ledger/accounts/acct_4"},
    {"method": "POST", "path": "/api/ledger/accounts/settle_9f3a1_3"},
    {"method": "POST", "path": "/api/ledger/bulk_reconcile"},   # other directory
    {"method": "GET", "path": "/health"},                        # no directory
]


class TestMineProbeCases:
    def test_structural_triples_without_naming_assumptions(self):
        cases = mine_probe_cases(INVENTORY)
        by_candidate = {c["candidate"]: c for c in cases}
        assert "/api/ledger/accounts/acct_2" in by_candidate
        case = by_candidate["/api/ledger/accounts/acct_3"]
        assert case["baseline"] == "/api/ledger/accounts/acct_1"  # first observed
        assert case["control"] == "/api/ledger/accounts/acct_4"   # next observed
        assert case["requires_state_transition"] is True          # directory has POSTs
        assert case["case_id"].startswith("SD-")

    def test_control_alternatives_in_observation_order(self):
        cases = mine_probe_cases(INVENTORY)
        case = {c["candidate"]: c for c in cases}["/api/ledger/accounts/acct_2"]
        # alternatives exclude the baseline (acct_1) and the control (acct_3)
        assert case["control_alternatives"] == ["/api/ledger/accounts/acct_4"]
        assert "/api/ledger/accounts/acct_1" not in case["control_alternatives"]

    def test_cyclic_control_wrap_and_self_exclusion(self):
        cases = mine_probe_cases(INVENTORY)
        last = {c["candidate"]: c for c in cases}["/api/ledger/accounts/acct_4"]
        assert last["control"] == "/api/ledger/accounts/acct_1"  # cyclic wrap
        assert last["control"] != last["candidate"]

    def test_cap_is_enforced(self):
        big = [
            {"method": "GET", "path": f"/api/x/items/item_{n}"} for n in range(40)
        ] + [{"method": "POST", "path": "/api/x/items/mutate_1"}]
        cases = mine_probe_cases(big, max_cases=5)
        assert len(cases) == 5

    def test_directory_without_stateful_surface(self):
        inv = [{"method": "GET", "path": f"/r/objs/o_{n}"} for n in range(4)]
        cases = mine_probe_cases(inv)
        assert cases and all(not c["requires_state_transition"] for c in cases)

    def test_too_few_reads_yield_nothing(self):
        inv = [
            {"method": "GET", "path": "/r/objs/o_1"},
            {"method": "GET", "path": "/r/objs/o_2"},
        ]
        assert mine_probe_cases(inv) == []

    def test_deterministic(self):
        assert mine_probe_cases(INVENTORY) == mine_probe_cases(INVENTORY)


class TestCampaignProberClient:
    def test_scope_refusal_before_any_request(self):
        sent = []

        def executor(plan):
            sent.append(plan)
            return SimpleNamespace(status_code=200, text="{}", headers={})

        client = CampaignProberClient(
            executor, base_url="http://t",
            allowed_prefixes=["/api/ledger"],
        )
        with pytest.raises(Exception):
            client.get("/internal/admin/accounts/acct_9")
        assert sent == []                      # nothing left the process
        assert client.scope_refusals == ["/internal/admin/accounts/acct_9"]
        response = client.get("/api/ledger/accounts/acct_1")
        assert response.status_code == 200
        assert len(sent) == 1
        assert sent[0].url == "http://t/api/ledger/accounts/acct_1"
        assert sent[0].method == "GET"

    def test_no_scope_declared_means_no_refusal(self):
        sent = []

        def executor(plan):
            sent.append(plan)
            return SimpleNamespace(status_code=200, text="{}", headers={})

        client = CampaignProberClient(executor, base_url="http://t")
        client.get("/anything/at/all")
        assert len(sent) == 1


class _ScriptedExecutor:
    """A minimal in-process target: routes -> (status, body)."""

    def __init__(self, routes, base_url):
        self.routes = routes
        self.base_url = base_url
        self.requests = []

    def __call__(self, plan):
        from urllib.parse import urlsplit
        self.requests.append((plan.method, urlsplit(plan.url).path))
        key = (plan.method, urlsplit(plan.url).path)
        status, body = self.routes.get(key, (404, '{"status": "not_found"}'))
        return SimpleNamespace(
            status_code=status, text=body,
            headers={"X-Actor-Echo": "attacker"},
        )


class TestRunStatefulDiscovery:
    def _routes(self):
        return {
            ("GET", "/api/ledger/accounts/acct_1"): (
                200, '{"owner": "attacker", "granted": true, "actor": "attacker"}'),
            ("GET", "/api/ledger/accounts/acct_2"): (
                403, '{"owner": "User_B", "granted": false, "actor": "attacker"}'),
            ("GET", "/api/ledger/accounts/acct_3"): (
                200, '{"owner": "User_B", "granted": true, "actor": "attacker"}'),
            ("GET", "/api/ledger/accounts/acct_4"): (
                403, '{"owner": "User_C", "granted": false, "actor": "attacker"}'),
        }

    def test_confirmed_outcome_promotes_finding_with_provenance(self):
        executor = _ScriptedExecutor(self._routes(), "http://t")
        state = {
            "base_url": "http://t",
            "engagement_id": "eng-1",
            "endpoint_inventory": [
                {"method": "GET", "path": "/api/ledger/accounts/acct_1"},
                {"method": "GET", "path": "/api/ledger/accounts/acct_2"},
                {"method": "GET", "path": "/api/ledger/accounts/acct_3"},
                {"method": "GET", "path": "/api/ledger/accounts/acct_4"},
            ],
        }
        summary = run_stateful_discovery(state, executor=executor, base_url="http://t")
        assert summary["enabled"] is True
        assert summary["cases_mined"] == 3
        assert summary["confirmed"] == 1
        finding = summary["findings"][0]
        evidence = finding.evidence
        assert evidence["confirmation_authority"] == "cqa_v2.guarded_causal_evaluate"
        assert evidence["case"]["candidate"] == "/api/ledger/accounts/acct_3"
        assert evidence["verdict"] == "CONFIRMED"
        assert finding.vuln_class in ("idor", "auth_bypass")
        assert summary["requests_issued"] <= MAX_TOTAL_REQUESTS
        # the per-case provenance record
        confirmed_case = [
            p for p in summary["per_case"] if p["verdict"] == "CONFIRMED"
        ][0]
        assert confirmed_case["requests"] > 0

    def test_budget_honesty(self):
        executor = _ScriptedExecutor(self._routes(), "http://t")
        state = {
            "base_url": "http://t",
            "endpoint_inventory": [
                {"method": "GET", "path": f"/api/ledger/accounts/acct_{n}"}
                for n in range(1, 5)
            ],
        }
        summary = run_stateful_discovery(
            state, executor=executor, base_url="http://t", max_requests=2
        )
        assert summary["budget_exhausted"] is True
        assert len(executor.requests) <= 2

    def test_scope_refused_cases_never_probed(self):
        executor = _ScriptedExecutor(self._routes(), "http://t")
        state = {
            "base_url": "http://t",
            "allowed_endpoints": ["/api/ledger"],
            "endpoint_inventory": [
                {"method": "GET", "path": "/api/ledger/accounts/acct_1"},
                {"method": "GET", "path": "/api/ledger/accounts/acct_2"},
                {"method": "GET", "path": "/api/ledger/accounts/acct_3"},
                {"method": "GET", "path": "/internal/admin/acct_9"},
                {"method": "GET", "path": "/internal/admin/acct_10"},
                {"method": "GET", "path": "/internal/admin/acct_11"},
            ],
        }
        summary = run_stateful_discovery(state, executor=executor, base_url="http://t")
        assert summary["cases_scope_refused"] >= 1
        assert "/internal/admin/acct_10" in summary["scope_refusals"]
        assert "/internal/admin/acct_11" in summary["scope_refusals"]
        probed = {p["candidate"] for p in summary["per_case"]}
        assert all(c.startswith("/api/ledger") for c in probed)

    def test_fail_soft_on_garbage(self):
        def executor(plan):
            raise RuntimeError("transport is broken")

        state = {"base_url": "http://t", "endpoint_inventory": INVENTORY}
        summary = run_stateful_discovery(state, executor=executor, base_url="http://t")
        assert summary["enabled"] is True
        assert summary["findings"] == []       # never a fake confirmation

    def test_no_inventory_means_no_cases(self):
        executor = _ScriptedExecutor({}, "http://t")
        summary = run_stateful_discovery(
            {"base_url": "http://t"}, executor=executor, base_url="http://t"
        )
        assert summary["cases_mined"] == 0
        assert summary["findings"] == []


class TestEvidenceIntegrity:
    def test_full_application_log_survives_pair_confirmation(self):
        """A composition confirmed via the pairwise loop must record the
        SINGLES applied before it (state persists — under-reporting the
        chain would be evidence loss)."""

        routes = {
            ("GET", "/x/res/own_1"): (200, '{"owner": "attacker", "granted": true, "actor": "attacker"}'),
            ("GET", "/x/res/target_1"): None,   # filled below (stateful)
            ("GET", "/x/res/ctrl_1"): (403, '{"owner": "User_C", "granted": false, "actor": "attacker"}'),
            ("POST", "/x/res/aaa_1"): (200, '{"status": "ok"}'),
            ("POST", "/x/res/bbb_1"): (200, '{"status": "ok"}'),
        }
        state_box = {"flipped": False}

        def body_for_target():
            if state_box["flipped"]:
                return '{"owner": "User_B", "granted": true, "actor": "attacker"}'
            return '{"owner": "attacker", "granted": true, "actor": "attacker"}'

        class Client:
            def get(self, path, headers=None):
                if path == "/x/res/target_1":
                    return SimpleNamespace(
                        status_code=200, text=body_for_target(),
                        headers={"X-Actor-Echo": "attacker"})
                status, body = routes[("GET", path)]
                return SimpleNamespace(
                    status_code=status, text=body,
                    headers={"X-Actor-Echo": "attacker"})

            def post(self, path, headers=None):
                if path == "/x/res/bbb_1":
                    state_box["flipped"] = True   # the SECOND single flips it
                return SimpleNamespace(
                    status_code=200, text='{"status": "ok"}',
                    headers={"X-Actor-Echo": "attacker"})

            def request(self, method, path, headers=None):
                return self.post(path, headers) if method == "POST" else self.get(path, headers)

        source = ObservedSurfaceSource([
            {"method": "POST", "path": "/x/res/aaa_1"},
            {"method": "POST", "path": "/x/res/bbb_1"},
        ])
        case = {
            "case_id": "SD-TEST",
            "baseline": "/x/res/own_1",
            "candidate": "/x/res/target_1",
            "control": "/x/res/ctrl_1",
            "requires_state_transition": True,
        }
        out = StatefulCaseProber(
            Client(), base_url="http://t", transition_source=source
        ).probe(case)
        assert out.verdict == "CONFIRMED"
        # the confirming single is recorded AND the earlier applied single
        assert out.transitions_applied == ["/x/res/aaa_1", "/x/res/bbb_1"]
        # the ordered evidence trace: reads and transitions interleaved
        kinds = [s["kind"] for s in out.evidence_trace]
        assert "transition" in kinds and "read" in kinds
        steps = [s["step"] for s in out.evidence_trace]
        assert steps == sorted(steps)   # strictly ordered
        transition_steps = [s for s in out.evidence_trace if s["kind"] == "transition"]
        assert [t["path"] for t in transition_steps] == [
            "/x/res/aaa_1", "/x/res/bbb_1",
        ]   # no transition silently disappears
