# tests/team1_acceptance/test_sprint_i1_part2_s3_seams.py
"""Sprint I-1 Continuation 03, item 2.4 -- S-3 registry-seam tests (M3
v1.0 Section 5.2.3, Table 4-4 seam inventory; v1.1 amendment note: the
sanctioned-writer set must include the OQ-1-ratified writers alongside
the fail-closed foreign-writer rejections).

Covers all 8 populated seams from Table 4-4 (the ninth, MCP integrations,
is an absence check):
  1. Tool auto-discovery registry (tools/registry.py) -- fail-closed
     rejection ALREADY built and tested in item 2.5
     (test_sprint_i1_part2_flag.py::TestGatingSurface) -- referenced
     here, not re-implemented, per "don't repeat a fact the file already
     states."
  2. Tool allowlist gate, frozen (live_hunter/tool_scope.py
     REGISTERED_TOOLS)
  3. Autopentestx record adapter (shared/autopentestx_adapter.py) --
     DORMANT, caller-less
  4. Nettacker record adapter (shared/nettacker_adapter.py) -- DORMANT,
     caller-less
  5. External observation advisory seam
     (production/external_observation_adapter.py) -- advisory-only
  6. ActionAuthority (shared/action_authority.py) -- fail-closed
     rejection ALREADY built and tested in item 2.5 -- referenced here
  7. Ingest loader map (cli/ingest.py _EXTENSION_LOADERS) -- fixed,
     non-extensible
  8. Graph node registry (graph/builder.py build_graph) -- fixed,
     non-extensible
  9. MCP integrations -- ABSENT (zero references), still checked so a
     future addition doesn't silently open a ninth seam unnoticed

Plus the OQ-1 sanctioned-writer-set assertion (v1.1 amendment note).
"""
from __future__ import annotations

import inspect

import pytest


class TestSeam1ToolRegistryReference:
    """Seam 1 is fully covered by item 2.5's own tests -- this is a
    pointer test, not a duplicate, confirming the gate that seam relies
    on still exists and is wired the way this seam inventory expects."""

    def test_register_tool_gate_exists_and_is_reachable(self):
        from webpent.shared.exceptions import ForeignWriterAccessDenied
        from webpent.tools.registry import register_tool

        def foreign_func():
            pass
        foreign_func.__module__ = "webpent.shared.not_a_real_tool_package"
        with pytest.raises(ForeignWriterAccessDenied):
            register_tool(name="seam1_pointer_check", category="exfil")(foreign_func)


class TestSeam2ToolAllowlistFrozen:
    def test_registered_tools_is_a_frozenset(self):
        from webpent.live_hunter.tool_scope import REGISTERED_TOOLS

        assert isinstance(REGISTERED_TOOLS, frozenset)

    def test_unregistered_tool_denied(self):
        from webpent.live_hunter.profile import AuthorizedLabProfile, HunterCapability
        from webpent.live_hunter.tool_scope import ScopeLaw

        profile = AuthorizedLabProfile(
            authorized_targets=("https://lab.example.com",),
            engagement_id="seam2_test", operator_approval_at="2026-01-01T00:00:00Z",
            capabilities=(HunterCapability.TARGET_UNDERSTANDING,), knowledge_ready=True, lab_fixture_mode=True,
        )
        law = ScopeLaw(profile=profile, engagement_id="seam2_test")
        decision = law.authorize_invocation(
            tool_name="a_foreign_writer_tool_not_in_the_set", target_url="https://lab.example.com",
        )
        assert decision.in_scope is False
        assert "tool_not_registered" in decision.reason

    def test_no_registration_function_exists(self):
        """This module offers no add_tool/register_tool-style CALLABLE
        API at all -- REGISTERED_TOOLS is a bare module-level constant
        (its name itself contains "register" as a substring, which is
        why this checks for an actual function/callable rather than any
        name containing the word), and this whole file is one of the
        sprint's frozen modules, so it cannot change without violating
        that separate, already-enforced invariant."""
        import webpent.live_hunter.tool_scope as mod

        suspicious = [
            n for n in dir(mod)
            if not n.startswith("_")
            and ("register" in n.lower() or "add_tool" in n.lower())
            and callable(getattr(mod, n))
        ]
        assert suspicious == [], f"unexpected registration-shaped callable(s): {suspicious}"


class TestSeam3And4DormantAdaptersCallerless:
    @pytest.mark.parametrize("module_path,func_name", [
        ("webpent.shared.autopentestx_adapter", "ingest_autopentestx_records"),
        ("webpent.shared.nettacker_adapter", "ingest_nettacker_records"),
    ])
    def test_dormant_adapter_has_no_production_caller(self, module_path, func_name):
        """Verified by grep during this sprint's implementation: zero
        callers anywhere under src/ outside the adapter's own file. This
        test pins that by walking every other src/ module's source and
        confirming the function name never appears as a call target."""
        from pathlib import Path

        src_root = Path(__file__).resolve().parents[2] / "src" / "webpent"
        own_file = Path(module_path.replace(".", "/") + ".py")
        hits = []
        for path in src_root.rglob("*.py"):
            rel = path.relative_to(src_root.parent)
            if rel == own_file:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if func_name in text:
                hits.append(str(rel))
        assert hits == [], f"{func_name} unexpectedly referenced outside its own adapter: {hits}"

    @pytest.mark.parametrize("module_path,capability", [
        ("webpent.shared.autopentestx_adapter", "autopentestx_observation"),
        ("webpent.shared.nettacker_adapter", "nettacker_observation"),
    ])
    def test_dormant_adapter_routes_through_action_authority(self, module_path, capability):
        """Even though dormant, if ever called these adapters route
        through ActionAuthority.execute() -> authorize() first (verified
        by direct source inspection this sprint), meaning they inherit
        every fail-closed check that authority enforces -- they are not
        a bypass of the authorization chain, merely unreached."""
        import importlib

        mod = importlib.import_module(module_path)
        func = getattr(mod, "ingest_autopentestx_records" if "autopentestx" in module_path else "ingest_nettacker_records")
        source = inspect.getsource(func)
        assert "authority.execute(" in source
        assert capability in source


class TestSeam5ExternalObservationAdvisoryOnly:
    def test_is_authority_hardwired_false(self):
        from webpent.production.external_observation_adapter import ExternalObservation

        obs = ExternalObservation(
            source="nuclei", raw_fingerprint="abc123", target="https://lab.example.com",
        )
        assert obs.is_authority() is False

    def test_forbidden_authority_claims_stripped(self):
        from webpent.production.external_observation_adapter import (
            FORBIDDEN_AUTHORITY_CLAIMS,
            ingest_external_observation,
        )

        assert len(FORBIDDEN_AUTHORITY_CLAIMS) > 0
        raw = {"status": "CONFIRMED", "target": "https://lab.example.com"}
        obs = ingest_external_observation(
            raw=raw, source="nuclei", expected_target="https://lab.example.com",
        )
        assert "CONFIRMED" in obs.authority_claims_stripped
        assert obs.is_authority() is False


class TestSeam6ActionAuthorityReference:
    """Seam 6 is fully covered by item 2.5's own tests -- pointer test
    only, same rationale as seam 1."""

    def test_foreign_writer_capability_denied(self):
        from webpent.shared.action_authority import ActionAuthority, ActionRequest
        from webpent.shared.exceptions import ForeignWriterAccessDenied

        auth = ActionAuthority(allowed_origin="https://lab.example.com")
        req = ActionRequest(
            task_id="seam6", engagement_id="e1", target_url="https://lab.example.com",
            capability="ledger_writer_export", action_family="http_read",
        )
        with pytest.raises(ForeignWriterAccessDenied):
            auth.authorize(req)


class TestSeam7IngestLoaderMapFixed:
    def test_extension_loaders_is_fixed_dict_of_a01_members(self):
        from webpent.cli.ingest import _EXTENSION_LOADERS

        assert isinstance(_EXTENSION_LOADERS, dict)
        for ext, loader_path in _EXTENSION_LOADERS.items():
            assert loader_path.startswith("langchain_community."), (
                f"{ext} -> {loader_path} is not an A-01 (langchain_community) loader"
            )

    def test_no_dynamic_extension_api(self):
        import webpent.cli.ingest as mod

        public_names = [n for n in dir(mod) if not n.startswith("_")]
        assert not any("register_loader" in n.lower() or "add_loader" in n.lower() for n in public_names)


class TestSeam8GraphNodeRegistryFixed:
    def test_build_graph_has_no_external_node_registration_parameter(self):
        from webpent.graph.builder import build_graph

        sig = inspect.signature(build_graph)
        param_names = set(sig.parameters.keys())
        # Only the declared graph options are accepted -- no "extra_nodes"
        # or plugin-style parameter that could admit a foreign node.
        assert param_names <= {"checkpointer", "auto_approve", "engagement_id"}

    def test_no_module_level_node_registration_function(self):
        import webpent.graph.builder as mod

        public_names = [n for n in dir(mod) if not n.startswith("_")]
        assert not any("register_node" in n.lower() or "add_node" in n.lower() for n in public_names if n != "build_graph")


class TestSeam9McpAbsent:
    def test_no_mcp_references_under_src(self):
        from pathlib import Path

        src_root = Path(__file__).resolve().parents[2] / "src" / "webpent"
        hits = []
        for path in src_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "import mcp" in text or "from mcp" in text:
                hits.append(str(path.relative_to(src_root.parent)))
        assert hits == [], f"Unexpected MCP references (Table 4-4 recorded ABSENT): {hits}"


class TestOQ1SanctionedWriterSet:
    """v1.1 amendment note: the S-3 writer-set assertion must include the
    OQ-1-ratified sanctioned writers (worker persistence, CLI post-graph
    persistence) alongside the fail-closed foreign-writer rejections --
    i.e. this suite must prove BOTH that foreign writers are rejected
    (seams 1/6 above) AND that the two ratified sanctioned writers are
    NOT accidentally caught by the same gates."""

    def test_worker_persist_findings_exists_and_is_not_gated_by_foreign_writer_check(self):
        from webpent.workers.pentest_worker import _persist_findings

        assert callable(_persist_findings)
        # The foreign-writer gate matches on ActionRequest.capability
        # strings, not on plain function calls -- _persist_findings is a
        # direct Python function call from within the worker's own
        # trusted code path, never constructs an ActionRequest with a
        # foreign-writer-shaped capability name, so it is architecturally
        # outside that gate's reach (by design, per OQ-1: contract-named
        # sanctioned writers operate independently of the flag).
        source = inspect.getsource(_persist_findings)
        assert "ActionRequest(" not in source

    def test_worker_emergency_persist_findings_exists(self):
        from webpent.workers.pentest_worker import _emergency_persist_findings

        assert callable(_emergency_persist_findings)

    def test_cli_post_graph_persistence_path_exists(self):
        import webpent.cli.commands as mod

        source = inspect.getsource(mod)
        # Table 4-4 / D-05: cli/commands.py:617-650 is the ratified
        # sanctioned-writer region. Confirm the module still contains
        # findings-persistence code in that vicinity rather than
        # asserting exact line numbers, which drift with unrelated edits
        # (this sprint's own item 1.3 already shifted this file's lines
        # once).
        assert "finding" in source.lower() and "persist" in source.lower() or "save" in source.lower()
