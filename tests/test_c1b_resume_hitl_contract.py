"""C1(b) TC-2 — strict-HITL resume contract (the documented decision).

The v14 lineage's ``--auto-approve`` scoped resume gate (U-10c/RA-5 HITL
architecture) was silently dropped by the resurrection scripts — resume
became strictly HITL.  TC-2 C1(b) chose to KEEP the strict-HITL design
and DOCUMENT the removal in the drift register (DRIFT_REGISTER.md,
DR-002) rather than restore a gate whose exact scoped conditions are not
reconstructible from surviving artifacts.  The conservative direction is
the defensible one — but it must be a DECISION, not a resurrection
accident.  These tests pin the decision as a behavioral contract:

  1. The service-campaign resume path is operator-gated: only an
     OPERATOR_HALTED campaign can be resumed, and resume re-enters
     RUNNING without any auto-approve carry-through.
  2. ``CampaignSpec`` structurally has NO ``auto_approve`` field — the
     service path cannot smuggle an auto-approve flag into plan/start/
     resume.
  3. The graph default (``build_graph()`` with no ``auto_approve``)
     compiles WITH the HITL interrupts (scope review + execution
     sandbox) — a resumed campaign therefore re-enters HITL-gated.
"""
from __future__ import annotations

import os
import sys
from dataclasses import fields
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.service.facade import MultiCampaignService  # noqa: E402
from webpent.service.models import CampaignLifecycle, CampaignSpec  # noqa: E402


def _service(tmp_root: Path) -> MultiCampaignService:
    return MultiCampaignService(root=tmp_root)


def _spec(campaign_id: str) -> CampaignSpec:
    return CampaignSpec(campaign_id, "http://127.0.0.1:9/lab-c1b",
                        budget_limit=5.0, max_actions=10)


class TestStrictHitlResumeContract:
    def test_resume_is_operator_gated_and_carries_no_auto_approve(self, tmp_path):
        """Only an OPERATOR_HALTED campaign can resume; the resume
        transition is OPERATOR_HALTED -> RUNNING with no approval flag
        threading (the state simply clears the halt).
        """
        svc = _service(tmp_path)
        svc.plan(_spec("c1b-halted"))
        # resume of a PLANNED (non-halted) campaign is rejected — resume
        # is not a start alias; it is the operator's un-halt action.
        with pytest.raises(ValueError):
            svc.resume("c1b-halted")
        svc.start("c1b-halted")
        svc.halt("c1b-halted", requested_by="operator")
        snap = svc.resume("c1b-halted")
        assert snap["state"] == CampaignLifecycle.RUNNING.value
        # The snapshot exposes NO auto-approve field (nothing smuggled).
        assert "auto_approve" not in snap

    def test_campaign_spec_structurally_has_no_auto_approve(self):
        """The service campaign spec cannot carry auto-approve — the
        scoped-resume gate's data path was removed BY DECISION (DR-002),
        and the removal is structural, not incidental.
        """
        spec_fields = {f.name for f in fields(CampaignSpec)}
        assert "auto_approve" not in spec_fields
        # And constructing a spec with that kwarg fails loudly.
        with pytest.raises(TypeError):
            CampaignSpec("c1b-x", "http://127.0.0.1:9/x", auto_approve=True)  # type: ignore[call-arg]

    def test_graph_default_compiles_with_hitl_interrupts(self):
        """``build_graph()`` with no ``auto_approve`` compiles WITH the
        HITL ``interrupt_before`` set (scope review + execution sandbox)
        — the entry state every resumed campaign re-enters under.
        """
        from webpent.graph.builder import NODE_EXECUTION_SANDBOX, NODE_SCOPE_REVIEW, build_graph

        graph = build_graph()
        interrupts = set(getattr(graph, "interrupt_before_nodes", ()) or ())
        assert NODE_SCOPE_REVIEW in interrupts
        assert NODE_EXECUTION_SANDBOX in interrupts

    def test_scan_path_auto_approve_remains_available_for_cicd(self):
        """The strict-HITL decision scopes to RESUME only: the scan entry
        keeps its chartered ``--auto-approve`` compile-time bypass for
        CI/CD pipelines (U-10c's original, untouched authority).
        """
        from webpent.graph.builder import NODE_EXECUTION_SANDBOX, NODE_SCOPE_REVIEW, build_graph

        graph = build_graph(auto_approve=True)
        interrupts = set(getattr(graph, "interrupt_before_nodes", ()) or ())
        assert NODE_SCOPE_REVIEW not in interrupts
        assert NODE_EXECUTION_SANDBOX not in interrupts
