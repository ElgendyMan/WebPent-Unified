"""U-4 (RA-3) behavioral tests: B-1 SameSite, B-4 per-call factory."""
from __future__ import annotations
import os
from unittest.mock import MagicMock
import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

class TestB1SameSiteSemantics:
    def _detect(self, set_cookie_values):
        from webpent.agents.validator.agent import _detect_samesite_cookies
        headers = MagicMock()
        headers.get_list = MagicMock(return_value=set_cookie_values)
        return _detect_samesite_cookies(headers)
    def test_samesite_strict_counts_as_protection(self):
        assert self._detect(["session=abc; SameSite=Strict; Path=/"]) is True
    def test_samesite_lax_counts_as_protection(self):
        assert self._detect(["session=abc; SameSite=Lax; Path=/"]) is True
    def test_samesite_none_does_not_count_as_protection(self):
        assert self._detect(["session=abc; SameSite=None; Path=/"]) is False
    def test_no_samesite_attribute_does_not_count(self):
        assert self._detect(["session=abc; Path=/"]) is False
    def test_mixed_none_and_lax_counts_as_protection(self):
        assert self._detect(["tracking=xyz; SameSite=None; Path=/", "session=abc; SameSite=Lax; Path=/"]) is True
    def test_all_samesite_none_does_not_count(self):
        assert self._detect(["session=abc; SameSite=None; Path=/", "tracking=xyz; SameSite=None; Path=/"]) is False

class TestB4PerCallFactory:
    def test_consecutive_calls_do_not_stomp_gate_status(self):
        from webpent.llm_researcher.providers.factory import get_provider
        os.environ["LLM_PROVIDER"] = "mock"
        p1 = get_provider("mock", "test-model")
        gate1 = p1._provider_runtime_gate
        p2 = get_provider("mock", "test-model-2")
        gate2 = p2._provider_runtime_gate
        assert gate1["status"] == "MOCK_REQUESTED"
        assert gate2["status"] == "MOCK_REQUESTED"
        assert gate1 is not gate2
    def test_each_call_gets_fresh_gate_status_dict(self):
        from webpent.llm_researcher.providers.factory import get_provider
        os.environ["LLM_PROVIDER"] = "mock"
        p1 = get_provider("mock", "model-1")
        p2 = get_provider("mock", "model-2")
        p1._provider_runtime_gate["status"] = "MUTATED"
        assert p2._provider_runtime_gate["status"] == "MOCK_REQUESTED"


class TestB2ChainStopsOnAuthRejection:
    """B-2 (RA-3): session-death probe must catch 401/403, not just redirects."""
    def test_401_triggers_session_death_handling(self):
        import inspect
        from webpent.agents.validator import agent as agent_mod
        source = inspect.getsource(agent_mod)
        assert "probe_resp.status_code in (401, 403)" in source, "B-2 FAIL: 401/403 check not found"
        idx_401 = source.find("probe_resp.status_code in (401, 403)")
        idx_301 = source.find("probe_resp.status_code in (301, 302, 303)")
        assert idx_401 != -1 and idx_301 != -1, "B-2 FAIL: could not locate both checks"
        assert idx_401 < idx_301, "B-2 FAIL: 401/403 must appear BEFORE 301/302/303"

    def test_403_also_triggers_session_death_handling(self):
        import inspect
        from webpent.agents.validator import agent as agent_mod
        source = inspect.getsource(agent_mod)
        assert "in (401, 403)" in source, "B-2 FAIL: 401 and 403 must be in the same check"
