"""E2E Wave R-4 regression locks: in-graph tool promotion chain fixes.

Runtime proofs (2026-09-15, ground-truth lab campaigns) discovered:
  D1  Validator GET branch dropped target_param -> in-graph sqlmap tested the
      wrong parameter ("not injectable") despite the world model knowing it.
  D2  ProofBundle construction crashed on UUID hypothesis_id (Finding model
      carries UUID; bundle declares str) -> whole engagement aborted.
  D3  Stage-0 differential observations were built without target_backed/
      evidence_origin provenance and with bare-hex digests, so the strict
      verifier's _target_observation_ok() ALWAYS failed
      (target_backed_baseline_and_candidate_required) and no in-graph
      dalfox/xss promotion could ever pass — POST-form XSS additionally had
      no differential path at all (GET query-only).

These locks pin the fixes without weakening the authority bar.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse, urlunparse

from webpent.agents.validator.agent import _strict_replay_observation
from webpent.shared.verifier import verify_replay_evidence


def _verifier_fingerprint(url: str) -> str:
    parsed = urlparse(str(url))
    shape = urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "", "")
    )
    return f"sha256:{hashlib.sha256(shape.encode('utf-8', 'replace')).hexdigest()}"


def test_l5_strict_observation_carries_provenance_and_prefixes():
    """L5: formatter output satisfies _target_observation_ok's contract."""
    url = "http://127.0.0.1:9/xss/stored"
    bare = hashlib.sha256(b"req").hexdigest()
    obs = _strict_replay_observation(
        url_shape=url,
        role="candidate",
        status_code=200,
        body_length=128,
        target_fingerprint=hashlib.sha256(b"http://127.0.0.1:9/xss/stored").hexdigest(),
        request_digest=bare,
        response_digest=bare,
        body_delta=5,
    )
    assert obs["target_backed"] is True
    assert obs["evidence_origin"] == "target_runtime"
    assert obs["request_digest"].startswith("sha256:")
    assert obs["response_digest"].startswith("sha256:")
    assert obs["target_fingerprint"].startswith("sha256:")
    assert obs["observation_role"] == "candidate"


def test_l6_formatter_fingerprint_matches_verifier_computation():
    """L6: prefixed grounding fingerprint equals the verifier's own shape hash."""
    url = "http://127.0.0.1:9/sqli?username=admin"
    bare_fp = hashlib.sha256(b"http://127.0.0.1:9/sqli").hexdigest()
    obs = _strict_replay_observation(
        url_shape=url,
        role="baseline",
        status_code=200,
        body_length=10,
        target_fingerprint=bare_fp,
        request_digest=hashlib.sha256(b"x").hexdigest(),
        response_digest=hashlib.sha256(b"y").hexdigest(),
    )
    expected = _verifier_fingerprint("http://127.0.0.1:9/sqli")
    assert obs["target_fingerprint"] == expected


def test_l7_verifier_accepts_uuid_hypothesis_id_without_crash():
    """L7: UUID hypothesis_id must not abort bundle construction (D2).

    Builds a fully target-backed observation set (as Stage 0 now emits) and
    asserts the verifier reaches a promotion decision (bundle built or a
    semantic block) instead of raising ValidationError.
    """
    import uuid as _uuid

    from webpent.models.findings import Finding

    url = "http://127.0.0.1:9/xss/stored"
    fp = _verifier_fingerprint(url)
    req = f"sha256:{hashlib.sha256(b'req').hexdigest()}"
    res = f"sha256:{hashlib.sha256(b'res').hexdigest()}"
    control_req = f"sha256:{hashlib.sha256(b'control').hexdigest()}"
    mk = lambda role, rq: {  # noqa: E731
        "url_shape": url,
        "status_code": 200,
        "body_length": 100,
        "observation_role": role,
        "target_backed": True,
        "evidence_origin": "target_runtime",
        "target_fingerprint": fp,
        "request_digest": rq,
        "response_digest": res,
    }
    finding = Finding(
        id=_uuid.uuid4(),
        thread_id="lock-l7",
        url=url,
        vuln_class="xss",
        title="L7 UUID hypothesis id regression lock",
        severity="medium",
        description="regression lock for strict verifier bundle construction",
        tool_name="dalfox",
        confidence_level="Needs Human Review",
        hypothesis_id=_uuid.uuid4(),  # UUID — crashed before the fix
        reasoning="regression lock L7",
        evidence={},
    )
    result = verify_replay_evidence(
        finding,
        baseline=mk("baseline", req),
        candidate=mk("candidate", req),
        negative_control=mk("negative_control", control_req),
        causal_signal=True,
        negative_control_complete=True,
        require_target_backed=True,
        validator_id="validator.dalfox",
        validator_version="strict-tool-replay.v1",
        causal_basis="lock",
        engagement_id="lock-l7",
        hypothesis_id=finding.hypothesis_id,
        scope_context={},
        identity_context={},
    )
    # The UUID crash happened BEFORE any decision could be returned; reaching
    # a VerificationResult at all proves the coercion works. A passed verdict
    # additionally proves the observation contract.
    assert result is not None
    assert result.passed is True or result.reason  # decision, not exception


def test_l8_get_branch_threads_target_param(monkeypatch):
    """L8: the validator GET branch must pass target_param to the tool (D1)."""
    captured = {}

    def _fake_tool(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return "TOOL OUTPUT"

    from webpent.agents.validator import agent as validator_agent
    from webpent.models.findings import Finding
    from webpent.shared.engagement_scope import set_engagement_target_hosts

    set_engagement_target_hosts("127.0.0.1")
    monkeypatch.setattr(
        validator_agent, "get_tool", lambda name: type("E", (), {"func": _fake_tool})()
    )

    finding = Finding(
        id=_uuid4(),
        thread_id="lock-l8",
        url="http://127.0.0.1:9/sqli?username=admin",
        vuln_class="sqli",
        title="L8 target param threading regression lock",
        severity="high",
        description="regression lock for validator GET branch target_param",
        tool_name="dynamic_prioritization",
        confidence_level="Pending",
        hypothesis_id=None,
        reasoning="regression lock L8",
        evidence={},
        request_method="GET",
        request_data={},
        target_param="username",
    )

    validator_agent._validate_with_tool(
        finding,
        "sqli",
        None,
        stealth_mode=False,
        playwright_enabled=False,
        auth_state=None,
        session_cookies={},
        credentials={},
        target_url="http://127.0.0.1:9/",
        thread_id="lock-l8",
        identity_profiles=[],
        engagement_id="lock-l8",
        target_scope=["127.0.0.1"],
        target_package=None,
    )
    assert captured["kwargs"].get("target_param") == "username" or captured["args"][1:2] == ["username"]


def _uuid4():
    import uuid as _uuid

    return _uuid.uuid4()
