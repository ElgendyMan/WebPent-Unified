"""TEAM-1 Phase 4 — non-DVWA hypothesis generation acceptance tests.

Acceptance criteria:
  * hypotheses are NON-EMPTY for structurally different authorized lab
    targets that share nothing with DVWA's route vocabulary,
  * PARAMETER hypotheses are produced (param names, path parameters,
    resource identifiers, form fields),
  * findings/hypotheses do not depend on DVWA keyword names — a target with
    zero DVWA-shaped segments still gets rich structural coverage,
  * the parameter classifier runs on the seed URL even when
    ``skip_recon`` is enabled (the seed URL is analyzed by the node),
  * producers are generic (no target-specific hardcoding).
"""

from __future__ import annotations

from uuid import uuid4

from webpent.agents.hypothesis_analyzer.agent import (
    _generic_form_field_hypotheses,
    _generic_parameter_hypotheses,
    _generic_path_parameter_hypotheses,
    hypothesis_node,
)
from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.models.targets import Target


def _state(*, url: str, crawled_data: dict | None = None, skip_recon: bool = False):
    return {
        "target": Target(url=url),
        "hypotheses": [],
        "crawled_data": crawled_data or {"endpoints": [], "forms": []},
        "skip_recon": skip_recon,
        "thread_id": str(uuid4()),
    }


def _classes(hypotheses: list[Hypothesis]) -> set[str]:
    return {h.vuln_class for h in hypotheses}


def test_structured_rest_api_target_produces_hypotheses() -> None:
    """Target A: REST-style API, no DVWA vocabulary anywhere."""
    url = "http://10.20.30.40:8080/api/v2/customers/550e8400-e29b-41d4-a716-446655440000?expand=profile"
    state = _state(url=url, skip_recon=True)
    result = hypothesis_node(state)
    hypotheses = result.get("hypotheses") or []
    assert hypotheses, "REST target produced no hypotheses"
    classes = _classes(hypotheses)
    assert "idor" in classes, "UUID resource identifier must yield an IDOR hypothesis"
    # The seed URL (skip_recon) was analyzed by the node itself.
    assert any(str(h.target_url) == url for h in hypotheses), (
        "the seed URL must be analyzed even under skip_recon=True"
    )


def test_traditional_form_target_produces_parameter_hypotheses() -> None:
    """Target B: classic server-rendered app with query params + POST form."""
    seed = "http://192.168.77.23/inventory/search?query=wrench&file=report.pdf"
    form = {
        "source_url": seed,
        "action": "/inventory/order",
        "method": "POST",
        "data": {"item_id": "42", "comment": "", "csrf_token": "x"},
    }
    state = _state(
        url=seed,
        crawled_data={"endpoints": [seed], "forms": [form]},
        skip_recon=True,
    )
    result = hypothesis_node(state)
    hypotheses = result.get("hypotheses") or []
    assert hypotheses, "form/query target produced no hypotheses"

    classes = _classes(hypotheses)
    # Parameter-name producers: file reference -> LFI, query -> XSS surface.
    assert "lfi" in classes, "file= query parameter must yield an LFI hypothesis"
    assert "xss" in classes, "free-text field must yield an XSS surface hypothesis"
    # Form-field producer: item_id -> IDOR surface.
    assert "idor" in classes, "form identifier field must yield an IDOR hypothesis"

    params = {h.target_param for h in hypotheses if h.target_param}
    assert params, "parameter hypotheses must carry the observed parameter"
    # The discovered POST form context (item_id) legitimately takes
    # precedence over query-param naming; assert observed params surfaced.
    assert any(name in (p or "") for p in params for name in ("file", "query", "item_id"))


def test_unit_producers_are_target_agnostic() -> None:
    """Producers derive from structure only — no DVWA literals anywhere."""
    param_hits = _generic_parameter_hypotheses(
        "https://app.internal/?account=9123&next=/dashboard&proxy=http://x"
    )
    param_classes = {c for c, _, _ in param_hits}
    assert {"idor", "open_redirect", "ssrf"} <= param_classes

    path_hits = _generic_path_parameter_hypotheses("https://app.internal/orders/12345/")
    assert {c for c, _, _ in path_hits} == {"sqli"}

    form_hits = _generic_form_field_hypotheses(
        {"description": "", "attachment_url": "", "submit": "ok"}
    )
    assert {c for c, _, _ in form_hits} == {"xss", "ssrf"}

    # Negative control: a meaningless parameter yields nothing.
    assert _generic_parameter_hypotheses("https://app.internal/?rapid=1") == []


def test_no_dvwa_keyword_dependency_in_generic_sources() -> None:
    """The generic producer tables contain no DVWA-specific vocabulary."""
    from webpent.agents.hypothesis_analyzer import agent as ha

    corpus = " ".join(
        fragment for fragment, _, _ in ha._PARAM_NAME_SIGNALS
    ) + " " + " ".join(
        fragment for fragment, _, _ in ha._FORM_FIELD_SIGNALS
    )
    for dvwa_literal in ("dvwa", "sqli_blind", "xss_r", "xss_s", "xss_d", "weak_id", "open_redirect/"):
        assert dvwa_literal not in corpus.lower(), (
            f"generic producer table contains target-specific literal {dvwa_literal!r}"
        )


def test_hypothesis_status_is_open_and_structured() -> None:
    """Emitted hypotheses are first-class UNEXPLORED objects with params."""
    url = "http://172.16.9.9:9000/records?page=3"
    result = hypothesis_node(_state(url=url, skip_recon=True))
    hypotheses = result.get("hypotheses") or []
    assert hypotheses
    for h in hypotheses:
        assert isinstance(h, Hypothesis)
        assert h.status == HypothesisStatus.UNEXPLORED
        assert h.vuln_class
        assert h.origin
