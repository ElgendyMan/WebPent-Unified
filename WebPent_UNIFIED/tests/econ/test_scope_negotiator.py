"""U-ECON-3 — ScopeNegotiator tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

from webpent.econ.scope_negotiator import ScopeNegotiator

CLEAN_SCOPE = """
app.example.com
api.example.com
dashboard.example.org
"""

AMBIGUOUS_SCOPE = """
*.example.com
192.168.1.0/24
example-corp and subsidiaries, related domains etc
com
"""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any network attempt inside these tests explodes immediately."""

    def _blocked(*args, **kwargs):  # pragma: no cover - only hit on violation
        raise AssertionError("network access attempted from the scope negotiator")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked)


def test_parse_yaml_json_markdown_scopes(tmp_path):
    negotiator = ScopeNegotiator()
    # YAML file
    yaml_path = tmp_path / "scope.yaml"
    yaml_path.write_text("in_scope:\n  - app.example.com\n  - api.example.com\n", encoding="utf-8")
    yaml_entries = negotiator.analyze(yaml_path).in_scope
    assert "app.example.com" in yaml_entries
    # JSON file
    json_path = tmp_path / "scope.json"
    json_path.write_text(
        json.dumps({"in_scope": ["app.example.com", "api.example.com"]}), encoding="utf-8"
    )
    assert negotiator.analyze(json_path).in_scope == ["api.example.com", "app.example.com"]
    # markdown text with bullets and emphasis
    markdown = "# Scope\n- **app.example.com**\n- api.example.com\n"
    md_entries = negotiator.analyze(markdown).in_scope
    assert "app.example.com" in md_entries and "api.example.com" in md_entries
    # plain text lines
    assert negotiator.analyze(CLEAN_SCOPE).in_scope == [
        "api.example.com",
        "app.example.com",
        "dashboard.example.org",
    ]


def test_ambiguity_patterns_detected():
    negotiator = ScopeNegotiator()
    analysis = negotiator.analyze(AMBIGUOUS_SCOPE)
    types = {a.ambiguity_type for a in analysis.ambiguities}
    assert "wildcard" in types
    assert "cidr" in types
    assert "vague_qualifier" in types
    assert "bare_domain" in types
    assert analysis.inquiry_needed is True
    assert analysis.gray_zones, "ambiguous entries must land in gray zones, not clean scope"
    entries_flagged = {a.entry for a in analysis.ambiguities}
    assert "*.example.com" in entries_flagged
    assert "192.168.1.0/24" in entries_flagged


def test_inquiry_generated_not_sent():
    negotiator = ScopeNegotiator()
    analysis = negotiator.analyze(AMBIGUOUS_SCOPE)
    inquiry = negotiator.generate_inquiry(analysis)
    assert isinstance(inquiry, str)
    for ambiguity in analysis.ambiguities:
        assert ambiguity.suggested_question in inquiry
    assert "will not touch anything outside" in inquiry
    # nothing to send: the object exposes no send/submit/post capability at all
    for attr in ("send", "submit", "post", "dispatch", "email"):
        assert not hasattr(negotiator, attr)
    # clean scope -> no inquiry needed
    clean = negotiator.analyze(CLEAN_SCOPE)
    assert clean.inquiry_needed is False
    assert "No ambiguities" in negotiator.generate_inquiry(clean)


def test_no_network_calls_made():
    # the module itself imports no network machinery
    import webpent.econ.scope_negotiator as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("requests", "urllib", "httpx", "socket", "urlopen"):
        assert f"import {banned}" not in source, f"econ core must not import {banned}"
    # and analysis runs while every network primitive raises
    negotiator = ScopeNegotiator()
    analysis = negotiator.analyze(CLEAN_SCOPE)
    assert analysis.in_scope and analysis.ambiguities == []


def test_confidence_reflects_ambiguity():
    negotiator = ScopeNegotiator()
    clean = negotiator.analyze(CLEAN_SCOPE)
    dirty = negotiator.analyze(AMBIGUOUS_SCOPE)
    assert clean.confidence == 1.0
    assert dirty.confidence < clean.confidence
    assert dirty.confidence >= 0.0
