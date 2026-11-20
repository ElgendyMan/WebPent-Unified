# tests/test_advanced_validators.py
"""2026-10-25 capability batch — cache poisoning + prototype pollution
canonical validators. Two-request proof discipline; no single-request
reflection can ever reach CONFIRMED.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

av = importlib.import_module("webpent.production.advanced_validators")

MARKER = "webpent-poison-abc123"


def _ev(status=200, body="", headers=None, elapsed_ms=10, **extra):
    ev = {
        "status_code": status,
        "response_body": body,
        "headers": headers or {},
        "elapsed_ms": elapsed_ms,
        "url": "https://target.test/",
    }
    ev.update(extra)
    return ev


# ---------------------------------------------------------------------------
# Cache poisoning — the two-request proof
# ---------------------------------------------------------------------------
class TestCachePoisoning:
    def _poisoned_triple(self):
        return (
            _ev(body="<html>clean page</html>"),                       # baseline
            _ev(body=f"<html>cdn={MARKER}.example</html>"),            # candidate (victim)
            _ev(body="<html>other page</html>"),                       # negative control
        )

    def test_confirmed_two_request_proof(self):
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.CONFIRMED
        assert result.details["poison_marker"] == MARKER

    def test_refuted_marker_in_baseline(self):
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        baseline["response_body"] = f"<html>cdn={MARKER}.example</html>"
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "marker_in_baseline"

    def test_refuted_marker_in_negative_control(self):
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        control["response_body"] = f"<html>cdn={MARKER}.example</html>"
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "marker_in_control"

    def test_refuted_when_marker_missing_after_poison(self):
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        candidate["response_body"] = "<html>still clean</html>"
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "marker_missing_after_poison"

    def test_refuted_self_reflection(self):
        """Candidate that carried the poison header itself is reflection."""
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        candidate["request_headers"] = {"x-forwarded-host": f"{MARKER}.example"}
        candidate["headers"] = {"x-forwarded-host": f"{MARKER}.example"}
        candidate["response_body"] = f"you requested host {MARKER}.example"
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "self_reflection"

    def test_confirmed_header_only_reflection(self):
        """FIX regression guard (2026-10-25 critique): poisoning that
        manifests ONLY in a response header (a Location carrying the
        injected host) is the strongest real-world gadget and must
        confirm, not refute as marker_missing_after_poison."""
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = MARKER
        candidate["response_body"] = "<html>clean page</html>"
        candidate["headers"] = {"Location": f"https://{MARKER}.example/evil"}
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.CONFIRMED
        assert result.details["poison_marker"] == MARKER

    def test_fail_closed_on_missing_evidence(self):
        with pytest.raises(Exception):
            av.validate_cache_poisoning(baseline=None, candidate=None, negative_control=None)

    def test_short_marker_never_confirms(self):
        baseline, candidate, control = self._poisoned_triple()
        candidate["poison_marker"] = "abc"
        result = av.validate_cache_poisoning(
            baseline=baseline, candidate=candidate, negative_control=control,
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "no_marker"


# ---------------------------------------------------------------------------
# Prototype pollution — __proto__ payload vs benign-key control
# ---------------------------------------------------------------------------
class TestPrototypePollution:
    MARKER = "webpent-ppoll-deadbeef"

    def test_confirmed_differential(self):
        result = av.validate_prototype_pollution(
            baseline=_ev(body='{"user":{"name":"a"}}'),
            candidate=_ev(
                body=f'{{"user":{{"name":"a"}},"__proto__":{{"webpent_probe":"{self.MARKER}"}}}}',
                poison_marker=self.MARKER,
            ),
            negative_control=_ev(body='{"user":{"name":"a"},"benign":{"webpent_probe":"other"}}'),
        )
        assert result.outcome == av.ValidationOutcome.CONFIRMED

    def test_refuted_marker_in_baseline(self):
        result = av.validate_prototype_pollution(
            baseline=_ev(body=f"marker {self.MARKER} pre-present"),
            candidate=_ev(body=f"echo {self.MARKER}", poison_marker=self.MARKER),
            negative_control=_ev(body="clean"),
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "marker_in_baseline"

    def test_refuted_benign_key_also_reflects(self):
        """Same value under a benign key ALSO reflects -> plain echo."""
        result = av.validate_prototype_pollution(
            baseline=_ev(body="clean"),
            candidate=_ev(body=f"echo {self.MARKER}", poison_marker=self.MARKER),
            negative_control=_ev(body=f"echo {self.MARKER}"),
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "control_also_reflects"

    def test_refuted_no_reflection(self):
        result = av.validate_prototype_pollution(
            baseline=_ev(body="clean"),
            candidate=_ev(body='{"ok":true}', poison_marker=self.MARKER),
            negative_control=_ev(body="clean"),
        )
        assert result.outcome == av.ValidationOutcome.REFUTED
        assert result.refutation_path == "no_pollution_reflection"

    def test_fail_closed_on_missing_evidence(self):
        with pytest.raises(Exception):
            av.validate_prototype_pollution(baseline=None, candidate=None, negative_control=None)
