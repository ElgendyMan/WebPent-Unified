# tests/test_capability_e2e.py
"""2026-10-25 capability batch — END-TO-END probe→validator integration.

FIX regression guard (2026-10-25 critique): the unit tests built evidence
dicts by hand, so nothing proved that a TENTATIVE finding shaped EXACTLY
as the probe agents emit it (role dicts + marker placement) flows through
run_validator to a verdict. The first version of the probe agents placed
the poison marker only at the finding level, so every probe finding
reached the canonical validator as a guaranteed "no_marker" REFUTATION —
a bug the unit tests could never catch. This file pins the integration.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pv = importlib.import_module("webpent.production.validators")
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


class TestCachePoisoningProbeShapeE2E:
    """Evidence dict shaped exactly as agents/advanced_web_vulns emits it."""

    def _probe_shaped_finding_evidence(self, *, confirm: bool):
        marker = MARKER if confirm else MARKER + "-zz"
        marker = MARKER
        return {
            "baseline": {
                **_ev(body="<html>clean page</html>"),
                "poison_marker": marker,
            },
            "poison_request": {
                **_ev(body=f"<html>cdn={marker}.example</html>",
                      headers={"X-Cache": "MISS"}),
                "request_headers": {"x-forwarded-host": f"{marker}.example"},
                "poison_marker": marker,
            },
            "candidate": {
                **_ev(
                    body=f"<html>cdn={marker}.example</html>" if confirm
                    else "<html>still clean</html>",
                    headers={"X-Cache": "HIT"},
                ),
                "poison_marker": marker,
            },
            "negative_control": {
                **_ev(body="<html>other page</html>",
                      url="https://target.test/other?cb=x"),
                "poison_marker": marker,
            },
            "poison_marker": marker,
        }

    def _validate(self, evidence):
        # The same role extraction the validator agent performs over
        # finding["evidence"]:
        return pv.run_validator(
            "CACHE_POISONING",
            baseline=evidence.get("baseline"),
            candidate=evidence.get("candidate"),
            negative_control=evidence.get("negative_control"),
        )

    def test_probe_finding_confirms(self):
        evidence = self._probe_shaped_finding_evidence(confirm=True)
        result = self._validate(evidence)
        assert result.outcome == pv.ValidationOutcome.CONFIRMED
        assert result.details["poison_marker"] == MARKER

    def test_probe_finding_refutes_when_victim_clean(self):
        evidence = self._probe_shaped_finding_evidence(confirm=False)
        # Override: victim (candidate) stayed clean after poisoning.
        evidence["candidate"]["response_body"] = "<html>still clean</html>"
        result = self._validate(evidence)
        assert result.outcome == pv.ValidationOutcome.REFUTED
        assert result.refutation_path == "marker_missing_after_poison"

    def test_probe_finding_refutes_on_self_reflection(self):
        evidence = self._probe_shaped_finding_evidence(confirm=True)
        # The victim request itself carried the poison header: the probe
        # would have reflected itself instead of poisoning the cache key.
        evidence["candidate"]["request_headers"] = {
            "x-forwarded-host": f"{MARKER}.example",
        }
        result = self._validate(evidence)
        assert result.outcome == pv.ValidationOutcome.REFUTED
        assert result.refutation_path == "self_reflection"


class TestPrototypePollutionProbeShapeE2E:
    def _probe_shaped_finding_evidence(self, *, reflect: bool):
        marker = "webpent_probe_e2e"
        return {
            "baseline": {
                **_ev(body="<html>clean page</html>"),
                "poison_marker": marker,
            },
            "candidate": {
                **_ev(
                    body=f"<html>config.webpent_probe_e2e={marker}</html>"
                    if reflect else "<html>clean page</html>",
                    url="https://target.test/?__proto__[webpent_probe_e2e]=" + marker,
                ),
                "poison_marker": marker,
            },
            "negative_control": {
                **_ev(body="<html>clean page</html>",
                      url="https://target.test/?benign[webpent_probe_e2e]=" + marker),
                "poison_marker": marker,
            },
            "poison_marker": marker,
        }

    def _validate(self, evidence):
        return pv.run_validator(
            "PROTOTYPE_POLLUTION",
            baseline=evidence.get("baseline"),
            candidate=evidence.get("candidate"),
            negative_control=evidence.get("negative_control"),
        )

    def test_probe_finding_confirms(self):
        result = self._validate(self._probe_shaped_finding_evidence(reflect=True))
        assert result.outcome == pv.ValidationOutcome.CONFIRMED

    def test_probe_finding_refutes_without_pollution(self):
        result = self._validate(self._probe_shaped_finding_evidence(reflect=False))
        assert result.outcome == pv.ValidationOutcome.REFUTED
