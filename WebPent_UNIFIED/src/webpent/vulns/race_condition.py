"""Race condition (TOCTOU) experiment construction and result analysis.

PURE LOGIC ONLY. This module never performs I/O. It builds the bounded
concurrent-request experiment that AVI executes through the existing governed
boundary (ModernOrchestrator.execute_real_request -> ToolBoundary + ScopeLaw)
and summarizes the returned per-request observations into structured fields.

The canonical validator ``validate_race_condition`` lives in
``webpent.production.validators`` next to ``validate_idor`` — ONE authority per
family, the same place every other family validator lives (see the sprint
report: "validator function (like validate_idor)"). It consumes exactly the
structured-field contract defined below.

Detection model (mirrors IDOR's baseline/candidate/negative-control semantics):

* baseline         — one sequential state-changing request (must succeed once)
* candidate        — N concurrent requests that should only succeed once; if
                     more than one succeeds the endpoint lacks atomic
                     check-and-act locking (TOCTOU)
* negative_control — the same bounded burst against a request the server is
                     expected to reject, proving the burst mechanism itself is
                     not the source of the observed differential
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Bounded burst size. Five is the sprint-specified ceiling; it is enforced as a
# hard clamp so a caller can never widen the concurrency window.
MAX_CONCURRENT_REQUESTS = 5
MIN_CONCURRENT_REQUESTS = 2

RACE_CONDITION_EXPERIMENT_ID = "exp_race_condition_v1"
RACE_CONDITION_FAMILY = "RACE_CONDITION"

# Structured-field contract read by validate_race_condition.
BURST_ATTEMPTS_KEY = "_concurrent_attempts"
BURST_SUCCESSES_KEY = "_concurrent_successes"
BURST_EXPECTED_KEY = "_concurrent_expected_successes"
BURST_STATUSES_KEY = "_concurrent_statuses"


def clamp_concurrency(value: Any) -> int:
    """Clamp a requested burst size into the bounded [2, 5] window."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = MAX_CONCURRENT_REQUESTS
    return max(MIN_CONCURRENT_REQUESTS, min(MAX_CONCURRENT_REQUESTS, parsed))


@dataclass(frozen=True)
class RaceConditionExperiment:
    """Bounded concurrent-request experiment for one state-changing endpoint."""

    endpoint_path: str
    method: str
    concurrency: int
    expected_successes: int
    body: dict[str, Any] | None = None
    content_type: str = "application/json"
    principal_alias: str | None = None
    control_path: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def as_hypothesis(self, *, target_url: str, hypothesis_id: str) -> dict[str, Any]:
        """Project to the AVI hypothesis shape (advisory input, no credentials)."""
        candidate_request: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.endpoint_path,
            "concurrent": True,
            "concurrency": self.concurrency,
            "expected_successes": self.expected_successes,
            "content_type": self.content_type,
        }
        baseline_request: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.endpoint_path,
            "content_type": self.content_type,
        }
        control_request: dict[str, Any] = {
            "method": str(self.method).upper(),
            "path": self.control_path or self.endpoint_path,
            "concurrent": True,
            "concurrency": self.concurrency,
            "expected_successes": 0,
            "content_type": self.content_type,
        }
        if self.body is not None:
            candidate_request["body"] = dict(self.body)
            baseline_request["body"] = dict(self.body)
            if self.control_path is None:
                control_request["body"] = dict(self.body)
        if self.principal_alias:
            candidate_request["principal_alias"] = self.principal_alias
            baseline_request["principal_alias"] = self.principal_alias
            control_request["principal_alias"] = self.principal_alias
        if self.headers:
            for spec in (baseline_request, candidate_request, control_request):
                spec["headers"] = dict(self.headers)
        return {
            "id": hypothesis_id,
            "hypothesis_id": hypothesis_id,
            "vulnerability_class": RACE_CONDITION_FAMILY,
            "api_type": "rest",
            "path": self.endpoint_path,
            "method": str(self.method).upper(),
            "information_value": 0.9,
            "requests": {
                "baseline": baseline_request,
                "candidate": candidate_request,
                "negative_control": control_request,
            },
            "family_contract_version": "v1",
        "executable": True,
            "hypothesis_template": (
                "a state-changing endpoint may be reusable by a concurrent burst "
                "because it lacks atomic check-and-act locking"
            ),
            "expected_evidence": [
                "candidate_concurrent_successes>expected_successes",
                "baseline_single_success",
                "control_burst_not_over_accepted",
            ],
            "target_url": str(target_url),
            "metadata": {
                "experiment_id": RACE_CONDITION_EXPERIMENT_ID,
                "concurrency": self.concurrency,
                "expected_successes": self.expected_successes,
                "requires_concurrency": True,
            },
        }


def build_race_condition_experiment(
    *,
    endpoint_path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    content_type: str = "application/json",
    concurrency: int = MAX_CONCURRENT_REQUESTS,
    expected_successes: int = 1,
    principal_alias: str | None = None,
    control_path: str | None = None,
    headers: dict[str, str] | None = None,
) -> RaceConditionExperiment:
    """Build one bounded concurrent-request experiment.

    ``concurrency`` is clamped into [2, 5]; ``expected_successes`` is floored at
    0 so the guard can never be inverted into an "always confirmed" state.
    """
    try:
        expected = max(0, int(expected_successes))
    except (TypeError, ValueError):
        expected = 1
    return RaceConditionExperiment(
        endpoint_path=str(endpoint_path),
        method=str(method or "POST").upper(),
        concurrency=clamp_concurrency(concurrency),
        expected_successes=expected,
        body=dict(body) if isinstance(body, dict) else None,
        content_type=str(content_type or "application/json"),
        principal_alias=str(principal_alias) if principal_alias else None,
        control_path=str(control_path) if control_path else None,
        headers={str(k): str(v) for k, v in (headers or {}).items()},
    )


def summarize_concurrent_results(results: list[dict[str, Any]], *, expected_successes: int = 1) -> dict[str, Any]:
    """Summarize a concurrent burst into validator-readable structured fields.

    A "success" is any 2xx response. Only aggregate counts and status codes are
    retained; no response body is duplicated here.
    """
    attempts = len(results)
    statuses: list[int] = []
    successes = 0
    for item in results:
        raw = item.get("status_code", item.get("status"))
        try:
            status = int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            status = 0
        statuses.append(status)
        if 200 <= status < 300:
            successes += 1
    try:
        expected = max(0, int(expected_successes))
    except (TypeError, ValueError):
        expected = 1
    return {
        BURST_ATTEMPTS_KEY: attempts,
        BURST_SUCCESSES_KEY: successes,
        BURST_EXPECTED_KEY: expected,
        BURST_STATUSES_KEY: statuses,
    }


__all__ = [
    "MAX_CONCURRENT_REQUESTS",
    "MIN_CONCURRENT_REQUESTS",
    "RACE_CONDITION_EXPERIMENT_ID",
    "RACE_CONDITION_FAMILY",
    "BURST_ATTEMPTS_KEY",
    "BURST_SUCCESSES_KEY",
    "BURST_EXPECTED_KEY",
    "BURST_STATUSES_KEY",
    "RaceConditionExperiment",
    "build_race_condition_experiment",
    "clamp_concurrency",
    "summarize_concurrent_results",
]
