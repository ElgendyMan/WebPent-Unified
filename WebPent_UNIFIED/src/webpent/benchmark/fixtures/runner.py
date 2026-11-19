# src/webpent/benchmark/fixtures/runner.py
"""Self-test harness runner (2026-10-25 proposals, Proposal 6).

Serves the vulnerable fixture app on loopback and drives WebPent's
REAL pipeline against it: the probe nodes (``advanced_web_vulns`` and
``graphql_testing``) run with their production flags ON, their
TENTATIVE findings flow through the canonical validators in
``production/validators.py`` via ``run_validator`` — the same one
authority per family — and the outcome is scored against the KNOWN
planted ground truth into a per-class confusion matrix.

This is the lesson of the 2026-10-25 critique turned into standing
infrastructure: the e2e test pinned ONE integration shape; the
harness exercises the actual probe→validator loop over live HTTP,
so no future probe/validator pair can merge without its integration
being measurable.

Safety: everything is loopback (127.0.0.1, ephemeral port), the
engagement-scope allowlist is scoped to the fixture's own URL for the
duration of the run, and the fixture app makes no outbound calls.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import uvicorn

from webpent.benchmark.fixtures.vulnbox_app import VULNBOX_MODES, build_vulnbox_app
from webpent.config.settings import Settings, activate_settings
from webpent.models.findings import Finding
from webpent.models.targets import Target
from webpent.production.validators import ValidationOutcome, run_validator
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)

# Planted ground truth per fixture mode (vuln-class values the
# pipeline is EXPECTED to confirm).
EXPECTED_CLASSES: dict[str, tuple[str, ...]] = {
    "graphql": ("graphql_introspection_exposure",),
    "web": ("cache_poisoning", "prototype_pollution"),
    "clean": (),
}

_STARTUP_TIMEOUT_S = 10.0
_SHUTDOWN_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class VulnboxTargetResult:
    """One fixture campaign: what the real pipeline confirmed/refuted."""

    mode: str
    base_url: str
    probe_nodes_run: tuple[str, ...]
    tentative_findings: int
    confirmed: tuple[str, ...]
    refuted: tuple[str, ...]
    validator_errors: tuple[str, ...]
    server_requests: int
    elapsed_seconds: float


@dataclass(frozen=True)
class VulnboxBenchmarkReport:
    """Aggregated confusion matrix across fixture modes.

    Scoring is per vuln class against the planted ground truth:
    TP = expected and confirmed, FP = confirmed but not planted,
    FN = planted but not confirmed.
    """

    run_id: str
    results: tuple[VulnboxTargetResult, ...]
    tp: tuple[str, ...] = field(default=())
    fp: tuple[str, ...] = field(default=())
    fn: tuple[str, ...] = field(default=())
    total_server_requests: int = 0
    elapsed_seconds: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tp": list(self.tp),
            "fp": list(self.fp),
            "fn": list(self.fn),
            "total_server_requests": self.total_server_requests,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "results": [
                {
                    "mode": r.mode,
                    "confirmed": list(r.confirmed),
                    "refuted": list(r.refuted),
                    "validator_errors": list(r.validator_errors),
                    "server_requests": r.server_requests,
                }
                for r in self.results
            ],
        }


class _FixtureServer:
    """Uvicorn daemon serving one fixture app on an ephemeral loopback port."""

    def __init__(self, mode: str) -> None:
        self.app = build_vulnbox_app(mode)
        config = uvicorn.Config(
            self.app, host="127.0.0.1", port=self._reserve_port(),
            log_level="warning",
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @staticmethod
    def _reserve_port() -> int:
        """Reserve an ephemeral loopback port (released for uvicorn to bind)."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def __enter__(self) -> "_FixtureServer":
        self.thread.start()
        deadline = time.monotonic() + _STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.server.started:
                return self
            if not self.thread.is_alive():
                raise RuntimeError("vulnbox fixture server died during startup")
            time.sleep(0.05)
        raise RuntimeError("vulnbox fixture server failed to start in time")

    @property
    def base_url(self) -> str:
        config_host = self.server.config.host or "127.0.0.1"
        return f"http://{config_host}:{self.server.config.port}"

    def __exit__(self, *exc: Any) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=_SHUTDOWN_TIMEOUT_S)


def _roles_of(finding: Finding) -> dict[str, Any]:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    return {
        "baseline": evidence.get("baseline"),
        "candidate": evidence.get("candidate"),
        "negative_control": evidence.get("negative_control"),
    }


def _run_probe_nodes(state: dict[str, Any], modes: str) -> list[Finding]:
    """Run the real probe nodes appropriate for the fixture mode."""
    from webpent.agents.advanced_web_vulns.agent import advanced_web_vulns_node
    from webpent.agents.graphql_testing.agent import graphql_testing_node

    findings: list[Finding] = []
    nodes_run: list[str] = []
    if modes in ("web", "clean"):
        updates = advanced_web_vulns_node(state)  # type: ignore[arg-type]
        nodes_run.append("advanced_web_vulns")
        findings.extend(updates.get("findings") or [])
    if modes == "graphql":
        updates = graphql_testing_node(state)  # type: ignore[arg-type]
        nodes_run.append("graphql_testing")
        findings.extend(updates.get("findings") or [])
    return findings


def _run_one_mode(
    mode: str, flags: Settings, run_nodes: bool
) -> tuple[VulnboxTargetResult, list[str]]:
    """Serve one fixture, run the real pipeline, score it.

    Returns the target result plus the list of confirmed vuln-class
    names (for aggregation).
    """
    started = time.monotonic()
    confirmed: list[str] = []
    refuted: list[str] = []
    validator_errors: list[str] = []
    probe_nodes_run: tuple[str, ...] = ()
    findings: list[Finding] = []

    with _FixtureServer(mode) as fixture:
        base_url = fixture.base_url
        token = set_engagement_target_hosts(base_url)
        try:
            # The WHOLE pipeline (probe nodes AND validation) runs inside
            # the activated target settings, so flag-gated capture hooks
            # (e.g. the Proposal 1 refutation ledger) observe the same
            # configuration the probes ran with.
            with activate_settings(flags):
                state: dict[str, Any] = {
                    "target": Target(url=base_url + "/"),
                    "crawled_data": (
                        {"graphql_urls": [f"{base_url}/graphql"]}
                        if mode == "graphql" else {}
                    ),
                    "findings": [],
                    "messages": [],
                }
                if run_nodes:
                    findings = _run_probe_nodes(state, mode)
                    probe_nodes_run = (
                        ("advanced_web_vulns",) if mode == "web"
                        else ("advanced_web_vulns", "graphql_testing")
                        if mode == "clean" else ("graphql_testing",)
                    )
                    for finding in findings:
                        raw_class = finding.vuln_class
                        vuln_class = (
                            raw_class.value if hasattr(raw_class, "value") else str(raw_class)
                        )
                        try:
                            result = run_validator(vuln_class.upper(), **_roles_of(finding))
                        except Exception as exc:  # noqa: BLE001 — validator fail-closed
                            validator_errors.append(f"{vuln_class}: {exc}")
                            continue
                        if result.outcome == ValidationOutcome.CONFIRMED:
                            confirmed.append(vuln_class)
                        elif result.outcome == ValidationOutcome.REFUTED:
                            refuted.append(vuln_class)
        finally:
            clear_engagement_target_hosts(token)

    requests_served = int(fixture.app.state.request_count["requests"])  # type: ignore[attr-defined]
    result = VulnboxTargetResult(
        mode=mode,
        base_url=base_url,
        probe_nodes_run=probe_nodes_run,
        tentative_findings=len(findings) if run_nodes else 0,
        confirmed=tuple(sorted(confirmed)),
        refuted=tuple(sorted(refuted)),
        validator_errors=tuple(validator_errors),
        server_requests=requests_served,
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
    return result, confirmed


def run_vulnbox_campaign(
    modes: tuple[str, ...] = ("graphql", "web", "clean"),
    *,
    run_nodes: bool = True,
    flags: Settings | None = None,
) -> VulnboxBenchmarkReport:
    """Run the self-test harness over the requested fixture modes.

    ``run_nodes=False`` is a smoke-check mode: servers start and score
    zero (used to verify fixture health without the probe pipeline).
    """
    for mode in modes:
        if mode not in VULNBOX_MODES:
            raise ValueError(f"unknown vulnbox mode {mode!r}")
    if flags is None:
        flags = Settings(
            enable_graphql_testing=True,
            enable_advanced_web_vulns=True,
        )

    started = time.monotonic()
    results: list[VulnboxTargetResult] = []
    all_confirmed: list[str] = []
    for mode in modes:
        result, confirmed = _run_one_mode(mode, flags, run_nodes)
        results.append(result)
        all_confirmed.extend(confirmed)

    expected = {c for mode in modes for c in EXPECTED_CLASSES[mode]}
    confirmed_set = set(all_confirmed)
    tp = tuple(sorted(expected & confirmed_set))
    fp = tuple(sorted(confirmed_set - expected))
    fn = tuple(sorted(expected - confirmed_set))
    return VulnboxBenchmarkReport(
        run_id=uuid.uuid4().hex[:12],
        results=tuple(results),
        tp=tp,
        fp=fp,
        fn=fn,
        total_server_requests=sum(r.server_requests for r in results),
        elapsed_seconds=round(time.monotonic() - started, 3),
    )


__all__ = [
    "EXPECTED_CLASSES",
    "VulnboxBenchmarkReport",
    "VulnboxTargetResult",
    "run_vulnbox_campaign",
]
