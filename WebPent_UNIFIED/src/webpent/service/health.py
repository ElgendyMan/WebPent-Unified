"""Security-gate and frozen-manifest health monitoring."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from webpent.service.cost_alerts import AlertDispatcher
from webpent.service.models import HealthRun
from webpent.service.store import ServiceStore

GATES = (
    "check_state_contract",
    "check_orchestrator_construction_authority",
    "check_isolation_denylist",
    "check_vault_import_authority",
    "verify_test_count",
    "check_tool_boundary_prompt_boundary",
)
HEALTH_INTERVAL_SECONDS = 3600
MANIFEST_INTERVAL_SECONDS = 86400


class HealthMonitor:
    def __init__(self, store: ServiceStore, alerts: AlertDispatcher, *, project_root: str | Path) -> None:
        self.store = store
        self.alerts = alerts
        self.project_root = Path(project_root)

    def _run_gate(self, gate: str, timeout: float = 120.0) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(self.project_root / "scripts" / f"{gate}.py")],
            cwd=self.project_root, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONPATH": f"{self.project_root / 'src'}:{self.project_root}",},
        )
        return int(proc.returncode), (proc.stdout + "\n" + proc.stderr).strip()

    def run(self, *, gate_runner: Callable[[str], tuple[int, str]] | None = None,
            timeout: float = 120.0) -> list[HealthRun]:
        results: list[HealthRun] = []
        source_digest = self._source_digest()
        for gate in GATES:
            started = datetime.now(timezone.utc).isoformat()
            try:
                exit_code, output = (gate_runner or self._run_gate)(gate) if gate_runner else self._run_gate(gate, timeout)
            except Exception as exc:
                exit_code, output = 124, f"{type(exc).__name__}:{exc}"
            ended = datetime.now(timezone.utc).isoformat()
            digest = hashlib.sha256(output.encode("utf-8", "replace")).hexdigest()[:32]
            result = HealthRun(uuid.uuid4().hex, gate, exit_code, exit_code == 0, digest, output[-2000:], started, ended, source_digest)
            self.store.save_health_run(result)
            if not result.ok:
                self.alerts.health_failure(gate_name=gate, output_digest=digest, source_digest=source_digest)
            results.append(result)
        return results

    def verify_authority_manifest(self) -> dict[str, object]:
        """Verify the checked-in authority manifest; caller-supplied maps are not trusted."""
        script = self.project_root / "scripts" / "verify_frozen_manifest.py"
        try:
            proc = subprocess.run(
                [sys.executable, str(script)], cwd=self.project_root, capture_output=True,
                text=True, timeout=120,
                env={**os.environ, "PYTHONPATH": f"{self.project_root / 'src'}:{self.project_root}"},
            )
            output = (proc.stdout + "\n" + proc.stderr).strip()
            result: dict[str, object] = {"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": output[-2000:]}
        except Exception as exc:
            result = {"ok": False, "exit_code": 124, "output": f"{type(exc).__name__}:{exc}"}
        if not result["ok"]:
            digest = hashlib.sha256(str(result["output"]).encode()).hexdigest()[:32]
            self.alerts.health_failure(gate_name="frozen_manifest", output_digest=digest, source_digest=self._source_digest())
        return result

    def verify_manifest(self, manifest: dict[str, str] | None = None) -> dict[str, object]:
        """Compatibility wrapper; verification always uses the authoritative file."""
        return self.verify_authority_manifest()

    def hourly_gate_tick(self, *, gate_runner: Callable[[str], tuple[int, str]] | None = None) -> list[HealthRun]:
        return self.run(gate_runner=gate_runner)

    def daily_manifest_tick(self, manifest: dict[str, str] | None = None) -> dict[str, object]:
        return self.verify_authority_manifest()

    def scheduled_tick(self, *, now: datetime | None = None, gate_runner: Callable[[str], tuple[int, str]] | None = None) -> dict[str, object]:
        current = now or datetime.now(timezone.utc)
        result: dict[str, object] = {"gates": [], "manifest": None, "ran": []}
        gate_job = self.store.get_health_schedule("hourly_gates")
        if gate_job is None or current >= datetime.fromisoformat(gate_job["next_run"]):
            runs = self.hourly_gate_tick(gate_runner=gate_runner)
            next_run = (current + timedelta(seconds=HEALTH_INTERVAL_SECONDS)).isoformat()
            self.store.set_health_schedule("hourly_gates", last_run=current.isoformat(), next_run=next_run)
            result["gates"] = [item.as_dict() for item in runs]
            result["ran"].append("hourly_gates")
        manifest_job = self.store.get_health_schedule("daily_manifest")
        if manifest_job is None or current >= datetime.fromisoformat(manifest_job["next_run"]):
            manifest_result = self.daily_manifest_tick()
            next_run = (current + timedelta(seconds=MANIFEST_INTERVAL_SECONDS)).isoformat()
            self.store.set_health_schedule("daily_manifest", last_run=current.isoformat(), next_run=next_run)
            result["manifest"] = manifest_result
            result["ran"].append("daily_manifest")
        return result

    def run_forever(self, *, stop_event: object, sleep_seconds: float = 30.0, gate_runner: Callable[[str], tuple[int, str]] | None = None) -> None:
        """Resident deployment loop; tests can stop it with a threading.Event."""
        import time
        while not bool(getattr(stop_event, "is_set")()):
            self.scheduled_tick(gate_runner=gate_runner)
            time.sleep(max(0.1, float(sleep_seconds)))

    def _source_digest(self) -> str:
        files = sorted((self.project_root / "src" / "webpent").rglob("*.py"))
        digest = hashlib.sha256()
        for path in files:
            digest.update(str(path.relative_to(self.project_root)).encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()[:32]


__all__ = ["GATES", "HEALTH_INTERVAL_SECONDS", "MANIFEST_INTERVAL_SECONDS", "HealthMonitor"]
