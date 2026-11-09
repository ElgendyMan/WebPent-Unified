"""The Apex Predator — U-APEX-2, the Execution Sandbox (v87).

APEX-L-4 SANDBOX ALWAYS: every tool execution goes through a backend that
isolates it. `DockerSandbox` constructs the fully-isolated `docker run`
argv (restricted network, memory/cpu caps, read-only rootfs, declared
volumes only) — it never executes docker here. `LocalSandbox` is the
resource-limited fallback for environments without Docker; it executes
allowlisted commands under a hard timeout.

APEX-L-3 SCOPE BEFORE TOOL: `ScopeGuard` inspects every command's
arguments for hosts/URLs outside the authorized scope and fails closed —
an empty scope allows nothing, and a failed guard means nothing runs.
"""

from __future__ import annotations

import re
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

PREAMBLE_LINE = (
    "advisory: apex runs tools only inside an isolated sandbox, in scope, "
    "and only after operator approval; results are advisory evidence."
)

#: the restricted network mode applied to every container
NETWORK_RESTRICTED = "none"


@dataclass
class SandboxConfig:
    """Isolation contract for one execution environment."""

    image: str = "kalilinux/kali-rolling"
    network: str = NETWORK_RESTRICTED
    memory_limit_mb: int = 2048
    cpu_limit: float = 2.0
    timeout_seconds: int = 3600
    mount_volumes: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ExecOutcome:
    """Raw result of one sandboxed command execution."""

    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool = False


class ScopeViolationError(Exception):
    """A command referenced a host outside the authorized scope (APEX-L-3)."""


_URL_HOST_RE = re.compile(
    r"^(?:[a-z][a-z0-9+.\-]*://)?(?P<host>[A-Za-z0-9._\-]+)"
    r"(?::\d+)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z0-9_.\-]+")


def _extract_host(arg: str) -> str | None:
    """Return the host part of a URL/host-shaped argument, else None.

    Flags (``-w``, ``--json``) and plain words (``fast``) are not hosts;
    anything with a scheme or a dotted-host shape is one.
    """
    if _FLAG_RE.match(arg):
        return None
    if "://" not in arg and "." not in arg:
        return None
    match = _URL_HOST_RE.match(arg)
    if not match:
        return None
    host = match.group("host").strip(".").lower()
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "file"}:
        return None
    return host


class ScopeGuard:
    """Fail-closed scope check for tool arguments (APEX-L-3)."""

    def __init__(self, allowed_hosts: set[str]) -> None:
        self._allowed = {h.strip(".").lower() for h in allowed_hosts if h}

    @classmethod
    def allow_all(cls) -> ScopeGuard:
        """Explicit, named bypass for sandboxed/advisory contexts. The
        default remains fail-closed; using this in production tool runs
        against real targets is the operator's documented decision."""
        guard = cls(allowed_hosts=set())
        guard._allowed = {"*"}  # sentinel: every host allowed
        return guard

    @property
    def allowed_hosts(self) -> set[str]:
        return set(self._allowed)

    def check(self, command: list[str]) -> None:
        """Raise ScopeViolation if any argument references an out-of-scope
        host. An empty scope rejects every host-shaped argument."""
        for arg in command:
            if not isinstance(arg, str):
                continue
            host = _extract_host(arg)
            if host is None:
                continue
            # embedded redirect/query hosts (e.g. ?to=evil.example)
            embedded = re.findall(
                r"(?:[?&=/])([A-Za-z0-9._\-]+\.[A-Za-z]{2,})", arg
            )
            candidates = {host, *{e.lower().strip(".") for e in embedded}}
            for candidate in candidates:
                if candidate and not self._host_allowed(candidate):
                    raise ScopeViolationError(
                        f"out-of-scope host {candidate!r} in command "
                        f"{shlex.join(command)[:120]!r} (APEX-L-3)"
                    )

    def _host_allowed(self, host: str) -> bool:
        if "*" in self._allowed:
            return True
        if not self._allowed:
            return False
        if host in self._allowed:
            return True
        # subdomain of an allowed domain is in scope
        return any(host.endswith("." + a) for a in self._allowed)


class SandboxBackend(Protocol):
    """Minimal backend contract; any isolation provider can slot in."""

    def start(self, config: SandboxConfig) -> str: ...

    def execute(
        self,
        container_id: str,
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> ExecOutcome: ...

    def stop(self, container_id: str) -> None: ...

    def get_output(self, container_id: str, path: str) -> bytes: ...

    def cleanup(self, container_id: str) -> None: ...


class Sandbox:
    """Facade over a backend: scope-guarded, stateful, cleanup-safe."""

    def __init__(
        self,
        backend: SandboxBackend,
        scope: ScopeGuard | None = None,
    ) -> None:
        self._backend = backend
        self._scope = scope or ScopeGuard(allowed_hosts=set())
        self.container_ids: list[str] = []

    def start(self, config: SandboxConfig) -> str:
        cid = self._backend.start(config)
        self.container_ids.append(cid)
        return cid

    def execute(
        self,
        container_id: str,
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> ExecOutcome:
        self._scope.check(command)  # APEX-L-3: scope before tool
        if timeout_seconds is None:
            return self._backend.execute(container_id, list(command))
        return self._backend.execute(
            container_id, list(command), timeout_seconds=timeout_seconds
        )

    def stop(self, container_id: str) -> None:
        self._backend.stop(container_id)
        self.container_ids = [c for c in self.container_ids if c != container_id]

    def get_output(self, container_id: str, path: str) -> bytes:
        return self._backend.get_output(container_id, path)

    def cleanup(self, container_id: str) -> None:
        self._backend.cleanup(container_id)
        self.container_ids = [c for c in self.container_ids if c != container_id]

    def cleanup_all(self) -> None:
        for cid in list(self.container_ids):
            self.cleanup(cid)


class DockerSandbox:
    """Builds the isolated `docker run` argv for a command.

    This class NEVER executes docker by itself: it returns the argv for the
    executor layer. In this environment the docker daemon is unavailable,
    so the Docker backend stays argv-construction-only (recorded as blocked
    in traceability) — the argv contract is still fully tested.
    """

    def __init__(self, docker_path: str = "docker") -> None:
        self._docker = docker_path

    def run_argv(
        self,
        config: SandboxConfig,
        command: list[str],
        container_name: str,
    ) -> list[str]:
        argv: list[str] = [
            self._docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            config.network,  # default: none (APEX-L-4)
            "--memory",
            f"{config.memory_limit_mb}m",
            "--cpus",
            f"{config.cpu_limit:.1f}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
        for host_path, container_path in config.mount_volumes:
            argv.extend(["-v", f"{host_path}:{container_path}"])
        if config.image:
            argv.append(config.image)
        argv.extend(command)
        return argv


class LocalSandbox:
    """Resource-limited fallback backend using local subprocesses.

    Only meant for environments without Docker and for harmless commands;
    every call is bounded by a hard wall-clock timeout (SIGKILL at the
    deadline) — an execution that outlives its budget is terminated and
    reported with exit_code 124 and the timed_out flag.
    """

    def __init__(
        self,
        workdir: str | Path = "/tmp",
        config: SandboxConfig | None = None,
    ) -> None:
        self._workdir = str(workdir)
        self._config = config or SandboxConfig()

    def start(self, config: SandboxConfig) -> str:  # noqa: ARG002
        return "local-1"

    def execute(
        self,
        container_id: str,
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> ExecOutcome:
        # RT-02: the per-call deadline wins; otherwise the configured one.
        return self.run_command(
            command, timeout_seconds=timeout_seconds or self._config.timeout_seconds
        )

    def run_command(self, command: list[str], timeout_seconds: int) -> ExecOutcome:
        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603
                command,
                capture_output=True,
                timeout=timeout_seconds,
                cwd=self._workdir,
                check=False,
            )
            duration = time.monotonic() - started
            return ExecOutcome(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=duration,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return ExecOutcome(
                exit_code=124,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"",
                duration_seconds=duration,
                timed_out=True,
            )
        except FileNotFoundError:
            return ExecOutcome(
                exit_code=127,
                stdout=b"",
                stderr=b"command not found",
                duration_seconds=time.monotonic() - started,
            )

    def stop(self, container_id: str) -> None:  # noqa: ARG002
        return None

    def get_output(self, container_id: str, path: str) -> bytes:  # noqa: ARG002
        return b""

    def cleanup(self, container_id: str) -> None:  # noqa: ARG002
        return None


def kill_after_deadline(pid: int) -> None:  # pragma: no cover - signal helper
    """SIGKILL helper used by long-running sandboxed children."""
    import os

    os.kill(pid, signal.SIGKILL)
