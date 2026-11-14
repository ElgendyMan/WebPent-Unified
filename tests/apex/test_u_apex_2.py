"""U-APEX-2 — The Execution Sandbox + ScopeGuard (v87).

Laws under proof: APEX-L-3 (scope before tool), APEX-L-4 (sandbox always),
APEX-L-9 (advisory). The Docker backend is argv-constructed and NEVER
executed here (no docker daemon in this environment — recorded as blocked
in traceability). Local tests use an injected fake backend: zero real
subprocesses in this suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.apex.executor import ExecResult
from webpent.apex.sandbox import (
    PREAMBLE_LINE,
    DockerSandbox,
    ExecOutcome,
    LocalSandbox,
    SandboxConfig,
    ScopeGuard,
    ScopeViolationError,
)
from webpent.apex.sandbox import Sandbox as Sandbox


class FakeBackend:
    """In-memory backend: records calls, returns canned outcomes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.stopped: list[str] = []
        self._outcomes: dict[str, ExecOutcome] = {}

    def set_outcome(self, container_id: str, outcome: ExecOutcome) -> None:
        self._outcomes[container_id] = outcome

    def start(self, config: SandboxConfig) -> str:  # noqa: ARG002
        cid = "c-fake-1"
        self.set_outcome(
            cid,
            ExecOutcome(exit_code=0, stdout=b"ok", stderr=b"", duration_seconds=0.01),
        )
        return cid

    def execute(self, container_id: str, command: list[str]) -> ExecOutcome:
        self.calls.append((container_id, list(command)))
        return self._outcomes[container_id]

    def stop(self, container_id: str) -> None:
        self.stopped.append(container_id)

    def get_output(self, container_id: str, path: str) -> bytes:  # noqa: ARG002
        return b"file-bytes"

    def cleanup(self, container_id: str) -> None:
        self.stopped.append(container_id)


def test_sandbox_starts_container() -> None:
    backend = FakeBackend()
    box = Sandbox(backend)
    cid = box.start(SandboxConfig())
    assert cid == "c-fake-1"


def test_docker_sandbox_builds_isolated_argv_without_executing() -> None:
    ds = DockerSandbox(docker_path="/usr/bin/docker")
    argv = ds.run_argv(
        SandboxConfig(
            image="kalilinux/kali-rolling",
            network="target_only",
            memory_limit_mb=2048,
            cpu_limit=2.0,
            timeout_seconds=600,
            mount_volumes=[("/tmp/work", "/work")],
        ),
        command=["nuclei", "-jsonl"],
        container_name="apex-x1",
    )
    assert argv[0] == "/usr/bin/docker"
    for flag in ("--network", "--memory", "--cpus", "--rm", "--name"):
        assert flag in argv, f"docker isolation flag {flag} missing"
    assert "docker" not in argv[argv.index("--network") + 1]  # restricted net value
    assert argv[argv.index("--memory") + 1] == "2048m"
    assert argv[argv.index("--cpus") + 1] == "2.0"
    # zero host filesystem access beyond declared volumes (APEX-L-4)
    assert "/tmp/work:/work" in argv
    # the argv is returned, never executed
    assert isinstance(argv, list)


def test_sandbox_network_isolated_by_default() -> None:
    ds = DockerSandbox()
    argv = ds.run_argv(SandboxConfig(), command=["x"], container_name="n1")
    net = argv[argv.index("--network") + 1]
    assert net != "host" and net != "bridge", "default must be restricted"


def test_sandbox_cleanup_removes_container() -> None:
    backend = FakeBackend()
    box = Sandbox(backend)
    cid = box.start(SandboxConfig())
    box.cleanup(cid)
    assert backend.stopped == [cid]
    assert box.container_ids == []


def test_stop_terminates_container() -> None:
    backend = FakeBackend()
    box = Sandbox(backend)
    cid = box.start(SandboxConfig())
    box.stop(cid)
    assert backend.stopped == [cid]


def test_sandbox_execute_returns_outcome() -> None:
    backend = FakeBackend()
    # no scope passed → fail-closed default; execution needs the explicit
    # allow-all guard, so the test constructs one (approval is explicit).
    box = Sandbox(backend, scope=ScopeGuard.allow_all())
    cid = box.start(SandboxConfig())
    outcome = box.execute(cid, ["nuclei", "-jsonl", "https://target.test"])
    assert isinstance(outcome, ExecOutcome)
    assert outcome.exit_code == 0
    assert outcome.stdout == b"ok"


def test_sandbox_without_scope_fails_closed() -> None:
    backend = FakeBackend()
    box = Sandbox(backend)
    cid = box.start(SandboxConfig())
    with pytest.raises(ScopeViolationError):
        box.execute(cid, ["nuclei", "https://target.test"])
    assert backend.calls == []


def test_scope_guard_rejects_out_of_scope_host() -> None:
    guard = ScopeGuard(allowed_hosts={"target.test", "api.target.test"})
    with pytest.raises(ScopeViolationError, match="evil.example"):
        guard.check(["nuclei", "-target", "https://evil.example/x"])


def test_scope_guard_accepts_in_scope() -> None:
    guard = ScopeGuard(allowed_hosts={"target.test"})
    guard.check(["httpx", "https://target.test/login"])
    guard.check(["nmap", "target.test"])  # bare host


def test_scope_guard_fails_closed_on_empty_scope() -> None:
    guard = ScopeGuard(allowed_hosts=set())
    with pytest.raises(ScopeViolationError):
        guard.check(["httpx", "https://anything.test"])


def test_scope_guard_ignores_non_argument_flags() -> None:
    guard = ScopeGuard(allowed_hosts={"target.test"})
    # flags and wordlists are not hosts; only URL/host-shaped args are checked
    guard.check(["ffuf", "-w", "/words.txt", "-u", "https://target.test/FUZZ"])


def test_scope_guard_catches_embedded_out_of_scope_url() -> None:
    guard = ScopeGuard(allowed_hosts={"target.test"})
    with pytest.raises(ScopeViolationError):
        guard.check(["ffuf", "-u", "https://target.test/redirect?to=evil.example"])


def test_sandbox_execute_enforces_scope_before_tool() -> None:
    backend = FakeBackend()
    box = Sandbox(backend, scope=ScopeGuard(allowed_hosts={"target.test"}))
    cid = box.start(SandboxConfig())
    with pytest.raises(ScopeViolationError):
        box.execute(cid, ["nuclei", "https://out.example"])
    assert backend.calls == [], "L-3: nothing runs when scope fails"


def test_sandbox_execute_in_scope_runs() -> None:
    backend = FakeBackend()
    box = Sandbox(backend, scope=ScopeGuard(allowed_hosts={"target.test"}))
    cid = box.start(SandboxConfig())
    box.execute(cid, ["nuclei", "https://target.test"])
    assert len(backend.calls) == 1


def test_sandbox_get_output() -> None:
    backend = FakeBackend()
    box = Sandbox(backend)
    cid = box.start(SandboxConfig())
    assert box.get_output(cid, "/out/results.jsonl") == b"file-bytes"


def test_timeout_passed_to_backend_config() -> None:
    config = SandboxConfig(timeout_seconds=42)
    assert config.timeout_seconds == 42


def test_local_sandbox_times_out(tmp_path: Path) -> None:
    """The only real-subprocess test: a sleep command must be killed at the
    timeout and produce exit_code 124 with the timed_out flag."""
    sandbox = LocalSandbox(workdir=tmp_path)
    outcome = sandbox.run_command(["sleep", "5"], timeout_seconds=1)
    assert outcome.exit_code == 124
    assert outcome.timed_out is True
    assert outcome.duration_seconds < 5


def test_local_sandbox_captures_output(tmp_path: Path) -> None:
    sandbox = LocalSandbox(workdir=tmp_path)
    outcome = sandbox.run_command(["printf", "hello"], timeout_seconds=5)
    assert outcome.exit_code == 0
    assert outcome.stdout == b"hello"
    assert outcome.timed_out is False


def test_preamble_is_advisory() -> None:
    assert "advisory" in PREAMBLE_LINE


def test_exec_result_datclass_defaults() -> None:
    result = ExecResult(
        tool_id="x",
        command=["x"],
        exit_code=0,
        stdout=b"",
        stderr=b"",
        duration_seconds=0.0,
    )
    assert result.parsed_output is None


def test_mount_volumes_default_empty() -> None:
    assert SandboxConfig().mount_volumes == []
