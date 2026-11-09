"""U-APEX-3 — The Tool Executor (v87): run + capture + deterministic parse."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from webpent.apex.executor import TIMED_OUT_EXIT, ExecResult, ToolExecutor
from webpent.apex.sandbox import ExecOutcome, Sandbox, SandboxConfig, ScopeGuard
from webpent.apex.tool_registry import ToolRegistry

WORK = Path(__file__).resolve().parents[2]


def _registry(tmp_path: Path, output_format: str = "jsonl") -> ToolRegistry:
    path = tmp_path / "tools.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "tools": [
                    {
                        "id": "fakejson",
                        "name": "Fake JSONL",
                        "category": "scanning",
                        "binary": "fakejson",
                        "install_command": "pip install fakejson",
                        "input_type": "url_list",
                        "output_format": output_format,
                        "capabilities": ["cap_a"],
                        "speed": "fast",
                        "stealth": "medium",
                        "vetted": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return ToolRegistry.load(path)


class ScriptedSandbox:
    """Minimal sandbox double returning canned outcomes in order."""

    def __init__(self, outcomes: list[ExecOutcome]) -> None:
        self._outcomes = list(outcomes)
        self.commands: list[list[str]] = []

    def execute(
        self,
        container_id: str,
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> ExecOutcome:  # noqa: ARG002
        self.commands.append(list(command))
        return self._outcomes.pop(0)

    def cleanup(self, container_id: str) -> None:  # noqa: ARG002
        return None

    def start(self, config: SandboxConfig) -> str:  # noqa: ARG002
        return "c"

    def stop(self, container_id: str) -> None:  # noqa: ARG002
        return None

    def get_output(self, container_id: str, path: str) -> bytes:  # noqa: ARG002
        return b""


def _sandbox_with(outcome: ExecOutcome) -> Sandbox:
    return Sandbox(ScriptedSandbox([outcome]), scope=ScopeGuard.allow_all())


class _Tick:
    """Injectable deterministic clock."""

    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.5
        return self.value


def test_execute_returns_result(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry, clock=_Tick())
    outcome = ExecOutcome(exit_code=0, stdout=b'{"a":1}\n', stderr=b"",
                          duration_seconds=0.01)
    sandbox = _sandbox_with(outcome)
    result = executor.execute("fakejson", ["-t", "target.test"], sandbox)
    assert isinstance(result, ExecResult)
    assert result.tool_id == "fakejson"
    assert result.command == ["fakejson", "-t", "target.test"]
    assert result.exit_code == 0
    assert result.succeeded is True
    assert result.parsed_output is not None
    assert result.parsed_output["count"] == 1


def test_unknown_tool_rejected_before_execution(tmp_path: Path) -> None:
    from webpent.apex.tool_registry import UnknownToolError

    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    sandbox = ScriptedSandbox([])
    with pytest.raises(UnknownToolError):
        executor.execute("ghost", [], Sandbox(sandbox))  # type: ignore[arg-type]
    assert sandbox.commands == []


def test_timeout_handled(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    outcome = ExecOutcome(exit_code=1, stdout=b"", stderr=b"killed",
                          duration_seconds=5.0, timed_out=True)
    result = executor.execute_with_timeout(
        "fakejson", ["-t", "target.test"], _sandbox_with(outcome), timeout=5
    )
    assert result.exit_code == TIMED_OUT_EXIT
    assert result.timed_out is True
    assert result.succeeded is False


def test_output_parsed_correctly_jsonl(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    raw = b'{"id":1}\n{"id":2}\nnot-json\n\n{"id":3}\n'
    parsed = executor.parse_output("fakejson", raw)
    assert parsed is not None
    assert parsed["format"] == "jsonl"
    assert parsed["count"] == 3
    assert parsed["records"][0] == {"id": 1}


def test_output_parsed_correctly_json(tmp_path: Path) -> None:
    registry = _registry(tmp_path, output_format="json")
    executor = ToolExecutor(registry)
    parsed = executor.parse_output("fakejson", json.dumps({"k": "v"}).encode())
    assert parsed is not None
    assert parsed["format"] == "json"
    assert parsed["records"] == [{"k": "v"}]


def test_output_parsed_correctly_xml(tmp_path: Path) -> None:
    registry = _registry(tmp_path, output_format="xml")
    executor = ToolExecutor(registry)
    raw = b"<run><host name='a'/><host name='b'/></run>"
    parsed = executor.parse_output("fakejson", raw)
    assert parsed is not None
    assert parsed["format"] == "xml"
    assert parsed["count"] == 2


def test_output_parsed_correctly_text(tmp_path: Path) -> None:
    registry = _registry(tmp_path, output_format="text")
    executor = ToolExecutor(registry)
    parsed = executor.parse_output("fakejson", b"line1\nline2\n")
    assert parsed is not None
    assert parsed["format"] == "text"
    assert parsed["count"] == 2


def test_empty_output_parses_to_none(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    assert executor.parse_output("fakejson", b"") is None
    assert executor.parse_output("fakejson", b"   \n  ") is None


def test_malformed_json_is_structured_not_fatal(tmp_path: Path) -> None:
    registry = _registry(tmp_path, output_format="json")
    executor = ToolExecutor(registry)
    parsed = executor.parse_output("fakejson", b"{oops")
    assert parsed is not None
    assert parsed["error"] == "malformed_json"


def test_deterministic_output_parsing(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    raw = b'{"a":1}\n{"b":[1,2]}\n'
    first = executor.parse_output("fakejson", raw)
    second = executor.parse_output("fakejson", raw)
    assert first == second


def test_exit_code_captured(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    outcome = ExecOutcome(exit_code=3, stdout=b"", stderr=b"boom",
                          duration_seconds=0.1)
    result = executor.execute("fakejson", [], _sandbox_with(outcome))
    assert result.exit_code == 3
    assert result.stderr == b"boom"


def test_as_dict_shape(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    executor = ToolExecutor(registry)
    outcome = ExecOutcome(exit_code=0, stdout=b"x", stderr=b"",
                          duration_seconds=0.2)
    result = executor.execute("fakejson", [], _sandbox_with(outcome))
    as_dict = result.as_dict()
    for key in ("tool_id", "exit_code", "duration_seconds", "parsed_output",
                "timed_out", "succeeded"):
        assert key in as_dict
