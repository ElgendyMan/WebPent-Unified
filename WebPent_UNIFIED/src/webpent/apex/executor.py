"""The Apex Predator — U-APEX-3, the Tool Executor (v87).

Runs ONE registered tool inside the sandbox (APEX-L-4, after the scope
guard — APEX-L-3), captures stdout/stderr/exit code, and parses the output
by the tool's declared `output_format` deterministically. Parsing is pure:
the same bytes always yield the same parsed dict (L-6 fusion depends on
stable shapes). The executor never sends anything anywhere — execution
results are advisory evidence for the fusion engine (APEX-L-9).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass

from webpent.apex.sandbox import Sandbox, ScopeGuard
from webpent.apex.tool_registry import ToolRegistry, UnknownToolError

#: exit code reserved for "the deadline killed it" (GNU timeout convention)
TIMED_OUT_EXIT = 124

_MAX_STDOUT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ExecResult:
    """One tool execution's full measured outcome."""

    tool_id: str
    command: list[str]
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    parsed_output: dict | None = None
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def as_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "duration_seconds": round(self.duration_seconds, 4),
            "parsed_output": self.parsed_output,
            "timed_out": self.timed_out,
            "succeeded": self.succeeded,
        }


class UnknownToolForExecutionError(UnknownToolError):
    """An execution was requested for a tool id outside the registry."""


class ToolExecutor:
    """Execute one registered tool and parse its output."""

    def __init__(
        self,
        registry: ToolRegistry,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._registry = registry
        self._clock = clock  # injected for deterministic durations

    def _require_registered(self, tool_id: str) -> None:
        """RT-10: the dead-code exception now guards the execution path."""
        if not self._registry.has(tool_id):
            raise UnknownToolForExecutionError(
                f"tool {tool_id!r} is not in the vetted registry"
            )

    def _now(self) -> float:
        if self._clock is not None:
            return float(self._clock())
        return 0.0

    def execute(
        self,
        tool_id: str,
        args: list[str],
        sandbox: Sandbox,
        scope: ScopeGuard | None = None,
    ) -> ExecResult:
        self._require_registered(tool_id)
        spec = self._registry.get(tool_id)
        command = [spec.binary, *args]
        if scope is not None:
            scope.check(command)
        started = self._now()
        outcome = sandbox.execute("", command)
        duration = max(0.0, self._now() - started) if self._clock else 0.0
        return ExecResult(
            tool_id=tool_id,
            command=command,
            exit_code=outcome.exit_code,
            stdout=outcome.stdout[:_MAX_STDOUT_BYTES],
            stderr=outcome.stderr[:_MAX_STDOUT_BYTES],
            duration_seconds=duration if self._clock else outcome.duration_seconds,
            parsed_output=self.parse_output(tool_id, outcome.stdout),
            timed_out=outcome.timed_out,
        )

    def execute_with_timeout(
        self,
        tool_id: str,
        args: list[str],
        sandbox: Sandbox,
        timeout: int,
        scope: ScopeGuard | None = None,
    ) -> ExecResult:
        """Same as execute() but the sandboxed command is bounded by the
        given wall-clock deadline; a killed run reports exit 124."""
        self._require_registered(tool_id)
        spec = self._registry.get(tool_id)
        command = [spec.binary, *args]
        if scope is not None:
            scope.check(command)
        started = self._now()
        # RT-02: the caller's deadline must actually reach the backend,
        # not be accepted and silently dropped.
        outcome = sandbox.execute("", command, timeout_seconds=timeout)
        duration = max(0.0, self._now() - started) if self._clock else 0.0
        timed_out = outcome.timed_out
        exit_code = TIMED_OUT_EXIT if timed_out else outcome.exit_code
        return ExecResult(
            tool_id=tool_id,
            command=command,
            exit_code=exit_code,
            stdout=outcome.stdout[:_MAX_STDOUT_BYTES],
            stderr=outcome.stderr[:_MAX_STDOUT_BYTES],
            duration_seconds=duration if self._clock else outcome.duration_seconds,
            parsed_output=self.parse_output(tool_id, outcome.stdout),
            timed_out=timed_out,
        )

    # -- parsing (pure, deterministic) ---------------------------------------

    def parse_output(self, tool_id: str, raw: bytes) -> dict | None:
        """Parse by the tool's declared output_format. Returns None for
        empty output; malformed content yields a structured error payload,
        never an exception (fusion must survive bad tool output)."""
        spec = self._registry.get(tool_id)
        if not raw.strip():
            return None
        text = raw.decode("utf-8", errors="replace")
        fmt = spec.output_format
        if fmt == "jsonl":
            return self._parse_jsonl(text)
        if fmt == "json":
            return self._parse_json(text)
        if fmt == "xml":
            return self._parse_xml(text)
        return self._parse_text(text)

    @staticmethod
    def _parse_jsonl(text: str) -> dict | None:
        records: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                loaded = json.loads(line)
            except json.JSONDecodeError:
                continue  # a bad line is skipped, not fatal
            if isinstance(loaded, dict):
                records.append(loaded)
        return {"format": "jsonl", "records": records, "count": len(records)}

    @staticmethod
    def _parse_json(text: str) -> dict | None:
        if not text.strip():
            return None
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            return {"format": "json", "error": "malformed_json", "records": []}
        return {
            "format": "json",
            "records": loaded if isinstance(loaded, list) else [loaded],
            "count": 1 if not isinstance(loaded, list) else len(loaded),
        }

    @staticmethod
    def _parse_xml(text: str) -> dict | None:
        if not text.strip():
            return None
        try:
            root = ET.fromstring(text)  # noqa: S314 - tool output, no entities
        except ET.ParseError:
            return {"format": "xml", "error": "malformed_xml", "records": []}
        records: list[dict] = []
        for child in root:
            records.append({
                "tag": child.tag,
                "attrs": dict(child.attrib),
                "text": (child.text or "").strip(),
            })
        return {"format": "xml", "root": root.tag, "records": records,
                "count": len(records)}

    @staticmethod
    def _parse_text(text: str) -> dict | None:
        if not text.strip():
            return None
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return {"format": "text", "lines": lines[:5000], "count": len(lines)}
