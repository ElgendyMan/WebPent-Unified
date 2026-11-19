"""Bounded OOB providers for validator integrations.

The local WebPent callback remains the default provider.  The optional
Interactsh provider is deliberately explicit: it starts one short-lived
client session, stores payload/interaction files with restrictive permissions,
redacts tokens from diagnostics, and returns an observation only.  A caller
must still apply the normal target-correlation, negative-control, proof-bundle,
and replay gates before promotion.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

_PAYLOAD_RE = re.compile(r"(?i)(?:https?://)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?:/[^\s]*)?$")


@dataclass(frozen=True)
class OobInteraction:
    """Redacted interaction observation correlated to one generated payload."""

    provider: str
    finding_id: str
    payload_host: str
    interaction_type: str
    observed_at: str | None
    evidence_digest: str


class OobProvider(Protocol):
    def open(self, finding_id: str) -> str | None: ...

    def poll(
        self, finding_id: str, timeout_seconds: float, max_attempts: int
    ) -> OobInteraction | None: ...

    def close(self, finding_id: str) -> None: ...


@dataclass
class _Session:
    process: subprocess.Popen[str]
    directory: tempfile.TemporaryDirectory[str]
    output_path: Path
    payload_path: Path
    session_path: Path
    payload_host: str


class InteractshProvider:
    """Use an explicitly configured interactsh-client without shell execution."""

    name = "interactsh"

    def __init__(
        self,
        *,
        binary: str = "interactsh-client",
        server: str = "",
        token: str = "",
        poll_interval_seconds: int = 1,
        command_runner: Callable[..., subprocess.Popen[str]] | None = None,
    ) -> None:
        self.binary = binary
        self.server = server.strip()
        self.token = token
        self.poll_interval_seconds = max(1, min(30, int(poll_interval_seconds)))
        self._command_runner = command_runner or subprocess.Popen
        self._sessions: dict[str, _Session] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.server and self.binary)

    def open(self, finding_id: str) -> str | None:
        if not self.enabled or finding_id in self._sessions:
            return None
        directory = tempfile.TemporaryDirectory(prefix="webpent-oob-")
        root = Path(directory.name)
        output_path = root / "interactions.jsonl"
        payload_path = root / "payloads.txt"
        session_path = root / "session.bin"
        for path in (output_path, payload_path, session_path):
            path.touch(mode=0o600)

        command = [
            self.binary,
            "-server",
            self.server,
            "-number",
            "1",
            "-poll-interval",
            str(self.poll_interval_seconds),
            "-disable-update-check",
            "-json",
            "-o",
            str(output_path),
            "-ps",
            "-psf",
            str(payload_path),
            "-sf",
            str(session_path),
        ]
        if self.token:
            command.extend(["-token", self.token])
        try:
            process = self._command_runner(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                env={**os.environ, "HOME": str(root)},
            )
        except (OSError, ValueError) as exc:
            directory.cleanup()
            logger.warning("Interactsh provider unavailable: %s", type(exc).__name__)
            return None

        payload_host = self._wait_for_payload(payload_path, process, timeout=5.0)
        if payload_host is None:
            self._terminate(process)
            directory.cleanup()
            return None
        self._sessions[finding_id] = _Session(
            process=process,
            directory=directory,
            output_path=output_path,
            payload_path=payload_path,
            session_path=session_path,
            payload_host=payload_host,
        )
        return f"https://{payload_host}"

    def poll(
        self, finding_id: str, timeout_seconds: float, max_attempts: int
    ) -> OobInteraction | None:
        session = self._sessions.get(finding_id)
        if session is None:
            return None
        deadline = time.monotonic() + max(0.1, min(30.0, timeout_seconds))
        attempts = 0
        while attempts < max(1, min(300, max_attempts)) and time.monotonic() < deadline:
            attempts += 1
            interaction = self._read_interaction(session, finding_id)
            if interaction is not None:
                return interaction
            time.sleep(min(0.3, self.poll_interval_seconds))
        return None

    def close(self, finding_id: str) -> None:
        session = self._sessions.pop(finding_id, None)
        if session is None:
            return
        self._terminate(session.process)
        session.directory.cleanup()

    @staticmethod
    def _wait_for_payload(
        payload_path: Path, process: subprocess.Popen[str], timeout: float
    ) -> str | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                candidates = [
                    line.strip()
                    for line in payload_path.read_text(errors="replace").splitlines()
                    if line.strip()
                ]
            except OSError:
                candidates = []
            if candidates:
                candidate = candidates[0].split()[0]
                match = _PAYLOAD_RE.search(candidate)
                if match:
                    return match.group(1)
            if process.poll() is not None:
                return None
            time.sleep(0.1)
        return None

    @staticmethod
    def _read_interaction(session: _Session, finding_id: str) -> OobInteraction | None:
        try:
            lines = session.output_path.read_text(errors="replace").splitlines()
        except OSError:
            return None
        for line in lines[-100:]:
            try:
                record: Any = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
            if session.payload_host.lower() not in serialized.lower():
                continue
            digest = __import__("hashlib").sha256(serialized.encode()).hexdigest()
            interaction_type = str(
                record.get("protocol") or record.get("type") or "unknown"
            )[:40]
            observed_at = record.get("timestamp") or record.get("time")
            return OobInteraction(
                provider="interactsh",
                finding_id=finding_id,
                payload_host=session.payload_host,
                interaction_type=interaction_type,
                observed_at=str(observed_at) if observed_at else None,
                evidence_digest=digest,
            )
        return None

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        try:
            process.terminate()
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            with suppress(OSError):
                process.kill()


def build_oob_provider(settings: Any) -> OobProvider | None:
    """Build the explicitly selected provider; local callback remains separate."""
    provider = str(getattr(settings, "oob_provider", "local")).strip().lower()
    if provider != "interactsh":
        return None
    token_value = getattr(settings, "interactsh_token", "")
    if hasattr(token_value, "get_secret_value"):
        token_value = token_value.get_secret_value()
    return InteractshProvider(
        binary=str(getattr(settings, "interactsh_binary", "interactsh-client")),
        server=str(getattr(settings, "interactsh_server", "")),
        token=str(token_value or ""),
        poll_interval_seconds=int(
            getattr(settings, "interactsh_poll_interval_seconds", 1)
        ),
    )


def redact_provider_command(command: list[str]) -> list[str]:
    """Return a diagnostic-safe command representation."""
    redacted: list[str] = []
    redact_next = False
    for item in command:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
        elif item in {"-token", "--token", "-t"}:
            redacted.append(item)
            redact_next = True
        else:
            redacted.append(shlex.quote(item) if " " in item else item)
    return redacted
