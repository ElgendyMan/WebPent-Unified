"""Safe command policy for deserialization OOB payload generation.

The generated command is executed by a vulnerable target after it deserializes
our payload. It must therefore be treated as a security boundary even though
our local subprocess receives argv safely. Only bounded HTTP callback commands
are accepted; arbitrary shell commands are rejected.
"""

from __future__ import annotations

import shlex
from urllib.parse import urlparse


def _bounded_seconds(value: str, flag: str) -> None:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise UnsafeDeserializationCommandError(f"{flag} requires a numeric timeout") from exc
    if not 0 < seconds <= 10:
        raise UnsafeDeserializationCommandError(f"{flag} must be between 0 and 10 seconds")


def _validate_client_flags(client: str, flags: list[str]) -> None:
    """Validate argv-like client flags; deny file/proxy/redirect escape hatches."""
    index = 0
    while index < len(flags):
        flag = flags[index]
        if client == "curl":
            if flag in {"--fail", "--silent", "--show-error"}:
                index += 1
                continue
            if flag in {"--max-time", "--connect-timeout"}:
                if index + 1 >= len(flags):
                    raise UnsafeDeserializationCommandError(f"{flag} requires a value")
                _bounded_seconds(flags[index + 1], flag)
                index += 2
                continue
            if flag == "--output":
                if index + 1 >= len(flags) or flags[index + 1] != "/dev/null":
                    raise UnsafeDeserializationCommandError(
                        "curl output is restricted to /dev/null"
                    )
                index += 2
                continue
        elif client == "wget":
            if flag == "--no-verbose" or flag == "--tries=1":
                index += 1
                continue
            if flag.startswith("--timeout="):
                _bounded_seconds(flag.split("=", 1)[1], "--timeout")
                index += 1
                continue
            if flag == "--output-document=-":
                index += 1
                continue
        raise UnsafeDeserializationCommandError(f"unsupported or unsafe {client} flag: {flag}")


class UnsafeDeserializationCommandError(ValueError):
    """Raised when a payload command is outside the OOB callback policy."""


_MAX_COMMAND_LENGTH = 512
_ALLOWED_CLIENTS = {"curl", "wget"}
_FORBIDDEN_SHELL_CHARS = frozenset(";&|`$()<>\n\r")


def _validate_callback_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeDeserializationCommandError(
            "deserialization callback URL must use http or https"
        )
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeDeserializationCommandError(
            "deserialization callback URL must have a host and no credentials"
        )
    if parsed.fragment:
        raise UnsafeDeserializationCommandError(
            "deserialization callback URL must not contain a fragment"
        )


def validate_deserialization_command(command: str) -> str:
    """Validate and return a normalized OOB callback command.

    Supported forms are argv-like ``curl`` or ``wget`` commands. The command
    may contain safe client flags, but it cannot contain shell syntax or any
    executable other than the two HTTP clients. The final argument must be a
    single HTTP(S) callback URL.
    """
    if not isinstance(command, str) or not command.strip():
        raise UnsafeDeserializationCommandError("deserialization command is empty")
    if len(command) > _MAX_COMMAND_LENGTH:
        raise UnsafeDeserializationCommandError(
            f"deserialization command exceeds {_MAX_COMMAND_LENGTH} characters"
        )
    if any(char in command for char in _FORBIDDEN_SHELL_CHARS):
        raise UnsafeDeserializationCommandError(
            "deserialization command contains shell metacharacters"
        )

    try:
        tokens = shlex.split(command, comments=False, posix=True)
    except ValueError as exc:
        raise UnsafeDeserializationCommandError(
            "deserialization command has invalid quoting"
        ) from exc
    if len(tokens) < 2 or tokens[0] not in _ALLOWED_CLIENTS:
        raise UnsafeDeserializationCommandError("only curl or wget callback commands are permitted")

    callback_url = tokens[-1]
    _validate_callback_url(callback_url)
    _validate_client_flags(tokens[0], tokens[1:-1])
    return shlex.join(tokens)


def build_oob_command_templates(oob_url: str) -> tuple[str, ...]:
    """Build the bounded callback command set used by validators."""
    _validate_callback_url(oob_url)
    return (
        shlex.join(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--output",
                "/dev/null",
                oob_url,
            ]
        ),
        shlex.join(
            [
                "wget",
                "--no-verbose",
                "--timeout=5",
                "--tries=1",
                "--output-document=-",
                oob_url,
            ]
        ),
    )
