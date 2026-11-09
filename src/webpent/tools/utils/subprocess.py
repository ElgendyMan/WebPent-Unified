# src/webpent/tools/utils/subprocess.py
"""webpent.tools.utils.subprocess

Thin, opinionated wrapper around :mod:`subprocess` used by every tool
wrapper in the framework.

Design goals:
  * Fail loudly with framework-specific exceptions (``ToolNotFoundError``
    vs ``ToolExecutionError``) so callers can distinguish *missing
    binary* from *broken execution*.
  * Always capture stdout and stderr as text (UTF-8, errors replaced)
    so they survive even when the underlying tool emits garbled bytes —
    UNLESS ``binary_output=True`` is requested, in which case raw bytes
    are returned without decoding (V5 Sprint 8: required for ysoserial
    whose serialized Java payloads are NOT valid UTF-8 and would be
    corrupted by ``errors="replace"``).
  * Enforce a timeout to prevent hung scans from blocking the graph.
  * Run each child in a new POSIX session (``start_new_session=True``)
    so that timeout-triggered ``SIGKILL`` propagates to the entire
    process group, including grandchildren spawned by tools such as
    ``nuclei`` or ``nmap``. This prevents orphan/zombie accumulation
    on long engagements.
  * Catch :class:`OSError` (and subclasses such as
    :class:`PermissionError`) so that race conditions between the
    ``shutil.which`` check and the actual ``exec`` — or OS-level
    failures like EMFILE — surface as clean :class:`ToolExecutionError`
    instances rather than raw tracebacks.

V6 Absolute-Flawless P0 FIX (CISO + Red Team audit — Command Injection):
    The previous implementation accepted a ``cmd`` list and forwarded
    it to :func:`subprocess.run` without explicitly setting
    ``shell=False``. While :mod:`subprocess` defaults to ``shell=False``
    when ``cmd`` is a list, omitting the explicit keyword made the
    security posture implicit and brittle — a future refactor that
    accidentally passed a single string (e.g. ``cmd = " ".join(parts)``)
    would silently flip to ``shell=True`` semantics and allow shell
    metacharacter injection from attacker-controlled target URLs.

    This wrapper now:
      1. **Type-rejects** any ``cmd`` that is not a ``list[str]`` — a
         ``str`` argument raises ``TypeError`` immediately so the bug
         surfaces at the caller rather than being silently re-interpreted
         as a shell command.
      2. **Validates** that every element of ``cmd`` is a ``str`` —
         bytes, None, and other types are rejected so an accidental
         ``None`` placeholder can never become the literal string
         ``"None"`` inside a shell token.
      3. **Explicitly passes ``shell=False``** to :func:`subprocess.run`
         in both the text and binary paths. Even though this is the
         default, the explicit keyword documents the security
         contract and protects against any future ``subprocess``
         release that changes the default.
      4. Provides a :func:`quote_for_logging` helper that uses
         :func:`shlex.quote` ONLY for assembling a human-readable
         log line — never for constructing the actual command. This
         satisfies the "use shlex.quote only if string construction
         is unavoidable" CISO directive: the only place we construct
         a string is for diagnostic logging, where injection is a
         non-issue.
"""

from __future__ import annotations

import ctypes
import os
import shlex
import shutil
import signal
import subprocess
import sys
from contextlib import suppress

from webpent.shared.exceptions import ToolExecutionError, ToolNotFoundError

# Default timeout (seconds) when none is supplied by the caller. Chosen
# generously so long-running scans (e.g. Nuclei with many templates)
# are not prematurely killed.
_DEFAULT_TIMEOUT = 300

# Canonical executable manifest. Custom tool paths must be explicitly listed in
# WEBPENT_ALLOWED_EXECUTABLES; accepting arbitrary configured paths would turn
# a compromised setting into an execution primitive.
_EXECUTABLE_MANIFEST = frozenset(
    {
        "arjun",
        "dalfox",
        "echo",
        "ffuf",
        "gau",
        "httpx",
        "httpx-pd",
        "java",
        "katana",
        "nmap",
        "nuclei",
        "php",
        "phpggc",
        "printf",
        "python",
        "python3",
        "sqlmap",
        "subfinder",
        "ysoserial",
    }
)
# ULTIMATE PLAN 2026-10-27, proposal 5: gau (archive URL discovery) and
# nmap (bounded infra probe, top-N/-sT only — the wrapper refuses -sS
# raw-socket and NSE script modes) joined the deliberate manifest. Both
# wrappers are settings-gated (enable_archive_discovery /
# enable_infra_scan, default off) AND scope-checked before spawn.


def _allowed_executable_names() -> frozenset[str]:
    configured = os.getenv("WEBPENT_ALLOWED_EXECUTABLES", "")
    custom = {item.strip() for item in configured.split(",") if item.strip()}
    custom.update({os.path.basename(sys.executable), "pytest"})
    return frozenset(_EXECUTABLE_MANIFEST | custom)


def validate_executable(executable: str) -> None:
    """Enforce the central executable manifest before process creation."""
    name = os.path.basename(executable)
    if name not in _allowed_executable_names():
        raise PermissionError(
            f"Executable {executable!r} is not in the WebPent manifest. "
            "Register a deliberate custom basename via "
            "WEBPENT_ALLOWED_EXECUTABLES."
        )


def quote_for_logging(cmd: list[str]) -> str:
    """Render ``cmd`` as a shell-quoted, human-readable string for logs.

    V6 Absolute-Flawless: This helper exists ONLY for diagnostic
    logging — the actual subprocess invocation always uses the list
    form with ``shell=False``. Using :func:`shlex.quote` here means
    that even if an attacker-controlled value contains shell
    metacharacters, the logged line is unambiguous and cannot be
    accidentally copy-pasted into a shell to reproduce an injection.
    """
    # Defensive: never trust the input shape, even though run_command
    # also validates. A logger helper must not crash on bad input.
    if not isinstance(cmd, (list, tuple)):
        return repr(cmd)
    return " ".join(shlex.quote(str(part)) for part in cmd)


def _validate_cmd(cmd: list[str]) -> None:
    """V6 Absolute-Flawless: enforce the list[str] contract for ``cmd``.

    A ``str`` argument would cause :func:`subprocess.run` to interpret
    it as a single shell command (effectively ``shell=True``), which
    is a command-injection vector when the string contains
    attacker-controlled substrings (e.g. a target URL with a
    ``;`` shell metacharacter). We reject ``str`` and other non-list
    types outright so the bug surfaces at the caller.
    """
    if not isinstance(cmd, list):
        raise TypeError(
            f"run_command() requires cmd to be a list[str] — got "
            f"{type(cmd).__name__}. Passing a str would invoke the "
            f"shell and allow command injection via attacker-controlled "
            f"target URLs. Construct the command as a list, e.g. "
            f'["nuclei", "-u", url, "-json"].'
        )
    if not cmd:
        raise ValueError("run_command() requires a non-empty command list.")
    for i, part in enumerate(cmd):
        if not isinstance(part, str):
            raise TypeError(
                f"run_command() cmd[{i}] must be str, got "
                f"{type(part).__name__} (value={part!r}). Non-str "
                f"elements would be stringified by subprocess and could "
                f"introduce unexpected shell tokens."
            )


def _set_parent_death_signal(expected_parent_pid: int | None = None) -> None:
    """Terminate a tool child if its WebPent parent exits unexpectedly.

    ``expected_parent_pid`` is captured before ``Popen`` forks. It is
    essential in containers: the application commonly runs as PID 1, so
    checking ``os.getppid() == 1`` would incorrectly kill every legitimate
    tool child. The child is killed only when its parent PID differs from the
    captured WebPent process. The no-op fallback keeps the wrapper portable
    on non-Linux POSIX platforms.
    """
    if sys.platform != "linux":
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # PR_SET_PDEATHSIG is Linux ABI constant 1.
        if libc.prctl(1, signal.SIGKILL) != 0:
            return
        # Close the small race where the parent exits before prctl runs.
        # PID 1 is a valid application parent inside a container; only a
        # change from the captured parent PID indicates orphaning.
        if expected_parent_pid is not None and os.getppid() != expected_parent_pid:
            os.kill(os.getpid(), signal.SIGKILL)
    except (OSError, AttributeError, TypeError):
        # Failure to install the optional safeguard must not change the
        # established command/timeout error contract.
        return


def run_command(
    cmd: list[str],
    timeout: int | None = None,
    input_data: str | None = None,
    binary_output: bool = False,
) -> str | bytes:
    """Execute a subprocess command and return its stdout.

    Args:
        cmd: Argument vector, e.g. ``["nuclei", "-u", url, "-json"]``.
            ``cmd[0]`` is treated as the executable name. MUST be a
            ``list[str]`` — passing a ``str`` raises ``TypeError``
            because it would invoke the shell and allow command
            injection. Each element must also be ``str`` (not bytes).
        timeout: Wall-clock timeout in seconds. ``None`` falls back to
            :data:`_DEFAULT_TIMEOUT`. Use a smaller value for fast tools
            (e.g. httpx probing) and a larger one for long scans.
        input_data: Optional string piped to the child's stdin. Used by
            tools such as ``httpx`` that consume hosts from stdin.
        binary_output: V5 Sprint 8 — when ``True``, return raw ``bytes``
            from stdout without UTF-8 decoding. Required for tools like
            ``ysoserial`` that emit binary serialized payloads which
            would be corrupted by ``errors="replace"``. When ``False``
            (default), stdout is decoded as UTF-8 with errors replaced,
            preserving backward compatibility with all existing callers.

    Returns:
        The decoded stdout of the command (``str`` when
        ``binary_output=False``, ``bytes`` when ``binary_output=True``).

    Raises:
        TypeError: If ``cmd`` is not a ``list[str]`` (e.g. a bare
            string that would trigger shell interpretation).
        ToolNotFoundError: If ``cmd[0]`` cannot be resolved to an
            executable on ``PATH``.
        ToolExecutionError: If the command times out, exits non-zero,
            or fails at the OS level (permission denied, file-descriptor
            exhaustion, race-condition FileNotFoundError, etc.).
        ValueError: If ``cmd`` is empty.
    """
    # V6 Absolute-Flawless P0: Validate the cmd contract BEFORE any
    # subprocess work. This is the command-injection defense.
    _validate_cmd(cmd)

    executable = cmd[0]
    try:
        validate_executable(executable)
    except PermissionError as exc:
        raise ToolExecutionError(
            cmd=cmd,
            returncode=-1,
            stdout="",
            stderr=str(exc),
        ) from exc
    # Resolve the absolute path up front so we can produce a clear
    # ToolNotFoundError rather than letting subprocess surface a generic
    # FileNotFoundError.
    if shutil.which(executable) is None:
        raise ToolNotFoundError(executable)

    effective_timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT

    # V5 Sprint 8: when binary_output=True, do NOT pass text=True /
    # encoding / errors to subprocess.run — we want raw bytes back so
    # binary payloads (ysoserial's Java serialized stream) survive
    # intact. The text-mode path is unchanged for backward compat.
    #
    # V6 Absolute-Flawless P0: ``shell=False`` is passed EXPLICITLY in
    # both branches. This is the default when ``cmd`` is a list, but
    # stating it explicitly documents the security contract and guards
    # against any future ``subprocess`` release that flips the default.
    process: subprocess.Popen[str] | subprocess.Popen[bytes] | None = None
    expected_parent_pid = os.getpid()
    # POSIX-only process-group hardening. On Windows preexec_fn and
    # start_new_session are unsupported (ValueError), and the child already
    # runs isolated in its own process with no shared group signal surface.
    # The parent-death-signal safeguard itself is Linux-only by design and
    # stays a no-op elsewhere.
    _posix = sys.platform != "win32"
    _group_kwargs: dict = (
        {
            "start_new_session": True,
            "preexec_fn": lambda: _set_parent_death_signal(expected_parent_pid),
        }
        if _posix
        else {}
    )
    try:
        if binary_output:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                **_group_kwargs,
            )
            stdout, stderr = process.communicate(
                input=input_data.encode("utf-8") if input_data else None,
                timeout=effective_timeout,
            )
        else:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                encoding="utf-8",
                errors="replace",
                **_group_kwargs,
            )
            stdout, stderr = process.communicate(
                input=input_data,
                timeout=effective_timeout,
            )
    except subprocess.TimeoutExpired as exc:
        if process is not None and process.poll() is None:
            with suppress(ProcessLookupError, AttributeError, OSError):
                if hasattr(os, "killpg"):
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
        if process is not None:
            group_stdout, group_stderr = process.communicate()
        else:
            group_stdout, group_stderr = None, None
        stdout = group_stdout if group_stdout is not None else exc.stdout
        stderr = group_stderr if group_stderr is not None else exc.stderr
        if binary_output:
            stdout = stdout if isinstance(stdout, bytes) else b""
            stderr = stderr if isinstance(stderr, bytes) else b""
        else:
            stdout = stdout if isinstance(stdout, str) else ""
            stderr = stderr if isinstance(stderr, str) else ""
        if not stderr:
            stderr = f"Command timed out after {effective_timeout}s."
        raise ToolExecutionError(
            cmd=cmd,
            returncode=-1,
            stdout=stdout,
            stderr=stderr,
        ) from exc
    except OSError as exc:
        # Covers: FileNotFoundError (race — executable removed between
        # shutil.which and exec), PermissionError (exec bit flipped,
        # or parent dir not traversable), and EMFILE/ENFILE (too many
        # open file descriptors). All are converted to a clean
        # ToolExecutionError so the graph never sees a raw OS error.
        raise ToolExecutionError(
            cmd=cmd,
            returncode=-1,
            stdout="",
            stderr=f"OS error while executing {executable!r}: {exc}",
        ) from exc

    if process is not None and process.returncode != 0:
        raise ToolExecutionError(
            cmd=cmd,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    return stdout
