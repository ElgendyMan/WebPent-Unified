"""Safe, shallow Git source acquisition for the ingest CLI."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

_MAX_CLONE_TIMEOUT_SECONDS = 300


class GitSourceError(RuntimeError):
    """Raised when a Git source cannot be validated or cloned."""


def validate_git_url(repo_url: str) -> str:
    """Validate and normalize a public HTTPS Git URL.

    The ingest wrapper deliberately does not accept shell-style SSH URLs or
    embedded credentials. This keeps the command predictable and prevents
    credentials from being copied into subprocess arguments or logs.
    """
    value = str(repo_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise GitSourceError("Only HTTPS Git URLs with a hostname are supported")
    if parsed.username or parsed.password:
        raise GitSourceError("Git URLs containing embedded credentials are not allowed")
    if parsed.fragment:
        raise GitSourceError("Git URL fragments are not supported")
    return value


def _run_git(
    args: list[str], *, cwd: Path | None, timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            cwd=str(cwd) if cwd else None,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise GitSourceError(f"Git command timed out after {timeout_seconds} seconds") from exc
    except OSError as exc:
        raise GitSourceError(f"Could not start git: {exc}") from exc


def clone_repository(
    repo_url: str,
    destination: Path,
    *,
    git_ref: str | None = None,
    timeout_seconds: int = _MAX_CLONE_TIMEOUT_SECONDS,
) -> Path:
    """Clone one repository shallowly and return its checkout path.

    The destination must not already exist. The subprocess is invoked without
    a shell, terminal prompts are disabled, tags are omitted, and checkout
    hooks are disabled for this data-ingestion-only operation.

    BUG FIX (TEAM-1, 2026-10): ``git clone --branch <ref>`` only resolves
    ``ref`` against the remote's advertised branch/tag refs — it 404s with
    "Remote branch <ref> not found in upstream origin" for a bare commit
    SHA (verified empirically against a real pinned SHA from
    ``knowledge_sources.yaml``, which is exactly what every caller in this
    codebase passes). ``--branch`` is tried first, unchanged, for the
    common/fast case of an actual branch or tag name; on failure this now
    falls back to an empty-repo ``init`` + ``fetch --depth 1 <ref>`` +
    ``checkout FETCH_HEAD``, which resolves a commit SHA, a branch, or a
    tag identically (the same sequence verified manually against GitHub).
    """
    url = validate_git_url(repo_url)
    if git_ref is not None and (not git_ref.strip() or git_ref.lstrip().startswith("-")):
        raise GitSourceError("Git ref must be a non-empty name and cannot start with '-'")
    ref = git_ref.strip() if git_ref else None

    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise GitSourceError(f"Clone destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    branch_command = ["clone", "--depth", "1", "--no-tags", "--config", "core.hooksPath=/dev/null"]
    if ref:
        branch_command.extend(["--branch", ref])
    branch_command.extend(["--", url, str(destination)])

    completed = _run_git(branch_command, cwd=None, timeout_seconds=timeout_seconds)
    if completed.returncode == 0:
        return destination

    branch_error = (completed.stderr or completed.stdout or "git clone failed").strip()
    if destination.exists():
        import shutil

        shutil.rmtree(destination, ignore_errors=True)

    if not ref:
        # No ref was requested at all — the branch-less clone itself
        # failed, so there is no commit-SHA fallback to try.
        raise GitSourceError(f"Git clone failed: {branch_error[-1000:]}")

    # Fallback path: ``ref`` may be a commit SHA (or any ref the remote
    # doesn't advertise as a branch/tag). init + fetch + checkout resolves
    # any of those the same way.
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        # RED-TEAM FIX (2026-10, finding #8): `init` moved inside this
        # try/except (was a separate check before the block started) so an
        # init failure gets the same destination cleanup as the other
        # three fallback steps below. Previously, a failed `git init` left
        # behind whatever it had partially created at `destination` with
        # nothing to remove it.
        init = _run_git(
            ["init", "--quiet", "--", str(destination)], cwd=None, timeout_seconds=timeout_seconds
        )
        if init.returncode != 0:
            raise GitSourceError(
                f"Git clone failed (branch lookup: {branch_error[-500:]}); "
                f"fallback init also failed: "
                f"{(init.stderr or init.stdout or '').strip()[-500:]}"
            )
        remote = _run_git(
            ["remote", "add", "origin", url], cwd=destination, timeout_seconds=timeout_seconds
        )
        if remote.returncode != 0:
            raise GitSourceError(
                f"Git clone failed (branch lookup: {branch_error[-500:]}); "
                f"fallback remote add also failed: "
                f"{(remote.stderr or remote.stdout or '').strip()[-500:]}"
            )
        fetch = _run_git(
            ["fetch", "--depth", "1", "origin", ref],
            cwd=destination,
            timeout_seconds=timeout_seconds,
        )
        if fetch.returncode != 0:
            raise GitSourceError(
                f"Git clone failed: '{ref}' is neither a reachable branch/tag "
                f"({branch_error[-300:]}) nor a fetchable commit "
                f"({(fetch.stderr or fetch.stdout or '').strip()[-500:]})"
            )
        checkout = _run_git(
            ["checkout", "--quiet", "FETCH_HEAD"],
            cwd=destination,
            timeout_seconds=timeout_seconds,
        )
        if checkout.returncode != 0:
            raise GitSourceError(
                f"Git clone fallback fetched '{ref}' but checkout failed: "
                f"{(checkout.stderr or checkout.stdout or '').strip()[-500:]}"
            )
        return destination
    except GitSourceError:
        import shutil

        shutil.rmtree(destination, ignore_errors=True)
        raise
