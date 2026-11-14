# src/webpent/graph/checkpoints.py
"""LangGraph checkpointing with SQLite contention and secret hygiene."""

from __future__ import annotations

import copy
import logging
import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver

logger = logging.getLogger(__name__)

_DEFAULT_SESSIONS_DB_PATH = "./memory/global/sessions.db"
_BUSY_TIMEOUT_MS = 30_000
_STRICT_MSGPACK_ENV = "LANGGRAPH_STRICT_MSGPACK"
_SECRET_CHANNELS = {"session_cookies", "session_headers", "identity_profiles"}
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "cookies",
        "credentials",
        "jwt_weak_secret_candidates",
        "password",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "session_cookies",
        "session_headers",
        "set-cookie",
        "token",
    }
)

_SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "private_key",
    "refresh_token",
    "session_token",
    "totp",
)


def _is_sensitive_key(key: str) -> bool:
    normalized_key = key.lower().replace("-", "_")
    return (
        normalized_key in _SENSITIVE_KEYS
        or normalized_key.endswith("_secret")
        or any(fragment in normalized_key for fragment in _SECRET_KEY_FRAGMENTS)
    )


def _runtime_context_descriptor(value: Any) -> dict[str, Any] | None:
    """Project a live RuntimeContext before generic deepcopy/redaction."""
    try:
        from webpent.shared.runtime import RuntimeContext, RuntimeFactory
    except (ImportError, AttributeError):
        return None
    if isinstance(value, RuntimeContext):
        return RuntimeFactory.descriptor(value)
    return None


def _redact_value(value: Any, key: str | None = None) -> Any:
    """Recursively remove secret-shaped values from persisted structures."""
    runtime_descriptor = _runtime_context_descriptor(value)
    if runtime_descriptor is not None:
        return runtime_descriptor
    normalized_key = key.lower().replace("-", "_") if key else ""
    if normalized_key and _is_sensitive_key(normalized_key):
        if isinstance(value, dict):
            return {}
        if isinstance(value, list):
            return []
        if isinstance(value, tuple):
            return ()
        return ""
    if isinstance(value, dict):
        return {
            str(item_key): _redact_value(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    return copy.deepcopy(value)


def _ensure_parent_dir(db_path: str) -> None:
    """Create the parent directory for ``db_path`` if it does not exist."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Created checkpoint parent directory: %s", path.parent)


def _enforce_checkpoint_deserialization_policy() -> None:
    """Require strict checkpoint deserialization outside local lab mode."""
    profile = os.getenv("ENVIRONMENT_PROFILE", "lab").strip().lower() or "lab"
    strict_value = os.getenv(_STRICT_MSGPACK_ENV, "").strip().lower()
    strict_enabled = strict_value in {"1", "true", "yes", "on"}
    if profile in {"staging", "production"} and not strict_enabled:
        raise RuntimeError(
            f"{_STRICT_MSGPACK_ENV}=true is required for {profile} checkpoint persistence"
        )
    if profile == "lab" and not strict_enabled:
        logger.warning(
            "%s is not enabled in lab mode; checkpoint deserialization is less restrictive",
            _STRICT_MSGPACK_ENV,
        )


def _set_busy_timeout(conn: sqlite3.Connection) -> None:
    """Apply and verify the checkpoint connection busy timeout."""
    try:
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        result = conn.execute("PRAGMA busy_timeout").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError("Unable to enforce SQLite checkpoint busy_timeout=30000") from exc
    if not result or int(result[0]) != _BUSY_TIMEOUT_MS:
        raise RuntimeError(f"SQLite checkpoint busy_timeout policy was not applied: {result!r}")
    logger.debug("Set busy_timeout=%d on checkpoint connection", _BUSY_TIMEOUT_MS)


def _redact_channel(channel: str, value: Any) -> Any:
    """Return a checkpoint-safe copy of one state channel."""
    if channel == "runtime_context":
        # UM-DR-34 §7 — safe-failure contract.  The historic branch
        # caught every exception and persisted ``{}`` SILENTLY: on
        # resume, ``RuntimeFactory.from_descriptor({})`` rebuilt a
        # BLANK runtime (budget/kill-switch accounting reset) or dropped
        # the channel — an undebuggable false-success resume.
        #
        # The contract now:
        #   1. never persist raw runtime secrets as a fallback;
        #   2. record a structured, secret-free failure event (channel,
        #      exception CLASS ONLY — never values, never secrets);
        #   3. persist an explicit DEGRADED marker so the artifact can
        #      never be mistaken for a valid empty context;
        #   4. the restore path refuses to rebuild a runtime from the
        #      degraded marker (no silent resume-as-if-complete).
        try:
            from webpent.shared.runtime import RuntimeContext, RuntimeFactory

            if isinstance(value, RuntimeContext):
                return RuntimeFactory.descriptor(value)
            if isinstance(value, dict) and value.get("runtime_context_status") == "degraded":
                return dict(value)
            return dict(value) if isinstance(value, dict) else {}
        except Exception as exc:  # noqa: BLE001 — see contract above
            logger.error(
                "Checkpoint runtime_context redaction FAILED — persisting "
                "explicit degraded marker (resume will NOT silently "
                "rebuild a blank runtime): channel=runtime_context, "
                "error_type=%s",
                type(exc).__name__,
            )
            return {
                "runtime_context_status": "degraded",
                "degraded_reason": type(exc).__name__,
            }
    if channel in _SECRET_CHANNELS:
        return {}
    if channel == "jwt_weak_secret_candidates":
        return []
    if channel == "credentials" and isinstance(value, dict):
        redacted = _redact_value(value)
        if isinstance(redacted, dict) and "password" in redacted:
            redacted["password"] = ""
        return redacted
    if channel == "auth_state" and isinstance(value, dict):
        redacted = _redact_value(value)
        if isinstance(redacted, dict):
            for key in (
                "cookies",
                "credentials",
                "password",
                "session_cookies",
                "access_token",
                "refresh_token",
            ):
                if key in redacted:
                    redacted[key] = {} if isinstance(redacted[key], dict) else []
        return redacted
    return _redact_value(value, channel)


def _redact_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Copy a checkpoint and remove operator secrets before serialization.

    R2-graph-05: only ``channel_values`` carry secrets. ``channel_versions``
    and ``versions_seen`` are langgraph ordering metadata whose channel-NAMED
    keys tripped the name-based redaction and silently destroyed the resume
    ordering state (e.g. ``credentials`` -> ""); they are copied verbatim.
    """
    version_keys = ("channel_versions", "versions_seen")
    safe_checkpoint: dict[str, Any] = {}
    for key, value in checkpoint.items():
        if key == "channel_values":
            continue
        if key in version_keys:
            safe_checkpoint[key] = copy.deepcopy(value)
            continue
        safe_checkpoint[key] = _redact_value(value, key)
    channels = checkpoint.get("channel_values")
    safe_checkpoint["channel_values"] = (
        {
            channel: _redact_channel(channel, value) for channel, value in channels.items()
        }
        if isinstance(channels, dict)
        else {}
    )
    return safe_checkpoint


def _restore_runtime_secrets(checkpoint_tuple: Any) -> Any:
    """Restore secrets from the worker vault only in the returned runtime tuple."""
    if checkpoint_tuple is None:
        return None
    checkpoint = copy.deepcopy(checkpoint_tuple.checkpoint)
    channels = checkpoint.get("channel_values")
    if not isinstance(channels, dict):
        return checkpoint_tuple

    try:
        from webpent.auth.reauth_vault import (
            identity_vault_key,
            unseal_identity_profiles,
            unseal_reauth_secret,
            unseal_session_cookies,
        )

        configurable = checkpoint_tuple.config.get("configurable", {})
        thread_id = str(channels.get("thread_id") or configurable.get("thread_id") or "")
        if not thread_id:
            return checkpoint_tuple
        client_id = str(channels.get("client_id") or "").strip()
        engagement_id = str(channels.get("engagement_id") or "").strip()
        runtime_descriptor = channels.get("runtime_context")
        if isinstance(runtime_descriptor, dict):
            engagement_id = engagement_id or str(
                runtime_descriptor.get("engagement_id") or ""
            ).strip()
        identity_key = (
            identity_vault_key(client_id, engagement_id)
            if client_id and engagement_id
            else thread_id
        )
        password = unseal_reauth_secret(thread_id)
        if password:
            credentials = dict(channels.get("credentials") or {})
            credentials["password"] = password
            channels["credentials"] = credentials
        cookies = unseal_session_cookies(thread_id)
        if cookies:
            channels["session_cookies"] = cookies
        profiles = unseal_identity_profiles(identity_key) if identity_key else {}
        if not profiles and identity_key and identity_key != thread_id:
            profiles = unseal_identity_profiles(thread_id)
        if profiles:
            channels["identity_profiles"] = profiles
            primary_headers = next(
                (
                    dict(profile.get("headers") or {})
                    for profile in profiles.values()
                    if isinstance(profile, dict)
                    and profile.get("validated")
                    and isinstance(profile.get("headers"), dict)
                    and profile.get("headers")
                ),
                {},
            )
            if primary_headers:
                channels["session_headers"] = primary_headers
    except Exception as exc:
        logger.error(
            "Checkpoint runtime secret restoration failed closed for thread_id=%s: %s",
            checkpoint_tuple.config.get("configurable", {}).get("thread_id", ""),
            exc,
        )

    try:
        from webpent.shared.runtime import RuntimeFactory

        descriptor = channels.get("runtime_context")
        if isinstance(descriptor, dict) and descriptor.get("runtime_context_status") == "degraded":
            # UM-DR-34 §7: a degraded runtime context must NOT resume as
            # though it were complete — no silent blank-runtime rebuild,
            # no false-success.  Drop the channel (nodes fall back to
            # the legacy path) and surface the degradation loudly.
            logger.error(
                "Checkpoint runtime context is DEGRADED for thread_id=%s "
                "(reason=%s) — refusing to rebuild; resume continues on "
                "the legacy path without runtime accounting.",
                checkpoint_tuple.config.get("configurable", {}).get("thread_id", ""),
                descriptor.get("degraded_reason", "unknown"),
            )
            channels.pop("runtime_context", None)
        else:
            rebuilt_runtime = RuntimeFactory.from_descriptor(descriptor)
            if rebuilt_runtime is not None:
                channels["runtime_context"] = rebuilt_runtime
            else:
                channels.pop("runtime_context", None)
    except Exception as exc:
        logger.error(
            "Checkpoint runtime context restoration failed closed for thread_id=%s: %s",
            checkpoint_tuple.config.get("configurable", {}).get("thread_id", ""),
            exc,
        )
        channels.pop("runtime_context", None)

    pending_writes = checkpoint_tuple.pending_writes
    if pending_writes:
        pending_writes = [
            (task_id, channel, _redact_channel(channel, value))
            for task_id, channel, value in pending_writes
        ]
    return checkpoint_tuple._replace(
        checkpoint=checkpoint,
        pending_writes=pending_writes,
    )


class RedactingSqliteSaver(SqliteSaver):
    """SqliteSaver that never serializes the designated secret channels."""

    def put(
        self,
        config: Any,
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        return super().put(
            config,
            _redact_checkpoint(checkpoint),
            _redact_value(metadata),
            new_versions,
        )

    def put_writes(
        self,
        config: Any,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        safe_writes = [(channel, _redact_channel(channel, value)) for channel, value in writes]
        super().put_writes(config, safe_writes, task_id, task_path)

    def get_tuple(self, config: Any) -> Any:
        return _restore_runtime_secrets(super().get_tuple(config))

    def list(self, config: Any, **kwargs: Any) -> Iterator[Any]:
        for checkpoint_tuple in super().list(config, **kwargs):
            yield _restore_runtime_secrets(checkpoint_tuple)


@contextmanager
def _managed_factory_saver(factory: Any) -> Iterator[RedactingSqliteSaver]:
    """Apply policy to the official LangGraph factory path."""
    with factory as saver:
        _enforce_checkpoint_deserialization_policy()
        _set_busy_timeout(saver.conn)
        yield RedactingSqliteSaver(conn=saver.conn, serde=saver.serde)


@contextmanager
def _managed_fallback_saver(conn: sqlite3.Connection) -> Iterator[RedactingSqliteSaver]:
    """Wrap a fallback connection with enforced policy and safe closure."""
    try:
        _enforce_checkpoint_deserialization_policy()
        _set_busy_timeout(conn)
        yield RedactingSqliteSaver(conn=conn)
    finally:
        conn.close()


def get_checkpointer(db_path: str | Path | None = None):
    """Return a target-scoped, contention-safe redacting saver.

    An explicit path always wins.  Otherwise an active target workspace owns
    the sessions database; callers outside a workspace retain the historical
    global path for backward compatibility.
    """
    resolved_path = db_path
    if resolved_path is None:
        try:
            from webpent.shared.target_workspace_context import (
                get_active_target_workspace,
            )

            workspace = get_active_target_workspace()
        except ImportError:
            workspace = None
        if workspace is not None:
            resolved_path = workspace.sessions_database_path
    if resolved_path is None:
        resolved_path = _DEFAULT_SESSIONS_DB_PATH
    resolved_path = str(resolved_path)
    _ensure_parent_dir(resolved_path)
    try:
        saver_factory = SqliteSaver.from_conn_string(conn_string=resolved_path)
        logger.info("LangGraph SqliteSaver checkpointer factory created at %s", resolved_path)
        return _managed_factory_saver(saver_factory)
    except (TypeError, AttributeError):
        logger.warning("SqliteSaver.from_conn_string unavailable; using explicit connection")
        conn = sqlite3.connect(resolved_path, check_same_thread=False)
        return _managed_fallback_saver(conn)
