"""Target-scoped filesystem and resource identity.

A workspace is derived from the target origin plus client and engagement
identity.  It deliberately contains only non-secret descriptors; credentials,
cookies, and live handles never enter the descriptor or checkpoint state.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_SAFE_PART = re.compile(r"[^a-zA-Z0-9._-]+")


def _normalize_origin(target_origin: str) -> str:
    parsed = urlsplit(str(target_origin or "").strip())
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("target_origin must be an absolute HTTP(S) URL")
    port = parsed.port
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{hostname}{'' if default_port else f':{port}'}"


def _safe_part(value: str, *, fallback: str) -> str:
    cleaned = _SAFE_PART.sub("-", str(value or "").strip()).strip(".-_")
    return cleaned[:64] or fallback


@dataclass(frozen=True, slots=True)
class TargetWorkspace:
    """Filesystem namespace for one target and one engagement."""

    workspace_root: Path
    workspace_id: str
    target_origin: str
    client_id: str
    engagement_id: str

    @classmethod
    def for_target(
        cls,
        *,
        workspace_root: str | Path,
        target_origin: str,
        client_id: str = "",
        engagement_id: str = "",
    ) -> TargetWorkspace:
        origin = _normalize_origin(target_origin)
        client = str(client_id or "").strip()
        engagement = str(engagement_id or "").strip()
        identity = "|".join((client, engagement, origin))
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        readable = "-".join(
            (
                _safe_part(client, fallback="client"),
                _safe_part(engagement, fallback="engagement"),
                _safe_part(urlsplit(origin).hostname or "target", fallback="target"),
            )
        )
        workspace_id = f"{readable}-{digest}"
        return cls(
            workspace_root=Path(workspace_root).expanduser().resolve(),
            workspace_id=workspace_id,
            target_origin=origin,
            client_id=client,
            engagement_id=engagement,
        )

    @property
    def root(self) -> Path:
        return self.workspace_root / self.workspace_id

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def sessions_dir(self) -> Path:
        return self.root / "sessions"

    @property
    def rag_dir(self) -> Path:
        return self.root / "rag"

    @property
    def databases_dir(self) -> Path:
        return self.root / "databases"

    @property
    def ledger_dir(self) -> Path:
        return self.root / "ledgers"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{(self.databases_dir / 'webpent.sqlite3').as_posix()}"

    @property
    def findings_ledger_path(self) -> Path:
        return self.ledger_dir / "findings.sqlite3"

    @property
    def action_ledger_path(self) -> Path:
        return self.ledger_dir / "actions.sqlite3"

    @property
    def sessions_database_path(self) -> Path:
        return self.sessions_dir / "checkpoints.sqlite3"

    @property
    def decision_log_database_path(self) -> Path:
        """Append-only decision log path isolated to this workspace."""
        return self.databases_dir / "decision_log.sqlite3"

    @property
    def chroma_path(self) -> Path:
        return self.rag_dir / "chroma_db"

    def ensure(self) -> TargetWorkspace:
        for directory in (
            self.reports_dir,
            self.artifacts_dir,
            self.sessions_dir,
            self.rag_dir,
            self.databases_dir,
            self.ledger_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def as_dict(self) -> dict[str, str]:
        """Return a checkpoint-safe, non-secret workspace descriptor."""
        return {
            "workspace_id": self.workspace_id,
            "workspace_root": str(self.workspace_root),
            "target_origin": self.target_origin,
            "client_id": self.client_id,
            "engagement_id": self.engagement_id,
            "reports_dir": str(self.reports_dir),
            "artifacts_dir": str(self.artifacts_dir),
            "sessions_database_path": str(self.sessions_database_path),
            "decision_log_database_path": str(self.decision_log_database_path),
            "rag_dir": str(self.rag_dir),
            "database_url": self.database_url,
            "findings_ledger_path": str(self.findings_ledger_path),
            "action_ledger_path": str(self.action_ledger_path),
            "chroma_path": str(self.chroma_path),
        }

    def settings_overrides(self) -> dict[str, object]:
        """Return storage-only Settings overrides for this workspace."""
        return {
            "output_dir": self.reports_dir,
            "database_url": self.database_url,
            "findings_ledger_path": self.findings_ledger_path,
            "action_ledger_path": self.action_ledger_path,
            "reauth_vault_database_url": self.database_url,
        }


def build_target_workspace(
    settings: object,
    *,
    target_origin: str,
    client_id: str = "",
    engagement_id: str = "",
) -> TargetWorkspace:
    """Build a workspace from Settings without reading secrets."""
    root = getattr(settings, "target_workspace_root", Path("~/.webpent/workspaces"))
    return TargetWorkspace.for_target(
        workspace_root=root,
        target_origin=target_origin,
        client_id=client_id,
        engagement_id=engagement_id,
    )
