"""TEAM-1 Phase 2 — compose workspace parity contract tests.

Static, docker-free verification that every compose deployment gives the
api and worker services the IDENTICAL storage posture:

  * both services set WEBPENT_DATABASE_URL to the SAME absolute value,
  * both services set WEBPENT_TARGET_WORKSPACE_ROOT to the SAME value,
  * both services mount the SAME runtime directory (and no service mounts
    a single ``webpent.db`` FILE — the WAL -wal/-shm siblings of a
    file-bind are per-container, which silently splits database state),
  * the API-visible state == worker-visible state == persisted workspace
    state (env parity is what makes that identity possible).
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

COMPOSE_FILES = [
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.dev.yml",
    ROOT / "docker-compose.test.yml",
]


def _load(compose: Path) -> dict:
    return yaml.safe_load(compose.read_text(encoding="utf-8"))


def _service_env(service: dict) -> dict[str, str]:
    raw = service.get("environment")
    env: dict[str, str] = {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    for entry in raw or []:
        if isinstance(entry, str) and "=" in entry:
            key, _, value = entry.partition("=")
            env[key] = value
    return env


def test_all_compose_files_exist() -> None:
    for compose in COMPOSE_FILES:
        assert compose.is_file(), f"missing {compose.name}"


def _resolve_compose_default(value: str) -> str:
    """Resolve ``${VAR:-default}`` fallbacks to their default literal.

    Production compose files let operators override the database URL via
    .env; the parity contract is about the RESOLVED default both services
    converge on when no override is supplied.
    """
    if value.startswith("${") and ":-" in value:
        return value[2:-1].partition(":-")[2]
    return value


def test_api_and_worker_storage_env_is_identical() -> None:
    for compose in COMPOSE_FILES:
        doc = _load(compose)
        services = doc.get("services") or {}
        assert "api" in services and "worker" in services, compose.name
        api_env = _service_env(services["api"])
        worker_env = _service_env(services["worker"])

        for key in ("WEBPENT_DATABASE_URL", "WEBPENT_TARGET_WORKSPACE_ROOT"):
            assert key in api_env, f"{compose.name}: api missing {key}"
            assert key in worker_env, f"{compose.name}: worker missing {key}"
            assert api_env[key] == worker_env[key], (
                f"{compose.name}: {key} differs between api and worker — "
                "the two processes would resolve different databases"
            )

        db_url = _resolve_compose_default(api_env["WEBPENT_DATABASE_URL"])
        assert db_url.startswith("sqlite:////"), (
            f"{compose.name}: database URL must be an absolute sqlite path "
            "(three-slash relative paths anchor to the process CWD)"
        )


def test_no_single_file_db_bind_remains() -> None:
    for compose in COMPOSE_FILES:
        doc = _load(compose)
        for name, service in (doc.get("services") or {}).items():
            for mount in service.get("volumes") or []:
                if isinstance(mount, dict):
                    source = str(mount.get("source", ""))
                    target = str(mount.get("target", ""))
                else:
                    parts = str(mount).split(":")
                    source = parts[0] if parts else ""
                    target = parts[1] if len(parts) > 1 else ""
                assert not target.rstrip("/").endswith("webpent.db") or target.endswith(
                    ("/runtime", "runtime")
                ), (
                    f"{compose.name}:{name} binds a single webpent.db file — "
                    "per-container WAL siblings split database state; mount the "
                    "runtime directory instead"
                )


def test_runtime_directory_is_shared_verbatim() -> None:
    for compose in COMPOSE_FILES:
        doc = _load(compose)
        services = doc.get("services") or {}

        def runtime_targets(service: dict) -> list[str]:
            targets = []
            for mount in service.get("volumes") or []:
                if isinstance(mount, dict):
                    source, target = str(mount.get("source", "")), str(mount.get("target", ""))
                else:
                    parts = str(mount).split(":")
                    source, target = parts[0], parts[1] if len(parts) > 1 else ""
                if source.endswith("runtime"):
                    targets.append(target)
            return targets

        api_targets = runtime_targets(services["api"])
        worker_targets = runtime_targets(services["worker"])
        assert api_targets and worker_targets, (
            f"{compose.name}: both services must mount ./runtime"
        )
        assert api_targets == worker_targets
        workspace_root = _service_env(services["api"])["WEBPENT_TARGET_WORKSPACE_ROOT"]
        assert any(
            target.rstrip("/") in workspace_root or workspace_root.startswith(target.rstrip("/"))
            for target in api_targets
        ), (
            f"{compose.name}: WEBPENT_TARGET_WORKSPACE_ROOT must live inside the "
            "shared runtime mount so the API can resolve worker workspaces"
        )


def test_worker_workspace_resume_path_uses_shared_root(tmp_path, monkeypatch) -> None:
    """The same workspace_id derives from registry inputs on both sides."""
    from webpent.config.settings import get_settings
    from webpent.shared.target_workspace import build_target_workspace

    monkeypatch.setenv("WEBPENT_TARGET_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("WEBPENT_DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    get_settings.cache_clear()

    a = build_target_workspace(
        get_settings(), target_origin="http://lab.local", client_id="c1", engagement_id="e1"
    )
    b = build_target_workspace(
        get_settings(), target_origin="http://lab.local", client_id="c1", engagement_id="e1"
    )
    assert a.workspace_id == b.workspace_id
    assert a.database_url == b.database_url
    assert str(a.databases_dir).startswith(str(tmp_path / "ws"))
    get_settings.cache_clear()
