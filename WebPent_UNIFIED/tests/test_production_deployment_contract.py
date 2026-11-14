import os
import re
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE = PROJECT_ROOT / "docker-compose.yml"
ROOTLESS_COMPOSE = PROJECT_ROOT / "docker-compose.rootless.yml"
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
ENTRYPOINT = PROJECT_ROOT / "entrypoint.sh"


def test_production_compose_uses_container_bind_and_external_tls_redis() -> None:
    content = PRODUCTION_COMPOSE.read_text(encoding="utf-8")

    assert "WEBPENT_API_HOST=0.0.0.0" in content
    assert "WEBPENT_REDIS_URL=${REDIS_URL:?REDIS_URL must be set to a rediss:// URL}" in content
    assert (
        "WEBPENT_RATE_LIMIT_REDIS_URL=${RATE_LIMIT_REDIS_URL:?"
        "RATE_LIMIT_REDIS_URL must be set to a rediss:// URL}"
    ) in content
    assert "WEBPENT_AUTH_ENABLED=true" in content
    assert "WEBPENT_RATE_LIMIT_ENABLED=true" in content
    assert "redis://redis:6379" not in content


def test_production_compose_does_not_start_a_plaintext_redis_service() -> None:
    content = PRODUCTION_COMPOSE.read_text(encoding="utf-8")

    assert "\n  redis:\n" not in content
    assert "docker-compose.dev.yml" in content
    assert "externally managed Redis over TLS" in content


def test_entrypoint_drops_privileges_and_limits_ownership_reconciliation() -> None:
    content = ENTRYPOINT.read_text(encoding="utf-8")

    assert 'TARGET_USER="${WEBPENT_RUN_AS_USER:-webpent}"' in content
    assert 'exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"' in content
    assert '"/app/webpent.db"' in content
    assert '"/app/memory"' in content
    assert '"/app/output"' in content
    assert "chmod -R 777" not in content


# ---------------------------------------------------------------------------
# D-1 (v0.28.0 — docs/PRODUCTION_FIX_PLAN_0270.md): optional documented
# rootless mode + runtime verification that the privilege drop actually
# happened. The entrypoint is the deployment trust boundary; these gates
# pin both new behaviors at the source level and exercise the rootless
# branch functionally.
# ---------------------------------------------------------------------------


def test_entrypoint_has_fail_closed_rootless_branch() -> None:
    """A non-root start must exec the command DIRECTLY (no gosu, no chown)
    — before D-1 the root path ran unconditionally and gosu as non-root
    broke every `user:`-directed container."""
    content = ENTRYPOINT.read_text(encoding="utf-8")

    # The guard reads the real uid, not an env-var guess.
    assert 'CURRENT_UID="$(id -u)"' in content
    assert 'if [ "${CURRENT_UID}" -ne 0 ]; then' in content
    # Rootless path execs the command directly — no silent second mechanism.
    assert 'exec "$@"' in content
    # The mode is announced (operator evidence in container logs).
    assert "ROOTLESS MODE" in content
    # The rootless GUARD branch is before the root path's gosu probe
    # (code-level structural order — header comments mention gosu too).
    assert content.index('if [ "${CURRENT_UID}" -ne 0 ]; then') < content.index(
        'DROPPED_UID="$(gosu'
    )


def test_entrypoint_verifies_privilege_drop_fail_closed() -> None:
    """Root path must PROVE the drop landed (gosu runs `id -u` as the
    target) and refuse to start the app on probe failure or uid mismatch
    — the declared D-1 runtime verification."""
    content = ENTRYPOINT.read_text(encoding="utf-8")

    assert 'DROPPED_UID="$(gosu "${TARGET_UID}:${TARGET_GID}" id -u' in content
    # Probe failure → fatal exit.
    assert "privilege-drop probe failed" in content
    assert "exit 1" in content
    # Mismatch between requested and delivered uid → fatal exit.
    assert 'if [ "${DROPPED_UID}" != "${TARGET_UID}" ]; then' in content
    assert "privilege drop did not land" in content
    # Verification happens BEFORE the exec handover (structural order).
    assert content.index("DROPPED_UID=") < content.rindex("exec gosu")
    # Success is announced (the operator's per-boot evidence line).
    assert "privilege drop VERIFIED" in content


def test_entrypoint_is_valid_bash() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(ENTRYPOINT)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, f"entrypoint.sh has bash syntax errors: {proc.stderr}"


def test_entrypoint_rootless_branch_executes_functionally() -> None:
    """Functional proof of the rootless branch on a non-root runner: the
    entrypoint must exec the canary directly and exit with its code."""
    if os.geteuid() == 0:  # pragma: no cover — root runners exercise the other branch
        import pytest

        pytest.skip("rootless functional path requires a non-root runner")
    proc = subprocess.run(
        ["bash", str(ENTRYPOINT), "python3", "-c", "print('rootless-canary-ok')"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "rootless-canary-ok" in proc.stdout
    assert "ROOTLESS MODE" in proc.stdout
    # And the declared mode line does not overclaim: no gosu on this path.
    assert "no gosu" in proc.stdout


def test_entrypoint_root_mode_drop_verification_functional() -> None:
    """Functional proof of the D-1 drop verification on a ROOT runner,
    using a stub gosu that reports a CONTROLLABLE uid:
    (a) honest stub → entrypoint verifies and execs the canary;
    (b) lying stub (wrong uid) → entrypoint MUST fail closed (exit 1).
    Skipped on non-root runners (the guard branch is root-only by design).
    """
    if os.geteuid() != 0:  # pragma: no cover — this sandbox runs non-root
        import pytest

        pytest.skip("root-path drop verification requires a root runner")
    import stat
    import textwrap

    stub_dir = Path(os.environ.get("WEBPENT_TEST_TMP", "/tmp")) / "entrypoint_stub_gosu"
    stub_dir.mkdir(parents=True, exist_ok=True)

    def _stub(report_uid: str) -> Path:
        stub = stub_dir / "gosu"
        stub.write_text(
            textwrap.dedent(
                f"""
                #!/bin/bash
                # test stub: first arg is 'UID:GID', rest is the command
                shift
                if [ "$1" = "id" ]; then echo {report_uid}; exit 0; fi
                exec "$@"
                """
            )
        )
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        return stub

    env = {**os.environ, "PATH": f"{stub_dir}:{os.environ['PATH']}"}

    # (a) honest drop → exec proceeds.
    _stub("1000")
    ok = subprocess.run(
        ["bash", str(ENTRYPOINT), "python3", "-c", "print('drop-ok')"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert ok.returncode == 0, ok.stderr
    assert "privilege drop VERIFIED" in ok.stdout
    assert "drop-ok" in ok.stdout

    # (b) lying drop → fail-closed refusal.
    _stub("0")
    bad = subprocess.run(
        ["bash", str(ENTRYPOINT), "python3", "-c", "print('SHOULD_NOT_RUN')"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert bad.returncode == 1
    assert "privilege drop did not land" in bad.stderr
    assert "SHOULD_NOT_RUN" not in bad.stdout


def test_rootless_compose_override_pins_explicit_uid_fail_fast() -> None:
    """The rootless override must exist, cover BOTH app services, and
    REFUSE to start without explicitly exported WEBPENT_UID/WEBPENT_GID
    (the ${UID:-1000} silent-fallback trap is the root cause this whole
    entrypoint exists to fix — no new instance of it is allowed)."""
    import yaml

    content = ROOTLESS_COMPOSE.read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    services = parsed["services"]
    assert set(services) == {"api", "worker"}
    for name, svc in services.items():
        user_expr = svc["user"]
        assert "${WEBPENT_UID:?" in user_expr, name
        assert "${WEBPENT_GID:?" in user_expr, name
        # No silent numeric fallback anywhere in the override.
        assert ":-1000" not in user_expr
    # The file teaches the mandatory exports in its header.
    assert 'export WEBPENT_UID="$(id -u)"' in content
    assert 'export WEBPENT_GID="$(id -g)"' in content


def test_docker_image_metadata_matches_current_project_version() -> None:
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert 'org.opencontainers.image.title="WebPent v60"' in content
    assert 'org.opencontainers.image.version="${WEBPENT_VERSION}"' in content
    assert 'ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]' in content
    assert not re.search(r"^USER\s+(?:root|webpent)\s*$", content, re.MULTILINE)
    # RESIDUAL CLOSURE 0.26.0 pattern applied to the image metadata (0.28.0):
    # the ARG default must AGREE with the pyproject SSOT dynamically — the
    # old hardcoded 0.3.0 pin was the same fossil class as the stale
    # __version__ pin that gate fixed.
    arg = re.search(r"^ARG WEBPENT_VERSION=(\S+)", content, re.MULTILINE)
    assert arg is not None, "Dockerfile has no WEBPENT_VERSION ARG"
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyproject_version = re.search(
        r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE
    ).group(1)
    assert arg.group(1) == pyproject_version


def test_ci_security_environment_contract_is_explicit() -> None:
    content = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for key, value in {
        "LLM_ENABLED": '"false"',
        "EMBEDDINGS_OFFLINE": '"true"',
        "DISABLE_RAG": '"true"',
        "AUTH_ENABLED": '"false"',
        "FFUF_ENABLED": '"false"',
        "WEBHOOK_ENABLED": '"false"',
    }.items():
        assert f"{key}: {value}" in content
    assert "verify_test_count.py" in content
    assert "scripts/test_count_floor.json" in content or "test_count_floor.json" in content
    assert "tests/test_vip_audit_gap_closure.py" in content

