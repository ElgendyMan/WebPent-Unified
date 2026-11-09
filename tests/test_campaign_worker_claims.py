# tests/test_campaign_worker_claims.py
"""Track 12 item 3 operational wiring (v0.25.0) — campaign-lifetime
worker claims.

Covers: the adapter's outcome projection (ACQUIRED/RENEWED/TAKEOVER
held; BUSY/SCOPE_CONFLICT refused; ledger outage fails open), the
settings-driven factory (default-off / enabled / construction failure),
and the MultiCampaignService integration (claim held while RUNNING,
released on halt/complete, second worker refused, fail-open on ledger
outage, exact default-off behavior preservation).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.production.campaign_worker_claims import (
    CampaignWorkerClaims,
    _scope_hash,
    _work_unit_id,
    make_campaign_claims_from_settings,
)
from webpent.production.worker_coordination import WorkerCoordinator, _slug
from webpent.service.facade import MultiCampaignService
from webpent.service.models import CampaignLifecycle, CampaignSpec


def _claim_file(coord: Path, campaign_id: str) -> Path:
    """The coordinator stores claims as '<slug(work_unit)>.json'."""
    return next(coord.rglob(f"{_slug(_work_unit_id(campaign_id))}.json"))


def _coordinator(tmp_path: Path, worker_id: str) -> WorkerCoordinator:
    return WorkerCoordinator(tmp_path / "coord", worker_id=worker_id)


def _adapter(tmp_path: Path, worker_id: str = "worker-a") -> CampaignWorkerClaims:
    return CampaignWorkerClaims(_coordinator(tmp_path, worker_id))


# ----------------------------------------------------------------------
# adapter projection
# ----------------------------------------------------------------------
def test_work_unit_and_scope_hash_are_deterministic_and_content_free() -> None:
    assert _work_unit_id("camp-1") == "campaign:camp-1"
    first = _scope_hash("acme", "https://t.example.com")
    second = _scope_hash("acme", "https://t.example.com")
    other = _scope_hash("acme", "https://other.example.com")
    assert first == second
    assert first != other
    assert len(first) == 16


def test_claim_acquire_then_renew_is_held(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    decision = adapter.claim("camp-1", client_id="acme", target_url="https://t.example.com")
    assert decision["held"] is True
    assert decision["outcome"] in {"acquired", "renewed", "takeover"}
    renewed = adapter.claim("camp-1", client_id="acme", target_url="https://t.example.com")
    assert renewed["held"] is True
    assert renewed["outcome"] == "renewed"


def test_busy_second_worker_is_refused_fail_closed(tmp_path: Path) -> None:
    holder = _adapter(tmp_path, worker_id="worker-a")
    first = holder.claim("camp-1", client_id="acme", target_url="https://t.example.com")
    assert first["held"] is True

    second = _adapter(tmp_path, worker_id="worker-b")
    denied = second.claim("camp-1", client_id="acme", target_url="https://t.example.com")
    assert denied["held"] is False
    assert denied["outcome"] == "busy"
    assert denied["holder_worker_id"] == "worker-a"


def test_scope_conflict_is_refused_never_taken_over(tmp_path: Path) -> None:
    holder = _adapter(tmp_path, worker_id="worker-a")
    assert holder.claim("camp-1", client_id="acme", target_url="https://t.example.com")["held"]

    second = _adapter(tmp_path, worker_id="worker-b")
    conflict = second.claim("camp-1", client_id="acme", target_url="https://evil.example.com")
    assert conflict["held"] is False
    assert conflict["outcome"] == "scope_conflict"


def test_release_frees_the_unit_for_the_next_worker(tmp_path: Path) -> None:
    holder = _adapter(tmp_path, worker_id="worker-a")
    assert holder.claim("camp-1", client_id="acme", target_url="https://t.example.com")["held"]
    holder.release("camp-1", client_id="acme", target_url="https://t.example.com")

    second = _adapter(tmp_path, worker_id="worker-b")
    acquired = second.claim("camp-1", client_id="acme", target_url="https://t.example.com")
    assert acquired["held"] is True
    assert acquired["outcome"] == "acquired"


def test_ledger_outage_fails_open_with_fail_open_marker(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    # Poison the ledger: the claim path exists as a DIRECTORY, so the
    # coordinator's os.open(O_RDWR) fails -> DENIED_ERROR inside the
    # coordinator. The adapter must fail OPEN (resource guard, not a
    # scope decision) and mark the decision.
    coord = tmp_path / "coord"
    claims_dir = coord / "clients"
    assert not list(claims_dir.rglob("*.json"))  # empty before first claim
    probe = adapter.claim("camp-x", client_id="acme", target_url="https://t.example.com")
    assert probe["held"] is True
    poisoned = _claim_file(coord, "camp-x")
    poisoned.unlink()
    poisoned.mkdir()
    # Release the probe claim first so the poisoned unit starts empty.
    adapter.release("camp-x", client_id="acme", target_url="https://t.example.com")

    outage = adapter.claim("camp-x", client_id="acme", target_url="https://t.example.com")
    assert outage["held"] is True
    assert outage["outcome"] == "denied_error"
    assert outage.get("fail_open") is True


# ----------------------------------------------------------------------
# settings-driven factory
# ----------------------------------------------------------------------
def test_factory_is_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.config.settings import get_settings

    monkeypatch.delenv("WEBPENT_WORKER_COORDINATION_ENABLED", raising=False)
    monkeypatch.delenv("WEBPENT_WORKER_COORDINATION_DIR", raising=False)
    get_settings.cache_clear()
    try:
        assert make_campaign_claims_from_settings() is None
    finally:
        get_settings.cache_clear()


def test_factory_enabled_requires_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from webpent.config.settings import get_settings

    monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_ENABLED", "true")
    monkeypatch.delenv("WEBPENT_WORKER_COORDINATION_DIR", raising=False)
    get_settings.cache_clear()
    try:
        assert make_campaign_claims_from_settings() is None  # no dir -> off
        monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_DIR", str(tmp_path / "coord"))
        get_settings.cache_clear()
        adapter = make_campaign_claims_from_settings()
        assert adapter is not None
        assert adapter.coord_dir == str(tmp_path / "coord")
    finally:
        get_settings.cache_clear()


def test_factory_construction_failure_falls_back_to_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from webpent.config.settings import get_settings

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("file blocks mkdir", encoding="utf-8")
    monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_DIR", str(blocker))
    get_settings.cache_clear()
    try:
        assert make_campaign_claims_from_settings() is None
    finally:
        get_settings.cache_clear()


# ----------------------------------------------------------------------
# facade integration
# ----------------------------------------------------------------------
def _plan(service: MultiCampaignService, name: str, client_id: str = "acme") -> dict:
    spec = CampaignSpec(
        campaign_id=name,
        target_url=f"https://{name}.example.com",
        owner_id="owner",
        budget_limit=10.0,
        max_actions=10,
        retry_limit=2,
        metadata={"client_id": client_id},
    )
    return service.plan(spec)


def _enable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from webpent.config.settings import get_settings

    monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_WORKER_COORDINATION_DIR", str(tmp_path / "coord"))
    get_settings.cache_clear()


def test_facade_default_off_creates_no_coordination_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from webpent.config.settings import get_settings

    monkeypatch.delenv("WEBPENT_WORKER_COORDINATION_ENABLED", raising=False)
    monkeypatch.delenv("WEBPENT_WORKER_COORDINATION_DIR", raising=False)
    get_settings.cache_clear()
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    assert service.start("camp-1")["state"] == CampaignLifecycle.RUNNING
    assert not (tmp_path / "coord").exists()  # zero behavior change
    service.halt("camp-1")


def test_facade_holds_claim_while_running_and_refuses_second_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _enable(monkeypatch, tmp_path)
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    assert service.start("camp-1")["state"] == CampaignLifecycle.RUNNING
    # The claim exists in the shared coordination dir while RUNNING.
    assert _claim_file(tmp_path / "coord", "camp-1").is_file()

    # A second worker (fresh coordinator, same shared dir) is refused.
    rival = CampaignWorkerClaims(
        WorkerCoordinator(tmp_path / "coord", worker_id="worker-rival")
    )
    decision = rival.claim("camp-1", client_id="acme", target_url="https://camp-1.example.com")
    assert decision["held"] is False
    assert decision["outcome"] == "busy"
    service.halt("camp-1")


def test_facade_halt_releases_claim_for_the_next_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _enable(monkeypatch, tmp_path)
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    service.start("camp-1")
    service.halt("camp-1")

    rival = CampaignWorkerClaims(
        WorkerCoordinator(tmp_path / "coord", worker_id="worker-rival")
    )
    decision = rival.claim("camp-1", client_id="acme", target_url="https://camp-1.example.com")
    assert decision["held"] is True
    assert decision["outcome"] == "acquired"
    rival.release("camp-1", client_id="acme", target_url="https://camp-1.example.com")


def test_facade_complete_releases_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _enable(monkeypatch, tmp_path)
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    service.start("camp-1")
    service.complete("camp-1")

    rival = CampaignWorkerClaims(
        WorkerCoordinator(tmp_path / "coord", worker_id="worker-rival")
    )
    decision = rival.claim("camp-1", client_id="acme", target_url="https://camp-1.example.com")
    assert decision["held"] is True
    rival.release("camp-1", client_id="acme", target_url="https://camp-1.example.com")


def test_facade_start_failure_releases_the_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _enable(monkeypatch, tmp_path)
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    service.start("camp-1")
    service.halt("camp-1")
    # A halted campaign cannot restart -> start fails AFTER the claim was
    # taken; the claim must be released by the failure path.
    with pytest.raises(ValueError, match="campaign_operator_halted"):
        service.start("camp-1")
    rival = CampaignWorkerClaims(
        WorkerCoordinator(tmp_path / "coord", worker_id="worker-rival")
    )
    decision = rival.claim("camp-1", client_id="acme", target_url="https://camp-1.example.com")
    assert decision["held"] is True
    rival.release("camp-1", client_id="acme", target_url="https://camp-1.example.com")


def test_facade_ledger_outage_fails_open_and_starts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _enable(monkeypatch, tmp_path)
    # Poison the shared dir: the campaign's claim path will be a directory.
    coord = tmp_path / "coord"
    coord.mkdir()
    service = MultiCampaignService(root=tmp_path / "svc")
    _plan(service, "camp-1")
    # Learn the client slug dir by starting a probe campaign first.
    _plan(service, "camp-probe", client_id="acme")
    service.start("camp-probe")
    claim_path = _claim_file(coord, "camp-probe")
    claim_path.unlink()
    claim_path.mkdir()  # any os.open(O_RDWR) on it now fails
    service.halt("camp-probe")

    # The poisoned campaign still starts (fail-open) — resource guard
    # outage must not deadlock operations.
    assert service.start("camp-1")["state"] == CampaignLifecycle.RUNNING
    service.halt("camp-1")
