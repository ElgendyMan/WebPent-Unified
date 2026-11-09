"""Authenticated read/write API for the application-owned campaign service."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from webpent.api.auth import User, get_current_user
from webpent.service.facade import MultiCampaignService
from webpent.service.models import CampaignSpec

_service = MultiCampaignService(
    root=os.getenv("WEBPENT_SERVICE_ROOT", "/tmp/webpent-service"),
    project_root=Path(__file__).resolve().parents[3],
)
router = APIRouter(prefix="/api/v1/service", tags=["multi-campaign-service"])


class CampaignCreateRequest(BaseModel):
    campaign_id: str = Field(min_length=1, max_length=128)
    target_url: str = Field(min_length=8, max_length=1000)
    budget_limit: float = Field(default=10.0, gt=0, le=1_000_000)
    max_actions: int = Field(default=100, gt=0, le=1_000_000)
    retry_limit: int = Field(default=2, ge=0, le=10)
    window_start: str | None = None
    window_end: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


def _owner(user: User) -> str:
    return str(getattr(user, "username", None) or getattr(user, "sub", None) or "operator")[:128]


def _is_admin(user: User) -> bool:
    """P2-02 (0.33.0): correct admin predicate for the multi-campaign API.

    The old ``getattr(user, "is_admin", False)`` probed a field that does
    not exist on ``api.auth.User`` (it has ``role`` + ``is_global_admin``),
    so this module's admin paths were permanently dead (fail-closed but
    broken functionality: /service/health 403 for real admins, tenant
    admins unable to see cross-owner campaigns they are entitled to).
    """
    return bool(getattr(user, "is_global_admin", False)) or getattr(user, "role", "") == "admin"


def _check_owner(campaign_id: str, user: User) -> None:
    try:
        snapshot = _service.snapshot(campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="campaign_not_found") from exc
    if snapshot["owner_id"] != _owner(user) and not _is_admin(user):
        raise HTTPException(status_code=403, detail="campaign_owner_required")


@router.post("/campaigns", status_code=201)
def create_campaign(payload: CampaignCreateRequest, user: User = Depends(get_current_user)) -> dict[str, Any]:
    if payload.metadata.get("vault") or payload.metadata.get("credentials"):
        raise HTTPException(status_code=400, detail="credential_material_not_accepted")
    spec = CampaignSpec(
        campaign_id=payload.campaign_id,
        target_url=payload.target_url,
        owner_id=_owner(user),
        budget_limit=payload.budget_limit,
        max_actions=payload.max_actions,
        retry_limit=payload.retry_limit,
        window_start=payload.window_start,
        window_end=payload.window_end,
        metadata=payload.metadata,
    )
    try:
        return _service.plan(spec)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/campaigns")
def list_campaigns(user: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    owner = _owner(user)
    return [item for item in (_service.snapshot(row["campaign_id"]) for row in _service.manager.store.list_campaigns())
            if item["owner_id"] == owner or _is_admin(user)]


@router.post("/campaigns/{campaign_id}/start")
def start_campaign(campaign_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    _check_owner(campaign_id, user)
    try:
        return _service.start(campaign_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/halt")
def halt_campaign(campaign_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    _check_owner(campaign_id, user)
    try:
        return _service.halt(campaign_id, _owner(user))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/resume")
def resume_campaign(campaign_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    _check_owner(campaign_id, user)
    try:
        return _service.resume(campaign_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/campaigns/{campaign_id}")
def campaign_dashboard(campaign_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    _check_owner(campaign_id, user)
    return _service.dashboard(campaign_id)


@router.get("/campaigns/{campaign_id}/cost")
def campaign_cost(campaign_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    _check_owner(campaign_id, user)
    return _service.costs.snapshot(campaign_id).as_dict()


@router.get("/campaigns/{campaign_id}/findings")
def campaign_findings(campaign_id: str, user: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    _check_owner(campaign_id, user)
    return _service.store.list_findings(campaign_id)


@router.get("/health")
def service_health(user: User = Depends(get_current_user)) -> dict[str, Any]:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="admin_required")
    return {"health_runs": _service.store.list_health_runs(), "alerts": _service.store.list_alerts("system")}


__all__ = ["router"]
