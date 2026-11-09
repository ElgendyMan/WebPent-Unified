"""Tenant-isolation family — passive analyzers (cross-tenant boundary)."""
from .analyzer import CrossTenantAccessMatrix, TenantBoundaryDetector, _looks_like_object_ref
from .scenarios import TENANT_SCENARIOS

__all__ = ["CrossTenantAccessMatrix", "TenantBoundaryDetector", "TENANT_SCENARIOS", "_looks_like_object_ref"]
