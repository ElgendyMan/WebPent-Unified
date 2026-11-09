"""Realistic Target Assessment v1 contracts and local harness APIs."""

from .auth_campaign import (
    PermissionGraph,
    RtaAuthProfiles,
    build_permission_graph,
    run_authenticated_read_campaign,
)
from .contracts import (
    DiscoveredSurface,
    DiscoverySnapshot,
    HttpObservation,
    HttpRequestSpec,
    RtaAssessment,
    RtaCase,
    RtaDisposition,
    RtaScope,
    SyntheticAuthContext,
)
from .discovery import discover_loopback_target
from .harness import LocalTargetConfig, create_target_app, default_target_configs
from .local_server import serve_loopback
from .validation import (
    RtaCaseResult,
    RtaGroundTruth,
    RtaProof,
    RtaValidationRun,
    build_ground_truth,
    default_auth_profiles,
    run_rta_validation,
)

__all__ = [
    "PermissionGraph",
    "RtaAuthProfiles",
    "build_permission_graph",
    "run_authenticated_read_campaign",
    "LocalTargetConfig",
    "create_target_app",
    "default_target_configs",
    "serve_loopback",
    "discover_loopback_target",
    "RtaCaseResult",
    "RtaGroundTruth",
    "RtaProof",
    "RtaValidationRun",
    "build_ground_truth",
    "default_auth_profiles",
    "run_rta_validation",
    "DiscoveredSurface",
    "DiscoverySnapshot",
    "HttpObservation",
    "HttpRequestSpec",
    "RtaAssessment",
    "RtaCase",
    "RtaDisposition",
    "RtaScope",
    "SyntheticAuthContext",
]
