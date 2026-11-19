"""Vulnerability Arsenal Sprint A — pure-logic family modules.

Five new vulnerability families follow the exact IDOR architecture:
hypothesis template -> concrete request triple -> M4/AVI execution ->
causal differential validator -> 8-gate promotion.

Trust-chain doctrine preserved: these modules are PURE LOGIC. They build
request specs, analyze redacted observations, and validate differentials.
No module here opens raw HTTP — every request is executed by the existing
ModernOrchestrator (ToolBoundary + ScopeLaw) and the validators in
production/validators.py remain the single canonical authority per family.

Zero false positives rule: a family validator CONFIRMS only on a causal
differential where the negative control stays clean, mirroring
validate_idor's baseline/candidate/negative-control semantics.
"""
from webpent.vulns.race_condition import (
    MAX_CONCURRENT_REQUESTS,
    build_race_condition_experiment,
    summarize_concurrent_results,
)
from webpent.vulns.business_logic import (
    BUSINESS_LOGIC_FIELD_SHAPES,
    build_business_logic_probes,
)
from webpent.vulns.file_upload import (
    FILE_UPLOAD_SCENARIOS,
    build_upload_probe,
)
from webpent.vulns.jwt_analyzer import (
    JWT_MANIPULATION_SCENARIOS,
    build_jwt_variants,
)
from webpent.vulns.mass_assignment import (
    MASS_ASSIGNMENT_FIELD_VARIANTS,
    build_mass_assignment_probes,
)

__all__ = [
    # race condition
    "MAX_CONCURRENT_REQUESTS",
    "build_race_condition_experiment",
    "summarize_concurrent_results",
    "validate_race_condition",  # canonical, resolved lazily from production.validators
    # business logic
    "BUSINESS_LOGIC_FIELD_SHAPES",
    "build_business_logic_probes",
    "validate_business_logic",
    # file upload
    "FILE_UPLOAD_SCENARIOS",
    "build_upload_probe",
    "validate_file_upload",
    # jwt
    "JWT_MANIPULATION_SCENARIOS",
    "build_jwt_variants",
    "validate_jwt_manipulation",
    # mass assignment
    "MASS_ASSIGNMENT_FIELD_VARIANTS",
    "build_mass_assignment_probes",
]


def __getattr__(name: str):
    # Canonical validators stay in webpent.production.validators (ONE authority
    # per family). Resolve them lazily so importing webpent.vulns never creates
    # an import cycle.
    if name == "validate_race_condition":
        from webpent.production.validators import validate_race_condition as _v
        return _v
    if name == "validate_business_logic":
        from webpent.production.validators import validate_business_logic as _v
        return _v
    if name == "validate_file_upload":
        from webpent.production.validators import validate_file_upload as _v
        return _v
    if name == "validate_jwt_manipulation":
        from webpent.production.validators import validate_jwt_manipulation as _v
        return _v
    if name == "validate_mass_assignment":
        from webpent.production.validators import validate_mass_assignment as _v
        return _v
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
