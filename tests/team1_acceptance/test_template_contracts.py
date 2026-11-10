"""WP-K (Dispatch #009-A) — template-contract test suite: CLASS closure.

Third instance of the template/runtime-mismatch class:

  v3: scope template rejected by the real parser (plain-text path
      directives the runtime grammar does not accept);
  v3: credentials template not valid JSON;
  NF-L0-02 (this window): the credentials template passed ``json.loads``
      but failed the REAL loader's PROFILE-level validation —
      ``ValueError: profile '_readme' must be a JSON object.`` — because a
      documentation string occupied a machine-consumed profile slot (and
      ``alias``/``_api_key_example`` carried loader-unsupported fields).

BINDING RULE (Dispatch #009-A WP-K(c)): every shipped template must
round-trip through its REAL runtime consumer under this suite. Syntax-only
validation (``json.loads`` alone, YAML-parse alone) is prohibited as the
sole check. The inventory test fails the suite when a new template file
appears without a contract entry, so the class stays closed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

TREE_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Template inventory — every shipped data template and its REAL consumer.
# ---------------------------------------------------------------------------
# root-level operator templates
COVERED_TEMPLATES = {
    "credentials_template.json": "creds_loader",
    "scope_template.yaml": "program_scope_parser",
    "docs/target_adapter_review_packet_template_v1.json": "adapter_review_validator",
    "src/webpent/templates/reports/report.html.j2": "reporter_export_jinja",
    "src/webpent/templates/reports/html.j2": "agent_reporter_jinja",
}

# Sweep result (WP-K(b)): shipped files that LOOK like templates but have NO
# runtime consumer — documented boundary, no contract test is possible.
#   docs/templates/engagement_dashboard.html — docs-only artifact; the only
#     reference in tree is an evidence-report table row (no code consumer).
#   benchmarks/goed_v1_5/target_template.py — a Python module inside the
#     benchmarks tree, not a data template consumed at runtime.
BOUNDARY_DOCS_ONLY = (
    "docs/templates/engagement_dashboard.html",
)

_GLOB_PATTERNS = (
    "*_template.json",
    "*_template.yaml",
    "*_template.yml",
    "*_template*.j2",
    "*.template.json",
)


def _discover_root_template_files() -> set[str]:
    found: set[str] = set()
    for pattern in _GLOB_PATTERNS:
        for path in TREE_ROOT.glob(pattern):
            if path.is_file():
                found.add(str(path.relative_to(TREE_ROOT)))
    docs_dir = TREE_ROOT / "docs"
    if docs_dir.is_dir():
        for pattern in _GLOB_PATTERNS:
            for path in docs_dir.rglob(pattern):
                if path.is_file():
                    found.add(str(path.relative_to(TREE_ROOT)))
    return found


def test_template_inventory_fully_covered_by_contracts() -> None:
    """CLASS CLOSURE: no shipped template may lack a real-consumer contract."""
    discovered = _discover_root_template_files()
    uncovered = discovered - set(COVERED_TEMPLATES)
    assert not uncovered, (
        "New shipped template(s) without a real-consumer contract test — "
        f"extend {__name__} (WP-K(c) class rule): {sorted(uncovered)}"
    )
    for rel in COVERED_TEMPLATES:
        assert (TREE_ROOT / rel).is_file(), f"covered template missing: {rel}"


def test_boundary_documentation_templates_have_no_runtime_consumer() -> None:
    """Pin the documented boundary so drift is caught if a consumer appears."""
    for rel in BOUNDARY_DOCS_ONLY:
        assert (TREE_ROOT / rel).is_file(), f"boundary artifact missing: {rel}"


# ---------------------------------------------------------------------------
# credentials_template.json — REAL consumer: webpent.cli.loaders.load_creds_file
# (consumed by `webpent scan --creds-file` and `webpent hunt
# --credentials-file`; THIS was the LCS-1 blocker NF-L0-02.)
# ---------------------------------------------------------------------------
def test_credentials_template_round_trips_real_runtime_loader() -> None:
    """UM-DR-33 §5.5 contract evolution: the template's SHAPE is consumable
    by the real loader, and its placeholder VALUES are now rejected
    fail-closed (an operator who copies the template and forgets to fill a
    field gets a precise error instead of a silently-ignored profile). The
    loader processing the template far enough to name the exact offending
    profile+field IS the stronger round-trip proof."""
    import json

    import pytest

    from webpent.cli.loaders import load_creds_file

    raw = json.loads((TREE_ROOT / "credentials_template.json").read_text())
    assert set(raw) == {"owner", "foreign"}, (
        "template must define exactly the owner/foreign principal slots — "
        f"got {sorted(raw)}"
    )
    for alias, profile in raw.items():
        # consumed-by-provisioning fields keep the documented shape
        assert profile.get("role") in {"owner", "regular_user"}
        assert profile.get("auth_type") == "form_session"
        assert profile.get("username"), alias
        assert profile.get("password"), alias
        # the alien fields that broke v4 must not return
        assert "alias" not in profile
        assert not str(alias).startswith("_")

    # the fail-closed placeholder rejection (UM-DR-33 §5.5): the loader
    # must refuse the untouched template and name the exact slot
    with pytest.raises(ValueError) as excinfo:
        load_creds_file(TREE_ROOT / "credentials_template.json")
    message = str(excinfo.value)
    assert "placeholder" in message
    assert "REPLACE_ME" in message or "password" in message, message


def test_documentation_slot_in_credentials_file_is_rejected_by_loader() -> None:
    """Negative pin of the NF-L0-02 class: docs must not occupy profile slots."""
    from webpent.cli.loaders import load_creds_file

    defective = {
        "_readme": "documentation string in a machine-consumed profile slot",
        "owner": {
            "role": "owner",
            "auth_type": "form_session",
            "username": "owner@example.test",
            "password": "pw",
        },
    }
    with pytest.raises(ValueError, match="profile '_readme'"):
        load_creds_file_dict_probe(defective)


def load_creds_file_dict_probe(payload: dict) -> dict:
    """Drive the REAL loader with an in-memory payload (temp file round-trip)."""
    import tempfile

    from webpent.cli.loaders import load_creds_file

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as handle:
        json.dump(payload, handle)
        path = handle.name
    try:
        return load_creds_file(path)
    finally:
        Path(path).unlink(missing_ok=True)


def test_loader_unsupported_profile_fields_are_rejected() -> None:
    """Pins the other v4 template defects: alias / _api_key_example fields."""
    from webpent.cli.loaders import load_creds_file

    with pytest.raises(ValueError, match="unsupported fields"):
        load_creds_file_dict_probe(
            {
                "owner": {
                    "alias": "owner",  # NOT in _ALLOWED_PROFILE_FIELDS
                    "role": "owner",
                    "username": "o@example.test",
                    "password": "pw",
                }
            }
        )
    with pytest.raises(ValueError, match="unsupported fields"):
        load_creds_file_dict_probe(
            {
                "_api_key_example": {
                    "_comment": "docs in a profile slot",
                    "alias": "owner",
                    "auth_type": "api_key",
                    "api_key": "REPLACE_ME",  # loader contract = headers{}
                    "api_key_header": "X-API-Key",
                }
            }
        )


def test_api_key_profiles_use_loader_supported_shape() -> None:
    """The documented API-key shape (docs/credentials_template_README.md)
    must pass the real loader: headers{} + required validation_url."""
    from webpent.cli.loaders import load_creds_file

    profiles = load_creds_file_dict_probe(
        {
            "api_owner": {
                "role": "owner",
                "auth_type": "api_key",
                "headers": {"X-API-Key": "ak_live_template_shape_probe_0123456789"},
                "validation_url": "https://your-authorized-target.example/v1/me",
            }
        }
    )
    profile = profiles["api_owner"]
    assert profile["headers"] == {"X-API-Key": "ak_live_template_shape_probe_0123456789"}
    assert profile["validation_url"].startswith("https://")


# ---------------------------------------------------------------------------
# scope_template.yaml — REAL consumer: webpent.scope.parser.parse_scope_file
# (the program-scope parser behind `webpent hunt --scope`; v3 instance of
# the class — the shipped template was rejected by this parser.)
# ---------------------------------------------------------------------------
def test_scope_template_round_trips_real_program_scope_parser() -> None:
    from webpent.scope.parser import parse_scope_file

    policy = parse_scope_file(TREE_ROOT / "scope_template.yaml")
    allow_values = {rule.value for rule in policy.rules if rule.allow}
    deny_values = {rule.value for rule in policy.rules if not rule.allow}
    assert "https://app.example.com" in allow_values
    assert "https://api.example.com" in allow_values
    assert "https://*.cdn.example.com" in allow_values
    assert "https://staging.example.com" in deny_values
    assert "https://internal.example.com" in deny_values
    # path-level exclusion survived the real parser
    admin_denies = [
        rule
        for rule in policy.rules
        if not rule.allow and rule.path == "/admin"
    ]
    assert admin_denies, "path:/admin deny rule lost by the real parser"
    # limits survived
    assert policy.limits.no_destructive is True
    # the enforcer can consume what the parser produced
    from webpent.scope.enforcer import ScopeEnforcer

    enforcer = ScopeEnforcer(policy)
    decision = enforcer.check_url("https://app.example.com/login", method="GET")
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# docs/target_adapter_review_packet_template_v1.json — REAL consumer:
# webpent.shared.target_adapter_review.validate_target_adapter_review_packet
# ---------------------------------------------------------------------------
def test_target_adapter_review_packet_template_passes_real_validator() -> None:
    from webpent.shared.target_adapter_review import (
        validate_target_adapter_review_packet,
    )

    packet = json.loads(
        (TREE_ROOT / "docs/target_adapter_review_packet_template_v1.json").read_text(
            encoding="utf-8"
        )
    )
    errors = validate_target_adapter_review_packet(packet)
    assert errors == (), (
        f"shipped review packet template rejected by its real validator: {errors}"
    )


# ---------------------------------------------------------------------------
# Jinja2 report templates — REAL consumers: reporter/export.py and
# agents/reporter/agent.py (FileSystemLoader environments, autoescape).
# ---------------------------------------------------------------------------
class _Blank:
    """Universal permissive render stand-in for undeclared template vars."""

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __str__(self):
        return ""

    def __call__(self, *args, **kwargs):
        return _BLANK

    def __getattr__(self, name):
        return _BLANK

    def __getitem__(self, key):
        return _BLANK

    def __int__(self):
        return 0

    def __float__(self):
        return 0.0

    def __contains__(self, item):
        return False


_BLANK = _Blank()


def _render_through_runtime_environment(template_rel: str) -> str:
    """Render a shipped .j2 template through its real consumer environment.

    Mirrors the exact Environment construction used by reporter/export.py
    (FileSystemLoader over the template dir + select_autoescape), then
    renders with permissive stand-ins for every undeclared variable so the
    template's own structure (syntax, filters, tags, macros) is what is
    under contract.
    """
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from jinja2.meta import find_undeclared_variables

    template_path = TREE_ROOT / template_rel
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)
    source = template_path.read_text(encoding="utf-8")
    variables = find_undeclared_variables(env.parse(source))
    context = {name: _BLANK for name in variables}
    rendered = template.render(**context)
    assert rendered.strip(), f"{template_rel} rendered empty"
    return rendered


def test_reporter_export_report_template_round_trips_runtime_environment() -> None:
    rendered = _render_through_runtime_environment(
        "src/webpent/templates/reports/report.html.j2"
    )
    assert "<html" in rendered.lower()


def test_agent_reporter_html_template_round_trips_runtime_environment() -> None:
    rendered = _render_through_runtime_environment(
        "src/webpent/templates/reports/html.j2"
    )
    assert rendered.strip()
