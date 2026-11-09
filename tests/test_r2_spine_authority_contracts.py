"""Sprint R2 — Choke-Point Restoration contract tests (Dispatch #002).

Three kinds of contracts live here, and the difference is load-bearing:

1. REAL PASSING contracts (T-03, T-07) pin behavior that already landed in the
   v5 frozen lineage (factory routing, production trace, campaign-worker
   factory construction). They exist because the M1 re-anchor (see
   deliverables/r2_dossiers/D1_ANCHOR_REPORT_R2.md) found NO test covering
   the graph-state production trace or the campaign-worker source contract.

2. STRICT-XFAIL dossier contracts (T-04, T-05, T-06, T-07b) pin the RATIFIED
   post-remediation behavior for findings whose fix targets are FROZEN files
   (constraint C2: never apply, never self-unfreeze). Each one fails today —
   that is the point: it makes the audited violation reproducible by a single
   command (acceptance criterion A10) and will XPASS (strictly FAILING the
   suite) the moment the corresponding unfreeze lands, forcing removal of the
   marker in the same change. Removing the xfail marker is part of the
   documented unfreeze checklist in each dossier.

Do not delete or un-xfail these without executing the matching dossier.
"""

from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "webpent"

# ---------------------------------------------------------------------------
# R3 rider R1(b) / RED-1 RF-06 hardening helpers (shared by T-03b/T-05/T-06).
# RED-1 proved line-scan nets are satisfiable by comments, alias/getattr and
# annotated-assignment forms; the hardened nets below are AST-based so that
# comments and docstrings cannot satisfy them, and reference-based (any
# read/alias/partial of the governed name, not just call sites).
# ---------------------------------------------------------------------------


def _parse_module(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _iter_source_modules(src: Path):
    for p in sorted(src.rglob("*.py")):
        tree = _parse_module(p)
        if tree is not None:
            yield p, tree


# ---------------------------------------------------------------------------
# T-03 — production trace carried in graph state (REAL — behavior already on v5)
# ---------------------------------------------------------------------------


def test_t03_graph_node_records_production_trace():
    """R2-01(iv)/T-03: after the modern-spine recon node runs, graph state must
    carry the factory's production-trace reference (entrypoint + config
    digest) so downstream evidence can attest which spine config produced
    the run. The recorded entrypoint must be a KNOWN_ENTRYPOINTS member.

    R3 E-4 UPDATE (Ruling R3-002 §3.4, rider R4): the entrypoint is now the
    TRUTHFUL, fail-closed derived label (mechanism (b), D3 probe). For THIS
    test process the conftest-declared truthful label is "direct_invoke"
    (tests invoke the node directly); the assertion additionally pins that
    the recorded value equals the explicit harness label — i.e. the node no
    longer invents a fallback value of its own.
    """
    import os

    from webpent.production.modern_spine_integration import (
        MODERN_SPINE_MODE,
        modern_spine_recon_node,
    )
    from webpent.production.production_spine import KNOWN_ENTRYPOINTS

    state = {
        # unique per run: the factory's config-digest drift registry is
        # process-global and keyed by engagement_id
        "engagement_id": f"t03_trace_{uuid.uuid4().hex[:10]}",
        "target_url": "https://target.example.com",
    }
    out = modern_spine_recon_node(state)

    trace = out.get("_production_trace")
    assert isinstance(trace, dict), "node must record the factory ProductionTrace summary"
    # entrypoint truthfulness (E-4): the recorded value is the process's
    # explicit, declared surface label — never a silently invented fallback.
    assert trace["entrypoint"] == os.environ["WEBPENT_ENTRYPOINT"]
    assert trace["entrypoint"] in KNOWN_ENTRYPOINTS
    assert re.fullmatch(r"[0-9a-f]{16}", trace["config_digest"]), (
        "config digest must be the factory's 16-hex ProductionSpineConfig digest"
    )
    assert "entrypoint_resolve" in trace["stages_seen"]
    assert "flag_resolution" in trace["stages_seen"]
    assert "spine_activation" in trace["stages_seen"]
    assert trace["spine_version"] == "production_spine_v1"
    assert out.get("modern_spine_mode") == MODERN_SPINE_MODE


def test_t03b_entrypoint_has_no_production_setter():
    """R2-01(ii) residual, documented in D2/R2-01: no src/ code SETS
    state["entrypoint"], so every graph run resolves as the truthful
    'direct_invoke' fallback. This test pins the RESIDUAL itself: when the
    unfreeze lands and call sites start threading real entrypoints, the
    assertion below must be updated in the same commit (the dossier's
    proposed diff includes exactly that change).

    HARDENED (R3 rider R1(b) / RED-1 RF-06): the original line-regex was
    blind to annotated assignments (``entrypoint: str = \"worker\"``),
    setattr string-key form, subscript assignment, dict-literal state
    returns, and any occurrence split across lines. The net is now AST
    based (comments/docstrings cannot satisfy it) and flags ALL of:
      1. kwarg ``entrypoint=...`` on calls OUTSIDE the documented factory
         vocabulary (ProductionSpineConfig / resolve_production_spine /
         ProductionTrace / run_autonomous_recon_campaign are the legitimate
         config/trace producers carrying truthful labels),
      2. ``setattr(x, \"entrypoint\", ...)`` string-key form,
      3. subscript assignment ``x[\"entrypoint\"] = ...``,
      4. dict literals with an \"entrypoint\" key outside the authority
         trace producer (production_spine.py summary()/digest dicts).
    """
    FACTORY_VOCABULARY_CALLS = {
        "ProductionSpineConfig",
        "resolve_production_spine",
        "ProductionTrace",
        "run_autonomous_recon_campaign",
    }
    DICT_KEY_EXEMPT_FILES = {"production_spine.py"}
    setters: list[str] = []
    for p, tree in _iter_source_modules(SRC):
        rel = p.relative_to(SRC.parent.parent)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fname = _call_name(node.func)
                if fname not in FACTORY_VOCABULARY_CALLS:
                    for kw in node.keywords:
                        if kw.arg == "entrypoint":
                            setters.append(f"{rel}:{node.lineno} (kwarg on {fname})")
                if (
                    fname == "setattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "entrypoint"
                ):
                    setters.append(f"{rel}:{node.lineno} (setattr string-key)")
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if (
                        isinstance(t, ast.Subscript)
                        and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "entrypoint"
                    ):
                        setters.append(f"{rel}:{node.lineno} (subscript assign)")
            if isinstance(node, ast.Dict) and p.name not in DICT_KEY_EXEMPT_FILES:
                for k in node.keys:
                    if isinstance(k, ast.Constant) and k.value == "entrypoint":
                        setters.append(f"{rel}:{node.lineno} (dict literal)")
    assert not setters, (
        f"entrypoint literal setters appeared (unfreeze landed?): {setters} — "
        "update D2/R2-01 and the T-03 entrypoint assertions accordingly"
    )


# ---------------------------------------------------------------------------
# T-07 — campaign worker constructs via the factory (REAL — landed on v5)
# ---------------------------------------------------------------------------


def test_t07_campaign_worker_uses_factory_no_loopback():
    """B-06 core (landed in v5 lineage): campaign_worker must construct the
    orchestrator via resolve_production_spine, must not hand-build a
    loopback profile (no 127.0.0.1/localhost literals), and its entrypoint
    literal must be a KNOWN_ENTRYPOINTS member (truthful, testable)."""
    from webpent.production.production_spine import KNOWN_ENTRYPOINTS

    src = (SRC / "production" / "campaign_worker.py").read_text(encoding="utf-8")
    assert "resolve_production_spine(" in src, "worker must resolve through the factory"
    assert "ProductionSpineConfig(" in src, "worker must build the canonical config"
    assert "AuthorizedLabProfile(" not in src, "worker must not hand-build a profile"
    # Loopback ban applies to ACTIVE code; historical explanation comments that
    # quote the removed literals (FIX 1 annotation) are not enforcement code.
    code_lines = [
        ln for ln in src.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    code = "\n".join(code_lines)
    assert "127.0.0.1" not in code and '"localhost"' not in code and "'localhost'" not in code, (
        "no hardcoded loopback targets in active code"
    )
    m = re.search(r'entrypoint\s*=\s*"([a-z_]+)"', src)
    assert m, "worker must pass an explicit entrypoint literal"
    assert m.group(1) in KNOWN_ENTRYPOINTS, (
        f"entrypoint {m.group(1)!r} must be in KNOWN_ENTRYPOINTS (fail-closed vocabulary)"
    )


@pytest.mark.xfail(
    reason="B-06 residual (D2/R2-04): ratified entrypoint is 'campaign_worker'; "
    "v5 uses 'worker' and KNOWN_ENTRYPOINTS (frozen) does not contain "
    "'campaign_worker'. DENIED for R3 — E-3 unfreeze denied, deferred to M3 "
    "(Ruling R3-002 §3.5); campaign_worker.py is explicitly NOT THAWED, so "
    "this stays xfail(strict) through Phase 1.",
    strict=True,
)
def test_t07b_campaign_worker_entrypoint_is_campaign_worker():
    src = (SRC / "production" / "campaign_worker.py").read_text(encoding="utf-8")
    m = re.search(r'entrypoint\s*=\s*"([a-z_]+)"', src)
    assert m and m.group(1) == "campaign_worker"
    from webpent.production.production_spine import KNOWN_ENTRYPOINTS

    assert "campaign_worker" in KNOWN_ENTRYPOINTS


# ---------------------------------------------------------------------------
# T-05 — sole confirmation authority inventory (REAL — E-1 landed R3)
# ---------------------------------------------------------------------------


def test_t05_sole_confirmation_authority_inventory():
    """Architectural inventory: the confirmation write (mark_oob_confirmed)
    must have NO production caller outside the promotion component.

    HARDENED (R3 rider R1(b) / RED-1 RF-06): RED-1 proved the original
    line-scan is blind to alias forms (``moo = db.mark_oob_confirmed`` then
    ``moo(...)``), getattr string form (``getattr(db, \"mark_oob_confirmed\")``),
    and functools.partial references. The net now flags ANY reference to the
    governed name outside the definition/promotion authority: Attribute
    access, Name binding, or string constant passed around (comments and
    docstrings cannot match — they never reach the AST).

    R3 E-1 PROOF-OF-FIX (Ruling R3-002 §3.2, rider R4): the xfail marker is
    removed in the same commit as the advisory demotion; the hardened net
    passes on the fixed tree — the OOB handler no longer references the
    confirmation write at all.
    """
    GOVERNED = "mark_oob_confirmed"
    definition = SRC / "memory" / "db.py"
    promotion = SRC / "production" / "autonomous_validation_v1.py"
    offenders: list[str] = []
    for p, tree in _iter_source_modules(SRC):
        if p in (definition, promotion):
            continue
        rel = p.relative_to(SRC.parent.parent)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == GOVERNED:
                offenders.append(f"{rel}:{node.lineno}: attribute reference .{GOVERNED}")
            elif isinstance(node, ast.Name) and node.id == GOVERNED:
                offenders.append(f"{rel}:{node.lineno}: name reference {GOVERNED}")
            elif isinstance(node, ast.Constant) and node.value == GOVERNED:
                # string-form reference (getattr/setattr/partial-by-name)
                offenders.append(f"{rel}:{node.lineno}: string-form reference '{GOVERNED}'")
    assert not offenders, f"confirmation write called outside promotion authority: {offenders}"


# ---------------------------------------------------------------------------
# T-04 — OOB callback must be advisory-only (REAL — E-1 landed R3)
# ---------------------------------------------------------------------------


def test_t04_oob_callback_is_advisory_only(tmp_path, monkeypatch):
    """Valid correlation token must NOT flip confidence and must attach an
    ADVISORY evidence record; nothing may construct/seal a ProofBundle here.

    R3 E-1 PROOF-OF-FIX (Ruling R3-002 §3.2, rider R4): the xfail marker is
    removed in the same commit as the advisory demotion. Amendments A/B/C
    applied: the handler docstring was rewritten (A), the Finding model
    carries the additive advisory_evidence field (B), and the fixture now
    asserts the REAL persistence contract — ``save_finding`` returns None
    (C, R2-V NF-04) — instead of the invented non-None value.
    """
    import uuid as _uuid
    from datetime import datetime, timezone

    from webpent.api.app import _oob_db_lookup_and_record_advisory
    from webpent.memory.db import DatabaseManager
    from webpent.models.findings import Confidence, Finding, Severity, VulnClass

    db = DatabaseManager(database_url=f"sqlite:///{tmp_path / 't04.db'}")
    db.init_db()
    monkeypatch.setattr("webpent.api.app.get_db_manager", lambda: db)

    token = _uuid.uuid4().hex * 2  # 64-hex unguessable per-finding token
    finding = Finding(
        id=_uuid.uuid4(),
        title="T-04 advisory-only contract fixture",
        severity=Severity.HIGH.value,
        description="ssrf oob advisory contract",
        tool_name="validator",
        payload="http://api:8000/api/oob/canary",
        url="http://lab.local/fetch?url=x",
        confidence=Confidence.TENTATIVE,
        confidence_level="AI-Assessed",
        reasoning="candidate",
        vuln_class=VulnClass.SSRF.value,
        created_at=datetime.now(timezone.utc),
        thread_id=None,
        oob_token=token,
    )
    # Amendment C (R2-V NF-04): the persistence contract is real —
    # save_finding persists and returns None; asserting the invented
    # non-None value was the fixture bug RED-1 proved necessary to flip.
    assert db.save_finding(finding) is None

    updated = _oob_db_lookup_and_record_advisory(
        finding.id,
        "T-04 contract callback context",
        {"method": "GET", "client_host": "203.0.113.7",
         "body_digest": "deadbeef", "callback_ts": "2026-10-05T00:00:00Z"},
    )

    assert updated is not None
    # RATIFIED contract (R3 E-1 landed — passes on the fixed tree):
    assert updated.confidence_level == "AI-Assessed", (
        "OOB callback must NEVER flip finding confidence"
    )
    assert updated.confidence == Confidence.TENTATIVE
    assert "oob" not in str(getattr(updated, "payload", "")).lower() or "confirmed-by" not in str(
        getattr(updated, "payload", "")
    ), "no confirmation marker may be written by the callback path"
    advisory = list(getattr(updated, "advisory_evidence", None) or [])
    assert advisory, "an ADVISORY evidence record must be attached to the finding"
    assert all(
        "confirm" not in str(rec.get("type", "")).lower() for rec in advisory
    ), "advisory records must not carry confirmation semantics"


# ---------------------------------------------------------------------------
# T-06 — graph path rejects UNSUPPORTED_LEGACY_ONLY (REAL — E-2 landed R3)
# ---------------------------------------------------------------------------


def test_t06_builder_rejects_unsupported_legacy_only():
    """The graph recon wiring itself must enforce the 'never re-route, only
    reject' invariant: builder.py's disabled branch must raise the loud,
    named error instead of silently running legacy-only.

    HARDENED (R3 rider R1(b) / RED-1 RF-06): RED-1 proved the bare substring
    check is satisfiable by a COMMENT mentioning the error name. Two
    comment-proof assertions now apply (both must hold):
      1. AST: builder.py contains a ``raise`` node whose exception is (or is
         constructed from) UnsupportedLegacyOnlyModeError;
      2. T-07 pattern: the substring must also appear in comment-stripped
         source lines (defence in depth for exotic constructions).

    R3 E-2 PROOF-OF-FIX (Ruling R3-002 §3.3, rider R4): the xfail marker is
    removed in the same commit as the builder-level rejection; the hardened
    net passes on the fixed tree — build_graph raises the named error at
    the composition point.
    """
    NAME = "UnsupportedLegacyOnlyModeError"
    builder_path = SRC / "graph" / "builder.py"
    builder_src = builder_path.read_text(encoding="utf-8")

    code_lines = [
        ln for ln in builder_src.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    stripped = "\n".join(code_lines)
    assert NAME in stripped, (
        "builder must fail the engagement closed (loud, named rejection) when "
        "WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY — not skip the "
        "modern node and continue legacy-only (comments do not count)"
    )

    tree = _parse_module(builder_path)
    assert tree is not None, "builder.py must parse"
    raises = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc
            candidates = []
            if isinstance(exc, ast.Call):
                candidates.append(_call_name(exc.func))
            candidates.append(getattr(exc, "id", None))
            candidates.append(getattr(exc, "attr", None))
            if NAME in candidates:
                raises.append(node.lineno)
    assert raises, (
        "builder must actually RAISE UnsupportedLegacyOnlyModeError on the "
        "disabled path — a comment or bare import does not enforce anything "
        f"(raise sites found: {raises})"
    )
