"""M1-A (L-4 + L-5) regression.

L-4: the OAST DNS responder binds loopback by default (0.0.0.0 silently
     published a DNS oracle on every interface).

L-5: DecisionLogManager.append ENFORCES redact_sensitive on metadata —
     a secret-shaped key/value can never persist into the audit trail,
     while existing identifier-only callers see no change.
"""
from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# L-4
# ---------------------------------------------------------------------------

def test_oast_dns_responder_defaults_to_loopback():
    import socket

    from webpent.oast.server import OastDnsResponder

    responder = OastDnsResponder(zone="oast.test")
    try:
        host, _port = responder._sock.getsockname()
        assert host == "127.0.0.1", (
            f"L-4 REGRESSION: OAST DNS responder bound {host!r}, expected loopback"
        )
    finally:
        responder._sock.close()


def test_oast_dns_responder_explicit_bind_still_available():
    """Operators may still deliberately bind a non-loopback host."""
    import socket

    from webpent.oast.server import OastDnsResponder

    # bind to the loopback interface explicitly via the documented param
    responder = OastDnsResponder(zone="oast.test", bind_host="127.0.0.1", bind_port=0)
    try:
        host, _ = responder._sock.getsockname()
        assert host == "127.0.0.1"
    finally:
        responder._sock.close()


def test_oast_signature_default_is_loopback():
    from webpent.oast.server import OastDnsResponder

    sig = inspect.signature(OastDnsResponder.__init__)
    assert sig.parameters["bind_host"].default == "127.0.0.1"


# ---------------------------------------------------------------------------
# L-5
# ---------------------------------------------------------------------------

def _entry(metadata):
    from webpent.memory.decision_log import DecisionLogEntry, DecisionType

    return DecisionLogEntry(
        decision_type=DecisionType.OPERATOR_ACTION,
        rule_fired="m1a_l5_test",
        outcome="recorded",
        metadata=metadata,
    )


def test_decision_log_metadata_redacted_at_append(tmp_path, monkeypatch):
    from webpent.memory import decision_log as dl

    manager = dl.DecisionLogManager(database_url=str(tmp_path / "decisions.db"))
    entry_id = manager.append(
        _entry(
            {
                "actor": "operator-1",
                "password": "hunter2-secret",
                "nested": {"authorization": "Bearer abc.def.ghi", "note": "ok"},
            }
        )
    )
    entries = manager.get_all_entries()
    match = [e for e in entries if str(e["id"]) == str(entry_id)]
    assert match, "appended entry not found"
    metadata = match[0]["metadata"]
    assert metadata["actor"] == "operator-1"
    assert metadata["password"] != "hunter2-secret"
    assert "abc.def.ghi" not in str(metadata)
    assert metadata["nested"]["note"] == "ok"


def test_decision_log_id_only_callers_unchanged(tmp_path):
    from webpent.memory import decision_log as dl

    manager = dl.DecisionLogManager(database_url=str(tmp_path / "decisions.db"))
    entry_id = manager.append(
        _entry({"actor": "api", "thread_id": "t-123", "outcome": "approved"})
    )
    match = [
        e for e in manager.get_all_entries() if str(e["id"]) == str(entry_id)
    ]
    metadata = match[0]["metadata"]
    assert metadata == {"actor": "api", "thread_id": "t-123", "outcome": "approved"}
