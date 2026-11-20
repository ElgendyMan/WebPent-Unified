#!/usr/bin/env python3
"""UM-DR-34 regeneration of docs/direct_io_inventory.json.

Window: UM-DR-34 — unified scope authority, safe egress & execution
governance.  The measured delta versus the recorded artifact:

  REMOVED identities (3 — the point of the §4.8 no-silent-raw-client
  fix in families/execution_node.py):
    * httpx (import), httpx.Client (call), and the companion
      getattr(httpx.Client.request, ...) — the executor used to build a
      RAW httpx.Client around a bare pinning transport, skipping the
      response-hook layer.  It now routes through
      webpent.shared.http.make_safe_httpx_client (full safe factory),
      recorded below as a safe_boundary_call identity.

  ADDED identities (5, established identity classes only):
    * families/execution_node.py:
        - safe_boundary_call: make_safe_httpx_client — the replacement
          boundary-routed client (§4.8).
        - getattr(resp, ... ) — dual-shape response reads in the
          executor (unchanged semantics, shifted lines).
    * scope/authority.py (NEW module):
        - getattr(spec, ... ) — fail-closed dual-shape reads over
          ScopeFileSpec projections in authority_from_scope_file_spec
          (the established defensive-read identity class).
    * shared/http.py:
        - getattr(... ) — the method-aware redirect guard reads the
          original request's method off the response object
          (§4.3; ``getattr(response.request, "method")``).
    * shared/untrusted_content.py:
        - getattr(cloned, ... ) — the additional_kwargs/tool_calls
          sanitization on cloned LangChain messages (§6.3).

No new raw transport sites of any kind: the ONLY network-capable
addition is the safe_boundary_call through the hardened factory.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. Removed identities match the DECLARED set exactly;
  2. Added identities match the DECLARED set exactly;
  3. The artifact's own integrity fields are updated coherently.

Usage: python3 scripts/regen_direct_io_inventory_umdr34.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

WINDOW = "UM-DR-34 SCOPE AUTHORITY WINDOW 2026-11-10"
REGEN_REASON = (
    "deliberate regen for the UM-DR-34 window: the raw httpx.Client "
    "construction in families/execution_node.py is REMOVED (replaced by "
    "the full safe factory — §4.8 no-silent-raw-client fix), and five "
    "documented identities are added (safe_boundary_call through "
    "make_safe_httpx_client, the method-aware redirect-guard read, the "
    "message-clone sanitization reads, the authority's dual-shape "
    "spec reads, and the executor's shifted response reads). No new "
    "raw transport sites."
)

DECLARED_REMOVALS = {
    ("src/webpent/families/execution_node.py", "call", "httpx.Client"),
    ("src/webpent/families/execution_node.py", "dynamic_resolution", "getattr(httpx.Client.request, ... )"),
    ("src/webpent/families/execution_node.py", "import", "httpx"),
}

DECLARED_ADDITIONS = {
    ("src/webpent/families/execution_node.py", "dynamic_resolution", "getattr(resp, ... )"),
    ("src/webpent/families/execution_node.py", "safe_boundary_call", "webpent.shared.http.make_safe_httpx_client"),
    ("src/webpent/scope/authority.py", "dynamic_resolution", "getattr(spec, ... )"),
    ("src/webpent/shared/http.py", "dynamic_resolution", "getattr(... )"),
    ("src/webpent/shared/untrusted_content.py", "dynamic_resolution", "getattr(cloned, ... )"),
}


def _identity(record: dict) -> tuple[str, str, str]:
    symbol = record.get("normalized_symbol") or record.get("symbol", "")
    return (record["file"], record["kind"], symbol)


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}

    removed = recorded_ids - fresh_ids
    added = fresh_ids - recorded_ids

    if removed != DECLARED_REMOVALS:
        print(f"ABORT: removed identities do not match the declared set:")
        for item in sorted(removed ^ DECLARED_REMOVALS)[:10]:
            print(f"  {item}")
        return 1
    if added != DECLARED_ADDITIONS:
        print(f"ABORT: added identities do not match the declared set:")
        for item in sorted(added ^ DECLARED_ADDITIONS)[:10]:
            print(f"  {item}")
        return 1

    artifact["records"] = fresh
    artifact["window"] = WINDOW
    artifact["regen_reason"] = REGEN_REASON
    artifact["regenerated_at"] = datetime.now(timezone.utc).isoformat()
    ARTIFACT.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n")
    print(
        f"Regenerated: {len(recorded)} -> {len(fresh)} records "
        f"(-{len(removed)} raw-client identities, +{len(added)} documented)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
