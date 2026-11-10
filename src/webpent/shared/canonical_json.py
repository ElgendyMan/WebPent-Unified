"""Canonical JSON serialization contract — UM-DR-33 Workstream A §3.6.

Single source of truth for how arbitrary JSON-serializable objects are
serialized to bytes for identity hashing (ground-truth manifests, fixture
manifests, evidence digests).

THE CONTRACT (fixed, versioned, never changed silently):

1. Key ordering      : ``sort_keys=True`` (lexicographic, recursive).
2. Whitespace        : none — compact separators ``(",", ":")``.
3. String escaping   : ``ensure_ascii=True`` (every non-ASCII code point
                       becomes a ``\\uXXXX`` escape; the byte stream is
                       therefore pure ASCII).
4. Number handling   : Python ``json`` default (ints exact; floats via
                       ``repr`` semantics — floats SHOULD be avoided in
                       hashed manifests; use ints or strings).
5. Byte encoding     : UTF-8 (identical to ASCII under ensure_ascii).
6. Top-level type    : the object as given — no wrapping, no trailing
                       newline.

History (recorded, not hidden): before UM-DR-33 the repository hashed the
same ``GROUND_TRUTH_MANIFEST`` through two different serializers —
``json.dumps(obj, sort_keys=True)`` (spaced separators; produced
``b78ad5c66f82108b759098cd7b31145a4b59b21cfc7223b9df9ce163956a583f``) in
``benchmarks/campaign_identity_target.py``, and the compact form (produced
``58684262356fa0c39fe7bde74cecec97f56746c2c019288249af120d72f87374``) in
``scripts/experiment_provenance.py``. Both digests described the SAME
manifest object. UM-DR-33 §3.6 resolves this to the compact form above:
every identity hash in the repository is now computed by this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = [
    "CANONICAL_JSON_CONTRACT_ID",
    "canonical_json_bytes",
    "canonical_json_sha256",
]

#: Stable identifier of this contract, embedded in provenance records.
CANONICAL_JSON_CONTRACT_ID = "canonical-json/v1 (sort_keys, compact, ensure_ascii, utf-8)"


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize *obj* to the canonical byte form (see module docstring)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_json_sha256(obj: Any) -> str:
    """SHA-256 of the canonical byte form of *obj*."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
