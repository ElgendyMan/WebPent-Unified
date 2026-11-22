"""UM-DR-44 A1 — is_empty() must consider EVERY identity dimension.

``HypothesisIdentityContext.is_empty()`` checked only ten dimensions
and omitted ``http_method`` and ``preconditions``.  A context carrying
ONLY ``http_method="POST"`` (or only preconditions) therefore reported
``is_empty() == True`` — the "legacy case" — and downstream consumers
treating empty contexts as legacy skipped real identity scoping:
two hypotheses differing only by HTTP method or preconditions
collapsed into one identity bucket.

Fix contract:

* is_empty() is True only when NO dimension at all carries a value —
  including http_method and preconditions;
* canonical_form() already includes both dimensions (unchanged — the
  structural contract below pins that is_empty() and canonical_form()
  stay dimension-consistent so this drift cannot reappear).
"""

from __future__ import annotations

import inspect

from webpent.production.hypothesis_identity import HypothesisIdentityContext


class TestIsEmptyCoversAllDimensions:
    def test_non_default_http_method_only_is_not_empty(self) -> None:
        """RED on the current tree: http_method was omitted entirely."""
        ctx = HypothesisIdentityContext(http_method="POST")
        assert ctx.is_empty() is False

    def test_default_get_http_method_alone_still_empty(self) -> None:
        """The Hypothesis model defaults request_method to "GET" for
        every legacy hypothesis — a bare GET carries no identity signal
        (documented default-method exception, see is_empty docstring)."""
        ctx = HypothesisIdentityContext(http_method="GET")
        assert ctx.is_empty() is True

    def test_preconditions_only_is_not_empty(self) -> None:
        """RED on the current tree: preconditions were omitted."""
        ctx = HypothesisIdentityContext(preconditions=("authenticated",))
        assert ctx.is_empty() is False

    def test_all_empty_is_empty(self) -> None:
        assert HypothesisIdentityContext().is_empty() is True

    def test_whitespace_only_is_empty(self) -> None:
        ctx = HypothesisIdentityContext(actor="  ", http_method="  ")
        assert ctx.is_empty() is True

    def test_every_single_dimension_alone_is_not_empty(self) -> None:
        dimensions = {
            "actor": "alice",
            "role": "admin",
            "tenant": "t1",
            "namespace": "ns1",
            "resource_owner": "bob",
            "object_id": "order-1",
            "operation": "read_order",
            "workflow_state": "submitted",
            "session": "sess-1",
            "auth_strength": "mfa",
            "http_method": "POST",
            "preconditions": ("authenticated",),
        }
        for dim, value in dimensions.items():
            ctx = HypothesisIdentityContext(**{dim: value})
            assert ctx.is_empty() is False, f"{dim} alone must not be empty"


class TestStructuralDimensionConsistency:
    def test_is_empty_and_canonical_form_share_dimensions(self) -> None:
        """Structural contract: every dimension canonical_form() prints
        must be consulted by is_empty() (and vice versa) — the omission
        bug was exactly these two sets drifting apart."""
        src = inspect.getsource(HypothesisIdentityContext)
        is_empty_src = src.split("def is_empty")[1].split("def ")[0]
        canonical_src = src.split("def canonical_form")[1].split("def ")[0]
        # every field name the canonical form prints (f"field=value" lines)
        printed = []
        for line in canonical_src.splitlines():
            stripped = line.strip()
            if stripped.startswith('f"') and "=" in stripped:
                name = stripped[2:stripped.index("=")]
                if name.replace("_", "").isalpha():
                    printed.append(name)
        assert len(printed) >= 12, f"parser found too few fields: {printed}"
        # documented exception: http_method participates only when
        # non-default (the model's request_method="GET" default carries
        # no identity signal) — it must still be CONSULTED, just guarded.
        for field in printed:
            if field == "http_method":
                assert "n.http_method" in is_empty_src, (
                    "is_empty() must consult http_method (guarded by the "
                    "documented default-method exception)"
                )
                continue
            assert f"n.{field}" in is_empty_src, (
                f"canonical_form prints {field} but is_empty() does not "
                "consult it — dimension drift"
            )
