#!/usr/bin/env python3
"""UM-DR-49 P0.4 — the Juice Shop public-truth catalog.

The truth is the app's OWN published scoreboard data (GET /api/Challenges
— 118 published challenges). The projection onto OUR six families is a
MECHANICAL, DECLARED keyword rule set over the PUBLIC name/category/
description text — no team-declared truth, no app-specific code in
production (this is a measurement artifact, not engine code).
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

OUT = Path("deliverables/umdr49/truth_catalogs")
FAMILY_SET = {"idor_bola", "workflow_abuse", "request_smuggling",
              "graphql_oracle", "tenant_confusion", "redirect_scope_bypass"}

# DECLARED projection rules (keyword -> family) over the PUBLIC text.
# Order matters: the first hit wins. 'redirect'/'scope' beats the
# category; the access-control category is the idor projection.
PROJECTION_RULES: list[tuple[str, str]] = [
    ("redirect", "redirect_scope_bypass"),
    ("graphql", "graphql_oracle"),
    ("broken access control", "idor_bola"),
    ("admin section", "idor_bola"),
    ("score access", "idor_bola"),
    ("forgot someone's password", "workflow_abuse"),
    ("password repeat", "workflow_abuse"),
    ("password reset", "workflow_abuse"),
    ("csrf", "workflow_abuse"),
    ("change behr", "workflow_abuse"),
    ("checkout", "workflow_abuse"),
    ("product tampering", "workflow_abuse"),
    ("five star feedback", "workflow_abuse"),
    ("forged review", "workflow_abuse"),
    ("tenant", "tenant_confusion"),
    ("fake geo", "tenant_confusion"),
    ("self-xss", None),
]


def project(challenge: dict) -> str | None:
    """Mechanical projection over the PUBLIC text (declared rules)."""
    text = " ".join(filter(None, [
        str(challenge.get("name") or ""),
        str(challenge.get("category") or ""),
        str(challenge.get("description") or ""),
    ])).lower()
    for keyword, family in PROJECTION_RULES:
        if keyword in text:
            return family
    return None


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
    raw = urllib.request.urlopen(f"{base}/api/Challenges", timeout=30).read()
    payload = json.loads(raw)
    data = payload.get("data") or payload
    items = []
    for c in data:
        family = project(c)
        items.append({
            "id": f"juiceshop:{c.get('key') or c.get('id')}",
            "name": c.get("name"),
            "category": c.get("category"),
            "difficulty": c.get("difficulty"),
            "projected_family": family,
            "in_projection": family in FAMILY_SET,
            "public_reference": (
                f"{base}/api/Challenges#key={c.get('key') or c.get('id')} "
                f"(the app's own published scoreboard data; the official "
                f"companion guide pwning.owasp-juice.shop documents every "
                f"challenge)"),
            "confirmation_criterion": (
                "the challenge's solved flag flips on the app's own "
                "scoreboard after a blind campaign probe"),
        })
    projected = [i for i in items if i["in_projection"]]
    catalog = {
        "schema": "umdr49-truth-catalog/1.0.0",
        "app": "juiceshop",
        "version_pinned": "v20.4.0 (prebuilt release package)",
        "public_source": (
            "GET /api/Challenges on the app's own scoreboard (the "
            "mission's declared public truth: the 100+ published "
            "challenges)"),
        "projection_rules": [
            {"keyword": k, "family": v} for k, v in PROJECTION_RULES],
        "total_items": len(items),
        "projected_items": len(projected),
        "items": items,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "juiceshop_truth.json").write_text(json.dumps(catalog, indent=1))
    print(f"juiceshop: {catalog['total_items']} challenges, "
          f"{catalog['projected_items']} projected onto our six families")
    from collections import Counter
    print("projection:", dict(Counter(i["projected_family"]
                                      for i in projected)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
