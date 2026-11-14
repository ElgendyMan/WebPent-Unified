"""v80 Task 2: advisory coverage packs for validator-uncovered classes.

Proven properties:

* the four packed classes (ssti, xxe, ssrf, backup_files) exist with
  probe descriptions and required oracles,
* the ledger is honest by construction: a class only leaves
  ``missing-validator`` when a real bundle class was recorded elsewhere,
* seeds are advisory, capped, and never executable payloads,
* everything is importable through the package ``__init__``.
"""

from __future__ import annotations

from webpent.autonomous import (
    CoveragePack,
    pack_hypothesis_seeds,
    pack_ledger_entries,
)
from webpent.autonomous.coverage_packs import PACKS


def test_four_packed_classes_exist() -> None:
    assert set(PACKS) == {"ssti", "xxe", "ssrf", "backup_files"}
    for label, pack in PACKS.items():
        assert isinstance(pack, CoveragePack)
        assert pack.class_label == label
        assert pack.probes, f"{label} pack must describe its probes"
        assert pack.required_oracles, f"{label} pack must require oracles"
        assert pack.status == "missing-validator"


def test_packs_carry_no_executable_payloads() -> None:
    # The packs ship probe descriptions and oracle requirements only.
    # Any string that looks like a concrete exploit payload is a bug.
    forbidden = ["{{7*7}}", "<!ENTITY", "${jndi:", "union select", "..%2f"]
    for pack in PACKS.values():
        text = " ".join(pack.probes + pack.required_oracles + pack.hypotheses).lower()
        for payload in forbidden:
            assert payload.lower() not in text


def test_ledger_is_honest_by_construction() -> None:
    rows = pack_ledger_entries()
    assert [row["class"] for row in rows] == ["backup_files", "ssrf", "ssti", "xxe"]
    assert all(row["status"] == "missing-validator" for row in rows)
    # A seen class upgrades only that class, and only to "validated".
    rows = pack_ledger_entries({"ssti"})
    by_class = {row["class"]: row["status"] for row in rows}
    assert by_class["ssti"] == "validated-by-bundle"
    assert by_class["xxe"] == "missing-validator"
    # Nothing ever self-reports "confirmed" from the pack side.
    assert all(row["status"] != "confirmed" for row in rows)


def test_seeds_are_advisory_and_capped() -> None:
    seeds = pack_hypothesis_seeds(cap=2)
    assert len(seeds) == 2
    for seed in seeds:
        assert seed["advisory"] is True
        assert seed["source"] == "coverage_pack"
        assert 0.0 <= float(seed["priority"]) <= 0.75
        assert "rationale" in seed
    default = pack_hypothesis_seeds()
    assert len(default) == 4


def test_pack_seeds_do_not_outrank_evidence_based_seeds() -> None:
    """CR-1: zero-evidence pack seeds rank below intel (proof-history) seeds."""
    for seed in pack_hypothesis_seeds():
        assert float(seed["priority"]) <= 0.5
