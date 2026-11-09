"""FORGE ingest sources — the spec's sources.yaml, as reviewable code.

Trust scores and licenses are THE FORGE's published values. The
ingester never fetches from these URLs itself (zero live network from
the core); a scheduled, human-supervised external task fetches content
and hands it to the ingester as strings (FORGE-L-9
SCHEDULED_INGESTION).
"""
from __future__ import annotations

from webpent.forge.schemas import SourceConfig

SOURCES: dict[str, SourceConfig] = {
    s.source_id: s for s in (
        SourceConfig(
            source_id="payloadsallthethings", kind="github_repo",
            url="https://github.com/swisskyrepo/PayloadsAllTheThings",
            license="MIT",
            license_url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LICENSE",
            trust_score=0.95),
        SourceConfig(
            source_id="hacktricks", kind="github_repo",
            url="https://github.com/cyberark/hacktricks",
            license="CC-BY-NC",
            license_url="https://github.com/cyberark/hacktricks/blob/master/LICENSE.md",
            trust_score=0.90),
        SourceConfig(
            source_id="seclists", kind="github_repo",
            url="https://github.com/danielmiessler/SecLists",
            license="MIT",
            license_url="https://github.com/danielmiessler/SecLists/blob/master/LICENSE",
            trust_score=0.90),
        SourceConfig(
            source_id="hackerone_disclosures", kind="api",
            url="https://api.hackerone.com/v1/hackers/reports",
            license="API-terms",
            license_url="https://www.hackerone.com/disclosure-guidelines",
            trust_score=0.85),
        SourceConfig(
            source_id="exploitdb", kind="github_repo",
            url="https://gitlab.com/exploit-database/exploitdb",
            license="GPLv2",
            license_url="https://gitlab.com/exploit-database/exploitdb/-/blob/main/LICENSE.md",
            trust_score=0.85),
        SourceConfig(
            source_id="nvd", kind="api",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            license="public-domain",
            license_url="https://nvd.nist.gov/general/disclaimer",
            trust_score=0.80),
        SourceConfig(
            source_id="pentest_cheatsheets", kind="github_repo",
            url="https://github.com/jhaddix/pentest_cheatsheets",
            license="unspecified",
            license_url="https://github.com/jhaddix/pentest_cheatsheets",
            trust_score=0.75),
        SourceConfig(
            source_id="waf_bypass_lists", kind="github_repo",
            url="https://github.com/0xInfection/Awesome-WAF",
            license="CC0",
            license_url="https://github.com/0xInfection/Awesome-WAF/blob/master/LICENSE",
            trust_score=0.80),
    )
}


def get_source(source_id: str) -> SourceConfig:
    """Raise KeyError with a clear message for an unknown source id."""
    if source_id not in SOURCES:
        known = ", ".join(sorted(SOURCES))
        raise KeyError(
            f"unknown ingest source '{source_id}' (known: {known})")
    return SOURCES[source_id]
