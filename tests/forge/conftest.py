"""Shared fixtures for the FORGE suite.

Zero live network: every ingester call receives PRE-FETCHED content as
a string. The corpus is versioned and deterministic; payloads get
attribution and license on every path.
"""
from __future__ import annotations

import pytest

from webpent.forge.schemas import PayloadAttribution, TargetContext
from webpent.forge.sources import get_source


# ---------------------------------------------------------------------------
# Sample source content (pre-fetched bodies, one per parser)
# ---------------------------------------------------------------------------

PAYLOADSALLTHETHINGS_MD = """# SQL Injection

## Authentication Bypass

```
' OR 1=1-- -
admin'--
```

## MySQL

```
SLEEP(5)
```
"""

HACKTRICKS_MD = """# SSRF

## Bypassing filters

```
http://127.0.0.1:80
http://169.254.169.254/latest/meta-data/
```
"""

SECLISTS_TXT = """' OR 1=1-- -
"<script>alert(1)</script>"
../../etc/passwd
"""

HACKERONE_JSON = """[
  {
    "title": "SQL injection in search",
    "weakness": "SQL Injection",
    "severity": "critical",
    "body": "The search parameter is injectable:\\n```\\n' UNION SELECT NULL--\\n```"
  }
]"""

EXPLOITDB_TXT = """12345|webapps|SQL Injection|' OR 1=1-- -
12346|webapps|Path Traversal|../../etc/passwd
"""

# Content that exercises deduplication.
DUPLICATED_TXT = """' OR 1=1-- -
' OR 1=1-- -
admin'--
"""


@pytest.fixture
def sample_contents():
    return {
        "payloadsallthethings": PAYLOADSALLTHETHINGS_MD,
        "hacktricks": HACKTRICKS_MD,
        "seclists": SECLISTS_TXT,
        "hackerone_disclosures": HACKERONE_JSON,
        "exploitdb": EXPLOITDB_TXT,
    }


@pytest.fixture
def attribution():
    source = get_source("payloadsallthethings")
    return PayloadAttribution(
        payload_id="pending",
        original_source=source.source_id,
        original_url=source.url,
        original_author="swisskyrepo",
        license=source.license,
        license_url=source.license_url,
        source_trust=source.trust_score,
    )


@pytest.fixture
def target_context():
    return TargetContext(
        tech_stack=["mysql", "php"],
        waf_detected=["cloudflare"],
        endpoints=["/search"],
        parameters=["q"],
        response_content_type="application/json",
        param_context=["query"],
    )
