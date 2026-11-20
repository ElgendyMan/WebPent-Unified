# v97 bbscout Provider Decision

**Decision:** Keep Bugcrowd, Intigriti, and YesWeHack fixture-only in this release. Do not build partial live adapters without provider-specific authorization, documented rate limits, typed error mapping, pagination confinement, and live contract tests.

The HackerOne adapter is read-only and supports only authenticated GET retrieval. It was not exercised live because no separate provider authorization or credentials were supplied. No provider integration is allowed to submit reports or test targets.

## Evidence

The offline bbscout suite returned `36 passed` with exit code `0`. A static AST scan found the only network call in provider modules at `hackerone.py:urlopen`, inside the read-only GET path; no write-method calls were found. Fixture providers contain no network call sites.

Raw stdout, stderr, and exit markers are stored in this directory. The external source tree remains outside the WebPent repository and is identified by the recorded deterministic hash.
