# VDP Scope Sources

Generated during the Ultimate Validation Sprint on 2026-10-03.

| Program | Official source | Evidence used | Important limitation |
|---|---|---|---|
| Yahoo | [Yahoo Intigriti program](https://app.intigriti.com/programs/yahoo/yahoobugbounty/detail) and [Yahoo VDP policy](https://legal.yahoo.com/xw/en/yahoo/coordinated-vulnerability-disclosure-program-policy/index.html) | Yahoo brands are described as the program context; the page explicitly lists `*.yahoo.net`, `*.vdms.com`, `*.yahooinc.com`, Yahoo regional domains, and SSP domains as not in scope; 50 requests/second limit is stated. | Scope changes; confirm the current asset list before testing. `*.yahoo.net` is denied here because the current page explicitly lists it as not in scope. |
| Comcast | [Comcast HackerOne security page](https://hackerone.com/comcast) and [Comcast responsible disclosure policy](https://www.xfinity.com/vulnerabilityreport) | Official policy asks researchers to avoid privacy violations, degradation, disruption, and destruction and provides the reporting route. | The static source did not expose a complete asset list; the YAML is conservative candidate scope and is marked review-required. |
| GitHub | [GitHub HackerOne page](https://hackerone.com/github) and [GitHub Bug Bounty rules](https://bounty.github.com/rules.html) | GitHub rules require GitHub-operated in-scope sites, own accounts/repositories for authorization testing, no excessive traffic, no PII access, and no public disclosure. | Third-party hosted subdomains are not automatically in scope; re-check the live target list before testing. |

These YAML files are **scope inputs, not authorization**. They must be reviewed against the live program policy immediately before any external engagement. No external VDP target was contacted during this sprint.
