# Program Scope Policy

`webpent hunt --target ... --scope scope.yaml` requires an operator-supplied policy for target execution. The policy is compiled before crawling and is enforced in addition to the existing `ScopeLaw` and `ToolBoundary` authorities.

## YAML example

```yaml
in_scope:
  - url: http://127.0.0.1:3000
    protocol: http
    port: 3000
    path: /
    allowed_methods: [GET, POST]
    max_severity: high
out_of_scope:
  - url: http://127.0.0.1:3000/admin
    path: /admin
limits:
  max_requests_per_second: 2
  max_concurrent_requests: 1
  max_violations: 5
  no_destructive: true
blacklisted_payloads:
  - "DROP TABLE"
  - "rm -rf"
instructions:
  - "Local authorized lab only"
```

## JSON example

```json
{
  "in_scope": [
    {"url": "https://app.example.test", "path": "/api", "allowed_methods": ["GET", "POST"]}
  ],
  "out_of_scope": [
    {"domain": "admin.example.test"}
  ],
  "limits": {
    "max_requests_per_second": 1,
    "max_concurrent_requests": 1,
    "max_violations": 3,
    "no_destructive": true
  }
}
```

## Plain text example

One origin per line is supported for simple local runs. `exclude:` rules are explicit denies and exact ports are preserved.

```text
http://127.0.0.1:3000
exclude: http://127.0.0.1:3001
```

## Enforcement behavior

- An empty or rule-less policy fails closed.
- Explicit deny rules win over allow rules.
- Unknown host, scheme, port, path, method, or severity is denied.
- Destructive methods are denied by default (`no_destructive: true`).
- Rate, concurrency, blacklist, and violation-threshold events are recorded as redacted scope metadata.
- Raw policy content is not sent to the LLM and is not written to campaign artifacts; only the policy fingerprint, counts, and decision categories are recorded.
