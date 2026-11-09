# OAST deployment guide (PROPOSALS_ULTIMATE_V2 §1, 2026-10-29)

The correlation engine (`webpent.shared.oob`) already mints per-probe
tokens, enforces deterministic evidence windows and drops unregistered
callbacks. What it does NOT ship is the network listener the target's
callbacks actually arrive on. That listener is the `webpent.oast`
package: a self-hosted HTTP collector plus an optional minimal DNS
A-responder, both stdlib-only and both fail-closed.

This guide is the operational half: what to run, what to expose, and
what never to do.

## 1. What the collector is

`OastCollectorServer` is an HTTP listener that:

* records any request carrying a probe token (a 32-hex path segment, or
  the leading label of the `Host` header when a zone is configured),
* serves those records on `GET {base}?token=...` in exactly the record
  shape `webpent.shared.oob.poll_remote_collector` consumes, so the
  existing OOB validator loop needs no changes,
* drops tokenless requests (HTTP 404) and never logs tokens.

`OastDnsResponder` (optional) is a UDP A-only responder for your zone:
in-zone queries are answered with your configured IP and recorded as
`dns` callbacks (token = leading label). Out-of-zone queries are
ignored — it is not a public resolver. DNS callbacks are the signal
that makes blind XXE and DNS-exfil SQLi confirmable when the target
cannot make outbound HTTP calls at all.

## 2. The zone (operator responsibility)

Probe hosts are minted as `<token>.<engagement>.<domain>`. You need one
wildcard DNS zone you control, e.g.:

```
oast.example.net.   IN NS     ns1.example.net.
*.oast.example.net. IN A      <your-collector-ip>
```

Every subdomain resolves to the collector, and the leading label
carries the probe identity. The responder answers A queries for any
name under the zone; no other records are served.

**Warnings, in order of severity:**

1. NEVER point the OAST zone at, or delegate it to, a target's
   infrastructure or a target-adjacent host. The zone is a sensor you
   own; pointing it at a target turns your sensor into their telemetry
   and can collide with their own testing or DNS controls.
2. Use a dedicated domain you do not use for anything else. Callback
   records and query logs are engagement evidence.
3. DNS resolution paths reveal the collector's IP to whatever resolves
   probe names. That is inherent to OOB testing; size your threat
   model accordingly.

## 3. Running it

Both listeners default to the safest possible posture (localhost,
DNS off) and are enabled through settings, all default-off:

```
enable_oast = true                       # master switch (default false)
oast_domain = oast.example.net           # your wildcard zone
oast_poll_endpoint = http://<collector>:<port>   # for poll_remote_collector
oast_collector_bind_host = 0.0.0.0       # only if the collector must be reachable
oast_collector_bind_port = 8443          # 0 = free port (tests)
oast_dns_listen_port = 53                # 0 = DNS responder off (default)
oast_dns_response_ip = <your-collector-ip>
oast_max_callbacks_per_token = 64        # bounded ring per token
```

With `enable_oast` false nothing binds a socket and nothing mints probe
URLs — the package stays inert library code.

Health check: `GET /healthz` returns `{"ok": true}`.

## 4. Exposure guidance

* Keep `oast_collector_bind_host` at `127.0.0.1` unless the collector
  genuinely must accept callbacks from a remote target network.
* When exposing it, put it behind TLS or an authenticated proxy if your
  engagement requires confidentiality of callback metadata; the
  collector itself speaks plain HTTP and authenticates nothing — its
  only identity gate is the 128-bit token shape, which is
  unguessable but not encrypted.
* The `/poll` endpoint answers any caller holding a valid token. That
  is by design (the webpent-side ingestion re-checks registration and
  drops unknown tokens), but it means poll responses are readable by
  anyone who learns a token. Treat tokens as secrets; never paste a
  probe URL into a report before it is redacted.
* Run the collector as an unprivileged user; it needs no privileges
  beyond its bind ports (UDP 53 may require a capability or a
  high-port + port-forward arrangement).

## 5. Clock and privacy notes

* Evidence windows are matched deterministically against
  `registered_at`; when the collector runs on a different machine than
  webpent, keep the clocks aligned (NTP) or widen the window. Clock
  skew can turn a real callback into an out-of-window miss — an
  INCONCLUSIVE, never a false positive.
* The collector keeps `source_ip` (the egress address that connected)
  for operator triage. Ingestion into webpent fingerprints it
  (truncated SHA-256) before anything reaches evidence stores; raw
  addresses live only in the collector's own memory and are lost on
  restart by design.
* Bodies are never stored — only a 16-hex SHA-256 digest and a byte
  count, capped at 4 KiB read.

## 6. What is intentionally NOT here

* No third-party fallback: if `oast_domain` is empty, probe minting
  stays fail-closed (`OOBCollaborator.enabled` false) — the framework
  never quietly degrades to interactsh.fun or any external service.
* No recursive DNS service: the responder answers A queries in-zone
  only.
* No HTTPS collector in this package: terminate TLS in front of it.
* No automatic DNS provisioning: wildcard setup above is manual and is
  the operator's responsibility, deliberately.
