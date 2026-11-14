# UM-DR-34 Canonical Scope Contract

**Phase 2 deliverable — the ONE authoritative engagement scope
authority.** Implementation: `src/webpent/scope/authority.py` (new);
typed-rule evolution: `src/webpent/scope/models.py`; adapter:
`src/webpent/scope/enforcer.py`; unified ingestion:
`src/webpent/scope/parser.py` + `shared/scope_file.py` (all re-pinned
per DR-009, `scripts/refreeze_manifest_umdr34.py`).

---

## 1. Architectural decision (§2.1)

No new independent scope engine was created. The canonical authority
**evolves the existing typed `ScopeRule`/`ScopePolicy`** and absorbs the
strict wildcard compiler semantics of `shared/wildcard_scope.py`:

* `webpent.scope.authority.EngagementScopeAuthority` — the ONE
  request-decision engine (immutable, deterministic, fingerprinted).
* `models.ScopeDecision` — extended in place with the canonical audit
  fields; every pre-existing constructor and test keeps working
  (first seven fields unchanged).
* `ScopeEnforcer` — compatibility adapter; host matching DELEGATES to
  `authority.compile_host_matcher` (its `fnmatch` implementation is
  deleted, not merely bypassed).
* `OriginPolicy` + the engagement context — remains the per-origin
  view used by the transports, now atomic and fail-closed (Phase 3).
* `ScopeLaw`/`ToolBoundary` — keep tool-capability/poison-argument
  duties; never re-implement host matching (§4.7 honored).

## 2. The decision interface (§2.2)

```python
authority.evaluate_request(
    url, *, method="GET", payload=None,
    request_kind=None, severity=None, redirect_context=None,
) -> ScopeDecision
```

The returned `ScopeDecision` carries, on every decision:

| Field | Meaning |
|---|---|
| `status` / `request_admitted` / `allowed` | IN/OUT_OF_SCOPE + admission |
| `normalized_origin`, `hostname`, `scheme`, `effective_port`, `normalized_path` | the normalized request target |
| `matched_allow_rule`, `matched_deny_rule` | `"<kind>:<value>"` of the deciding rules |
| `exclusion_reason`, `reason`, `violation_code` | stable reason tokens (see §5) |
| `scope_fingerprint` | the policy's sha256 fingerprint |
| `authorization_context_id` | the bound engagement's context id |
| `decision_seq`, `decision_timestamp` | monotonic per-authority sequence + wall clock |
| `may_proceed_to_network` | the single network-boundary flag |
| `redirect_context` | present when the decision is a redirect re-check |

Determinism: same `(policy, url, method, payload)` ⇒ same decision,
reason, matched rules (pinned by
`TestDecisionContract::test_deterministic_decisions`). Deny rules
ALWAYS take precedence (first matching deny wins even when an allow
also matches). UNKNOWN/malformed/missing state NEVER becomes an allow.

## 3. Scope semantics (§2.3)

**Host and IP.** Exact DNS hostname; exact IP literal (IPv4/IPv6
compressed); CIDR rules (`ip in network`, strict=False); wildcard rules
(see below); IDNA/punycode normalization (unicode declaration ⇔
xn-- form both match); trailing-dot normalization; `localhost` NOT
aliased in the canonical authority (the compat view keeps the
documented loopback alias in engagement_scope only).

**Wildcards — ONE compiler.** `*.example.com` compiles to the anchored
complete-label pattern `^(?:label\.)+example\.com$`:

* the apex `example.com` is NOT included (explicit entry required);
* `?`, `[seq]`, and any `*` that is not a single leading `*.` label are
  REJECTED AT COMPILE TIME (`scope_wildcard_must_be_leftmost_label`,
  `scope_rule_glob_syntax_denied`) — including inside `urlsplit`-hostile
  bracket syntax, which is detected and given the precise token;
* a wildcard never becomes an fnmatch/glob expression (the fnmatch
  implementation is deleted from the tree);
* a wildcard rule never matches a suffix of an unrelated domain
  (`example.com.attacker.net` pinned as denied).

**Scheme and port.** http/https distinguished; ws/wss explicitly
defined (an `http` rule admits `ws` requests, an `https` rule admits
`wss` — same TLS posture; pinned); effective default ports computed
correctly; explicit port `0` REJECTED (`request_url_port_zero_denied`);
out-of-range/negative ports rejected; **all port reads use explicit
`is None` handling** (the historic `parsed.port or default` that
treated 0 as omitted is deleted from both the authority and the
enforcer); a hostname-only rule (no declared port) matches ONLY the
scheme-default ports — a private-host exemption can never silently
authorize every port.

**Paths.** Include prefixes with segment-boundary matching (`/api` ≠
`/api2`); exclude prefixes with precedence over includes (deny-first
evaluation); exact-path and trailing-slash equivalence; dot-segments
normalized BEFORE matching (`/api/../admin` ⇒ `/admin` ⇒ denied under
an `/api` include); query/fragment never change the decision. Encoded
paths: `%2e`, `%2f`, `%5c`, double encoding, and raw backslash are
**AMBIGUOUS ⇒ conservatively denied** (`scope_path_ambiguous`) — the
authority never assumes a server will interpret an ambiguous path
safely.

**Methods and operations.** Explicit allowed-method sets; destructive
methods (DELETE/PUT/PATCH) blocked under the default
`no_destructive` limits; severity ceilings via the existing
`severity_allowed`; operator blacklisted payloads; request-kind carried
on the decision record. State-changing operations are not assumed to be
limited to DELETE/PUT/PATCH — method policy is per-rule and the
destructive list is a floor, not a ceiling.

## 4. Parser unification (§2.4)

One ingestion surface, no independent matching logic:

* scope files (`shared/scope_file.parse_scope_file` → `ScopeFileSpec`
  → `authority_from_scope_file_spec`);
* structured YAML/JSON, HackerOne-style and Bugcrowd-style exports
  (`scope/parser.parse_scope_text` — walks `rules/scope/targets/
  structured_scopes/assets`, `in_scope`/`out_of_scope`, per-item
  `allow`, limits, blacklists);
* plain-text line grammar (include/exclude/instruction/limits).

Fail-closed everywhere: empty or comment-only documents are rejected;
**a boolean `out_of_scope: true` marker on an export item no longer
CRASHES the parser** (baseline behavior) — it becomes a deny rule for
that item; an invalid rule never silently transforms into a broader
valid one (compile rejection propagates). Provenance: every policy
carries `source` and a sha256 fingerprint computed over the normalized
rule set.

## 5. Stable reason tokens

`request_url_rejected` (malformed/userinfo/port-0/out-of-range/scheme),
`scope_policy_empty`, `destructive_method_blocked`,
`blacklisted_payload_blocked`, `scope_path_ambiguous`,
`explicit_out_of_scope` (+ `matched_deny_rule`),
`unknown_scope` (no rule matched — the fail-closed default).

## 6. Compatibility modes (§4.6)

`authority_for_target_only(url)` — the explicit, narrowly-scoped
compatibility authority used when a caller supplies no full policy
(direct HunterRunner invocation): bounded to the EXACT declared origin
(scheme + host + effective port, no wildcards), mode reported as
`target_only`, every request still validated at the network boundary.
An omitted scope policy can no longer create an unbounded campaign.

## 7. Regression evidence

`tests/test_umdr34_canonical_scope_authority.py` — 38 tests: wildcard
matrix (incl. glob-metacharacter rejection and suffix-domain denial),
origin matrix (schemes/ports/userinfo/malformed), path matrix
(segment boundaries, encodings, exclusion precedence), method/severity/
payload matrix, determinism, deny precedence, decision-record fields,
parser unification (scope file, HackerOne, Bugcrowd, malformed),
target-only mode.
