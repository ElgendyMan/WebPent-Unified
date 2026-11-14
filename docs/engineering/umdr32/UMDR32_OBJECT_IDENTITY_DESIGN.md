# UM-DR-32 Object Identity Design

**Window:** UM-DR-32 §4 (Phase Two) — with the alias overlay (§5) built on it.
**Code:** `src/webpent/production/object_identity.py`, `src/webpent/production/alias_resolution.py`
**Status:** implemented, unit-tested, production-connected (via `identity_workflow`),
integration-tested, campaign-demonstrated on the controlled lab fixture.

---

## 1. The problem (§4.1)

The same business object is routinely visible through several endpoint
patterns (`/api/orders/123`, `/api/o/123`, a slug form, a nested
representation), while two resources may share a numeric identifier while
being different objects. An endpoint string establishes nothing about
object identity; the system must understand the OBJECT behind the
observation.

## 2. The object identity model (§4.2)

`ResourceObservation` (the ingest unit) → `ObjectIdentityRegistry` →
`ObjectIdentity` (the resolved record).

An identity anchors on **(engagement, tenant/namespace, resource_type,
stable object identifier)** — computed as a deterministic `uuid5` over
the anchor. **The URL path is never part of the anchor.**

- `ResourceObservation`: endpoint, method, resource_type, object_id and
  its **source** (`path_segment` | `response_body` | `query_param` |
  `workflow_object_ref` | `declared`), tenant, stable attributes
  (volatile and secret-shaped keys stripped deterministically), evidence
  list, observation provenance ref.
- `ObjectIdentity`: anchor fields, representations (the endpoints it was
  observed through), merged stable attributes, evidence refs,
  resolution status (`unresolved / resolved_by_evidence / ambiguous /
  conflicting`), confidence (grows only with corroborating evidence,
  capped 0.99).
- Principals are kept strictly separate (the principal model lives in
  `multi_identity.py`); ownership is an attribute, never an identifier.
- Bounded registry (default 5,000 identities, reported in stats, never
  silently exceeded).

## 3. Representation and alias model (§5)

`AliasResolver` builds a REVERSIBLE overlay over the registry — it never
mutates identities. Candidate discovery is evidence-only (five
structural signals, all from observed data):

- C1 two paths share the same terminal object id;
- C2 a Location/canonical evidence item names the other path;
- C3 an `api_resource_reference` evidence item names the other resource;
- C4 slug-form vs id-form whose bodies carry the same object id;
- C5 collection path that is the parent of an item path.

Classification states (§5.3, all reversible):
`confirmed_same_object`, `high_confidence_candidate`,
`possible_alternate`, `related_distinct`, `conflicting_evidence`,
`unknown`. A confirmed alias retains both representations, the shared
identity, the evidence, the decision method, the confidence and the
rejected interpretations (with reasons).

## 4. Identity relationships and evidence contract (§4.3/§4.4)

The six-way relationship vocabulary: `same_object`,
`alternate_representation`, `related_object`,
`same_identifier_different_namespace`, `ambiguous_identity`,
`distinct_object`.

Evidence kinds that CORROBORATE a same-object decision beyond a raw id
match: canonical link, Location header, api resource reference,
cross-endpoint body id, workflow reference, stable attribute signature.
A bare identifier match only opens a candidate — it never confirms.

The deterministic decision procedure (`ObjectIdentityRegistry.relate`):

1. Different observed tenants → `same_identifier_different_namespace`
   (absolute; nothing else is examined).
2. Different resource types → `related_object` when an explicit API
   reference links them, else `distinct_object`.
3. Same anchor WITH corroborating evidence → `alternate_representation`.
4. Same id, tenant unknown on either side → `ambiguous_identity`
   (abstain; never merge).
5. Attribute contradiction on stable keys → ambiguous with the
   contradiction preserved in the note.
6. Same anchor, same tenant, no corroboration → `same_object` candidate
   with an explicit "no corroboration — merge deferred" note.

Conflicting decisions across observations are APPENDED to the conflict
list, never overwritten. Numeric-id equality, path similarity and
resource-name similarity alone never merge anything.

## 5. Matching, abstention and tenant isolation rules

- Cross-tenant: never merged (rule 1), enforced in BOTH the registry and
  the alias layer (`rejected_interpretations: cross_tenant`).
- Cross-type: never merged without an explicit reference.
- Query-value distinctness: `?account=1` vs `?account=2` are distinct
  resources (the UM-DR-31.1 F10/F11 fingerprint contract — regression
  tests keep it).
- Collections are not aliases of items; parents are not children.
- Slug-vs-id pairs without body evidence: possible alternate at most
  (the lab fixture's abstain pair is never confirmed in any arm).
- Weak candidates stay candidates (`high_confidence_candidate`, never
  `confirmed_same_object`).

## 6. Integration path (§4.5/§5.5/§8)

```
observations_from_campaign_state(state)     # openapi routes, workflow
        │                                   # observations, declared
        ▼                                   # object observations
ObjectIdentityRegistry.ingest / relate
        ▼
AliasResolver.resolve (evidence-only overlay)
        ▼
identity_workflow_node                       # the production node
        ├─ object_identity_registry channel  (merge_dicts)
        ├─ identity_alias_graph channel      (merge_dicts)
        ├─ identity_research_hints           (ordering-only scheduling
        │                                     signals, consumed by
        │                                     stateful_research_hints —
        │                                     SAME budget, §8 contract)
        └─ hypotheses (deterministic ids, pool-deduped)
```

The node is flag-gated (`enable_object_identity`,
`enable_alias_resolution`, default False), double-gated at runtime,
bounded, advisory-only, and wired ahead of the strategist through the
composed conditional-redirect chain (`identity_workflow →
research_loop → strategist`); flag-off keeps the graph shape
byte-comparable (test-enforced).

## 7. Measured behavior (the controlled lab, §9)

Resolution metrics (4 ground-truth alias pairs; 4 never-merge pairs; 1
abstain pair):

| Arm | Correct | False merges | Missed | Precision | Abstention respected |
|---|---|---|---|---|---|
| baseline / object_identity-only | 0/4 | 0 | 4 | — | yes |
| alias_resolution and every later arm | **4/4** | **0** | **0** | **1.0** | yes |

Namespace separation (t1/t2 orders with the same id) held in every arm.
Vulnerability detection from alias knowledge alone: none (the honest
separation — resolution accuracy is not detection; the detection gains
come when the multi-identity layer consumes the alias graph for
cross-representation differentials, which found V-ALIAS-701).

## 8. Limitations

1. Resource types derive from path structure unless declared; a
   declared observation (schema-analyzed type + in-body id) dominates a
   path-derived hint (first-wins by structural richness) — but on
   targets with no schema and no body ids, genuine aliases under
   different path prefixes classify as `related_distinct` (type
   boundary) rather than aliases. Abstention is the honest outcome.
2. The registry is per-campaign-pass in-memory state; cross-campaign
   identity memory is future work.
3. `attribute_signature` corroboration currently requires explicit
   evidence items; automatic attribute-vector matching is future work.
