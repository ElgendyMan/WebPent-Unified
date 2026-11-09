"""L7 independent lab corpus.

A separately implemented, authorized loopback evaluation application.
This package shares NO code with the L6 fixture generation
(`webpent.egaie.eval_instances`, `webpent.egaie.http_target` fixture
data, `webpent.egaie.discovery_target`): it carries its own HTTP
plumbing, its own deployment surface, and its own ground truth
(`labsuite.evaluator`, imported by the benchmark harness only AFTER an
investigation finishes).

Shared dependencies (documented in docs/L7_DELIVERABLES.md):

- the engine's published observation contract: an index document with
  api groups, a kinds map and a schema block of semantic roles; an
  outcome header that marks granted/denied independent of the status
  code; the probe-credential protocol ("actor-a"/"actor-b" resolve to
  the deployment's own identities at request time). The lab implements
  this contract from its documentation, not from fixture code;
- `webpent.shared.http` and `webpent.shared.engagement_scope`: the
  safety plumbing every loopback client in the codebase uses.
"""
