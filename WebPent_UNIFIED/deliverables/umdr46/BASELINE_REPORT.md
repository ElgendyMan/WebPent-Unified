# UM-DR-46 P0.5 — BASELINE BENCHMARK report

Measured baseline of the converged trunk ``7f3807a`` (v0.44.0 / umdr45-convergence) BEFORE any Phase A+ code, per the mission ordering: measure the base first, build the brain, measure again — the delta is the evidence.

## System under test

* Entry point: ``webpent.cli.unified_hunt.run_unified_hunt`` (``webpent hunt`` core), mode=standard, no_llm=True, auto_approve=True — the OFFICIAL surface, unmodified.
* System-under-test proof: the only ``src/`` delta vs the v0.44.0 tag on this branch is the P0.3 removal of three provably-unimported modules (``agents/specialists/``, ``agents/team.py`` — zero importers per the UM-DR-45 agent decision register, re-verified in this window); the production graph is bit-identical in behavior.
* Battery: 6 family labs x 2 variants (vulnerable / secure) x 3 campaigns = 36 campaigns, fresh lab instance + fresh out-of-scope origin per campaign, cookie authentication (the channel the CLI surface carries), each campaign in a FRESH interpreter (subprocess) — the faithful shape of the official CLI entrypoint.
* Scoring: Tool-Confirmed findings only (CausalGuard + ProofBundle + replay); generated hypotheses are never TP. Attribution joins finding URLs to declared ground-truth anchors; any confirmation on a secure variant is an FP by definition.

## Overall

| Metric | Value |
| --- | --- |
| campaigns | 36 (36 completed, 0 error) |
| declared defects | 7 |
| TP / FP / FN | 6 / 0 / 18 |
| precision | 1.0 |
| recall | 0.25 |
| replay verified/total | 6/6 |
| timeouts/cancellations | 0 |
| out-of-scope origin zero requests (all campaigns) | True |

## Per family

| Family | Defects | TP | FP | FN | Precision | Recall | Reqs/campaign | Reqs/confirmed | t-first-candidate s | t-first-confirmed s | reproducible |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| idor_bola | 1 | 6 | 0 | 0 | 1.0 | 1.0 | 108.0 | 54.0 | 2.581 | 2.581 | True |
| workflow_abuse | 1 | 0 | 0 | 3 | None | 0.0 | 116.0 | None | None | None | True |
| request_smuggling | 1 | 0 | 0 | 3 | None | 0.0 | 97.0 | None | None | None | True |
| graphql_oracle | 1 | 0 | 0 | 3 | None | 0.0 | 107.0 | None | None | None | True |
| tenant_confusion | 1 | 0 | 0 | 3 | None | 0.0 | 94.0 | None | None | None | True |
| redirect_scope_bypass | 2 | 0 | 0 | 6 | None | 0.0 | 96.0 | None | None | None | True |

## Per campaign

| Family | Variant | Run | Status | Confirmed | Requests | Elapsed s | Guard calls | Replay |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| idor_bola | vulnerable | 1 | COMPLETED | 2 | 108 | 4.497 | 2 | 2/2 |
| idor_bola | vulnerable | 2 | COMPLETED | 2 | 108 | 4.346 | 2 | 2/2 |
| idor_bola | vulnerable | 3 | COMPLETED | 2 | 108 | 4.462 | 2 | 2/2 |
| idor_bola | secure | 1 | COMPLETED | 0 | 108 | 4.33 | 0 | 0/0 |
| idor_bola | secure | 2 | COMPLETED | 0 | 108 | 4.302 | 0 | 0/0 |
| idor_bola | secure | 3 | COMPLETED | 0 | 108 | 4.318 | 0 | 0/0 |
| workflow_abuse | vulnerable | 1 | COMPLETED | 0 | 116 | 3.696 | 0 | 0/0 |
| workflow_abuse | vulnerable | 2 | COMPLETED | 0 | 116 | 4.248 | 0 | 0/0 |
| workflow_abuse | vulnerable | 3 | COMPLETED | 0 | 116 | 4.277 | 0 | 0/0 |
| workflow_abuse | secure | 1 | COMPLETED | 0 | 116 | 4.32 | 0 | 0/0 |
| workflow_abuse | secure | 2 | COMPLETED | 0 | 116 | 4.332 | 0 | 0/0 |
| workflow_abuse | secure | 3 | COMPLETED | 0 | 116 | 4.323 | 0 | 0/0 |
| request_smuggling | vulnerable | 1 | COMPLETED | 0 | 97 | 3.897 | 0 | 0/0 |
| request_smuggling | vulnerable | 2 | COMPLETED | 0 | 97 | 3.929 | 0 | 0/0 |
| request_smuggling | vulnerable | 3 | COMPLETED | 0 | 97 | 3.911 | 0 | 0/0 |
| request_smuggling | secure | 1 | COMPLETED | 0 | 97 | 3.882 | 0 | 0/0 |
| request_smuggling | secure | 2 | COMPLETED | 0 | 97 | 4.423 | 0 | 0/0 |
| request_smuggling | secure | 3 | COMPLETED | 0 | 97 | 3.841 | 0 | 0/0 |
| graphql_oracle | vulnerable | 1 | COMPLETED | 0 | 107 | 4.281 | 0 | 0/0 |
| graphql_oracle | vulnerable | 2 | COMPLETED | 0 | 107 | 4.295 | 0 | 0/0 |
| graphql_oracle | vulnerable | 3 | COMPLETED | 0 | 107 | 4.248 | 0 | 0/0 |
| graphql_oracle | secure | 1 | COMPLETED | 0 | 107 | 3.691 | 0 | 0/0 |
| graphql_oracle | secure | 2 | COMPLETED | 0 | 107 | 4.343 | 0 | 0/0 |
| graphql_oracle | secure | 3 | COMPLETED | 0 | 107 | 4.226 | 0 | 0/0 |
| tenant_confusion | vulnerable | 1 | COMPLETED | 0 | 94 | 3.914 | 0 | 0/0 |
| tenant_confusion | vulnerable | 2 | COMPLETED | 0 | 94 | 3.908 | 0 | 0/0 |
| tenant_confusion | vulnerable | 3 | COMPLETED | 0 | 94 | 3.906 | 0 | 0/0 |
| tenant_confusion | secure | 1 | COMPLETED | 0 | 94 | 3.593 | 0 | 0/0 |
| tenant_confusion | secure | 2 | COMPLETED | 0 | 94 | 3.918 | 0 | 0/0 |
| tenant_confusion | secure | 3 | COMPLETED | 0 | 94 | 3.981 | 0 | 0/0 |
| redirect_scope_bypass | vulnerable | 1 | COMPLETED | 0 | 95 | 3.714 | 0 | 0/0 |
| redirect_scope_bypass | vulnerable | 2 | COMPLETED | 0 | 95 | 3.662 | 0 | 0/0 |
| redirect_scope_bypass | vulnerable | 3 | COMPLETED | 0 | 95 | 3.652 | 0 | 0/0 |
| redirect_scope_bypass | secure | 1 | COMPLETED | 0 | 97 | 3.648 | 0 | 0/0 |
| redirect_scope_bypass | secure | 2 | COMPLETED | 0 | 97 | 3.691 | 0 | 0/0 |
| redirect_scope_bypass | secure | 3 | COMPLETED | 0 | 97 | 3.638 | 0 | 0/0 |

## Honest notes

* MEASURED FINDING (harness design): the first battery draft ran all campaigns in ONE process and measurably degraded — after the first campaigns, request counts collapsed (108 → 4 → 1) and the session cookie stopped being carried. This is process-level state accumulation across sequential in-process campaigns in the shipped engine, NOT target behavior. The official CLI surface is a fresh process per hunt, so the battery runs each campaign in its own interpreter (subprocess) — both the faithful shape and structurally leak-free. The in-process degradation itself is recorded here as an observation for the Phase I (autonomous quality control) agenda.
* This baseline measures the SHIPPED surface. Families the CLI hunt surface cannot yet exercise end-to-end (e.g. no smuggling framing probes, no GraphQL query body crafting in the standard crawl) appear as FN with the lab requests proving what was actually probed — recorded, not hidden.
* The secure variants are the false-positive gate: any Tool-Confirmed finding there is a measured FP, and the enforced boundaries (admin gate, ownership 403s, decoys) must never confirm.
* The UM-DR-45 X-track battery A measured the query-param authentication wiring gap (recall 0.0 on labsuite targets). This battery removes that confounder by using cookie authentication — the channel the CLI surface actually carries.
* Every number in this report derives from ``BASELINE_METRICS.json`` (machine record); the report is generated, never hand-written.
