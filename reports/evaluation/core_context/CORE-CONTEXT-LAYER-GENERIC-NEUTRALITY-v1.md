# Core Target Context Layer — Generic Neutrality Scan v1

## Scope

The scan covers `src/webpent/shared/target_context.py` and the context-enabled `CampaignExecutor` integration. It checks that target names, routes, lesson semantics, and application business logic remain outside the Generic Core.

## Results

| Check | Result |
|---|---|
| WebGoat references in Generic Core | None |
| crAPI references in Generic Core | None |
| Juice Shop references in Generic Core | None |
| IDOR/LessonSession/target route references in Generic Core | None |
| Target names in context adapters | Present only in target-local adapter modules |
| Forbidden capability declarations | Explicitly guarded in Generic Core |
| Default credentials/token generation permission | Denied |
| External network/callback permission | Denied |
| Auth bypass/state mutation/destructive action permission | Denied |
| Candidate/negative-control role separation | Enforced by typed context roles and scope keys |

## Conclusion

The Generic Core owns contracts, policy, scope binding, lease lifecycle, readiness, snapshot/restore, cleanup, and typed status handling. WebGoat, crAPI, and Juice Shop names and semantics are confined to adapter/provider modules. No target-specific route, selector, authentication flow, or business predicate was added to the Generic Core.
