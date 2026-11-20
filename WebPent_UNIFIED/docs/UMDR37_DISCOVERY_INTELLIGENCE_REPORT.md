# UM-DR-37 Discovery Intelligence Report

Generated 2026-11-16T05:24:44.894368+00:00.

The three capabilities the mission separates (understanding /
reasoning / experimental discovery) map to measured components:

- **Understanding**: the appmodel (spec above) + knowledge layers.
- **Security reasoning**: multi-family hypothesis generation
  (hypothesis_analyzer URL/parameter signatures across ~20 vuln
  classes; six-family spine registry with ScenarioSpec contracts:
  preconditions, discriminator experiment, expected signal, negative
  control, evidence requirements); family-specific evidence rules are
  enforced per family (IDOR needs identity/resource/ownership context;
  the compiled-campaign contract is the reference shape).
- **Experimental discovery**: the EGAIE information-gain selector
  (gain + family bonus - cost - risk - repetition + state-record
  terms), the research loop priors, and the AVI registry selector.
  Info-gain priors are documented lookup constants — assumptions
  stated, not hidden.

Family support states (honest): access_control = PRODUCTION_PATH_
VERIFIED (3/3 campaigns); spine families = INTEGRATED (flag-gated,
lab-tested); signature families = IMPLEMENTED (hypothesis generation +
advisory contracts). No family beyond access control claims production
confirmation.
