# RSI production-readiness contracts

The active contract is [Observer v1](./v1/README.md).

Production-readiness contracts are versioned because the controls are part of the
system boundary. A new version must not silently weaken an accepted requirement.
If implementation evidence invalidates a requirement, work on that branch stops
until the decision is explicitly reopened and replaced.

The older architecture, roadmap, standards, threat-model, and live-capital
documents describe the broader long-term RSI concept. For the Observer v1 release,
this contract takes precedence whenever those documents imply execution, payments,
wallet access, public market intelligence, or a weaker data-retention rule.
