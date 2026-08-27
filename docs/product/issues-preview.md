# Denali Issues & Paths Preview

## Outcome

A practitioner can move from isolated posture findings to a prioritized security
consequence and inspect every fact and capability edge that supports it.

## Product surface

- Open-issue counts by severity and lifecycle state.
- Correlation coverage shown before issue totals are interpreted.
- Search and severity/state filters.
- Issue narrative, risk, and remediation guidance.
- A compact capability-path view across agent, execution identity, tool, and sensitive
  data.
- Contributing findings with their roles in the correlation.
- Direct evidence locators for every finding and relationship edge.
- Confidence and last-evaluation timestamps.

## Acceptance scenario

1. Seed the transparent local demonstration.
2. Open **Issues & paths** and see one critical confirmed issue.
3. Open the issue and inspect two contributing findings.
4. Inspect the three asserted capability edges: `runs_as`, `can_invoke`, and `can_write`.
5. Confirm that each edge is observed or externally verified and has its own evidence.
6. Remove or infer an edge and see no new issue; evaluation coverage becomes unknown.
7. Resolve a contributing finding and see the previously confirmed issue resolve.

## Explicitly deferred

- General-purpose graph query authoring.
- User-authored correlation rules.
- Cross-cloud vulnerability and exposure paths.
- Ticketing and assignment workflows.
- Automated remediation.
