# Denali Configuration Findings Preview

## Outcome

A practitioner can import AI security posture findings from Prowler or another OCSF
producer and investigate each evaluated condition without surrendering Denali's
standalone inventory, evidence, or user-experience boundaries.

## Product surface

- Open-finding counts by severity.
- Search and severity/state filters.
- Finding detail with description, risk, remediation, and source identity.
- Normalized affected-resource references that do not mint inventory assets or graph
  relationships.
- Compliance mappings and remediation references.
- Source evidence and observation history, including first seen, last seen, and last
  semantic change.
- Explicit fixture labelling for the local demonstration.

## Trust boundaries

- Findings are evaluated conditions; inventory assertions are observed resources.
- OCSF is a supported finding interchange, not Denali's inventory schema.
- Arbitrary OCSF `resources.data` is never persisted.
- Imports are additive unless the operator explicitly marks a complete, unfiltered
  report authoritative.
- Failed or partial imports cannot resolve prior findings by absence.
- Suppression and resolution are finding lifecycle states, not inventory deletion.
- A referenced resource is correlated to inventory only when a separately observed,
  evidence-bearing identifier supports that link.

## Next slice

Configuration findings become inputs to Denali issues. Issue rules will correlate
atomic findings with identity, exposure, data, and capability relationships while
preserving every contributing fact and its coverage state.
