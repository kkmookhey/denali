# Denali Inventory Preview

## Outcome

A practitioner can start Denali, scan a repository and live MCP server, optionally
connect AWS or Prowler, and receive an evidence-bearing inventory of the AI system and
its relationships in under ten minutes.

## First-class resource types

- AI agents
- Models and model artifacts
- MCP servers
- Tools and actions
- Guardrails
- Pipelines and training jobs
- AI datastores and knowledge bases
- AI workloads
- Code repositories and AI frameworks
- Execution identities
- Application endpoints and related cloud resources

## Required user surfaces

### Dashboard

- Inventory totals by resource type and source.
- Coverage and freshness before risk counts.
- Unreviewed, unwanted, newly discovered, changed, and withdrawn inventory.
- Declared-versus-observed deltas.

### Inventory explorer

- Search, filters, grouping, saved views, and source/coverage filters.
- Reusable presentation across every resource type.
- Explicit active, withdrawn, stale, and unknown states.

### Resource detail

- Overview and normalized properties.
- Relationships and capability paths.
- Evidence with source locator and assertion type.
- Findings and issues.
- Activity placeholder until a runtime provider exists.
- Governance: approved, unreviewed, unwanted, owner, notes.
- First seen, last seen, last changed, discovery source, and collection scope.

### Sources and coverage

- Connector capability declaration.
- Last successful and failed runs.
- Coverage by plane and scope.
- Partial, failed, not-supported, and unknown states.
- No successful-looking zero when a source could not inspect something.

## Initial sources

1. Repository detectors extracted from the previous work.
2. Live MCP observation and tool-description integrity.
3. Native AWS AgentCore runtimes, gateways, identities, endpoints, targets, and memories.
4. Native AWS Bedrock Agents Classic and Guardrails for existing estates.
5. Prowler OCSF findings adapter.
6. Generic OCSF finding import.
7. Eiger demo connector and fixtures.

## Acceptance scenario

1. Start the local stack.
2. Scan Eiger.
3. Observe its MCP endpoint.
4. See agents, models, frameworks, MCP servers, and tools.
5. Open an agent and inspect every relationship and its evidence.
6. Compare declared and observed tools.
7. See tool-description baseline and drift state.
8. Mark the agent approved, unreviewed, or unwanted.
9. Export the inventory as a Denali snapshot and AI-BOM.
10. Add Prowler or AWS and see cloud resources without changing Denali's UX.

## Explicitly deferred

- Generic CSPM scanning.
- Issue workflow and ticketing beyond the data contracts.
- Runtime threat investigation.
- Automated remediation.
- Mobile, voice, SOC, and general-purpose GRC features.
