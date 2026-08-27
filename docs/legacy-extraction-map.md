# Previous-work extraction map

Nothing is copied merely because it exists. Each component must preserve provenance,
pass its existing relevant tests, and conform to Denali's standalone contracts.

## Import early

| Previous component | Denali destination | Treatment |
| --- | --- | --- |
| `detectors/` | native repository connector | Adapt emissions to canonical assertions; retain detector tests |
| `ingest/run.py` | repository connector registry | Keep deterministic ordering and partial-failure semantics |
| MCP discovery/observation | native MCP connector | Preserve declared/observed delta, tool pins, and rug-pull behavior |
| Evidence helpers | domain/evidence | Preserve source locators and minimal evidence packets |
| Capability traversal | issue/graph core | Retain bounded traversal; generalize storage interface |
| Entity/edge reconciliation | Postgres inventory store | Preserve per-source scope and fail-closed withdrawal |
| Bedrock envelope and mapping | native AWS connector | Remove Prowler carrier shapes; retain boundary validation |
| AI framework mappings | compliance rule packs | Separate control claims from Prowler's file format |

## Import as optional integrations

| Previous component | Treatment |
| --- | --- |
| Prowler resource client | Prowler inventory adapter |
| Prowler check package | Optional outbound integration |
| Prowler Neo4j projection/query | Optional Prowler relationship provider after live proof |
| Prowler compliance JSON | Generated adapter output, not source of truth |

## Reuse as design reference, not architecture

- Shasta AI Inventory and AI Summary flows.
- Shasta evidence, framework, and asset-detail presentation.
- Selected generic React components that are not tied to Cognito, Clerk, AWS onboarding,
  or Shasta's API shapes.

## Archive

- Shasta cloud scanners duplicated by CSPMs.
- Shasta CDK, Cognito, Aurora, ECR, and SaaS deployment.
- SOC, iOS, voice, and broad CNAPP work.
- Prowler UI patches and brand patches.
- Snowflake posture as a Denali core feature.
- Documentation that defines the product as an AI layer over Prowler.

