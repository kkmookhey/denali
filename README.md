# Denali

Denali is an independent, open-source AI security platform.

Its job is to discover AI systems, explain what they can do, show the evidence behind
every claim, and correlate AI posture with identity, cloud, code, data, vulnerability,
and runtime context.

Denali integrates with CSPMs; it is not an extension of one. Prowler is the first
reference CSPM integration. OCSF is the interchange format for findings and activity,
while Denali owns a richer canonical model for durable inventory and relationships.

## Product sequence

1. **Inventory** — agents, models, MCP servers, tools, guardrails, pipelines, data,
   workloads, repositories, and identities.
2. **Findings** — atomic configuration, model, code, identity, and vulnerability facts.
3. **Issues** — correlated, evidence-bearing attack paths.
4. **Threats** — observed runtime behavior and investigations.

The first public milestone is **Denali Inventory Preview**. Its definition is in
[`docs/product/inventory-preview.md`](docs/product/inventory-preview.md).
The configuration-findings slice is defined in
[`docs/product/configuration-findings-preview.md`](docs/product/configuration-findings-preview.md).
The first deterministic correlation slice is defined in
[`docs/product/issues-preview.md`](docs/product/issues-preview.md).

## Repository status

This repository is intentionally new. Proven first-party components will be imported
from the CISOBrief history only after they conform to Denali's standalone contracts.
Shasta infrastructure and Prowler UI patches will not be carried forward.

The foundation currently contains canonical inventory, finding, software-component, and
vulnerability contracts; a Postgres assertion store; read/write inventory APIs;
read-only finding and vulnerability APIs; and independent web experiences for inventory,
AI configuration findings, and evidence-bearing issues. A transparent demo connector
provides fixture data for local product development; every fixture assertion and finding
is visibly identified as such in its evidence.

## Development

Requires Python 3.11 or newer and Docker for the runnable stack.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[api,aws,azure,dev]'
docker compose up -d --build
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali denali-demo-seed
```

The Denali web application is then available at <http://127.0.0.1:3080>. The API
remains available at <http://127.0.0.1:8088>, with interactive documentation at
<http://127.0.0.1:8088/docs>. The local stack deliberately uses ports `3080`, `8088`,
and `55450` to avoid colliding with the earlier CISOBrief development environment.

### Self-service AWS connection

Open **Connections**, select **Add AWS connection**, and declare the account and collection
planes Denali should validate. Automatic coverage discovers every enabled or opted-in AWS
Region on each validation and is the default. Selected-region coverage is available as an
explicit restriction and reports enabled Regions outside the declared scope. The
CloudFormation stack location is separate from inventory coverage: it only determines
where the onboarding stack is managed. When one-click launch is configured, **Launch in
AWS** publishes the exact per-connection template through a private, short-lived S3 URL
and opens AWS CloudFormation Quick Create with the stack name and Denali principal already
filled in. The customer still reviews the template, acknowledges IAM role creation, and
creates the stack. **Download template** remains available for restricted environments and
local installations. The stack creates one read-only assume role with an external-ID trust
condition; it creates no access keys and grants no remediation permissions.

Configure Quick Create on the Denali API with:

```bash
export DENALI_AWS_ONBOARDING_BUCKET=denali-onboarding-templates
export DENALI_AWS_PRINCIPAL_ARN=arn:aws:iam::123456789012:role/DenaliRuntime
```

The API principal needs `s3:PutObject` and `s3:GetObject` only for
`denali/onboarding/aws/*` in that bucket. Keep S3 Block Public Access enabled, enable
default bucket encryption, and add a lifecycle rule that deletes objects under that prefix
after one day. Presigned reads expire after one hour by default and may be shortened with
`DENALI_AWS_ONBOARDING_URL_SECONDS` (300–3600 seconds). The exact template version, SHA-256,
intended principal, and publication times are recorded on the connection; Denali does not
retain the S3 object key, presigned URL, or external ID in launch metadata.

Launching starts a bounded background check that waits up to 15 minutes for the role to
become assumable, then performs normal validation. Manual downloads use **Validate
connection** after deployment. Denali first verifies role assumption and exact account
binding, discovers the account's enabled Regions, then tests every declared plane in every
in-scope Region.
Successful authentication with a denied or unavailable plane is shown as partial coverage,
not healthy. Connection health is access validation only: it is not proof that collection
ran, that no findings exist, or that the account is safe.
Validation continues in the background while the Connections page polls for the completed
result, so broad multi-Region coverage is not constrained by an HTTP proxy timeout.

Connections must be disabled before deletion, and deletion requires the exact display
name. Deleting connection configuration retains evidence already collected through that
connection. The contract and its evidence boundary are documented in
[`docs/architecture/0018-self-service-aws-connections.md`](docs/architecture/0018-self-service-aws-connections.md).

### Self-service Azure connection

Azure uses Denali's multi-tenant Entra application plus ordinary Azure RBAC, not a customer
secret and not Azure Lighthouse. Open **Connections**, select **Microsoft Azure**, and enter
the customer tenant ID. **Prepare Azure setup** provides two views of the same exact artifact:
a command to run from Azure Cloud Shell and a script download for inspection/manual execution.
The script enumerates enabled subscriptions in that tenant, lets the customer select one,
several, or all, and assigns Azure Reader only at those selected subscription scopes. It then
prints a one-time completion code to paste back into Denali.

Configure the Denali API with its multi-tenant application and private script publisher:

```bash
export DENALI_AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
export DENALI_AZURE_CLIENT_SECRET='operator-managed-denali-app-secret'
export DENALI_AZURE_CONSENT_REDIRECT_URI=http://127.0.0.1:3080
export DENALI_AZURE_ONBOARDING_BUCKET=denali-onboarding-templates
```

The application registration must support accounts in any organizational directory and the
redirect URI must be registered exactly. Prefer a certificate or workload-federated runtime
credential in production; the client secret above belongs to Denali's infrastructure and is
never supplied by a customer or returned by the API. The script publisher needs only the same
private, encrypted, short-lived object controls described for AWS, under
`denali/onboarding/azure/*`.

Azure validation binds every selected subscription to the declared customer tenant, then
tests five independent Azure AI/control-plane entrypoints. Resource Graph coverage is
subscription-wide and therefore includes every Azure resource location; no preferred Region
limits visibility. Reader grants no remediation or Azure data-plane role. Microsoft Graph,
Entra sign-ins and applications, prompts, responses, and secrets remain outside this Azure
connection. See
[`docs/architecture/0019-self-service-azure-connections.md`](docs/architecture/0019-self-service-azure-connections.md).

Scan a source repository into Denali with the first-party repository connector:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-repo-scan /path/to/repository --app-id your-application
```

The connector discovers AI frameworks, model-provider references, MCP servers, and MCP
tools in Python, TypeScript, and JavaScript without executing repository code. It
excludes tests, fixtures, generated or
vendored directories, and symlinked source files. Evidence snippets are secret-redacted;
read or parse failures mark coverage partial so an incomplete scan cannot withdraw
previously observed assets.

Observe a running MCP Streamable HTTP server without invoking any tools:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-mcp-observe https://mcp.example.com/mcp --app-id your-application
```

For authenticated servers, place the bearer token in `DENALI_MCP_BEARER_TOKEN`; Denali
never accepts it as a command-line value or writes it to evidence. The observer performs
MCP initialization and paginated `tools/list` only. Cleartext HTTP is restricted to
loopback hosts unless explicitly overridden.

Discover current AWS AgentCore inventory using the normal AWS credential chain or a
named profile:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-agentcore-scan --regions us-east-1,us-west-2 --profile security-audit
```

AgentCore is Denali's primary AWS agent path. The connector inventories runtimes,
runtime endpoints, gateways, gateway targets, workload identities, execution roles, and
memories. Independent coverage planes prevent a failed target, endpoint, identity, or
memory API from shrinking unrelated inventory. It reads control-plane metadata only;
`GetMemory` always uses `without_decryption`. Environment names and values, source
artifacts, JWT details, request-header names, target schemas and credentials, memory
descriptions, namespace templates, and SDK exception text are never persisted.

Grant the scanning principal `bedrock-agentcore:ListAgentRuntimes`,
`bedrock-agentcore:GetAgentRuntime`, `bedrock-agentcore:ListAgentRuntimeEndpoints`,
`bedrock-agentcore:ListGateways`, `bedrock-agentcore:GetGateway`,
`bedrock-agentcore:ListGatewayTargets`, `bedrock-agentcore:GetGatewayTarget`,
`bedrock-agentcore:ListWorkloadIdentities`, `bedrock-agentcore:ListMemories`, and
`bedrock-agentcore:GetMemory` in every scanned region. The CLI also calls
`sts:GetCallerIdentity` to bind observations to the authenticated account.

Existing Amazon Bedrock Agents estates—now named Agents Classic by AWS—remain supported
through the separate Classic connector:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-aws-scan --regions us-east-1,us-west-2 --profile security-audit
```

The Classic connector uses read-only `ListAgents`, `GetAgent`, `ListGuardrails`, and
`GetGuardrail` calls. It discovers agents, their referenced foundation models, execution
roles, guardrails, and the evidence-backed relationships between them. Each region and
API family has an independent coverage boundary, so a failed guardrail read cannot erase
agents and a partial scan cannot withdraw prior inventory. For both AWS connectors,
"complete" means complete within the AWS principal's visibility; Denali cannot prove
that an IAM policy did not filter resources outside that visibility. Grant
`bedrock:ListAgents`, `bedrock:GetAgent`, `bedrock:ListGuardrails`, and
`bedrock:GetGuardrail` in every region you intend to scan with the Classic connector.

Raw agent instructions, guardrail blocked messages, topic names, and regex patterns are
not persisted. Denali stores configuration presence, normalized policy types and counts,
and an instruction hash and length so posture can be evaluated without copying sensitive
prompt content.

Discover a custom Lambda/ECS AI application inside one explicit CloudFormation stack:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-aws-stack-scan \
  --stack-name NiSalesAgentStack \
  --app-id anna-sales-agent \
  --display-name Anna \
  --region ap-south-1 \
  --profile security-audit
```

This connector covers custom applications that invoke Bedrock directly and therefore do
not appear in the managed Bedrock Agents or AgentCore APIs. It inventories only Lambda
functions and ECS task definitions with allow-listed `*_MODEL_ID` configuration, their
model identifiers, and their execution roles. It reads CloudFormation resource metadata,
Lambda configuration, and ECS task definitions; it never invokes a workload, downloads
code, reads secret values, or retains arbitrary environment variables. Grant only
`sts:GetCallerIdentity`, `cloudformation:ListStackResources`, `cloudformation:GetTemplate`,
`lambda:GetFunctionConfiguration`, and `ecs:DescribeTaskDefinition` for the bounded stack
and compute resources. A denied detail read makes coverage partial and cannot withdraw
previous inventory.

Evaluate evidence-backed configuration controls for the same custom AI stack:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-aws-stack-posture \
  --stack-name NiSalesAgentStack \
  --region ap-south-1 \
  --profile security-audit
```

The first posture slice evaluates only controls that AWS APIs can prove: effective
inline and attached role policies for Bedrock model-family wildcards, Bedrock model
invocation logging configuration, and retention on existing CloudWatch log groups for
model-backed Lambda and ECS workloads. It does not invoke models, read logs, retrieve
secrets, download code, or infer a failure from a denied API call. A complete scan is
authoritative for this stack and resolves a prior finding when its failed condition is
absent; a partial or failed scan cannot resolve anything.

In addition to the inventory permissions above, grant
`iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`,
`iam:GetPolicy`, `iam:GetPolicyVersion`,
`bedrock:GetModelInvocationLoggingConfiguration`, and `logs:DescribeLogGroups`.
The accepted control and evidence boundaries are documented in
[`docs/architecture/0008-custom-aws-ai-posture.md`](docs/architecture/0008-custom-aws-ai-posture.md).

Evaluate supported Bedrock Runtime call sites without executing repository code:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-repository-posture /path/to/repository
```

The initial TypeScript/JavaScript repository-posture check inspects literal AWS SDK
command inputs and reports when they do not request an AWS managed guardrail. Dynamic
objects and spreads are marked partial rather than treated as proof of absence. Evidence
contains property names and source locations only—not code snippets, prompts, payload
values, or secrets. See
[`docs/architecture/0009-repository-ai-posture.md`](docs/architecture/0009-repository-ai-posture.md).

Correlate those source-controlled deployment declarations with independently observed
Lambda and ECS AI workloads:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-code-to-cloud /path/to/repository \
  --name github.com/your-org/your-ai-application
```

Run the AWS stack inventory connector first. The code-to-cloud connector creates a
`DEPLOYED_BY` edge only when a literal IaC deployment identifier and an observed
CloudFormation logical ID agree. A shared model name or display name never creates a
link. Ambiguous matches remain partial and create no edge. For supported CDK/esbuild
artifacts, Denali then traces literal local-module imports from the declared bundle entry
and separates findings included in that artifact from repository-only context. Inclusion
does not claim that runtime execution reached the call. When an exact live S3 asset key or
container image tag also appears in a local CDK asset manifest, Denali reports the artifact
identity match separately. It does not convert that match into a Git-revision claim: absent
independently verifiable revision metadata in the deployed artifact, the revision remains
`unattested` (and a dirty checkout is always analysis context only). The trust boundaries are
documented in
[`docs/architecture/0010-evidence-led-code-to-cloud.md`](docs/architecture/0010-evidence-led-code-to-cloud.md)
and
[`docs/architecture/0011-static-artifact-inclusion.md`](docs/architecture/0011-static-artifact-inclusion.md),
and
[`docs/architecture/0012-deployment-artifact-provenance.md`](docs/architecture/0012-deployment-artifact-provenance.md).

Import findings from a Prowler JSON-OCSF report—or another producer that emits an OCSF
Findings class—with:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-ocsf-import ./output/prowler-output.ocsf.json \
  --connection-id prowler-production-aws
```

The importer deliberately does not turn an OCSF resource reference into a Denali asset
or graph edge. It stores a finding, normalized affected-resource references, compliance
mappings, and an evidence hash. Arbitrary `resources.data` content is never persisted;
Prowler reports can contain sensitive configuration values in that field. Imports are
additive by default. Pass `--authoritative` only for a complete, unfiltered report when
absence should resolve findings from the same connection and scope. A partial or failed
import can never resolve findings by absence.

The read API exposes `/v1/findings`, `/v1/findings/summary`, and
`/v1/findings/{finding_id}`. The independent Denali web application provides severity
and state filtering plus evidence, affected-resource, compliance, remediation, and
observation-history views. Run `denali-demo-seed` for three clearly labelled fixture
findings, or import a real OCSF report to replace the demonstration data.

Denali's vulnerability model is SBOM-first and scanner-neutral. Software components are
durable inventory assets; vulnerabilities are deduplicated conditions with independent
source observations. The API exposes `/v1/vulnerabilities`,
`/v1/vulnerabilities/summary`, and `/v1/vulnerabilities/{id}`. Syft plus Grype is the
native pipeline, while Trivy and Prowler remain first-class sources. The accepted design
and trust boundaries are documented in
[`docs/architecture/0006-sbom-first-vulnerability-model.md`](docs/architecture/0006-sbom-first-vulnerability-model.md).

Generate the SBOM and vulnerability report with pinned scanner versions, then import
both reports against the same explicit Denali target:

```bash
syft registry.example/agent@sha256:... -o json=agent.syft.json
grype registry.example/agent@sha256:... -o json > agent.grype.json

DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-syft-import agent.syft.json \
  --target-kind ai_workload --target-key registry.example/agent@sha256:... \
  --target-name agent-runtime

DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-grype-import agent.grype.json \
  --target-kind ai_workload --target-key registry.example/agent@sha256:...
```

The explicit target kind and key are a trust boundary: neither importer guesses durable
asset identity from a scanner filename, image tag, or display name. Syft and Grype use
the same target-and-package component identity, allowing vulnerability evidence to
correlate with the retained SBOM. Scanner-reported filesystem locations are retained as
evidence and do not multiply an installed package into separate components. Their native
JSON metadata can contain manifests,
configuration, package scripts, and secrets; Denali retains only bounded package,
match, database, and provenance fields. Grype match confidence is visibly derived by
Denali from the match type, and exploit status remains `unknown` until an explicit KEV
or exploit-intelligence source supplies that evidence.

Grype imports are additive by default. Use `--authoritative` only for a complete,
unfiltered scan when absence should resolve prior observations for the same target and
connection. Use `--partial` for truncated or otherwise incomplete scanner output; a
partial or failed import can never resolve by absence.

The Grype report's native source identity is stored separately from the explicit target.
Code to cloud shows vulnerability results on a workload only when that scanner-reported
artifact exactly matches the workload's currently observed image locator or digest. A
mismatch is shown as refused correlation, and an unscanned workload is shown as not
evaluated—neither state is rendered as zero vulnerabilities. A complete matched scan reports
both vulnerable package occurrences and distinct vulnerability IDs; multiple packages or
targets affected by one vulnerability can make the former larger than the latter. The complete
correlation contract is
documented in
[`docs/architecture/0013-artifact-vulnerability-correlation.md`](docs/architecture/0013-artifact-vulnerability-correlation.md).

Evaluate deterministic issues after collecting inventory and findings with:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-evaluate-issues
```

The initial rule requires two atomic security signals and three independently observed
or externally verified capability edges before it creates an issue. Missing, inferred,
or ambiguous edges produce an unknown evaluation state rather than a reachability claim.
The local `denali-demo-seed` command evaluates issues automatically.

Run the fast suite and the explicit Postgres contract gate with:

```bash
pytest
DENALI_TEST_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  pytest -q tests/test_inventory_postgres.py
```

The fast suite skips rather than disguises the Postgres integration tests when
`DENALI_TEST_DSN` is absent.

## Runtime activity imports

Denali can ingest bounded exports from four AI runtime sources without treating an
event as a detection or security issue:

- AWS Bedrock CloudTrail events
- Google Cloud Vertex AI audit-log entries
- Google Workspace Gemini audit activity
- Microsoft Entra AI-application sign-ins

Import a JSON document with the provider-neutral activity importer:

```bash
denali-activity-import activity.json \
  --format aws-bedrock-cloudtrail \
  --connection-id aws:123456789012 \
  --scope-key aws:123456789012:us-east-1 \
  --dsn postgresql://denali:denali-local@127.0.0.1:55450/denali
```

The accepted format names are `aws-bedrock-cloudtrail`, `gcp-vertex-audit`,
`google-workspace-gemini`, and `entra-ai-signin`. Imports preserve bounded raw evidence,
actor and session context, outcome, and collection coverage. Entity references link to
inventory only when an exact independently collected identifier already exists; an
activity event never creates an asset or a graph edge.

For live AWS accounts, Denali can collect Bedrock model-invocation metadata from the
account's regional CloudTrail Event History. This does not require a configured trail,
does not enable Bedrock model-invocation logging, and does not collect prompt or response
content:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-aws-runtime --profile my-read-only-profile --region ap-south-1 \
  --lookback-hours 24
```

The live connector declares coverage only for the Bedrock management operations it
queries: `Converse`, `ConverseStream`, `InvokeModel`, and
`InvokeModelWithResponseStream`. Bedrock Agent Runtime and other data events require a
separate data-event source and are never implied by this collection.

Vertex AI activity can be collected with Google Application Default Credentials:

```bash
gcloud auth application-default login
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-gcp-vertex-runtime --project-id my-test-project --lookback-hours 24
```

The Vertex connector reads matching Cloud Audit Log entries only. A complete query does
not claim that the project's Data Access logging settings captured every possible
invocation; that source-side boundary remains visible in the coverage detail.

Microsoft Entra enterprise applications, OAuth permission topology, sign-ins, and
application-management changes can be collected directly from Microsoft Graph:

```bash
export DENALI_ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000
export DENALI_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000000
export DENALI_ENTRA_CLIENT_SECRET='replace-me'
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-entra-scan --lookback-hours 168
```

The app registration needs Microsoft Graph application permissions appropriate to the
enabled planes: `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`AuditLog.Read.All`, and `Directory.Read.All`, with tenant admin consent. Each plane
reports coverage independently. A conservative catalog match adds an enterprise app to
the review inventory; it is not a security finding and does not assert how the vendor
uses customer data. Denali retains identifiers, permission topology, outcomes, and
bounded evidence, but not access tokens or sign-in IP addresses.

## Runtime detections

Evaluate deterministic runtime rules after collecting activity and inventory with:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-evaluate-detections
```

The first rules deliberately cover two narrow Entra conditions:

- three or more failed sign-ins by the same exact actor to the same exact AI
  application within a sliding 24-hour window;
- a successful consent or delegated-permission change for an active, unreviewed AI
  application, raised to high severity when the independently collected application
  inventory contains a high-impact delegated scope such as `Mail.ReadWrite`.

Both rules require an exact link to an independently inventoried `ai_application`.
Display-name similarity and unresolved activity references cannot create a detection.
Every detection retains references to the activity observations and asset assertions
that support it, along with the evaluation's coverage state. Re-evaluation is
idempotent. These event-backed detections do not resolve merely because their source
events age outside the query window; resolution requires explicit later lifecycle
evidence or a human decision.

The API exposes `/v1/detections`, `/v1/detections/summary`,
`/v1/detections/evaluations`, and `/v1/detections/{id}`. The web UI keeps these
detections separate from raw runtime activity and from composed graph issues.

The complete evidence and lifecycle contract is documented in
[`docs/architecture/0017-evidence-led-runtime-detections.md`](docs/architecture/0017-evidence-led-runtime-detections.md).

## Principles

- Evidence before inference.
- Deterministic security decisions; AI assists and explains.
- Declared, inferred, observed, and externally verified are different claims.
- Capability is not influence.
- Agent identity is not execution-principal identity.
- A failed or partial collection can never withdraw previously known inventory.
- Unknown coverage is visible; it never renders as zero risk.
- Every integration declares whether it provides findings, inventory, relationships,
  activity, or only a subset.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
