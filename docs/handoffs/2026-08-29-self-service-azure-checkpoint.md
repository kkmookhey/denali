# Denali self-service Azure checkpoint

Date: 2026-08-29
Branch: `main`
Base product commit: `63ab3a9`

## Product boundary

Denali remains an evidence-first AI security platform. An Azure connection records setup,
access, and validation state; it is not inventory evidence or a risk verdict. A healthy
connection means only that the configured application identity bound to the expected tenant,
the selected subscriptions were reachable, and the declared validation entrypoints worked at
the recorded time.

This slice adds Microsoft Azure only. GCP, GitHub, Slack, Jira, and Entra/Graph directory
collection were not added. The onboarding grant is Azure Resource Manager `Reader` at only
the subscriptions selected by the customer. It grants no remediation, data-plane access,
secret retrieval, prompt access, response access, or Microsoft Graph directory access.

## Customer model and decision

The normal customer path is one Entra tenant with one or more Azure subscriptions. Azure
Lighthouse is not the default: it is useful when a managed-service relationship must span
customer tenants, but it adds unnecessary machinery to the ordinary single-tenant flow.

Denali instead uses an operator-owned multitenant Entra application. The customer:

1. grants tenant consent to create the Denali enterprise application in their tenant;
2. opens Azure Cloud Shell from Denali;
3. runs a reviewable setup script that verifies the exact tenant, enumerates enabled
   subscriptions, and lets them select one, several, or all;
4. assigns the built-in `Reader` role to the tenant-local Denali service principal at only
   those subscription scopes; and
5. pastes a one-time completion code into Denali.

The completion code avoids requiring a public callback during local development. It is
short-lived, stored by Denali only as a SHA-256 hash, and consumed atomically. The final
connection configuration retains the selected subscription identifiers/names and the
tenant-local service-principal object ID, but not the raw code.

## Checkpointed capabilities

- Provider-neutral connection APIs and persistence now support both AWS and Azure without
  weakening the existing AWS contract.
- Azure create/list/detail/validate/disable/delete behavior, with normal responses exposing
  no client secret or setup token.
- Provider-native setup controls in the Connections UI: **Authorize Denali**, **Open Azure
  Cloud Shell**, a copyable command, and **Download setup script** for inspection/manual use.
- A private, short-lived setup-script publisher with exact version and SHA-256 launch
  metadata. The primary command downloads the script to a file before execution rather than
  using an opaque `curl | bash` pipeline.
- Exact-tenant verification in Cloud Shell and during Denali validation.
- Customer-controlled subscription enumeration and selection. Denali does not assume a
  default subscription or silently expand to every subscription.
- Five validation planes per selected subscription: Azure AI services accounts, Azure AI
  Search, Azure Machine Learning workspaces, Azure Bot Services, and Azure management
  activity.
- Independent subscription/plane results. Partial, failed, unsupported, and unknown coverage
  remain visible rather than being interpreted as no resources or no risk.
- All-location validation for every selected subscription. The setup location of any Denali
  infrastructure does not narrow collection to one Azure Region.

The detailed contract and evidence limits are in
[`docs/architecture/0019-self-service-azure-connections.md`](../architecture/0019-self-service-azure-connections.md).

## Verification performed

All repository checks were rerun against the complete worktree:

- Fast suite: `152 passed, 16 skipped`.
- Explicit PostgreSQL contract suite: `16 passed`.
- Ruff: all checks passed.
- Production web build: passed with Vite.
- Generated Azure setup script: passed `bash -n` syntax validation.
- API and web Docker image builds: passed.
- API, web, and PostgreSQL Compose services: healthy.
- `git diff --check`: passed.
- Filename/content scan found no cloud credential, client secret, private key, presigned URL,
  raw completion token, or environment file in the worktree.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains. The in-app browser
runtime was unavailable during this checkpoint, so the new Azure screens still require a
human browser pass.

## Live Azure context and human acceptance needed

The locally signed-in test tenant is `017c6f31-f951-4bda-a50a-c168c0e6f815`. It currently
reports two enabled subscriptions:

- `Azure subscription 1` (`cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5`)
- `Azure CIS Agent Testing` (`8cd2b4cc-c789-466d-a8f7-8f51fb20985d`)

These are identifiers, not credentials. After explicit human authorization, the live
acceptance prerequisite was created:

- App registration: `Denali Security Audit`
- Application/client ID: `37735ceb-483b-4a43-a084-1989ed720de5`
- Home-tenant application object ID: `f054accc-7c49-4d7c-b3f5-6f234bd84cab`
- Home-tenant service-principal object ID: `72bd7ece-a047-4489-ba3b-014b862c703c`
- Audience: `AzureADMultipleOrgs`
- Registered redirect: `http://127.0.0.1:3080`
- Required Microsoft Graph/API permissions: none

The local acceptance credential expires `2026-11-27` and is stored only in the macOS
Keychain entry with service `denali-azure-client-secret` and account `denali-local`. Its
value was never printed, documented, or committed. Client-credential token issuance was
verified, and all four Azure runtime settings are active in the healthy local API container.

The pre-existing `Transilience Managed Compliance` registration was deliberately not
reused. It is single-tenant, has four Microsoft Graph application permissions
(`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, and
`RoleManagement.Read.Directory`), and already has Reader plus Security Reader assignments
on the Azure CIS test subscription. Reusing or converting it would couple credential
lifecycle and cause Denali consent to exceed this slice's no-Graph evidence boundary.

The live acceptance pass must:

1. verify the revised consent-return success/failure notice in a connected browser;
2. validate an intentionally unselected-subscription path;
3. visually verify partial coverage, disable, and delete safeguards; and
4. remove test role assignments and the customer enterprise application if the acceptance
   environment should not retain them.

The first live connection is `4f0600b2-78ef-4bd6-bf62-6fb67d81ddbd` (`Test Azure`). The
customer flow successfully selected both test subscriptions and assigned Reader to the
Denali service principal at each exact subscription scope. The immediate validation reached
both subscriptions but recorded six `AccessDenied` plane results. Direct diagnostics with
the same application token subsequently returned HTTP 200 for all eight Resource Graph
queries, and **Validate again** produced a healthy result with all ten declared checks
passing. This was Azure RBAC propagation, not missing permissions.

The product now treats those two observed UX issues explicitly:

- the Entra redirect selects the connection and displays a clear success/failure notice,
  while explaining that consent and subscription RBAC are separate; and
- initial setup completion retries partial Azure coverage during the bounded onboarding
  window, persists only the final attempt, and still records independent failures if the
  window expires.

## Local runtime

The existing ignored `.env` remains invalid dotenv syntax and was neither printed nor
rewritten. AWS-backed local services continue to run with:

```bash
docker compose --env-file /dev/null \
  -f compose.yaml \
  -f /tmp/denali-demo-admin-sales.override.yaml \
  up -d --no-build
```

Local endpoints:

- Web: <http://127.0.0.1:3080>
- API: <http://127.0.0.1:8088>
- PostgreSQL: `127.0.0.1:55450`

Azure setup is configured in the current API container. Recreating that container without
supplying the four `DENALI_AZURE_*` values will clear them; retrieve the secret from the
macOS Keychain rather than copying it into the repository or the invalid `.env` file.

## Known limits

- The operator app registration and client-secret lifecycle are deployment responsibilities;
  this repository does not provision or persist that secret.
- The setup-script publisher currently uses the same S3-compatible private artifact pattern
  as AWS onboarding. A production deployment must configure the bucket and lifecycle policy.
- Setup completion is one-time and atomic, but it is not a durable background job. Validation
  still runs in the API process.
- `Reader` proves management-plane reachability only. Resource-specific collection can still
  expose narrower API availability or authorization limits, which must remain visible.
- Azure role assignments live in Azure. Disabling or deleting a Denali connection does not
  silently remove customer-side grants; the UI warns about that lifecycle boundary.
- Prompt and response contents remain outside this connection and evidence model. Any future
  content-aware runtime plane requires an explicit opt-in, separate permissions, redaction,
  retention, encryption, and evidence semantics.
- There is no automated browser regression suite.

## Recommended next slice

Perform the live Azure acceptance pass before expanding provider scope. Once accepted, use
the same provider-native pattern for GCP: console-native launch as the primary path, a
downloadable/reviewable setup artifact as the secondary path, customer selection of exact
projects, and independent project/location validation. GitHub should follow as its own
bounded slice using a GitHub App rather than copying Shasta's local personal-access-token
development path.

## Resume checklist

1. Read this checkpoint and ADR 0019; do not reconstruct the Azure design from prior chat.
2. Verify `git status --short --branch` is clean and start at or after the commit containing
   this handoff.
3. Do not create an Entra app registration, enterprise application, credential, or Azure role
   assignment without explicit authorization.
4. Keep customer subscription choice explicit and preserve selected/unselected coverage.
5. Run Ruff, the fast suite, the PostgreSQL contract gate, and the web production build
   before checkpointing further persistence/API work.
6. Preserve the distinction between connection health, collection coverage, observations,
   findings, detections, and risk verdicts.
