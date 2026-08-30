# Self-service Google Cloud connection checkpoint

Date: 2026-08-29
Branch: `main`

## Product boundary

This increment adds only self-service Google Cloud onboarding. GitHub, Slack, Jira, Google
Workspace, customer service-account keys, user OAuth refresh tokens, prompt/response content,
data-plane access, and remediation remain outside the slice.

A healthy Google Cloud connection means the recorded keyless principal could bind every
selected project to its immutable project number and call every declared validation
entrypoint at the recorded time. It is not inventory evidence, complete coverage, a finding,
or a risk verdict.

## Implemented flow

- Connection creation provisions a unique, keyless service account in Denali's configured
  operator project. The customer-visible plan records its email and immutable unique ID.
- Google Cloud Shell uses the customer's existing Google session to enumerate active projects
  and lets the customer select one, several, or all visible projects.
- The reviewable script grants only `roles/cloudasset.viewer` and `roles/logging.viewer` on
  the exact selected projects. Denali receives neither the Google session nor a customer key.
- Customers can inspect/download the exact script or run its short-lived copyable command.
- A one-time completion capability is stored only as a SHA-256 hash, is bound to the unique
  connection principal, expires with the script URL, and is consumed atomically.
- Project ID, name, and immutable project number become the stored coverage boundary. Each
  project and each declared plane validates independently.
- Initial validation retries bounded IAM propagation; later manual validation is a single
  evidence-bearing attempt.

The unique-principal design is deliberate tenant isolation. A shared global principal would
allow a valid setup capability to attempt to claim a known project already accessible to a
different connection. A per-connection identity plus immutable project-number rebinding
prevents that path unless access was independently granted to that exact connection.

## Declared coverage

All selected projects are queried project-wide across all resource locations:

- Vertex AI runtime: endpoints, reasoning engines, and cached content;
- Vertex AI development: models, datasets, pipelines, custom jobs, and notebook runtimes;
- Vertex AI Agent Builder / Discovery Engine: assistants, data stores, and engines;
- Dialogflow: agents, conversation profiles, and knowledge bases; and
- AI management activity through Cloud Logging metadata.

Cloud Logging access does not include a claim that prompts or responses are available. A
successful empty Cloud Asset query proves only the read entrypoint; resource-specific reads
and exact locations remain collection evidence.

## Operator configuration

The API requires:

```bash
DENALI_GCP_OPERATOR_PROJECT_ID=denali-operator-project
DENALI_GCP_ONBOARDING_BUCKET=denali-onboarding-templates
```

The operator identity needs `iam.serviceAccounts.create` in the operator project. The runtime
identity needs Service Account Token Creator on the connection principals, normally through
an operator-project grant. Production should use workload identity or attached credentials;
long-lived JSON keys are not accepted. The script publisher retains the existing private,
encrypted, short-lived S3-compatible artifact contract.

Deleting Denali configuration does not silently delete the Denali-owned service account or
customer-project IAM bindings. The UI surfaces that cleanup boundary and retained evidence.

## Verification performed

- Fast suite: `155 passed, 17 skipped`.
- Explicit PostgreSQL contract suite: `17 passed`.
- Focused Google Cloud suite: `3 passed`.
- Ruff: all checks passed.
- Production web build: passed with Vite.
- Generated Google Cloud setup script: passed `bash -n` syntax validation.
- API and web Docker image builds: passed.
- Existing API, web, and PostgreSQL Compose services remained healthy.
- `git diff --check`: passed.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains.

## Human acceptance completed

The user refreshed both the Google CLI and Application Default Credentials, and
`vertex-api-502308` was selected as the Denali operator project for this local acceptance.
The IAM Service Account Credentials API was already enabled. The signed-in local operator
identity was granted Service Account Token Creator in that operator project so the Denali
runtime could impersonate connection-specific principals without a JSON key.

The browser flow then completed successfully:

1. Denali created a unique keyless connection principal and exposed both its email and
   immutable service-account ID.
2. Cloud Shell enumerated the projects visible to the signed-in user.
3. The user selected exactly three projects: `ciso-copilot-496523`,
   `gen-lang-client-0693606939`, and `gen-lang-client-0374500022`.
4. The completion capability was accepted once and the project IDs were rebound to their
   immutable project numbers.
5. All 15 project/plane validation results passed across all resource locations, producing a
   healthy connection without any customer key or user token entering Denali.

The initial validation remained visibly in its retry state while Google Cloud IAM propagated,
then completed normally. Future UX should show elapsed time and retry context more clearly so
a bounded propagation wait is not mistaken for a frozen request; this does not change the
recorded validation evidence.

## Parked application UX

The user explicitly parked two cross-application issues: typography on newer pages is too
small, and internal navigation does not create browser-history entries, so Back exits the
single-page application. They should be addressed after the provider onboarding sequence,
not lost or silently mixed into this security contract.

## Next bounded slice

Implement GitHub as a GitHub App connection with explicit organization/repository boundaries,
least-privilege permissions, installation identity validation, and the same separation between
access health, collection evidence, findings, and risk conclusions.
