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

## Human acceptance pending

The local Google CLI configuration names `vertex-api-502308`, but its interactive user token
requires reauthentication. The saved Application Default Credentials also lack access to
that project. A browser-based `gcloud auth login` was attempted and returned without an
authorization code; no Google Cloud resource was created.

Live acceptance therefore needs a human to authenticate an identity that can create service
accounts in the selected Denali operator project, configure the two environment values above,
and run the UI flow against one or more customer test projects. Human review should confirm:

1. each new connection shows a different Denali service-account email;
2. Cloud Shell enumerates visible projects and grants only the two displayed roles;
3. the pasted completion code records only the selected projects;
4. validation binds immutable project numbers and shows independent partial failures; and
5. no key, Google session, prompt, response, or false zero-risk claim appears.

## Parked application UX

The user explicitly parked two cross-application issues: typography on newer pages is too
small, and internal navigation does not create browser-history entries, so Back exits the
single-page application. They should be addressed after the provider onboarding sequence,
not lost or silently mixed into this security contract.

## Next bounded slice

Complete the live Google Cloud acceptance above. Only after it passes, implement GitHub as a
GitHub App connection with explicit organization/repository boundaries, least-privilege
permissions, installation identity validation, and the same separation between access health,
collection evidence, findings, and risk conclusions.
