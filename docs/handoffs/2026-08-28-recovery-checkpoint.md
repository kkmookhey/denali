# Denali recovery checkpoint

Date: 2026-08-28
Branch: `main`
Recovered product commit: `2d875e8`

## Product direction

Denali is a standalone, open-source, evidence-first AI security platform. It is not
a Prowler extension or a general CSPM. Prowler is a featured open-source input and
showcase integration; Denali's canonical inventory, evidence, correlations, runtime
activity, detections, and user experience remain provider-neutral.

The product must preserve these boundaries:

- Observations, evaluated findings, detections, and correlated issues are different
  claims and remain separately represented.
- Every material claim retains its source, evidence locator, observation time,
  assertion class, confidence, and collection coverage.
- Missing, partial, failed, unsupported, and unknown coverage must stay visible and
  must never be presented as zero risk.
- Correlation requires deterministic identifiers or an explicitly described,
  bounded inference. Similar names alone do not prove identity or deployment.
- Remediation execution belongs to El Capitan. Denali provides investigation context
  and remediation guidance but does not duplicate the remediation control plane.

## Checkpointed capabilities

The recovered product increment includes:

- Canonical, evidence-bearing AI inventory and relationship assertions.
- Custom AWS AI workload discovery and AWS configuration posture checks.
- Repository inventory and repository-native AI posture findings.
- Deterministic code-to-cloud lineage, static artifact inclusion, deployment artifact
  provenance, and workload-level vulnerability correlation.
- SBOM-first software component inventory with Syft and scanner-neutral vulnerability
  ingestion with Grype.
- Provider-neutral runtime activity ingestion and retained activity evidence.
- Live AWS Bedrock activity ingestion from CloudTrail event history.
- Vertex AI activity ingestion contract and fixture path; live Google validation is
  intentionally parked pending account recovery.
- Microsoft Entra AI application inventory, delegated permission context, sign-in
  activity, configuration actors, and Shadow AI coverage.
- Evidence-led runtime detections and runtime evidence links into correlated issues.
- Product views for the evidence brief, inventory, Shadow AI, code-to-cloud, posture,
  vulnerabilities, issues and paths, runtime activity, detections, and source coverage.

## Verification performed

All checks were rerun against the recovered worktree before it was committed:

- PostgreSQL-backed full suite: `154 passed`.
- Fast suite without the PostgreSQL gate: `140 passed, 14 skipped`.
- Ruff: all checks passed.
- Production web build: passed with Vite.
- `git diff --check`: passed.
- Staged filename and content review: no environment file or live credential entered
  the commit.

One non-blocking Starlette `TestClient` deprecation warning remains in the test run.

## Environment context

- Anna's test AWS environment is available through the locally authenticated
  `sara-sales-agent` profile.
- The corporate Microsoft Entra tenant is a test source for live application,
  permission, sign-in, and directory-audit validation.
- Google Workspace and Vertex live validation are parked until the corporate Google
  account is recovered.
- Credentials are local secrets and must never be copied into documentation, fixtures,
  logs, commits, screenshots, or handoff material.

The ignored local `.env` file is currently not valid dotenv syntax, so plain
`docker compose` attempts to parse it and fail before Compose starts. Do not print or
rewrite that file during unrelated work. For secret-free local verification, Compose
can be invoked with `--env-file /dev/null`; use a purpose-built valid environment file
when a connector genuinely needs credentials.

## Known limits

- Self-service connection onboarding has not been implemented.
- Google live runtime collection has not yet been verified end to end.
- The frontend has a successful production build but no browser regression suite yet.
- Runtime observations are not security verdicts; detection rules must continue to
  state their thresholds, evidence inputs, and claim limits.
- The existing running local Compose services predated this checkpoint and were left
  running.

## Next product slice

Build self-service connections as a small, tested vertical slice rather than a broad
integration rewrite:

1. Add a provider-neutral connection model with explicit lifecycle, credential
   reference, declared scopes, coverage plans, last validation, and health state.
2. Add connection list/detail/create/validate API contracts without returning secrets.
3. Add a first-class Connections UI with setup progress, permissions, coverage,
   validation results, and delete/disable safeguards.
4. Implement AWS first, producing a downloadable CloudFormation onboarding plan and a
   deterministic post-deployment validation flow.
5. Extend the same contract to GCP, Azure/Entra, GitHub, Slack, and Jira. Reuse useful
   Shasta onboarding concepts selectively; do not transplant Shasta's product shell.

AWS is the first acceptance path because it can be validated against Anna's live test
environment. A connection is not "healthy" merely because credentials authenticate:
declared collection planes must be checked and incomplete coverage must be surfaced.

## Resume checklist

1. Start from `main` at or after product commit `2d875e8` and this handoff commit.
2. Confirm `git status --short --branch` is clean before making changes.
3. Read architecture decisions `0006` through `0017` and this handoff; do not reconstruct
   the long prior conversation.
4. Run the fast backend suite, Ruff, and the web production build before the next slice.
5. Use the PostgreSQL-backed suite before checkpointing any persistence/API work.
6. Keep the first self-service milestone limited to the connection contract and AWS
   onboarding path, then request a human browser pass.
