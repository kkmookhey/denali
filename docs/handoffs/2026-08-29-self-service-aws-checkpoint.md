# Denali self-service AWS checkpoint

Date: 2026-08-29
Branch: `main`
Base checkpoint commit: `3a99a8c`

## Product boundary

Denali remains a standalone, evidence-first AI security platform. A provider connection
is configuration and access state, not inventory evidence or a risk verdict. Connection
health means only that the exact configured role, account binding, Region discovery, and
declared validation calls worked at the recorded time.

The completed slice is AWS only. GCP, Azure/Entra, GitHub, Slack, and Jira were not added.
The AWS role grants bounded read-only control-plane access and explicitly grants no
remediation, workload invocation, task execution, role passing, secret retrieval, prompt
access, or response access.

## Checkpointed capabilities

- Provider-neutral connection persistence with lifecycle, credential reference, declared
  scopes, coverage plan, configuration, validation history, and health state.
- AWS connection create/list/detail/validate/disable/delete APIs. Normal API responses
  never return the generated external ID or AWS credentials.
- Safe deletion: a connection must be disabled first and the user must type its exact
  display name. Deleting configuration retains previously collected evidence.
- A first-class Connections UI with setup progress, permission review, validation state,
  Region coverage, compact plane summaries, and raw plane/Region results on demand.
- Generated CloudFormation that creates one `DenaliSecurityAuditRole`, trusts the configured
  Denali principal with a per-connection external ID, and creates no access keys.
- CloudFormation Quick Create as the primary onboarding path. Denali publishes the exact
  per-connection template under an unguessable private S3 key, returns a partition-correct
  AWS console link, prefills the stack name and Denali principal, and retains manual
  template download as a fallback.
- Launch metadata stores the template version, exact SHA-256, intended principal, and
  publication/expiration times. It never stores the S3 key, presigned URL, or external ID.
- Quick Create starts a bounded background validation job. Credential failures are retried
  for at most 15 minutes without persisting intermediate failures; the first credential
  success continues through the complete normal validation plan.
- Automatic Region coverage is the default. Every validation calls `ec2:DescribeRegions`
  and evaluates every enabled or opted-in Region. Selected-region mode is an explicit
  restriction and keeps excluded enabled Regions visible.
- Eight regional validation planes cover Bedrock Agents Classic agents and guardrails;
  AgentCore runtimes, gateways, workload identities, and memories; CloudTrail management
  activity; and Bedrock invocation-logging configuration. Results remain independent.
- Validation uses isolated AWS SDK sessions, bounded SDK timeouts/retries, and an eight-
  worker pool. Unsupported service/Region combinations are visible as `not_applicable`,
  never converted into empty inventory evidence.

The accepted contract and evidence limits are in
[`docs/architecture/0018-self-service-aws-connections.md`](../architecture/0018-self-service-aws-connections.md).

## Verification performed

All checks were rerun against the complete worktree before checkpointing:

- Fast suite: `150 passed, 15 skipped`.
- Explicit PostgreSQL contract suite: `15 passed`.
- Ruff: all checks passed.
- Production web build: passed with Vite.
- `git diff --check`: passed.
- API, web, and PostgreSQL Compose services: healthy.
- Filename/content review: no environment file, AWS credential, external ID, presigned URL,
  or live template object key entered the commit.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains.

## Live AWS acceptance result

The acceptance account is `331145994818`, accessed locally with the
`demo-admin-sales` profile. The local Denali runtime principal is
`arn:aws:iam::331145994818:user/sara-sales`. These identifiers are setup context, not
credentials; no access keys or session tokens are recorded here.

- Connection: `3db77d26-a1ab-4148-9171-d93f75557ba7` (`Sara Sales`).
- Observed account binding: `331145994818`.
- Health: `healthy`; credential state: `passed`.
- Enabled Regions discovered: 17.
- Validation results: 137 total, comprising 132 passed and 5 visible
  `not_applicable` service/Region checks.
- Summary: credentials validated and every applicable plane passed across all 17 enabled
  Regions.
- Working customer stack: `Denali` in `ap-south-1`, `CREATE_COMPLETE`.
- Working IAM role: `arn:aws:iam::331145994818:role/DenaliSecurityAuditRole`.
- Onboarding bucket: `denali-onboarding-331145994818-us-east-1` with S3 Block Public Access,
  SSE-S3 encryption, and a one-day expiration rule for `denali/onboarding/aws/`.
- Live Quick Create smoke test fetched the presigned template, matched its recorded SHA-256,
  omitted the external ID from the launch response, and returned the connection to healthy.
- Human review confirmed that **Launch in AWS** opened the native AWS creation experience
  and that keeping **Download template** as a secondary path is preferable.

The human test submitted a second stack, `Denali-3db77d26` in `us-east-1`, while the
working global IAM role already existed. AWS created no resources and rolled the test stack
back. The empty `ROLLBACK_COMPLETE` stack was verified to contain zero resources and was
deleted during checkpoint cleanup. The working `Denali` stack, IAM role, connection, and
onboarding bucket remain intact.

## Local runtime

The ignored `.env` is still not valid dotenv syntax. Do not print or rewrite it during
unrelated work. Use the secret-free Compose invocation:

```bash
docker compose --env-file /dev/null \
  -f compose.yaml \
  -f /tmp/denali-demo-admin-sales.override.yaml \
  up -d --build
```

The temporary override mounts `/Users/kkmookhey/.aws` read-only into the API container and
sets `AWS_PROFILE=demo-admin-sales`, `AWS_SDK_LOAD_CONFIG=1`, the onboarding bucket, and the
runtime principal ARN. It contains identifiers and paths but no AWS access keys. Because it
lives under `/tmp`, recreate it from this description after a reboot rather than copying
credentials into the repository.

Local endpoints remain:

- Web: <http://127.0.0.1:3080>
- API: <http://127.0.0.1:8088>
- PostgreSQL: `127.0.0.1:55450`

## Known limits

- Background validation and its duplicate-run lock are in-process. A production deployment
  with restarts or multiple API replicas needs a durable job/lease mechanism.
- Denali requires an operator-provisioned private S3 onboarding bucket and configured AWS
  runtime principal. Manual template download remains available when Quick Create is not
  configured.
- A named `DenaliSecurityAuditRole` supports one active Denali onboarding role per AWS
  account. A second stack using the same role name fails rather than taking ownership of an
  existing role.
- Validation proves the declared read-only entrypoints were callable. Resource-specific
  reads are exercised during collection only when matching resources exist.
- The AgentCore service/Region applicability catalog is point-in-time guidance. Live
  success always overrides the catalog; failed probes outside documented support remain
  `not_applicable` rather than permission conclusions.
- There is no automated browser regression suite. API, TypeScript, production-build, live
  S3, and human browser checks cover this slice.
- Prompt and response contents remain outside the current AWS role and evidence model.

## Recommended next decision

Before adding another provider, decide the prompt/response telemetry policy raised during
this slice. Runtime security may require prompt-aware signals, but raw content collection
must be an explicit tenant choice with separate permissions, redaction, retention,
encryption, and evidence boundaries. Do not silently widen the current read-only metadata
connection or reinterpret invocation-logging configuration as access to prompt content.

After that decision, either implement a bounded opt-in AWS runtime-content plane or begin
the next provider using the same connection contract and provider-native onboarding UX.

## Resume checklist

1. Read this checkpoint and ADR 0018; do not reconstruct the implementation from prior
   conversation memory.
2. Verify `git status --short --branch` is clean and start from the commit containing this
   handoff.
3. Confirm the working `Denali` stack in `ap-south-1` and the onboarding bucket before any
   destructive AWS action.
4. Start Compose with `--env-file /dev/null` and the purpose-built override when live AWS
   validation is needed.
5. Run Ruff, the fast suite, the PostgreSQL contract gate, and the web production build
   before checkpointing persistence/API changes.
6. Preserve the distinction between connection health, collection coverage, findings,
   runtime detections, and risk verdicts.
