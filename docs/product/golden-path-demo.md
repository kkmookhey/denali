# Code-to-cloud Golden Path demo

## The story

The local demo tenant intentionally contains two applications and no generic fixture corpus:

1. **Anna on AWS** — private GitHub source at immutable commit
   `19b38c952c81658d37863e368a7f70f9819ed567`, an independently observed Lambda and ECS
   worker in AWS account `331145994818` / `ap-south-1`, exact Lambda-to-repository proof,
   and six real source/AWS posture findings.
2. **Summit on Google Cloud** — public GitHub source at immutable commit
   `dacc2bbf9497612d31757ae8dfbdb4697eaa7563`, a private scale-to-zero Cloud Run service in
   project `vertex-api-502308` / `us-central1`, an exact service-to-repository proof, a
   least-privilege runtime service account, and a successful bounded Gemini 2.5 Flash call.

The dashboard's **Golden Path** panel is the starting point. Each card links to the full
source-to-runtime proof. The most useful demo sequence is:

1. Show the two Golden Path application cards on **Overview**.
2. Open **Code to cloud** and explain the exact immutable-source → declaration → runtime
   chain for Anna, then Summit.
3. Open Anna's two repository findings and four AWS stack findings. Explain that findings
   are evaluated conditions, while a `deployed_by` edge is lineage—not a vulnerability or
   issue by itself.
4. Open **Sources** or **Connections** to show the exact two-repository, one AWS Region, and
   one GCP project/resource boundaries.
5. Finish with the evidence boundary: three AI workloads, two repositories, two proven
   deployment links, six findings, and no fixture, vulnerability, or fabricated runtime
   records.

## Deterministic boundary

[`golden-paths/code-to-cloud.yaml`](../../golden-paths/code-to-cloud.yaml) is the versioned
acceptance contract. It preserves exactly three provider connections, names the two accepted
repositories and three accepted AI workloads, requires both proven deployment edges, rejects
fixture/scanner connector families, and caps every high-level row count.

Preview a local reset before changing anything:

```bash
denali-golden-path reset \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN"
```

Applying the reset requires the exact tenant UUID twice. It deletes only tenant-scoped Denali
data and disallowed Denali connection records; it never deletes GitHub repositories or cloud
resources:

```bash
denali-golden-path reset \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN" \
  --tenant-id 00000000-0000-4000-8000-000000000001 \
  --apply \
  --confirm-tenant 00000000-0000-4000-8000-000000000001
```

After revalidation and collection, enforce the acceptance contract:

```bash
denali-golden-path verify \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN"
```

## Collection order

The order matters because source correlation consumes independently observed deployment
targets:

1. Validate the GitHub, AWS, and GCP connections.
2. Collect AWS and GCP deployments.
3. Collect the `NiSalesAgentStack` topology and posture.
4. Collect GitHub source last; this performs repository inventory, posture, and exact
   code-to-cloud correlation against the already-observed targets.
5. Collect bounded runtime metadata, evaluate issues/detections, then run manifest
   verification.

The GCP connection includes an exact Cloud Asset resource-name selector for Summit. This
keeps the project boundary auditable without importing an older test service that also exists
in the project. Vertex AI audit collection currently completes with zero events because Data
Access audit logging is not enabled for the project. The UI must present that as no observed
runtime telemetry; it must not substitute fixture activity.

## Teardown

The Summit Cloud Run service is private, scales to zero, and is capped at one instance. Its
runtime identity has only `roles/aiplatform.user`. Exact cloud teardown commands and the
pinned image digest remain in the Summit repository. The Golden Path reset itself is local
and does not perform cloud teardown.
