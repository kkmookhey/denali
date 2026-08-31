# Code-to-cloud roadmap

## Goal

Build evidence-led source-to-runtime correlation across AWS, Google Cloud, Azure, and
Kubernetes without treating similar names, tags, or model identifiers as deployment proof.
Every provider slice must retain independent control-plane observation, immutable source
context, exact identity requirements, and visible proven, ambiguous, and unmatched outcomes.

## Sequential delivery plan

1. **Provider-neutral deployment identity layer — complete.** Extract shared provider,
   runtime-kind, scoped identifier, comparison, evidence, and disposition contracts. Adapt
   the existing AWS CDK Lambda/ECS implementation without weakening or changing its accepted
   joins.
2. **Google Cloud Run and Cloud Functions Gen2 — complete.** Bounded independent workload
   inventory, Terraform and deployment-YAML declarations, and exact project/location/resource,
   image, revision, and service-account evidence are implemented. A private, scale-to-zero
   Vertex AI fixture passed the live control-plane correlation acceptance on 2026-08-31; see
   [the acceptance record](gcp-code-to-cloud-live-acceptance-2026-08-31.md).
3. **Azure Container Apps and Azure Functions.** Add bounded independent workload inventory,
   Terraform/Bicep/ARM declarations, and exact subscription/resource-group/resource/revision,
   image, and managed-identity evidence. Validate with a small AI-powered test deployment.
4. **Broaden AWS coverage.** Add Terraform and SAM declarations, followed by EKS and SageMaker,
   while keeping each service behind its own explicit identifier and coverage contract.
5. **Shared Kubernetes correlation.** Correlate EKS, AKS, and GKE workloads through one
   Kubernetes identity layer using exact cluster, namespace, workload UID, revision, service
   account, and image-digest evidence.

## Acceptance rules for every step

- A runtime target is eligible only when independently and actively observed.
- Provider and runtime kind must agree before identifiers are evaluated.
- All required scoped identifiers must match using their declared exact or prefix semantics.
- Ambiguous or unmatched candidates remain observable and never create a deployment edge.
- Artifact identity and source-revision attestation remain separate claims.
- Provider test deployments must be minimal, tagged for Denali validation, cost-bounded, and
  accompanied by an explicit teardown path.
