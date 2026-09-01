# Shared Kubernetes code-to-cloud live acceptance — 2026-08-31

## Result

The shared Kubernetes workload correlation slice passed live acceptance through a temporary
Amazon EKS 1.35 control plane in the Shasta scanner AWS account. The fixture used no node
group, Fargate profile, running pod, load balancer, persistent volume, or image pull. A
zero-replica Deployment still supplied genuine Kubernetes API identity while bounding cost
to the short-lived EKS control plane.

AWS and Kubernetes observations were collected independently. One exact source declaration
created one persisted `DEPLOYED_BY` edge. An unmatched declaration remained visible without
an edge. A synthetic duplicate of the exact live target exercised the ambiguity guard and
created no edge.

## Accepted boundary

| Field | Value |
| --- | --- |
| AWS account | `470226123496` |
| Local AWS profile mapping | `default` mapped to IAM user `shasta-scanner` |
| Region | `us-east-1` |
| EKS cluster | `denali-k8s-acceptance-20260831` |
| Cluster ARN | `arn:aws:eks:us-east-1:470226123496:cluster/denali-k8s-acceptance-20260831` |
| Kubernetes version | `1.35` |
| Namespace | `denali-acceptance` |
| Workload | `Deployment/model-api` with zero replicas |
| Workload UID | `8a6e20e9-f259-4029-be5d-32f6fcb5493e` |
| Workload revision | `1` |
| Service account | `model-runtime` |
| Image digest | `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |

The EKS cluster carried `denali_ai_workload=true`, `Project=denali-fixture`, and a bounded
acceptance-purpose tag. The Kubernetes Deployment used the separate
`denali.ai/workload=true` opt-in label and source annotation.

## Independent observation evidence

The AWS control-plane collector completed both EKS planes:

- `aws_eks_deployment_inventory=complete`;
- `aws_eks_deployment_relationships=complete`.

It observed the exact cluster ARN and classified the explicitly tagged cluster as an AI
workload. Its bounded Region collection ingested 69 assertions across all supported AWS
deployment services and two relationships; these counts describe the account snapshot, not
69 Kubernetes fixture resources.

The Kubernetes API snapshot completed both workload planes:

- `kubernetes_workload_inventory=complete`;
- `kubernetes_workload_relationships=complete`.

It ingested three assertions: the observed cloud resource, the AI workload, and its service
account identity. It created exactly one `HOSTED_ON` and one `RUNS_AS` relationship. The
workload evidence retained the exact account, Region, cluster, namespace, kind, name, UID,
revision, service account, and image digest.

## Correlation and negative cases

The bounded source fixture contained two opt-in Kubernetes declarations and evaluated one
independently observed live workload target:

| Disposition | Count | Edge created |
| --- | ---: | --- |
| Proven | 1 | Yes, one `DEPLOYED_BY` edge |
| Unmatched | 1 | No |
| Ambiguous | 0 | No |

The proven declaration matched the exact AWS account, Region, cluster name, namespace,
Deployment kind, workload name, service account, and image digest. The second declaration
used a different workload name and remained an observable unmatched candidate.

For the ambiguity guard, the harness supplied a synthetic second target with the same exact
identity as the live target but a distinct natural key. The result was one ambiguous and one
unmatched declaration, zero proven declarations, and zero relationships. The synthetic
target was used only in memory and was not persisted as provider evidence.

## Persistence and minimization evidence

PostgreSQL retained exactly one deployment for the live workload/repository pair and one
latest correlation observation. The served API returned:

- provider `aws`;
- runtime kind `kubernetes_workload`;
- deployment framework `kubernetes_manifest`;
- correlation summary `1 proven / 0 ambiguous / 1 unmatched`.

The live Deployment included a non-secret placeholder environment value so minimization
could be tested. Denali retained the allow-listed environment-variable name used for AI
classification but did not retain its value. No Secret or ConfigMap object was requested.

## Exact teardown

After acceptance:

1. namespace `denali-acceptance` was deleted with all fixture objects;
2. EKS cluster `denali-k8s-acceptance-20260831` reached deleted state;
3. the sole `AmazonEKSClusterPolicy` attachment was removed from
   `DenaliKubernetesAcceptanceClusterRole`;
4. the dedicated IAM role was deleted; and
5. read-only EKS and IAM inventories both returned empty results for those exact names.

No VPC, subnet, node group, Fargate profile, repository, image, load balancer, or persistent
volume was created for this acceptance.

## Scope limit

This pass supplies live evidence for the shared contract through EKS. GKE and AKS workload
identity shapes continue to pass the same automated connector and exact-correlation contract,
but this record does not claim separate live GKE or AKS workload deployments.
