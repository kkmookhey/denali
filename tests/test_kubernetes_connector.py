import json
from pathlib import Path

import pytest

from denali.connectors.code_to_cloud import (
    CodeToCloudConnector,
    DeploymentTarget,
    _deployment_declarations,
)
from denali.connectors.kubernetes import (
    KubernetesSnapshotConnector,
    kubernetes_cluster_identity,
)
from denali.domain import AssetKind, CoverageState, DeploymentIdentity, RelationshipKind

DIGEST = "a" * 64
AWS_CLUSTER_KEY = "arn:aws:eks:us-east-1:123456789012:cluster/denali-models"


def _snapshot(*, image: str | None = None) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "model-api",
                    "namespace": "ai-prod",
                    "uid": "a4aa7a7a-74e1-4d88-a4ac-ae1a3bafaf20",
                    "resourceVersion": "9182",
                    "generation": 4,
                    "labels": {"denali.ai/workload": "true"},
                    "annotations": {"deployment.kubernetes.io/revision": "7"},
                },
                "spec": {
                    "template": {
                        "spec": {
                            "serviceAccountName": "model-runtime",
                            "containers": [
                                {
                                    "name": "api",
                                    "image": image or f"registry.example/model@sha256:{DIGEST}",
                                    "env": [
                                        {"name": "MODEL_ID", "value": "secret-model-value"},
                                        {"name": "API_TOKEN", "value": "do-not-retain"},
                                    ],
                                }
                            ],
                        }
                    }
                },
            }
        ],
    }


def _aws_identity() -> DeploymentIdentity:
    return kubernetes_cluster_identity(
        "aws",
        account_id="123456789012",
        region="us-east-1",
        cluster_name="denali-models",
    )


def test_snapshot_emits_exact_workload_identity_without_environment_values() -> None:
    batch = KubernetesSnapshotConnector(
        cluster_identity=_aws_identity(),
        cluster_natural_key=AWS_CLUSTER_KEY,
        snapshot=_snapshot(),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    workload = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD)
    assert workload.attributes["deployment_identifiers"] == {
        "account_id": ["123456789012"],
        "region": ["us-east-1"],
        "cluster_name": ["denali-models"],
        "namespace": ["ai-prod"],
        "workload_kind": ["deployment"],
        "workload_name": ["model-api"],
        "workload_uid": ["a4aa7a7a-74e1-4d88-a4ac-ae1a3bafaf20"],
        "workload_revision": ["7"],
        "service_account": ["model-runtime"],
        "image_digest": [f"sha256:{DIGEST}"],
    }
    assert workload.attributes["model_configuration_keys"] == ["MODEL_ID"]
    retained = json.dumps(dict(workload.evidence.payload))
    assert "secret-model-value" not in retained
    assert "do-not-retain" not in retained
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.HOSTED_ON,
        RelationshipKind.RUNS_AS,
    }


def test_unpinned_runtime_image_is_visible_but_not_digest_correlatable() -> None:
    batch = KubernetesSnapshotConnector(
        cluster_identity=_aws_identity(),
        cluster_natural_key=AWS_CLUSTER_KEY,
        snapshot=_snapshot(image="registry.example/model:latest"),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    workload = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD)
    assert "image_digest" not in workload.attributes["deployment_identifiers"]
    assert "without sha256 digests" in batch.coverage[0].detail


@pytest.mark.parametrize(
    ("provider", "kwargs", "expected"),
    [
        (
            "gcp",
            {"project": "denali-prod", "location": "us-central1"},
            {"project": ("denali-prod",), "location": ("us-central1",)},
        ),
        (
            "azure",
            {
                "subscription_id": "12345678-1234-4234-9234-123456789abc",
                "resource_group": "AI-Prod",
                "location": "West US 2",
            },
            {
                "subscription_id": ("12345678-1234-4234-9234-123456789abc",),
                "resource_group": ("ai-prod",),
                "location": ("westus2",),
            },
        ),
    ],
)
def test_provider_cluster_identities_are_exact(provider, kwargs, expected) -> None:
    identity = kubernetes_cluster_identity(provider, cluster_name="model-cluster", **kwargs)

    assert identity.runtime_kind == "kubernetes_cluster"
    for name, value in expected.items():
        assert identity.values(name) == value


def test_cluster_natural_key_cannot_escape_declared_scope() -> None:
    with pytest.raises(ValueError, match="does not match"):
        KubernetesSnapshotConnector(
            cluster_identity=_aws_identity(),
            cluster_natural_key=(
                "arn:aws:eks:us-east-1:999999999999:cluster/denali-models"
            ),
            snapshot=_snapshot(),
        )


def _manifest(provider_annotations: str, *, image: str | None = None) -> str:
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: model-api
  namespace: ai-prod
  annotations:
    denali.ai/workload: "true"
{provider_annotations}
spec:
  template:
    spec:
      serviceAccountName: model-runtime
      containers:
        - name: api
          image: {image or f'registry.example/model@sha256:{DIGEST}'}
"""


def test_manifest_and_runtime_snapshot_create_deterministic_edge(tmp_path: Path) -> None:
    manifest = _manifest(
        """    denali.ai/provider: aws
    denali.ai/account-id: "123456789012"
    denali.ai/region: us-east-1
    denali.ai/cluster-name: denali-models"""
    )
    (tmp_path / "deployment.yaml").write_text(manifest)
    workload = next(
        item
        for item in KubernetesSnapshotConnector(
            cluster_identity=_aws_identity(),
            cluster_natural_key=AWS_CLUSTER_KEY,
            snapshot=_snapshot(),
        ).collect().assets
        if item.asset.kind is AssetKind.AI_WORKLOAD
    )
    target = DeploymentTarget(
        natural_key=workload.asset.natural_key,
        display_name=workload.display_name,
        service="kubernetes",
        identity=DeploymentIdentity.from_record(
            {
                "provider": workload.attributes["provider"],
                "runtime_kind": workload.attributes["runtime_kind"],
                "identifiers": [
                    {"name": name, "value": value}
                    for name, values in workload.attributes["deployment_identifiers"].items()
                    for value in values
                ],
            }
        ),
        evidence_locator=workload.evidence.locator,
        evidence_payload=dict(workload.evidence.payload),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/model-api",
        targets=(target,),
    ).collect()

    assert len(batch.relationships) == 1
    relationship = batch.relationships[0]
    assert relationship.kind is RelationshipKind.DEPLOYED_BY
    assert relationship.attributes["correlation"] == "deterministic"
    assert relationship.attributes["deployment_framework"] == "kubernetes_manifest"
    assert relationship.attributes["provider"] == "aws"


def test_manifest_requires_a_pinned_image_and_exact_cloud_boundary() -> None:
    unpinned = _manifest(
        """    denali.ai/provider: gcp
    denali.ai/project-id: denali-prod
    denali.ai/location: us-central1
    denali.ai/cluster-name: model-cluster""",
        image="registry.example/model:latest",
    )
    missing_boundary = _manifest("    denali.ai/provider: azure")

    declarations, warnings = _deployment_declarations(unpinned, "k8s/deployment.yaml")
    missing, missing_warnings = _deployment_declarations(
        missing_boundary, "k8s/missing.yaml"
    )

    assert declarations == []
    assert missing == []
    assert "pinned by a sha256 digest" in warnings[0]
    assert "cluster-name must be a literal string" in missing_warnings[0]


@pytest.mark.parametrize(
    ("annotations", "provider", "identifier", "value"),
    [
        (
            """    denali.ai/provider: gcp
    denali.ai/project-id: denali-prod
    denali.ai/location: us-central1
    denali.ai/cluster-name: model-cluster""",
            "gcp",
            "project",
            "denali-prod",
        ),
        (
            """    denali.ai/provider: azure
    denali.ai/subscription-id: 12345678-1234-4234-9234-123456789abc
    denali.ai/resource-group: AI-Prod
    denali.ai/location: West US 2
    denali.ai/cluster-name: Model-Cluster""",
            "azure",
            "resource_group",
            "ai-prod",
        ),
    ],
)
def test_gke_and_aks_manifests_share_exact_workload_contract(
    annotations, provider, identifier, value
) -> None:
    declarations, warnings = _deployment_declarations(
        _manifest(annotations), "k8s/deployment.yaml"
    )

    assert warnings == []
    assert len(declarations) == 1
    declaration = declarations[0]
    assert declaration.identity.provider == provider
    assert declaration.identity.runtime_kind == "kubernetes_workload"
    assert declaration.identity.values(identifier) == (value,)
    assert declaration.identity.values("namespace") == ("ai-prod",)
    assert declaration.identity.values("image_digest") == (f"sha256:{DIGEST}",)
