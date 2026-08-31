"""Provider-neutral Kubernetes workload snapshot inventory.

The connector consumes a bounded Kubernetes API list export. It never reads Secret or
ConfigMap objects and never retains environment values. Provider cluster scope is explicit,
while workload UID, revision, service account, and digest-pinned images are observed from the
Kubernetes control-plane response.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    DeploymentIdentifier,
    DeploymentIdentity,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.kubernetes"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
INVENTORY_PLANE = "kubernetes_workload_inventory"
RELATIONSHIP_PLANE = "kubernetes_workload_relationships"
MAX_SNAPSHOT_BYTES = 20 * 1024 * 1024
MAX_WORKLOADS = 10_000
SUPPORTED_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
_DIGEST_IMAGE_RE = re.compile(r"^.+@sha256:(?P<digest>[0-9a-fA-F]{64})$")
_MODEL_KEY_RE = re.compile(
    r"^(?:[A-Z][A-Z0-9_]*_)?(?:MODEL_ID|MODEL_NAME|DEPLOYMENT_ID|ENDPOINT_NAME)$"
)
_AWS_CLUSTER_KEY_RE = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):eks:(?P<region>[^:]+):"
    r"(?P<account>[0-9]{12}):cluster/(?P<name>[^/]+)$"
)
_GCP_CLUSTER_KEY_RE = re.compile(
    r"^//container\.googleapis\.com/projects/(?P<project>[^/]+)/locations/"
    r"(?P<location>[^/]+)/clusters/(?P<name>[^/]+)$"
)
_AZURE_CLUSTER_KEY_RE = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourcegroups/(?P<group>[^/]+)/"
    r"providers/microsoft\.containerservice/managedclusters/(?P<name>[^/]+)$"
)


def kubernetes_cluster_identity(
    provider: str,
    *,
    account_id: str | None = None,
    project: str | None = None,
    project_number: str | None = None,
    subscription_id: str | None = None,
    resource_group: str | None = None,
    location: str | None = None,
    region: str | None = None,
    cluster_name: str,
) -> DeploymentIdentity:
    """Build one strict provider cluster boundary for Kubernetes workload inventory."""

    if provider == "aws":
        if not account_id or re.fullmatch(r"[0-9]{12}", account_id) is None or not region:
            raise ValueError("AWS Kubernetes scope requires account_id and region")
        identifiers = (
            DeploymentIdentifier("account_id", account_id, evidence_basis="declared_account_id"),
            DeploymentIdentifier("region", region, evidence_basis="declared_region"),
            DeploymentIdentifier(
                "cluster_name", cluster_name, evidence_basis="declared_cluster_name"
            ),
        )
    elif provider == "gcp":
        if not location or not (project or project_number):
            raise ValueError("GCP Kubernetes scope requires project identity and location")
        project_identifier = (
            DeploymentIdentifier("project", project, evidence_basis="declared_project_id")
            if project
            else DeploymentIdentifier(
                "project_number",
                str(project_number),
                evidence_basis="declared_project_number",
            )
        )
        identifiers = (
            project_identifier,
            DeploymentIdentifier("location", location, evidence_basis="declared_location"),
            DeploymentIdentifier(
                "cluster_name", cluster_name, evidence_basis="declared_cluster_name"
            ),
        )
    elif provider == "azure":
        if not subscription_id or not resource_group or not location:
            raise ValueError(
                "Azure Kubernetes scope requires subscription_id, resource_group, and location"
            )
        identifiers = (
            DeploymentIdentifier(
                "subscription_id",
                subscription_id.lower(),
                evidence_basis="declared_subscription_id",
            ),
            DeploymentIdentifier(
                "resource_group",
                resource_group.lower(),
                evidence_basis="declared_resource_group",
            ),
            DeploymentIdentifier(
                "location",
                location.lower().replace(" ", ""),
                evidence_basis="declared_location",
            ),
            DeploymentIdentifier(
                "cluster_name",
                cluster_name.lower(),
                evidence_basis="declared_cluster_name",
            ),
        )
    else:
        raise ValueError("Kubernetes provider must be aws, gcp, or azure")
    return DeploymentIdentity(provider, "kubernetes_cluster", identifiers)


class KubernetesSnapshotConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        cluster_identity: DeploymentIdentity,
        cluster_natural_key: str,
        snapshot: dict[str, Any],
    ):
        if cluster_identity.runtime_kind != "kubernetes_cluster":
            raise ValueError("cluster identity runtime kind must be kubernetes_cluster")
        if cluster_identity.provider not in {"aws", "gcp", "azure"}:
            raise ValueError("unsupported Kubernetes cloud provider")
        if not cluster_natural_key:
            raise ValueError("cluster natural key is required")
        _validate_cluster_natural_key(cluster_identity, cluster_natural_key)
        self.cluster_identity = cluster_identity
        self.cluster_natural_key = cluster_natural_key
        self.snapshot = snapshot

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        provider = self.cluster_identity.provider
        cluster_name = self.cluster_identity.values("cluster_name")[0]
        scope = f"kubernetes:{provider}:{self.cluster_natural_key}"
        connection = connection_id or scope
        warnings: list[str] = []
        items = self.snapshot.get("items")
        if self.snapshot.get("kind") not in {"List", None} or not isinstance(items, list):
            return _failed_batch(connection, scope, observed_at, "invalid Kubernetes List shape")
        if len(items) > MAX_WORKLOADS:
            return _failed_batch(
                connection,
                scope,
                observed_at,
                f"workload limit {MAX_WORKLOADS} exceeded",
            )

        assets: dict[tuple[AssetRef, str], AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion
        ] = {}
        ai_count = 0
        for position, item in enumerate(items):
            if not isinstance(item, dict) or item.get("kind") not in SUPPORTED_KINDS:
                continue
            try:
                parsed = _parse_workload(item)
            except ValueError as error:
                warnings.append(f"item {position}: {error}")
                continue
            cloud, workload, identity = self._assertions(parsed, observed_at)
            assets[(cloud.asset, INVENTORY_PLANE)] = cloud
            if workload is None:
                continue
            ai_count += 1
            assets[(workload.asset, INVENTORY_PLANE)] = workload
            cluster_ref = AssetRef(AssetKind.CLOUD_RESOURCE, self.cluster_natural_key)
            _relationship(
                relationships,
                workload.asset,
                cluster_ref,
                RelationshipKind.HOSTED_ON,
                workload.evidence,
            )
            if identity is not None:
                assets[(identity.asset, INVENTORY_PLANE)] = identity
                _relationship(
                    relationships,
                    workload.asset,
                    identity.asset,
                    RelationshipKind.RUNS_AS,
                    workload.evidence,
                )
            if parsed["unpinned_images"]:
                warnings.append(
                    f"{parsed['namespace']}/{parsed['kind']}/{parsed['name']}: "
                    "AI workload has image references without sha256 digests"
                )

        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(
            [
                f"Observed {len(items)} Kubernetes objects in {cluster_name}; "
                f"classified {ai_count} as AI workloads.",
                *warnings[:10],
            ]
        )
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"kubernetes-{provider}-{cluster_name}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(INVENTORY_PLANE, state, scope, detail),
                Coverage(RELATIONSHIP_PLANE, state, scope, detail),
            ),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _assertions(
        self, parsed: dict[str, Any], observed_at: datetime
    ) -> tuple[AssetAssertion, AssetAssertion | None, AssetAssertion | None]:
        provider = self.cluster_identity.provider
        uid = parsed["uid"]
        natural_key = f"kubernetes:{provider}:{self.cluster_natural_key}:{uid}"
        cloud_ref = AssetRef(AssetKind.CLOUD_RESOURCE, natural_key)
        evidence_payload = {
            "cluster_identity": self.cluster_identity.to_record(),
            "cluster_natural_key": self.cluster_natural_key,
            "namespace": parsed["namespace"],
            "kind": parsed["kind"],
            "name": parsed["name"],
            "workload_uid": uid,
            "workload_revision": parsed["revision"],
            "resource_version": parsed["resource_version"],
            "service_account": parsed["service_account"],
            "image_digests": parsed["image_digests"],
            "model_configuration_keys": parsed["model_keys"],
            "ai_classification": parsed["classification"],
        }
        evidence = Evidence(
            "kubernetes_api",
            (
                f"kubernetes://{provider}/{self.cluster_natural_key}/"
                f"{parsed['namespace']}/{parsed['kind'].lower()}/{parsed['name']}"
            ),
            observed_at,
            evidence_payload,
        )
        shared = {
            "provider": provider,
            "service": "kubernetes",
            "runtime_kind": "kubernetes_workload",
            "cluster_identity": self.cluster_identity.to_record(),
            "cluster_natural_key": self.cluster_natural_key,
            "namespace": parsed["namespace"],
            "workload_kind": parsed["kind"].lower(),
            "workload_name": parsed["name"],
            "workload_uid": uid,
            "workload_revision": parsed["revision"],
            "resource_version": parsed["resource_version"],
            "service_account": parsed["service_account"],
            "images": parsed["images"],
            "image_digests": parsed["image_digests"],
            "ai_classification": parsed["classification"],
            "model_configuration_keys": parsed["model_keys"],
        }
        cloud = AssetAssertion(
            cloud_ref,
            INVENTORY_PLANE,
            f"{parsed['namespace']}/{parsed['name']}",
            AssertionType.OBSERVED,
            1.0,
            evidence,
            shared,
        )
        if not parsed["classification"]:
            return cloud, None, None
        identifiers = {
            item.name: list(self.cluster_identity.values(item.name))
            for item in self.cluster_identity.identifiers
        }
        identifiers.update(
            {
                "namespace": [parsed["namespace"]],
                "workload_kind": [parsed["kind"].lower()],
                "workload_name": [parsed["name"]],
                "workload_uid": [uid],
                "workload_revision": [parsed["revision"]],
                "service_account": [parsed["service_account"]],
            }
        )
        if parsed["image_digests"]:
            identifiers["image_digest"] = parsed["image_digests"]
        workload = AssetAssertion(
            AssetRef(AssetKind.AI_WORKLOAD, natural_key),
            INVENTORY_PLANE,
            f"{parsed['namespace']}/{parsed['name']}",
            AssertionType.OBSERVED,
            1.0,
            evidence,
            {
                **shared,
                "deployment_identifiers": identifiers,
                "source_revision_status": "unattested",
            },
        )
        identity_key = (
            f"kubernetes:{provider}:{self.cluster_natural_key}:serviceaccount:"
            f"{parsed['namespace']}:{parsed['service_account']}"
        )
        identity = AssetAssertion(
            AssetRef(AssetKind.IDENTITY, identity_key),
            INVENTORY_PLANE,
            f"{parsed['namespace']}/{parsed['service_account']}",
            AssertionType.OBSERVED,
            1.0,
            evidence,
            {
                "provider": provider,
                "identity_type": "kubernetes_service_account",
                "cluster_natural_key": self.cluster_natural_key,
                "namespace": parsed["namespace"],
                "service_account": parsed["service_account"],
            },
        )
        return cloud, workload, identity


def _parse_workload(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("metadata is missing")
    name = _required_text(metadata.get("name"), "metadata.name")
    namespace = _required_text(metadata.get("namespace") or "default", "metadata.namespace")
    uid = _required_text(metadata.get("uid"), "metadata.uid")
    resource_version = _required_text(
        metadata.get("resourceVersion"), "metadata.resourceVersion"
    )
    kind = str(item["kind"])
    pod_spec = _pod_spec(item)
    service_account = _required_text(
        pod_spec.get("serviceAccountName") or "default", "serviceAccountName"
    )
    containers = [
        item
        for field in ("initContainers", "containers")
        for item in pod_spec.get(field, [])
        if isinstance(item, dict)
    ]
    if not containers:
        raise ValueError("pod template has no containers")
    images = sorted(
        {str(container["image"]) for container in containers if container.get("image")}
    )
    if not images:
        raise ValueError("pod template has no image references")
    image_digests = sorted(
        {
            f"sha256:{match.group('digest').lower()}"
            for image in images
            if (match := _DIGEST_IMAGE_RE.fullmatch(image))
        }
    )
    unpinned_images = sorted(image for image in images if not _DIGEST_IMAGE_RE.fullmatch(image))
    model_keys = sorted(
        {
            str(variable.get("name"))
            for container in containers
            for variable in container.get("env", [])
            if isinstance(variable, dict)
            and isinstance(variable.get("name"), str)
            and _MODEL_KEY_RE.fullmatch(str(variable["name"]))
        }
    )
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    annotations = (
        metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    )
    classification: list[str] = []
    if str(labels.get("denali.ai/workload", "")).lower() == "true" or str(
        annotations.get("denali.ai/workload", "")
    ).lower() == "true":
        classification.append("explicit_ai_workload_label")
    if model_keys:
        classification.append("model_configuration_key")
    revision = str(
        annotations.get("deployment.kubernetes.io/revision")
        or metadata.get("generation")
        or resource_version
    )
    return {
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "uid": uid,
        "resource_version": resource_version,
        "revision": revision,
        "service_account": service_account,
        "images": images,
        "image_digests": image_digests,
        "unpinned_images": unpinned_images,
        "model_keys": model_keys,
        "classification": classification,
    }


def _validate_cluster_natural_key(
    identity: DeploymentIdentity, natural_key: str
) -> None:
    provider = identity.provider
    expected_name = identity.values("cluster_name")[0]
    if provider == "aws":
        match = _AWS_CLUSTER_KEY_RE.fullmatch(natural_key)
        if (
            match is None
            or match.group("account") not in identity.values("account_id")
            or match.group("region") not in identity.values("region")
            or match.group("name") != expected_name
        ):
            raise ValueError("EKS cluster natural key does not match the declared scope")
        return
    if provider == "gcp":
        match = _GCP_CLUSTER_KEY_RE.fullmatch(natural_key)
        projects = {*identity.values("project"), *identity.values("project_number")}
        if (
            match is None
            or match.group("project") not in projects
            or match.group("location") not in identity.values("location")
            or match.group("name") != expected_name
        ):
            raise ValueError("GKE cluster natural key does not match the declared scope")
        return
    normalized = natural_key.lower()
    match = _AZURE_CLUSTER_KEY_RE.fullmatch(normalized)
    if (
        match is None
        or match.group("subscription") not in identity.values("subscription_id")
        or match.group("group") not in identity.values("resource_group")
        or match.group("name") != expected_name
    ):
        raise ValueError("AKS cluster natural key does not match the declared scope")


def _pod_spec(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("spec is missing")
    if item["kind"] == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
        template = job_spec.get("template") if isinstance(job_spec, dict) else None
    else:
        template = spec.get("template")
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        raise ValueError("pod template spec is missing")
    return pod_spec


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is missing")
    return value


def _relationship(
    relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
    source: AssetRef,
    target: AssetRef,
    kind: RelationshipKind,
    evidence: Evidence,
) -> None:
    relationships[(source, target, kind)] = RelationshipAssertion(
        source,
        target,
        RELATIONSHIP_PLANE,
        kind,
        AssertionType.OBSERVED,
        1.0,
        evidence,
    )


def _failed_batch(
    connection: str, scope: str, observed_at: datetime, detail: str
) -> InventoryBatch:
    return InventoryBatch(
        CONNECTOR_ID,
        connection,
        f"kubernetes-failed-{observed_at.isoformat()}",
        scope,
        observed_at,
        (
            Coverage(INVENTORY_PLANE, CoverageState.FAILED, scope, detail),
            Coverage(RELATIONSHIP_PLANE, CoverageState.FAILED, scope, detail),
        ),
    )


def _cluster_identity_from_args(args: argparse.Namespace) -> DeploymentIdentity:
    return kubernetes_cluster_identity(
        args.provider,
        account_id=args.account_id,
        project=args.project,
        project_number=args.project_number,
        subscription_id=args.subscription_id,
        resource_group=args.resource_group,
        location=args.location,
        region=args.region,
        cluster_name=args.cluster_name,
    )


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import a bounded Kubernetes workload export")
    parser.add_argument("snapshot", help="Kubernetes List JSON path, or - for stdin")
    parser.add_argument("--provider", choices=("aws", "gcp", "azure"), required=True)
    parser.add_argument("--cluster-name", required=True)
    parser.add_argument("--cluster-natural-key", required=True)
    parser.add_argument("--account-id")
    parser.add_argument("--project")
    parser.add_argument("--project-number")
    parser.add_argument("--subscription-id")
    parser.add_argument("--resource-group")
    parser.add_argument("--location")
    parser.add_argument("--region")
    parser.add_argument("--connection-id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        parser.error("--dsn or DENALI_DSN is required")
    try:
        if args.snapshot == "-":
            raw_snapshot = sys.stdin.buffer.read(MAX_SNAPSHOT_BYTES + 1)
        else:
            snapshot_path = Path(args.snapshot)
            if snapshot_path.stat().st_size > MAX_SNAPSHOT_BYTES:
                parser.error(f"snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
            raw_snapshot = snapshot_path.read_bytes()
        if len(raw_snapshot) > MAX_SNAPSHOT_BYTES:
            parser.error(f"snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
        snapshot = json.loads(raw_snapshot)
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"snapshot could not be read: {error.__class__.__name__}")
    if not isinstance(snapshot, dict):
        parser.error("snapshot root must be an object")
    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    batch = KubernetesSnapshotConnector(
        cluster_identity=_cluster_identity_from_args(args),
        cluster_natural_key=args.cluster_natural_key,
        snapshot=snapshot,
    ).collect(connection_id=args.connection_id)
    print(json.dumps(repository.ingest(args.tenant_id, batch), indent=2, default=str))


if __name__ == "__main__":
    import_main()
