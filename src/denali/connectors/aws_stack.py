"""Stack-scoped discovery for custom AWS-hosted AI systems.

Managed-agent APIs do not describe Lambda and ECS applications that call foundation
models directly. This connector starts from one explicit CloudFormation stack and
classifies only compute resources carrying allow-listed model identifiers. It never
invokes workloads, downloads code, or persists arbitrary environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.aws_stack"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
INVENTORY_PLANE = "aws_stack_ai_inventory"
RELATIONSHIP_PLANE = "aws_stack_ai_relationships"
MAX_PAGES = 100
_MODEL_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*MODEL_ID$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,299}$")


class AwsStackDiscoveryError(RuntimeError):
    """A bounded AWS control-plane read failed."""


class AwsStackConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        stack_name: str,
        app_id: str,
        display_name: str,
        cloudformation_client: Any,
        lambda_client: Any,
        ecs_client: Any,
        partition: str = "aws",
    ) -> None:
        self.account_id = _required("account_id", account_id)
        self.region = _required("region", region)
        self.stack_name = _required("stack_name", stack_name)
        self.app_id = _normalize_app_id(_required("app_id", app_id))
        self.display_name = _required("display_name", display_name)
        self.cloudformation_client = cloudformation_client
        self.lambda_client = lambda_client
        self.ecs_client = ecs_client
        self.partition = _required("partition", partition)

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"aws:{self.account_id}"
        scope = (
            f"aws:{self.account_id}:{self.region}:cloudformation:{self.stack_name}"
        )
        try:
            resources = _stack_resources(self.cloudformation_client, self.stack_name)
        except AwsStackDiscoveryError as error:
            return self._failed_batch(connection, scope, observed_at, str(error))

        warnings: list[str] = []
        try:
            template_resources = _stack_template_resources(
                self.cloudformation_client, self.stack_name
            )
        except AwsStackDiscoveryError as error:
            template_resources = {}
            warnings.append(str(error))

        assets: dict[tuple[AssetRef, str], AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion
        ] = {}
        agent_ref = AssetRef(AssetKind.AI_AGENT, f"app:{self.app_id}:agent")

        for resource in resources:
            resource_type = _string(resource.get("ResourceType"))
            logical_id = _string(resource.get("LogicalResourceId"))
            physical_id = _string(resource.get("PhysicalResourceId"))
            if not logical_id or not physical_id:
                continue
            try:
                if resource_type == "AWS::Lambda::Function":
                    self._collect_lambda(
                        physical_id,
                        logical_id,
                        agent_ref,
                        observed_at,
                        assets,
                        relationships,
                        template_resources.get(logical_id),
                    )
                elif resource_type == "AWS::ECS::TaskDefinition":
                    self._collect_ecs_task(
                        physical_id,
                        logical_id,
                        agent_ref,
                        observed_at,
                        assets,
                        relationships,
                        template_resources.get(logical_id),
                    )
            except AwsStackDiscoveryError as error:
                warnings.append(str(error))

        if any(relationship.source == agent_ref for relationship in relationships.values()):
            evidence = self._evidence(
                observed_at,
                "cloudformation",
                self.stack_name,
                {
                    "stack_name": self.stack_name,
                    "app_id": self.app_id,
                    "classification": "explicit_stack_scope_with_ai_compute",
                },
            )
            assets[(agent_ref, INVENTORY_PLANE)] = AssetAssertion(
                asset=agent_ref,
                coverage_plane=INVENTORY_PLANE,
                display_name=self.display_name,
                assertion_type=AssertionType.INFERRED,
                confidence=0.9,
                evidence=evidence,
                attributes={
                    "provider": "aws",
                    "account_id": self.account_id,
                    "region": self.region,
                    "stack_name": self.stack_name,
                    "deployment_type": "cloudformation",
                },
            )

        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(warnings[:10]) if warnings else None
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"aws-stack-{self.region}-{self.stack_name}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(INVENTORY_PLANE, state, scope, detail),
                Coverage(RELATIONSHIP_PLANE, state, scope, detail),
            ),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _collect_lambda(
        self,
        function_name: str,
        logical_id: str,
        agent_ref: AssetRef,
        observed_at: datetime,
        assets: dict[tuple[AssetRef, str], AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        template_resource: dict[str, Any] | None,
    ) -> None:
        try:
            response = self.lambda_client.get_function_configuration(FunctionName=function_name)
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("lambda:GetFunctionConfiguration", error)
            ) from error
        if not isinstance(response, dict):
            raise AwsStackDiscoveryError("lambda:GetFunctionConfiguration: invalid response shape")
        variables = response.get("Environment", {}).get("Variables", {})
        models = _model_entries(variables)
        if not models:
            return
        function_arn = _string(response.get("FunctionArn")) or (
            f"arn:{self.partition}:lambda:{self.region}:{self.account_id}:function:{function_name}"
        )
        workload_ref = AssetRef(AssetKind.AI_WORKLOAD, function_arn)
        deployment_artifact = _lambda_deployment_artifact(response, template_resource)
        payload = {
            "resource_type": "AWS::Lambda::Function",
            "logical_id": logical_id,
            "function_arn": function_arn,
            "model_configuration_keys": sorted(models),
            "runtime": _string(response.get("Runtime")),
            "package_type": _string(response.get("PackageType")),
            "deployment_artifact": deployment_artifact,
            "source_revision_status": "unattested",
        }
        evidence = self._evidence(observed_at, "lambda", function_name, payload)
        assets[(workload_ref, INVENTORY_PLANE)] = AssetAssertion(
            asset=workload_ref,
            coverage_plane=INVENTORY_PLANE,
            display_name=_string(response.get("FunctionName")) or function_name,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={
                "provider": "aws",
                "service": "lambda",
                "runtime_kind": "serverless_function",
                "account_id": self.account_id,
                "region": self.region,
                "stack_name": self.stack_name,
                "logical_id": logical_id,
                "deployment_identifiers": {
                    "cloudformation_logical_id": [logical_id],
                    "function_name": [
                        _string(response.get("FunctionName")) or function_name
                    ],
                },
                "runtime": _string(response.get("Runtime")),
                "package_type": _string(response.get("PackageType")),
                "memory_mb": response.get("MemorySize"),
                "timeout_seconds": response.get("Timeout"),
                "state": _string(response.get("State")),
                "last_modified": _string(response.get("LastModified")),
                "lambda_revision_id": _string(response.get("RevisionId")),
                "deployment_artifact": deployment_artifact,
                "source_revision_status": "unattested",
            },
        )
        self._add_relationship(
            relationships,
            agent_ref,
            workload_ref,
            RelationshipKind.HOSTED_ON,
            AssertionType.INFERRED,
            0.9,
            evidence,
        )
        role_arn = _string(response.get("Role"))
        if role_arn:
            self._add_identity_and_role(assets, relationships, workload_ref, role_arn, evidence)
        self._add_models(assets, relationships, workload_ref, models, observed_at, "lambda")

    def _collect_ecs_task(
        self,
        task_definition_arn: str,
        logical_id: str,
        agent_ref: AssetRef,
        observed_at: datetime,
        assets: dict[tuple[AssetRef, str], AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        template_resource: dict[str, Any] | None,
    ) -> None:
        try:
            response = self.ecs_client.describe_task_definition(
                taskDefinition=task_definition_arn, include=["TAGS"]
            )
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("ecs:DescribeTaskDefinition", error)
            ) from error
        task = response.get("taskDefinition") if isinstance(response, dict) else None
        if not isinstance(task, dict):
            raise AwsStackDiscoveryError("ecs:DescribeTaskDefinition: invalid response shape")
        models: dict[str, str] = {}
        container_names: list[str] = []
        model_container_images: list[dict[str, str]] = []
        for container in task.get("containerDefinitions", []):
            if not isinstance(container, dict):
                continue
            name = _string(container.get("name"))
            if name:
                container_names.append(name)
            environment = container.get("environment", [])
            if isinstance(environment, list):
                container_models = _model_entries(
                    {
                        item.get("name"): item.get("value")
                        for item in environment
                        if isinstance(item, dict)
                    }
                )
                models.update(container_models)
                image = _string(container.get("image"))
                if container_models and name and image:
                    model_container_images.append({"container_name": name, "image": image})
        if not models:
            return
        arn = _string(task.get("taskDefinitionArn")) or task_definition_arn
        family = _string(task.get("family")) or logical_id
        workload_ref = AssetRef(AssetKind.AI_WORKLOAD, arn)
        deployment_artifact = _ecs_deployment_artifact(
            model_container_images, template_resource
        )
        evidence = self._evidence(
            observed_at,
            "ecs",
            arn,
            {
                "resource_type": "AWS::ECS::TaskDefinition",
                "logical_id": logical_id,
                "task_definition_arn": arn,
                "model_configuration_keys": sorted(models),
                "container_names": sorted(container_names),
                "deployment_artifact": deployment_artifact,
                "source_revision_status": "unattested",
            },
        )
        assets[(workload_ref, INVENTORY_PLANE)] = AssetAssertion(
            asset=workload_ref,
            coverage_plane=INVENTORY_PLANE,
            display_name=family,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={
                "provider": "aws",
                "service": "ecs",
                "runtime_kind": "container_task",
                "account_id": self.account_id,
                "region": self.region,
                "stack_name": self.stack_name,
                "logical_id": logical_id,
                "deployment_identifiers": {
                    "cloudformation_logical_id": [logical_id],
                    "container_name": sorted(container_names),
                },
                "family": family,
                "revision": task.get("revision"),
                "network_mode": _string(task.get("networkMode")),
                "requires_compatibilities": sorted(
                    value
                    for value in task.get("requiresCompatibilities", [])
                    if isinstance(value, str)
                ),
                "registered_at": _timestamp(task.get("registeredAt")),
                "deployment_artifact": deployment_artifact,
                "source_revision_status": "unattested",
            },
        )
        self._add_relationship(
            relationships,
            agent_ref,
            workload_ref,
            RelationshipKind.HOSTED_ON,
            AssertionType.INFERRED,
            0.9,
            evidence,
        )
        role_arn = _string(task.get("taskRoleArn"))
        if role_arn:
            self._add_identity_and_role(assets, relationships, workload_ref, role_arn, evidence)
        self._add_models(assets, relationships, workload_ref, models, observed_at, "ecs")

    def _add_identity_and_role(
        self,
        assets: dict[tuple[AssetRef, str], AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        workload_ref: AssetRef,
        role_arn: str,
        evidence: Evidence,
    ) -> None:
        identity_ref = AssetRef(AssetKind.IDENTITY, role_arn)
        assets.setdefault(
            (identity_ref, INVENTORY_PLANE),
            AssetAssertion(
                asset=identity_ref,
                coverage_plane=INVENTORY_PLANE,
                display_name=role_arn.rsplit("/", 1)[-1],
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
                attributes={
                    "provider": "aws",
                    "principal_type": "iam_role",
                    "account_id": self.account_id,
                },
            ),
        )
        self._add_relationship(
            relationships,
            workload_ref,
            identity_ref,
            RelationshipKind.RUNS_AS,
            AssertionType.OBSERVED,
            1.0,
            evidence,
        )

    def _add_models(
        self,
        assets: dict[tuple[AssetRef, str], AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        workload_ref: AssetRef,
        models: dict[str, str],
        observed_at: datetime,
        service: str,
    ) -> None:
        for configuration_key, model_id in sorted(models.items()):
            model_ref = AssetRef(AssetKind.AI_MODEL, f"aws:bedrock:model:{model_id}")
            evidence = self._evidence(
                observed_at,
                service,
                workload_ref.natural_key,
                {
                    "model_id": model_id,
                    "configuration_key": configuration_key,
                    "classification": "allow_listed_model_configuration",
                },
            )
            assets.setdefault(
                (model_ref, INVENTORY_PLANE),
                AssetAssertion(
                    asset=model_ref,
                    coverage_plane=INVENTORY_PLANE,
                    display_name=model_id,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={"provider": "aws_bedrock", "model_id": model_id},
                ),
            )
            self._add_relationship(
                relationships,
                workload_ref,
                model_ref,
                RelationshipKind.USES,
                AssertionType.OBSERVED,
                1.0,
                evidence,
            )

    @staticmethod
    def _add_relationship(
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        source: AssetRef,
        target: AssetRef,
        kind: RelationshipKind,
        assertion_type: AssertionType,
        confidence: float,
        evidence: Evidence,
    ) -> None:
        relationships.setdefault(
            (source, target, kind),
            RelationshipAssertion(
                source=source,
                target=target,
                coverage_plane=RELATIONSHIP_PLANE,
                kind=kind,
                assertion_type=assertion_type,
                confidence=confidence,
                evidence=evidence,
            ),
        )

    def _evidence(
        self,
        observed_at: datetime,
        service: str,
        resource_id: str,
        payload: dict[str, Any],
    ) -> Evidence:
        return Evidence(
            source_type="aws_control_plane",
            locator=(
                f"aws://{self.account_id}/{self.region}/{service}/{self.stack_name}/{resource_id}"
            ),
            observed_at=observed_at,
            payload=payload,
        )

    def _failed_batch(
        self, connection: str, scope: str, observed_at: datetime, detail: str
    ) -> InventoryBatch:
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"aws-stack-{self.region}-{self.stack_name}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(INVENTORY_PLANE, CoverageState.FAILED, scope, detail),
                Coverage(RELATIONSHIP_PLANE, CoverageState.FAILED, scope, detail),
            ),
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Discover a custom AWS AI application stack")
    parser.add_argument("--stack-name", required=True, help="CloudFormation stack boundary")
    parser.add_argument("--app-id", required=True, help="stable Denali application namespace")
    parser.add_argument("--display-name", help="human-readable AI agent name")
    parser.add_argument("--region", help="AWS region; defaults to configured region")
    parser.add_argument("--profile", help="AWS shared-config profile")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise SystemExit("AWS discovery requires: pip install 'denali-ai-security[aws]'") from error

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    region = args.region or session.region_name
    if not region:
        raise SystemExit("--region or an AWS configured region is required")
    config = Config(
        connect_timeout=10,
        read_timeout=30,
        retries={"max_attempts": 3, "mode": "standard"},
    )
    identity = session.client("sts", config=config).get_caller_identity()
    account_id = _string(identity.get("Account"))
    identity_arn = _string(identity.get("Arn"))
    if not account_id or not identity_arn:
        raise SystemExit("STS GetCallerIdentity returned no account identity")
    partition = identity_arn.split(":", 2)[1] if identity_arn.startswith("arn:") else "aws"
    connector = AwsStackConnector(
        account_id=account_id,
        region=region,
        partition=partition,
        stack_name=args.stack_name,
        app_id=args.app_id,
        display_name=args.display_name or args.app_id.replace("-", " ").title(),
        cloudformation_client=session.client("cloudformation", region_name=region, config=config),
        lambda_client=session.client("lambda", region_name=region, config=config),
        ecs_client=session.client("ecs", region_name=region, config=config),
    )
    batch = connector.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest(args.tenant_id, batch)
    states = ",".join(f"{item.plane}={item.state.value}" for item in batch.coverage)
    print(
        f"Scanned AWS stack {account_id}/{region}/{args.stack_name}: "
        f"{result['assets']} assets, {result['relationships']} relationships; {states}"
    )
    if any(item.state is not CoverageState.COMPLETE for item in batch.coverage):
        raise SystemExit(2)


def _stack_resources(client: Any, stack_name: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_PAGES):
        request: dict[str, Any] = {"StackName": stack_name}
        if token:
            request["NextToken"] = token
        try:
            response = client.list_stack_resources(**request)
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("cloudformation:ListStackResources", error)
            ) from error
        resources = response.get("StackResourceSummaries") if isinstance(response, dict) else None
        if not isinstance(resources, list):
            raise AwsStackDiscoveryError(
                "cloudformation:ListStackResources: invalid response shape"
            )
        output.extend(item for item in resources if isinstance(item, dict))
        next_token = response.get("NextToken")
        if next_token is None:
            return output
        if not isinstance(next_token, str) or not next_token or next_token in seen:
            raise AwsStackDiscoveryError(
                "cloudformation:ListStackResources: invalid or repeated pagination token"
            )
        seen.add(next_token)
        token = next_token
    raise AwsStackDiscoveryError("cloudformation:ListStackResources: page safety limit exceeded")


def _stack_template_resources(client: Any, stack_name: str) -> dict[str, dict[str, Any]]:
    try:
        response = client.get_template(StackName=stack_name, TemplateStage="Processed")
    except Exception as error:
        raise AwsStackDiscoveryError(
            _safe_failure("cloudformation:GetTemplate", error)
        ) from error
    body = response.get("TemplateBody") if isinstance(response, dict) else None
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError as error:
            raise AwsStackDiscoveryError(
                "cloudformation:GetTemplate: invalid template JSON"
            ) from error
    resources = body.get("Resources") if isinstance(body, dict) else None
    if not isinstance(resources, dict):
        raise AwsStackDiscoveryError("cloudformation:GetTemplate: invalid response shape")
    return {
        logical_id: resource
        for logical_id, resource in resources.items()
        if isinstance(logical_id, str) and isinstance(resource, dict)
    }


def _lambda_deployment_artifact(
    response: dict[str, Any], template_resource: dict[str, Any] | None
) -> dict[str, str] | None:
    properties = (
        template_resource.get("Properties")
        if isinstance(template_resource, dict)
        else None
    )
    code = properties.get("Code") if isinstance(properties, dict) else None
    bucket = _string(code.get("S3Bucket")) if isinstance(code, dict) else None
    key = _string(code.get("S3Key")) if isinstance(code, dict) else None
    if not bucket or not key:
        return None
    artifact = {"kind": "s3_object", "bucket": bucket, "key": key}
    code_sha256 = _string(response.get("CodeSha256"))
    if code_sha256:
        artifact["code_sha256"] = code_sha256
    return artifact


def _ecs_deployment_artifact(
    model_container_images: list[dict[str, str]],
    template_resource: dict[str, Any] | None,
) -> dict[str, str] | None:
    del template_resource  # The observed task definition is the authoritative image locator.
    if len(model_container_images) != 1:
        return None
    return {"kind": "container_image", **model_container_images[0]}


def _model_entries(values: Any) -> dict[str, str]:
    if not isinstance(values, dict):
        return {}
    return {
        key: value
        for key, value in values.items()
        if isinstance(key, str)
        and isinstance(value, str)
        and _MODEL_KEY_RE.fullmatch(key)
        and _MODEL_ID_RE.fullmatch(value)
    }


def _safe_failure(operation: str, error: Exception) -> str:
    response = getattr(error, "response", None)
    code = None
    if isinstance(response, dict):
        error_data = response.get("Error")
        if isinstance(error_data, dict):
            code = _string(error_data.get("Code"))
    return f"{operation}: {code or error.__class__.__name__}"


def _normalize_app_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not normalized:
        raise ValueError("app_id must contain letters or digits")
    return normalized


def _required(label: str, value: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty without surrounding whitespace")
    return value


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _timestamp(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return _string(value)
