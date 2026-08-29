"""Evidence-bearing posture checks for custom AWS-hosted AI application stacks.

The inventory connector establishes which Lambda functions and ECS task definitions
are AI workloads. This connector independently re-reads that bounded CloudFormation
scope and evaluates only controls that AWS APIs can prove without invoking the
application or retrieving secret values.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from denali.connectors.aws_stack import (
    MAX_PAGES,
    AwsStackDiscoveryError,
    _model_entries,
    _safe_failure,
    _stack_resources,
    _string,
)
from denali.domain import (
    AffectedResource,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.aws_stack_posture"
CAPABILITIES = ConnectorCapabilities(findings=True)
FINDINGS_PLANE = "aws_stack_ai_configuration_findings"

_BEDROCK_INVOKE_ACTIONS = {
    "bedrock:converse",
    "bedrock:conversestream",
    "bedrock:invokemodel",
    "bedrock:invokemodelwithresponsestream",
}


@dataclass(frozen=True, slots=True)
class _RoleTarget:
    arn: str
    name: str
    model_ids: tuple[str, ...]
    workload_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _LogTarget:
    group_name: str
    resource_uid: str
    resource_name: str
    resource_type: str


class AwsStackPostureConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        stack_name: str,
        cloudformation_client: Any,
        lambda_client: Any,
        ecs_client: Any,
        iam_client: Any,
        bedrock_client: Any,
        logs_client: Any,
    ) -> None:
        self.account_id = _required("account_id", account_id)
        self.region = _required("region", region)
        self.stack_name = _required("stack_name", stack_name)
        self.cloudformation_client = cloudformation_client
        self.lambda_client = lambda_client
        self.ecs_client = ecs_client
        self.iam_client = iam_client
        self.bedrock_client = bedrock_client
        self.logs_client = logs_client

    def collect(self, *, connection_id: str | None = None) -> FindingBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"aws:{self.account_id}"
        scope = f"aws:{self.account_id}:{self.region}:cloudformation:{self.stack_name}"
        run_id = f"aws-stack-posture-{self.region}-{self.stack_name}-{observed_at.isoformat()}"
        try:
            resources = _stack_resources(self.cloudformation_client, self.stack_name)
        except AwsStackDiscoveryError as error:
            return FindingBatch(
                connector_id=self.connector_id,
                connection_id=connection,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=(Coverage(FINDINGS_PLANE, CoverageState.FAILED, scope, str(error)),),
                authoritative=True,
            )

        roles: dict[str, _RoleTarget] = {}
        logs: dict[str, _LogTarget] = {}
        warnings: list[str] = []
        for resource in resources:
            resource_type = _string(resource.get("ResourceType"))
            physical_id = _string(resource.get("PhysicalResourceId"))
            if not physical_id:
                continue
            try:
                if resource_type == "AWS::Lambda::Function":
                    role, log = self._lambda_targets(physical_id)
                    if role:
                        _merge_role(roles, role)
                    if log:
                        logs[log.group_name] = log
                elif resource_type == "AWS::ECS::TaskDefinition":
                    role, task_logs = self._ecs_targets(physical_id)
                    if role:
                        _merge_role(roles, role)
                    for log in task_logs:
                        logs[log.group_name] = log
            except AwsStackDiscoveryError as error:
                warnings.append(str(error))

        findings: list[FindingAssertion] = []
        for role in sorted(roles.values(), key=lambda item: item.arn):
            try:
                matches = _overbroad_bedrock_permissions(self.iam_client, role.name)
            except AwsStackDiscoveryError as error:
                warnings.append(str(error))
                continue
            if matches:
                findings.append(self._role_model_scope_finding(role, matches, observed_at))

        for log in sorted(logs.values(), key=lambda item: item.group_name):
            try:
                retention = _log_retention(self.logs_client, log.group_name)
            except AwsStackDiscoveryError as error:
                warnings.append(str(error))
                continue
            if retention is _LOG_GROUP_ABSENT:
                continue
            if retention is None:
                findings.append(self._log_retention_finding(log, observed_at))

        try:
            logging_response = self.bedrock_client.get_model_invocation_logging_configuration()
            if not isinstance(logging_response, dict):
                raise AwsStackDiscoveryError(
                    "bedrock:GetModelInvocationLoggingConfiguration: invalid response shape"
                )
            if not isinstance(logging_response.get("loggingConfig"), dict):
                findings.append(self._bedrock_logging_finding(observed_at))
        except AwsStackDiscoveryError as error:
            warnings.append(str(error))
        except Exception as error:
            warnings.append(
                _safe_failure("bedrock:GetModelInvocationLoggingConfiguration", error)
            )

        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return FindingBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(FINDINGS_PLANE, state, scope, detail),),
            findings=tuple(findings),
            authoritative=True,
        )

    def _lambda_targets(self, function_name: str) -> tuple[_RoleTarget | None, _LogTarget | None]:
        try:
            response = self.lambda_client.get_function_configuration(FunctionName=function_name)
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("lambda:GetFunctionConfiguration", error)
            ) from error
        if not isinstance(response, dict):
            raise AwsStackDiscoveryError("lambda:GetFunctionConfiguration: invalid response shape")
        models = _model_entries(response.get("Environment", {}).get("Variables", {}))
        if not models:
            return None, None
        function_arn = _string(response.get("FunctionArn"))
        role_arn = _string(response.get("Role"))
        role = (
            _RoleTarget(
                arn=role_arn,
                name=role_arn.rsplit("/", 1)[-1],
                model_ids=tuple(sorted(set(models.values()))),
                workload_names=(
                    _string(response.get("FunctionName")) or function_name,
                ),
            )
            if role_arn
            else None
        )
        function_uid = function_arn or function_name
        return role, _LogTarget(
            group_name=f"/aws/lambda/{function_name}",
            resource_uid=function_uid,
            resource_name=_string(response.get("FunctionName")) or function_name,
            resource_type="AWS Lambda Function",
        )

    def _ecs_targets(
        self, task_definition: str
    ) -> tuple[_RoleTarget | None, tuple[_LogTarget, ...]]:
        try:
            response = self.ecs_client.describe_task_definition(
                taskDefinition=task_definition, include=["TAGS"]
            )
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("ecs:DescribeTaskDefinition", error)
            ) from error
        task = response.get("taskDefinition") if isinstance(response, dict) else None
        if not isinstance(task, dict):
            raise AwsStackDiscoveryError("ecs:DescribeTaskDefinition: invalid response shape")
        models: dict[str, str] = {}
        log_groups: set[str] = set()
        for container in task.get("containerDefinitions", []):
            if not isinstance(container, dict):
                continue
            environment = container.get("environment")
            if isinstance(environment, list):
                models.update(
                    _model_entries(
                        {
                            item.get("name"): item.get("value")
                            for item in environment
                            if isinstance(item, dict)
                        }
                    )
                )
            log_configuration = container.get("logConfiguration")
            if isinstance(log_configuration, dict):
                options = log_configuration.get("options")
                if isinstance(options, dict):
                    group = _string(options.get("awslogs-group"))
                    if group:
                        log_groups.add(group)
        if not models:
            return None, ()
        task_arn = _string(task.get("taskDefinitionArn")) or task_definition
        task_name = _string(task.get("family")) or task_definition
        role_arn = _string(task.get("taskRoleArn"))
        role = (
            _RoleTarget(
                arn=role_arn,
                name=role_arn.rsplit("/", 1)[-1],
                model_ids=tuple(sorted(set(models.values()))),
                workload_names=(task_name,),
            )
            if role_arn
            else None
        )
        return role, tuple(
            _LogTarget(
                group_name=group,
                resource_uid=task_arn,
                resource_name=task_name,
                resource_type="AWS ECS Task Definition",
            )
            for group in sorted(log_groups)
        )

    def _role_model_scope_finding(
        self,
        role: _RoleTarget,
        matches: list[dict[str, Any]],
        observed_at: datetime,
    ) -> FindingAssertion:
        workload_label = ", ".join(role.workload_names)
        return self._finding(
            source_uid=f"{self.stack_name}:role:{role.arn}:bedrock-model-family-wildcard",
            rule_uid="DENALI-AWS-AI-IAM-001",
            title=(
                f"{workload_label} execution role can invoke an unrestricted "
                "Anthropic model family"
            ),
            description=(
                "The AI workload role has an Allow statement for Bedrock invocation against "
                "a foundation-model resource whose model identifier contains a wildcard. The "
                "configured inference-profile identifiers are narrower than this permission."
            ),
            risk=(
                "A compromised workload or an unintended configuration change could select "
                "another Anthropic model covered by the role, expanding model choice, cost, "
                "and data-processing behavior beyond the deployed configuration."
            ),
            remediation=(
                "Replace the foundation-model family wildcard with the exact underlying model "
                "ARNs required by the approved inference profiles and their destination regions. "
                "Retest global inference-profile routing after narrowing the policy."
            ),
            severity=FindingSeverity.MEDIUM,
            signal="identity.bedrock_model_family_wildcard",
            affected=AffectedResource(
                uid=role.arn,
                name=role.name,
                resource_type="AWS IAM Role",
                provider="AWS",
                account_uid=self.account_id,
                region=self.region,
            ),
            observed_at=observed_at,
            evidence_locator=f"aws://{self.account_id}/iam/role/{role.name}",
            evidence_payload={
                "configured_model_ids": list(role.model_ids),
                "workload_names": list(role.workload_names),
                "matching_policy_statements": matches,
                "evaluation": "allow_bedrock_invoke_with_wildcard_model_identifier",
            },
            attributes={"service": "iam", "role_arn": role.arn},
        )

    def _bedrock_logging_finding(self, observed_at: datetime) -> FindingAssertion:
        uid = f"aws:{self.account_id}:{self.region}:bedrock:model-invocation-logging"
        return self._finding(
            source_uid=f"{self.stack_name}:bedrock:model-invocation-logging-absent",
            rule_uid="DENALI-AWS-AI-LOG-001",
            title="Bedrock model invocation logging is not configured",
            description=(
                f"AWS returned no model invocation logging configuration for account "
                f"{self.account_id} in {self.region}. This check observes the Bedrock destination "
                "configuration only; it does not claim that CloudTrail or application telemetry "
                "is absent."
            ),
            risk=(
                "Security investigations may lack provider-side invocation records needed to "
                "correlate model use, abuse, and unexpected workload behavior."
            ),
            remediation=(
                "Configure Bedrock model invocation logging to an encrypted, access-controlled "
                "CloudWatch Logs or S3 destination. Choose prompt and response data capture only "
                "after applying the organization's data-retention and privacy requirements."
            ),
            severity=FindingSeverity.MEDIUM,
            signal="bedrock.invocation_logging_absent",
            affected=AffectedResource(
                uid=uid,
                name=f"Bedrock {self.region} invocation logging",
                resource_type="AWS Bedrock Account-Region Configuration",
                provider="AWS",
                account_uid=self.account_id,
                region=self.region,
            ),
            observed_at=observed_at,
            evidence_locator=f"aws://{self.account_id}/{self.region}/bedrock/invocation-logging",
            evidence_payload={
                "logging_config_present": False,
                "evaluation": "successful_empty_configuration_read",
            },
            attributes={"service": "bedrock"},
        )

    def _log_retention_finding(
        self, log: _LogTarget, observed_at: datetime
    ) -> FindingAssertion:
        return self._finding(
            source_uid=f"{self.stack_name}:logs:{log.group_name}:retention-unbounded",
            rule_uid="DENALI-AWS-AI-LOG-002",
            title=f"{log.resource_name} log group has no retention limit",
            description=(
                f"CloudWatch Logs reports no retentionInDays value for {log.group_name}, so "
                "events are retained indefinitely unless they are deleted separately."
            ),
            risk=(
                "AI workload logs may contain operational identifiers, errors, model telemetry, "
                "or customer context. Indefinite retention increases unnecessary data exposure."
            ),
            remediation=(
                "Set an explicit CloudWatch Logs retention period that matches incident-response "
                "and regulatory needs, and verify that application logging excludes sensitive "
                "prompt, response, credential, and customer content."
            ),
            severity=FindingSeverity.MEDIUM,
            signal="workload.log_retention_unbounded",
            affected=AffectedResource(
                uid=log.resource_uid,
                name=log.resource_name,
                resource_type=log.resource_type,
                provider="AWS",
                account_uid=self.account_id,
                region=self.region,
            ),
            observed_at=observed_at,
            evidence_locator=(
                f"aws://{self.account_id}/{self.region}/logs/log-group/{log.group_name}"
            ),
            evidence_payload={
                "log_group_name": log.group_name,
                "retention_in_days": None,
                "evaluation": "retention_in_days_absent",
            },
            attributes={"service": "logs", "log_group_name": log.group_name},
        )

    def _finding(
        self,
        *,
        source_uid: str,
        rule_uid: str,
        title: str,
        description: str,
        risk: str,
        remediation: str,
        severity: FindingSeverity,
        signal: str,
        affected: AffectedResource,
        observed_at: datetime,
        evidence_locator: str,
        evidence_payload: dict[str, Any],
        attributes: dict[str, Any],
    ) -> FindingAssertion:
        return FindingAssertion(
            source_uid=source_uid,
            rule_uid=rule_uid,
            title=title,
            description=description,
            risk=risk,
            remediation=remediation,
            remediation_references=(),
            severity=severity,
            state=FindingState.OPEN,
            evaluation_result=EvaluationResult.FAIL,
            class_uid=2003,
            class_name="Compliance Finding",
            observed_at=observed_at,
            evidence=Evidence(
                source_type="aws_control_plane",
                locator=evidence_locator,
                observed_at=observed_at,
                payload=evidence_payload,
            ),
            affected_resources=(affected,),
            attributes={
                "category": "AI Configuration",
                "product": "Denali AWS Stack Posture",
                "denali_signal": signal,
                "stack_name": self.stack_name,
                **attributes,
            },
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a custom AWS AI application stack")
    parser.add_argument("--stack-name", required=True, help="CloudFormation stack boundary")
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
        raise SystemExit("AWS posture requires: pip install 'denali-ai-security[aws]'") from error

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
    if not account_id:
        raise SystemExit("STS GetCallerIdentity returned no account identity")
    connector = AwsStackPostureConnector(
        account_id=account_id,
        region=region,
        stack_name=args.stack_name,
        cloudformation_client=session.client("cloudformation", region_name=region, config=config),
        lambda_client=session.client("lambda", region_name=region, config=config),
        ecs_client=session.client("ecs", region_name=region, config=config),
        iam_client=session.client("iam", config=config),
        bedrock_client=session.client("bedrock", region_name=region, config=config),
        logs_client=session.client("logs", region_name=region, config=config),
    )
    batch = connector.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_findings(args.tenant_id, batch)
    state = batch.coverage[0].state.value
    print(
        f"Evaluated AWS stack {account_id}/{region}/{args.stack_name}: "
        f"{result['findings']} open findings, {result['resolved_missing']} resolved by absence; "
        f"coverage={state}"
    )
    if batch.coverage[0].state is not CoverageState.COMPLETE:
        raise SystemExit(2)


def _merge_role(roles: dict[str, _RoleTarget], incoming: _RoleTarget) -> None:
    current = roles.get(incoming.arn)
    if current is None:
        roles[incoming.arn] = incoming
        return
    roles[incoming.arn] = _RoleTarget(
        arn=current.arn,
        name=current.name,
        model_ids=tuple(sorted(set(current.model_ids) | set(incoming.model_ids))),
        workload_names=tuple(
            sorted(set(current.workload_names) | set(incoming.workload_names))
        ),
    )


def _overbroad_bedrock_permissions(iam_client: Any, role_name: str) -> list[dict[str, Any]]:
    documents: list[tuple[str, str, dict[str, Any]]] = []
    for policy_name in _inline_policy_names(iam_client, role_name):
        try:
            response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        except Exception as error:
            raise AwsStackDiscoveryError(_safe_failure("iam:GetRolePolicy", error)) from error
        document = response.get("PolicyDocument") if isinstance(response, dict) else None
        if not isinstance(document, dict):
            raise AwsStackDiscoveryError("iam:GetRolePolicy: invalid response shape")
        documents.append(("inline", policy_name, document))
    for policy_name, policy_arn in _attached_policies(iam_client, role_name):
        try:
            policy = iam_client.get_policy(PolicyArn=policy_arn)
            policy_data = policy.get("Policy") if isinstance(policy, dict) else None
            version_id = (
                _string(policy_data.get("DefaultVersionId"))
                if isinstance(policy_data, dict)
                else None
            )
            if not version_id:
                raise AwsStackDiscoveryError("iam:GetPolicy: invalid response shape")
            version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            version_data = version.get("PolicyVersion") if isinstance(version, dict) else None
            document = version_data.get("Document") if isinstance(version_data, dict) else None
        except AwsStackDiscoveryError:
            raise
        except Exception as error:
            raise AwsStackDiscoveryError(_safe_failure("iam:GetPolicyVersion", error)) from error
        if not isinstance(document, dict):
            raise AwsStackDiscoveryError("iam:GetPolicyVersion: invalid response shape")
        documents.append(("attached", policy_name, document))

    matches: list[dict[str, Any]] = []
    for policy_kind, policy_name, document in documents:
        statements = document.get("Statement", [])
        for statement in _items(statements):
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            actions = sorted(
                action for action in _strings(statement.get("Action")) if _bedrock_invoke(action)
            )
            if not actions:
                continue
            resources = sorted(
                resource
                for resource in _strings(statement.get("Resource"))
                if _wildcard_model_resource(resource)
            )
            if resources:
                matches.append(
                    {
                        "policy_kind": policy_kind,
                        "policy_name": policy_name,
                        "actions": actions,
                        "resources": resources,
                    }
                )
    return matches


def _inline_policy_names(iam_client: Any, role_name: str) -> tuple[str, ...]:
    output: list[str] = []
    marker: str | None = None
    for _ in range(MAX_PAGES):
        request: dict[str, Any] = {"RoleName": role_name}
        if marker:
            request["Marker"] = marker
        try:
            response = iam_client.list_role_policies(**request)
        except Exception as error:
            raise AwsStackDiscoveryError(_safe_failure("iam:ListRolePolicies", error)) from error
        names = response.get("PolicyNames") if isinstance(response, dict) else None
        if not isinstance(names, list):
            raise AwsStackDiscoveryError("iam:ListRolePolicies: invalid response shape")
        output.extend(name for name in names if isinstance(name, str) and name)
        if not response.get("IsTruncated"):
            return tuple(output)
        marker = _string(response.get("Marker"))
        if not marker:
            raise AwsStackDiscoveryError("iam:ListRolePolicies: invalid pagination marker")
    raise AwsStackDiscoveryError("iam:ListRolePolicies: page safety limit exceeded")


def _attached_policies(iam_client: Any, role_name: str) -> tuple[tuple[str, str], ...]:
    output: list[tuple[str, str]] = []
    marker: str | None = None
    for _ in range(MAX_PAGES):
        request: dict[str, Any] = {"RoleName": role_name}
        if marker:
            request["Marker"] = marker
        try:
            response = iam_client.list_attached_role_policies(**request)
        except Exception as error:
            raise AwsStackDiscoveryError(
                _safe_failure("iam:ListAttachedRolePolicies", error)
            ) from error
        policies = response.get("AttachedPolicies") if isinstance(response, dict) else None
        if not isinstance(policies, list):
            raise AwsStackDiscoveryError("iam:ListAttachedRolePolicies: invalid response shape")
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            name = _string(policy.get("PolicyName"))
            arn = _string(policy.get("PolicyArn"))
            if name and arn:
                output.append((name, arn))
        if not response.get("IsTruncated"):
            return tuple(output)
        marker = _string(response.get("Marker"))
        if not marker:
            raise AwsStackDiscoveryError("iam:ListAttachedRolePolicies: invalid pagination marker")
    raise AwsStackDiscoveryError("iam:ListAttachedRolePolicies: page safety limit exceeded")


_LOG_GROUP_ABSENT = object()


def _log_retention(logs_client: Any, group_name: str) -> int | None | object:
    try:
        response = logs_client.describe_log_groups(logGroupNamePrefix=group_name, limit=50)
    except Exception as error:
        raise AwsStackDiscoveryError(_safe_failure("logs:DescribeLogGroups", error)) from error
    groups = response.get("logGroups") if isinstance(response, dict) else None
    if not isinstance(groups, list):
        raise AwsStackDiscoveryError("logs:DescribeLogGroups: invalid response shape")
    match = next(
        (
            item
            for item in groups
            if isinstance(item, dict) and item.get("logGroupName") == group_name
        ),
        None,
    )
    if match is None:
        return _LOG_GROUP_ABSENT
    retention = match.get("retentionInDays")
    return retention if isinstance(retention, int) and not isinstance(retention, bool) else None


def _bedrock_invoke(action: str) -> bool:
    normalized = action.lower()
    return normalized in _BEDROCK_INVOKE_ACTIONS or normalized == "bedrock:*"


def _wildcard_model_resource(resource: str) -> bool:
    if resource == "*":
        return True
    if ":foundation-model/" in resource:
        model_identifier = resource.split(":foundation-model/", 1)[1]
        return "*" in model_identifier or "?" in model_identifier
    if ":inference-profile/" in resource:
        profile_identifier = resource.split(":inference-profile/", 1)[1]
        return "*" in profile_identifier or "?" in profile_identifier
    return False


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(item for item in _items(value) if isinstance(item, str) and item)


def _required(label: str, value: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty without surrounding whitespace")
    return value
