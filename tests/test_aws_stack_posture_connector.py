from denali.connectors.aws_stack_posture import (
    FINDINGS_PLANE,
    AwsStackPostureConnector,
    _overbroad_bedrock_permissions,
)
from denali.domain import CoverageState


class AwsError(Exception):
    def __init__(self, code, message="must-not-be-persisted"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeCloudFormation:
    def __init__(self, resources=None, error=None):
        self.resources = resources or []
        self.error = error

    def list_stack_resources(self, **kwargs):
        if self.error:
            raise self.error
        return {"StackResourceSummaries": self.resources}


class FakeLambda:
    def __init__(self, functions):
        self.functions = functions

    def get_function_configuration(self, *, FunctionName):
        response = self.functions[FunctionName]
        if isinstance(response, Exception):
            raise response
        return response


class FakeEcs:
    def __init__(self, tasks):
        self.tasks = tasks

    def describe_task_definition(self, *, taskDefinition, include):
        assert include == ["TAGS"]
        response = self.tasks[taskDefinition]
        if isinstance(response, Exception):
            raise response
        return {"taskDefinition": response}


class FakeIam:
    def __init__(self, inline=None, attached=None, error=None):
        self.inline = inline or {}
        self.attached = attached or {}
        self.error = error

    def list_role_policies(self, *, RoleName, **kwargs):
        if self.error:
            raise self.error
        return {"PolicyNames": sorted(self.inline.get(RoleName, {})), "IsTruncated": False}

    def get_role_policy(self, *, RoleName, PolicyName):
        return {"PolicyDocument": self.inline[RoleName][PolicyName]}

    def list_attached_role_policies(self, *, RoleName, **kwargs):
        policies = self.attached.get(RoleName, {})
        return {
            "AttachedPolicies": [
                {"PolicyName": name, "PolicyArn": data["arn"]}
                for name, data in sorted(policies.items())
            ],
            "IsTruncated": False,
        }

    def get_policy(self, *, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, *, PolicyArn, VersionId):
        assert VersionId == "v1"
        for policies in self.attached.values():
            for data in policies.values():
                if data["arn"] == PolicyArn:
                    return {"PolicyVersion": {"Document": data["document"]}}
        raise KeyError(PolicyArn)


class FakeBedrock:
    def __init__(self, config=None, error=None):
        self.config = config
        self.error = error

    def get_model_invocation_logging_configuration(self):
        if self.error:
            raise self.error
        return {"loggingConfig": self.config} if self.config is not None else {}


class FakeLogs:
    def __init__(self, groups=None, error=None):
        self.groups = groups or {}
        self.error = error

    def describe_log_groups(self, *, logGroupNamePrefix, limit):
        assert limit == 50
        if self.error:
            raise self.error
        if logGroupNamePrefix not in self.groups:
            return {"logGroups": []}
        retention = self.groups[logGroupNamePrefix]
        group = {"logGroupName": logGroupNamePrefix}
        if retention is not None:
            group["retentionInDays"] = retention
        return {"logGroups": [group]}


LAMBDA_ROLE = "arn:aws:iam::331145994818:role/anna-agent-role"
ECS_ROLE = "arn:aws:iam::331145994818:role/anna-worker-role"
SONNET = "global.anthropic.claude-sonnet-4-5-v1:0"


def broad_policy():
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
                "Resource": [
                    f"arn:aws:bedrock:*:331145994818:inference-profile/{SONNET}",
                    "arn:aws:bedrock:*::foundation-model/anthropic.*",
                ],
            }
        ]
    }


def narrow_policy():
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock:Converse",
                "Resource": [
                    f"arn:aws:bedrock:*:331145994818:inference-profile/{SONNET}",
                    (
                        "arn:aws:bedrock:*::foundation-model/"
                        "anthropic.claude-sonnet-4-5-v1:0"
                    ),
                ],
            }
        ]
    }


def connector(*, iam=None, bedrock=None, logs=None, cloudformation=None):
    return AwsStackPostureConnector(
        account_id="331145994818",
        region="ap-south-1",
        stack_name="NiSalesAgentStack",
        cloudformation_client=cloudformation
        or FakeCloudFormation(
            [
                {
                    "ResourceType": "AWS::Lambda::Function",
                    "PhysicalResourceId": "ni-sales-agent",
                },
                {
                    "ResourceType": "AWS::Lambda::Function",
                    "PhysicalResourceId": "ni-sales-render",
                },
                {
                    "ResourceType": "AWS::ECS::TaskDefinition",
                    "PhysicalResourceId": "worker:10",
                },
            ]
        ),
        lambda_client=FakeLambda(
            {
                "ni-sales-agent": {
                    "FunctionName": "ni-sales-agent",
                    "FunctionArn": (
                        "arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-agent"
                    ),
                    "Role": LAMBDA_ROLE,
                    "Environment": {
                        "Variables": {
                            "BEDROCK_MODEL_ID": SONNET,
                            "SECRET_VALUE": "never-retain-this",
                        }
                    },
                },
                "ni-sales-render": {
                    "FunctionName": "ni-sales-render",
                    "Role": "arn:aws:iam::331145994818:role/render-role",
                    "Environment": {"Variables": {}},
                },
            }
        ),
        ecs_client=FakeEcs(
            {
                "worker:10": {
                    "taskDefinitionArn": (
                        "arn:aws:ecs:ap-south-1:331145994818:task-definition/worker:10"
                    ),
                    "family": "proposal-worker",
                    "taskRoleArn": ECS_ROLE,
                    "containerDefinitions": [
                        {
                            "name": "worker",
                            "environment": [
                                {"name": "PROPOSAL_MODEL_ID", "value": SONNET},
                                {"name": "SECRET_VALUE", "value": "never-retain-this-either"},
                            ],
                            "logConfiguration": {
                                "options": {"awslogs-group": "/ecs/proposal-worker"}
                            },
                        }
                    ],
                }
            }
        ),
        iam_client=iam
        or FakeIam(
            inline={
                "anna-agent-role": {"agent-policy": broad_policy()},
                "anna-worker-role": {"worker-policy": narrow_policy()},
            }
        ),
        bedrock_client=bedrock or FakeBedrock(),
        logs_client=logs
        or FakeLogs({"/aws/lambda/ni-sales-agent": None, "/ecs/proposal-worker": 30}),
    )


def test_complete_posture_scan_emits_only_proven_failed_controls() -> None:
    batch = connector().collect()

    assert batch.coverage[0].plane == FINDINGS_PLANE
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert batch.may_resolve_missing
    assert {finding.rule_uid for finding in batch.findings} == {
        "DENALI-AWS-AI-IAM-001",
        "DENALI-AWS-AI-LOG-001",
        "DENALI-AWS-AI-LOG-002",
    }
    assert {finding.affected_resources[0].uid for finding in batch.findings} == {
        LAMBDA_ROLE,
        "aws:331145994818:ap-south-1:bedrock:model-invocation-logging",
        "arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-agent",
    }
    assert "never-retain-this" not in str(batch)


def test_attached_policy_is_included_in_effective_role_review() -> None:
    iam = FakeIam(
        attached={
            "anna-agent-role": {
                "bedrock-managed": {
                    "arn": "arn:aws:iam::331145994818:policy/bedrock-managed",
                    "document": broad_policy(),
                }
            }
        }
    )

    matches = _overbroad_bedrock_permissions(iam, "anna-agent-role")

    assert matches == [
        {
            "policy_kind": "attached",
            "policy_name": "bedrock-managed",
            "actions": ["bedrock:Converse", "bedrock:InvokeModel"],
            "resources": ["arn:aws:bedrock:*::foundation-model/anthropic.*"],
        }
    ]


def test_permission_failure_is_partial_sanitized_and_non_authoritative_for_resolution() -> None:
    batch = connector(iam=FakeIam(error=AwsError("AccessDeniedException"))).collect()

    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert not batch.may_resolve_missing
    assert "AccessDeniedException" in (batch.coverage[0].detail or "")
    assert "must-not-be-persisted" not in str(batch)
    assert all(finding.rule_uid != "DENALI-AWS-AI-IAM-001" for finding in batch.findings)


def test_clean_controls_emit_no_findings_and_can_resolve_prior_failures() -> None:
    batch = connector(
        iam=FakeIam(
            inline={
                "anna-agent-role": {"agent-policy": narrow_policy()},
                "anna-worker-role": {"worker-policy": narrow_policy()},
            }
        ),
        bedrock=FakeBedrock(config={"textDataDeliveryEnabled": True}),
        logs=FakeLogs({"/aws/lambda/ni-sales-agent": 30, "/ecs/proposal-worker": 30}),
    ).collect()

    assert batch.findings == ()
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert batch.may_resolve_missing


def test_stack_boundary_failure_is_failed_and_cannot_resolve() -> None:
    batch = connector(
        cloudformation=FakeCloudFormation(error=AwsError("ValidationError"))
    ).collect()

    assert batch.findings == ()
    assert batch.coverage[0].state is CoverageState.FAILED
    assert not batch.may_resolve_missing
    assert "must-not-be-persisted" not in str(batch)
