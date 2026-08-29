from denali.connectors.aws_stack import (
    INVENTORY_PLANE,
    RELATIONSHIP_PLANE,
    AwsStackConnector,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind


class FakeCloudFormation:
    def __init__(self, resources=None, error=None, template=None, template_error=None):
        self.resources = resources or []
        self.error = error
        self.template = template or {"Resources": {}}
        self.template_error = template_error

    def list_stack_resources(self, **kwargs):
        if self.error:
            raise self.error
        return {"StackResourceSummaries": self.resources}

    def get_template(self, **kwargs):
        if self.template_error:
            raise self.template_error
        assert kwargs["TemplateStage"] == "Processed"
        return {"TemplateBody": self.template}


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


class AwsError(Exception):
    def __init__(self, code, message="must-not-be-persisted"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


def connector(*, cloudformation=None, functions=None, tasks=None):
    return AwsStackConnector(
        account_id="331145994818",
        region="ap-south-1",
        stack_name="NiSalesAgentStack",
        app_id="Anna Sales Agent",
        display_name="Anna",
        cloudformation_client=cloudformation
        or FakeCloudFormation(
            [
                {
                    "ResourceType": "AWS::Lambda::Function",
                    "LogicalResourceId": "AgentFn",
                    "PhysicalResourceId": "ni-sales-agent",
                },
                {
                    "ResourceType": "AWS::Lambda::Function",
                    "LogicalResourceId": "RenderFn",
                    "PhysicalResourceId": "ni-sales-render",
                },
                {
                    "ResourceType": "AWS::ECS::TaskDefinition",
                    "LogicalResourceId": "ProposalWorkerTask",
                    "PhysicalResourceId": "worker:10",
                },
            ],
            template={
                "Resources": {
                    "AgentFn": {
                        "Type": "AWS::Lambda::Function",
                        "Properties": {
                            "Code": {
                                "S3Bucket": "cdk-assets",
                                "S3Key": "lambda-asset.zip",
                            }
                        },
                    },
                    "ProposalWorkerTask": {
                        "Type": "AWS::ECS::TaskDefinition",
                        "Properties": {
                            "ContainerDefinitions": [
                                {
                                    "Name": "proposal-worker",
                                    "Image": "123.dkr.ecr/worker:worker-asset",
                                }
                            ]
                        },
                    },
                }
            },
        ),
        lambda_client=FakeLambda(
            functions
            or {
                "ni-sales-agent": {
                    "FunctionName": "ni-sales-agent",
                    "FunctionArn": "arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-agent",
                    "Role": "arn:aws:iam::331145994818:role/anna-agent-role",
                    "Runtime": "nodejs20.x",
                    "PackageType": "Zip",
                    "CodeSha256": "base64-sha256",
                    "LastModified": "2026-08-27T17:56:01.000+0000",
                    "RevisionId": "lambda-revision-id",
                    "MemorySize": 512,
                    "Timeout": 300,
                    "State": "Active",
                    "Environment": {
                        "Variables": {
                            "BEDROCK_MODEL_ID": "global.anthropic.claude-sonnet-4-5-v1:0",
                            "REVIEWER_MODEL_ID": "global.anthropic.claude-opus-4-6-v1",
                            "SLACK_SECRET": "never-store-this",
                        }
                    },
                },
                "ni-sales-render": {
                    "FunctionName": "ni-sales-render",
                    "FunctionArn": (
                        "arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-render"
                    ),
                    "Role": "arn:aws:iam::331145994818:role/render-role",
                    "Runtime": "nodejs20.x",
                    "Environment": {"Variables": {}},
                },
            }
        ),
        ecs_client=FakeEcs(
            tasks
            or {
                "worker:10": {
                    "taskDefinitionArn": (
                        "arn:aws:ecs:ap-south-1:331145994818:task-definition/worker:10"
                    ),
                    "family": "proposal-worker",
                    "revision": 10,
                    "taskRoleArn": "arn:aws:iam::331145994818:role/anna-worker-role",
                    "networkMode": "awsvpc",
                    "requiresCompatibilities": ["FARGATE"],
                    "containerDefinitions": [
                        {
                            "name": "proposal-worker",
                            "image": "123.dkr.ecr/worker:worker-asset",
                            "environment": [
                                {
                                    "name": "PROPOSAL_AUTHOR_MODEL_ID",
                                    "value": "global.anthropic.claude-sonnet-4-5-v1:0",
                                },
                                {"name": "API_SECRET", "value": "never-store-this-either"},
                            ],
                        }
                    ],
                }
            }
        ),
    )


def test_custom_stack_discovers_only_model_backed_compute_and_safe_metadata() -> None:
    batch = connector().collect()
    by_kind = {}
    for assertion in batch.assets:
        by_kind.setdefault(assertion.asset.kind, []).append(assertion)

    assert len(by_kind[AssetKind.AI_AGENT]) == 1
    assert by_kind[AssetKind.AI_AGENT][0].asset.natural_key == "app:anna-sales-agent:agent"
    assert {item.display_name for item in by_kind[AssetKind.AI_WORKLOAD]} == {
        "ni-sales-agent",
        "proposal-worker",
    }
    assert {item.display_name for item in by_kind[AssetKind.AI_MODEL]} == {
        "global.anthropic.claude-sonnet-4-5-v1:0",
        "global.anthropic.claude-opus-4-6-v1",
    }
    assert {item.display_name for item in by_kind[AssetKind.IDENTITY]} == {
        "anna-agent-role",
        "anna-worker-role",
    }
    assert not any(item.display_name == "ni-sales-render" for item in batch.assets)
    assert "never-store-this" not in str(batch)
    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.HOSTED_ON,
        RelationshipKind.RUNS_AS,
        RelationshipKind.USES,
    }
    workloads = {item.display_name: item for item in by_kind[AssetKind.AI_WORKLOAD]}
    assert workloads["ni-sales-agent"].attributes["deployment_artifact"] == {
        "kind": "s3_object",
        "bucket": "cdk-assets",
        "key": "lambda-asset.zip",
        "code_sha256": "base64-sha256",
    }
    assert workloads["proposal-worker"].attributes["deployment_artifact"] == {
        "kind": "container_image",
        "container_name": "proposal-worker",
        "image": "123.dkr.ecr/worker:worker-asset",
    }
    assert workloads["ni-sales-agent"].attributes["source_revision_status"] == "unattested"


def test_template_read_failure_keeps_inventory_but_marks_coverage_partial() -> None:
    cloudformation = FakeCloudFormation(
        [
            {
                "ResourceType": "AWS::Lambda::Function",
                "LogicalResourceId": "AgentFn",
                "PhysicalResourceId": "ni-sales-agent",
            }
        ],
        template_error=AwsError("AccessDeniedException"),
    )

    batch = connector(cloudformation=cloudformation, tasks={}).collect()

    assert any(item.asset.kind is AssetKind.AI_WORKLOAD for item in batch.assets)
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "AccessDeniedException" in (batch.coverage[0].detail or "")


def test_detail_failure_is_sanitized_and_cannot_authorize_withdrawal() -> None:
    cloudformation = FakeCloudFormation(
        [
            {
                "ResourceType": "AWS::Lambda::Function",
                "LogicalResourceId": "AgentFn",
                "PhysicalResourceId": "ni-sales-agent",
            }
        ]
    )
    batch = connector(
        cloudformation=cloudformation,
        functions={"ni-sales-agent": AwsError("AccessDeniedException")},
        tasks={},
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert not batch.may_withdraw(INVENTORY_PLANE)
    assert not batch.may_withdraw(RELATIONSHIP_PLANE)
    assert "AccessDeniedException" in (batch.coverage[0].detail or "")
    assert "must-not-be-persisted" not in str(batch)


def test_stack_list_failure_is_failed_not_successful_empty() -> None:
    batch = connector(
        cloudformation=FakeCloudFormation(error=AwsError("ValidationError")),
        functions={},
        tasks={},
    ).collect()

    assert batch.assets == ()
    assert {item.state for item in batch.coverage} == {CoverageState.FAILED}
    assert not batch.may_withdraw(INVENTORY_PLANE)
