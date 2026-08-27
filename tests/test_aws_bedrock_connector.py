from collections import deque
from typing import Any

from denali.connectors.aws_bedrock import (
    AGENT_INVENTORY_PLANE,
    AGENT_RELATIONSHIP_PLANE,
    GUARDRAIL_INVENTORY_PLANE,
    GUARDRAIL_RELATIONSHIP_PLANE,
    AwsBedrockRegionConnector,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind

ACCOUNT = "123456789012"
REGION = "us-east-1"
AGENT_ID = "ABCDEFGHIJ"
AGENT_ARN = f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/{AGENT_ID}"
GUARDRAIL_ID = "guardrail1"
GUARDRAIL_ARN = f"arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/{GUARDRAIL_ID}"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/denali-agent-role"


class FakeClient:
    def __init__(self, **operations: list[dict[str, Any] | Exception]) -> None:
        self.operations = {name: deque(values) for name, values in operations.items()}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str):
        def invoke(**parameters: Any) -> dict[str, Any]:
            self.calls.append((operation, parameters))
            value = self.operations[operation].popleft()
            if isinstance(value, Exception):
                raise value
            return value

        return invoke


def guardrail_summary(*, arn: str = GUARDRAIL_ARN) -> dict[str, Any]:
    return {
        "id": GUARDRAIL_ID,
        "arn": arn,
        "name": "customer-safety",
        "status": "READY",
        "version": "DRAFT",
    }


def guardrail_detail() -> dict[str, Any]:
    return {
        "guardrailId": GUARDRAIL_ID,
        "guardrailArn": GUARDRAIL_ARN,
        "name": "customer-safety",
        "status": "READY",
        "version": "DRAFT",
        "blockedInputMessaging": "blocked input text is not retained",
        "blockedOutputsMessaging": "blocked output text is not retained",
        "contentPolicy": {
            "filters": [
                {
                    "type": "PROMPT_ATTACK",
                    "inputStrength": "HIGH",
                    "outputStrength": "NONE",
                }
            ]
        },
        "sensitiveInformationPolicy": {
            "piiEntities": [{"type": "EMAIL", "action": "BLOCK"}],
            "regexes": [{"name": "customer-id", "pattern": "secret-pattern"}],
        },
        "topicPolicy": {"topics": [{"name": "internal-topic", "type": "DENY"}]},
    }


def agent_summary(agent_id: str = AGENT_ID) -> dict[str, Any]:
    return {
        "agentId": agent_id,
        "agentName": f"agent-{agent_id.lower()}",
        "agentStatus": "PREPARED",
    }


def agent_detail(
    *,
    guardrail_identifier: str | None = GUARDRAIL_ID,
    role_arn: str = ROLE_ARN,
) -> dict[str, Any]:
    guardrail = (
        {
            "guardrailIdentifier": guardrail_identifier,
            "guardrailVersion": "1",
        }
        if guardrail_identifier
        else None
    )
    return {
        "agent": {
            "agentId": AGENT_ID,
            "agentArn": AGENT_ARN,
            "agentName": "customer-support",
            "agentStatus": "PREPARED",
            "foundationModel": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "agentResourceRoleArn": role_arn,
            "instruction": "never persist this customer-specific system instruction",
            "guardrailConfiguration": guardrail,
            "idleSessionTTLInSeconds": 600,
        }
    }


def connector(agent_client: FakeClient, bedrock_client: FakeClient) -> AwsBedrockRegionConnector:
    return AwsBedrockRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        agent_client=agent_client,
        bedrock_client=bedrock_client,
    )


def coverage_by_plane(batch) -> dict[str, CoverageState]:
    return {item.plane: item.state for item in batch.coverage}


def test_phase_one_discovers_agents_models_roles_guardrails_and_relationships() -> None:
    agents = FakeClient(
        list_agents=[{"agentSummaries": [agent_summary()]}],
        get_agent=[agent_detail()],
    )
    bedrock = FakeClient(
        list_guardrails=[{"guardrails": [guardrail_summary()]}],
        get_guardrail=[guardrail_detail()],
    )

    batch = connector(agents, bedrock).collect()

    assert set(coverage_by_plane(batch).values()) == {CoverageState.COMPLETE}
    assert {item.asset.kind for item in batch.assets} == {
        AssetKind.AI_AGENT,
        AssetKind.AI_MODEL,
        AssetKind.IDENTITY,
        AssetKind.AI_GUARDRAIL,
    }
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.USES,
        RelationshipKind.RUNS_AS,
        RelationshipKind.PROTECTED_BY,
    }
    agent = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_AGENT)
    assert agent.asset.natural_key == AGENT_ARN
    assert agent.attributes["configuration_observed"] is True
    assert agent.attributes["instruction_length"] > 0
    assert agent.attributes["instruction_sha256"]
    assert "customer-specific" not in str(batch)
    assert "blocked input text" not in str(batch)
    assert "secret-pattern" not in str(batch)
    guardrail = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_GUARDRAIL)
    assert guardrail.attributes["content_filters"][0]["type"] == "PROMPT_ATTACK"
    assert guardrail.attributes["pii_entity_types"] == ["EMAIL"]
    assert guardrail.attributes["regex_filter_count"] == 1
    assert guardrail.attributes["denied_topic_count"] == 1
    assert bedrock.calls[1] == (
        "get_guardrail",
        {"guardrailIdentifier": GUARDRAIL_ID, "guardrailVersion": "DRAFT"},
    )


def test_per_agent_detail_failures_keep_distinct_assets_and_block_withdrawal() -> None:
    second_id = "KLMNOPQRST"
    agents = FakeClient(
        list_agents=[{"agentSummaries": [agent_summary(), agent_summary(second_id)]}],
        get_agent=[RuntimeError("secret from SDK"), RuntimeError("another secret")],
    )
    bedrock = FakeClient(list_guardrails=[{"guardrails": []}])

    batch = connector(agents, bedrock).collect()

    states = coverage_by_plane(batch)
    assert states[AGENT_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[AGENT_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert not batch.may_withdraw(AGENT_INVENTORY_PLANE)
    agent_keys = {
        item.asset.natural_key for item in batch.assets if item.asset.kind is AssetKind.AI_AGENT
    }
    assert agent_keys == {
        AGENT_ARN,
        f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/{second_id}",
    }
    assert "secret from SDK" not in str(batch)
    assert "RuntimeError" in (batch.coverage[0].detail or "")


def test_agent_list_failure_does_not_poison_guardrail_inventory_coverage() -> None:
    agents = FakeClient(list_agents=[PermissionError("credential-shaped detail")])
    bedrock = FakeClient(
        list_guardrails=[{"guardrails": [guardrail_summary()]}],
        get_guardrail=[guardrail_detail()],
    )

    batch = connector(agents, bedrock).collect()

    states = coverage_by_plane(batch)
    assert states[AGENT_INVENTORY_PLANE] is CoverageState.FAILED
    assert states[AGENT_RELATIONSHIP_PLANE] is CoverageState.FAILED
    assert states[GUARDRAIL_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[GUARDRAIL_RELATIONSHIP_PLANE] is CoverageState.FAILED
    assert batch.may_withdraw(GUARDRAIL_INVENTORY_PLANE)
    assert not batch.may_withdraw(AGENT_INVENTORY_PLANE)


def test_unresolved_attachment_is_not_fabricated_and_relationship_coverage_is_partial() -> None:
    agents = FakeClient(
        list_agents=[{"agentSummaries": [agent_summary()]}],
        get_agent=[agent_detail(guardrail_identifier="missingguardrail")],
    )
    bedrock = FakeClient(list_guardrails=[{"guardrails": []}])

    batch = connector(agents, bedrock).collect()

    states = coverage_by_plane(batch)
    assert states[AGENT_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[GUARDRAIL_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[AGENT_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert states[GUARDRAIL_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert not any(item.asset.kind is AssetKind.AI_GUARDRAIL for item in batch.assets)
    assert not any(item.kind is RelationshipKind.PROTECTED_BY for item in batch.relationships)


def test_inconsistent_guardrail_arn_is_rejected_without_hiding_agent_inventory() -> None:
    other_account_arn = f"arn:aws:bedrock:{REGION}:999999999999:guardrail/{GUARDRAIL_ID}"
    agents = FakeClient(
        list_agents=[{"agentSummaries": [agent_summary()]}],
        get_agent=[agent_detail()],
    )
    bedrock = FakeClient(
        list_guardrails=[{"guardrails": [guardrail_summary(arn=other_account_arn)]}]
    )

    batch = connector(agents, bedrock).collect()

    states = coverage_by_plane(batch)
    assert states[AGENT_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[GUARDRAIL_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[GUARDRAIL_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert not any(item.asset.kind is AssetKind.AI_GUARDRAIL for item in batch.assets)


def test_pagination_tokens_are_forwarded_and_repeated_tokens_fail_closed() -> None:
    agents = FakeClient(
        list_agents=[
            {"agentSummaries": [], "nextToken": "page-two"},
            {"agentSummaries": []},
        ]
    )
    bedrock = FakeClient(list_guardrails=[{"guardrails": []}])

    complete = connector(agents, bedrock).collect()

    assert coverage_by_plane(complete)[AGENT_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert agents.calls[1] == ("list_agents", {"nextToken": "page-two"})

    repeated = FakeClient(
        list_agents=[
            {"agentSummaries": [], "nextToken": "again"},
            {"agentSummaries": [], "nextToken": "again"},
        ]
    )
    failed = connector(repeated, FakeClient(list_guardrails=[{"guardrails": []}])).collect()

    assert coverage_by_plane(failed)[AGENT_INVENTORY_PLANE] is CoverageState.FAILED
