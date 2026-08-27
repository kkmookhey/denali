from datetime import UTC, datetime

from denali.connectors.demo import CAPABILITIES, CONNECTOR_ID, demo_batch, demo_findings_batch
from denali.domain import AssetKind, RelationshipCategory


def test_demo_connector_is_transparently_identified_and_complete() -> None:
    batch = demo_batch(datetime(2026, 8, 26, tzinfo=UTC))
    assert batch.connector_id == CONNECTOR_ID
    assert CAPABILITIES.inventory is True
    assert CAPABILITIES.relationships is True
    assert CAPABILITIES.findings is True
    assert all(item.evidence.source_type == "denali_demo_fixture" for item in batch.assets)
    assert batch.may_withdraw("demo_inventory") is True


def test_demo_inventory_exercises_ai_resource_and_authority_shapes() -> None:
    batch = demo_batch(datetime(2026, 8, 26, tzinfo=UTC))
    kinds = {item.asset.kind for item in batch.assets}
    assert {
        AssetKind.AI_AGENT,
        AssetKind.AI_MODEL,
        AssetKind.MCP_SERVER,
        AssetKind.AI_TOOL,
        AssetKind.AI_GUARDRAIL,
        AssetKind.IDENTITY,
        AssetKind.AI_DATASTORE,
    } <= kinds
    assert any(item.category is RelationshipCategory.CAPABILITY for item in batch.relationships)
    assert all(
        item.principal_ref is None or item.principal_ref.kind is AssetKind.IDENTITY
        for item in batch.relationships
    )


def test_demo_findings_are_explicit_and_authoritative_fixture_evidence() -> None:
    batch = demo_findings_batch(datetime(2026, 8, 26, tzinfo=UTC))

    assert len(batch.findings) == 3
    assert batch.authoritative is True
    assert batch.may_resolve_missing is True
    assert {finding.severity.value for finding in batch.findings} == {
        "critical",
        "high",
        "medium",
    }
    assert all(finding.evidence.payload["fixture"] is True for finding in batch.findings)
    assert all(finding.affected_resources for finding in batch.findings)
