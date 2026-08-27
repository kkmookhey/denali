from datetime import UTC, datetime

from denali.connectors.demo import CAPABILITIES, CONNECTOR_ID, demo_batch
from denali.domain import AssetKind, RelationshipCategory


def test_demo_connector_is_transparently_identified_and_complete() -> None:
    batch = demo_batch(datetime(2026, 8, 26, tzinfo=UTC))
    assert batch.connector_id == CONNECTOR_ID
    assert CAPABILITIES.inventory is True
    assert CAPABILITIES.relationships is True
    assert CAPABILITIES.findings is False
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
