from datetime import UTC, datetime

from denali.connectors.demo import (
    CAPABILITIES,
    CONNECTOR_ID,
    demo_activity_batch,
    demo_batch,
    demo_findings_batch,
    demo_software_batch,
    demo_vulnerability_batch,
)
from denali.domain import AssetKind, RelationshipCategory


def test_demo_connector_is_transparently_identified_and_complete() -> None:
    batch = demo_batch(datetime(2026, 8, 26, tzinfo=UTC))
    assert batch.connector_id == CONNECTOR_ID
    assert CAPABILITIES.inventory is True
    assert CAPABILITIES.relationships is True
    assert CAPABILITIES.findings is True
    assert CAPABILITIES.activity is True
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
    assert {finding.attributes["denali_signal"] for finding in batch.findings} == {
        "identity.overprivileged",
        "tool.write_without_confirmation",
        "guardrail.output_unverified",
    }


def test_demo_vulnerability_preview_is_transparent_and_correlated() -> None:
    observed_at = datetime(2026, 8, 26, tzinfo=UTC)
    software = demo_software_batch(observed_at)
    vulnerabilities = demo_vulnerability_batch(observed_at)

    component_refs = {
        item.asset for item in software.assets if item.asset.kind is AssetKind.SOFTWARE_COMPONENT
    }
    assert len(component_refs) == 3
    assert {item.component for item in vulnerabilities.vulnerabilities} == component_refs
    assert vulnerabilities.authoritative is True
    assert vulnerabilities.may_resolve_missing is True
    assert all(item.evidence.payload["fixture"] is True for item in vulnerabilities.vulnerabilities)
    assert all(item.attributes["fixture"] is True for item in vulnerabilities.vulnerabilities)


def test_demo_runtime_preview_separates_observation_from_risk() -> None:
    batch = demo_activity_batch(datetime(2026, 8, 26, tzinfo=UTC))

    assert len(batch.activities) == 6
    assert batch.coverage[0].state.value == "complete"
    assert {item.provider for item in batch.activities} == {
        "aws_bedrock",
        "mcp",
        "gcp_vertex_ai",
        "google_workspace_gemini",
        "microsoft_entra",
    }
    assert any(item.outcome.value == "failure" for item in batch.activities)
    assert all(item.evidence.payload["fixture"] is True for item in batch.activities)
