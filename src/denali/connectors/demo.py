"""Transparent fixture connector for the local Inventory Preview experience."""

from __future__ import annotations

import os
from datetime import UTC, datetime

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

CONNECTOR_ID = "denali.demo"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
DEFAULT_TENANT = "00000000-0000-4000-8000-000000000001"


def demo_batch(at: datetime | None = None) -> InventoryBatch:
    observed_at = at or datetime.now(UTC)
    refs = {
        "repo": AssetRef(AssetKind.CODE_REPOSITORY, "github:denali/eiger-demo"),
        "framework": AssetRef(AssetKind.AI_FRAMEWORK, "langchain"),
        "agent": AssetRef(AssetKind.AI_AGENT, "demo:customer-support-agent"),
        "model": AssetRef(AssetKind.AI_MODEL, "demo:anthropic.claude-3-5-sonnet"),
        "mcp": AssetRef(AssetKind.MCP_SERVER, "demo:customer-operations-mcp"),
        "read_tool": AssetRef(AssetKind.AI_TOOL, "demo:mcp:get-customer"),
        "write_tool": AssetRef(AssetKind.AI_TOOL, "demo:mcp:update-customer"),
        "guardrail": AssetRef(AssetKind.AI_GUARDRAIL, "demo:customer-data-guardrail"),
        "identity": AssetRef(AssetKind.IDENTITY, "demo:customer-agent-role"),
        "workload": AssetRef(AssetKind.AI_WORKLOAD, "demo:eiger-api"),
        "data": AssetRef(AssetKind.AI_DATASTORE, "demo:customer-records"),
    }
    names = {
        "repo": "Eiger Demo",
        "framework": "LangChain",
        "agent": "Customer Support Agent",
        "model": "Claude 3.5 Sonnet",
        "mcp": "Customer Operations MCP",
        "read_tool": "Get Customer",
        "write_tool": "Update Customer",
        "guardrail": "Customer Data Guardrail",
        "identity": "Customer Agent Role",
        "workload": "Eiger API",
        "data": "Customer Records",
    }
    attributes = {
        "repo": {"provider": "GitHub", "default_branch": "main"},
        "framework": {"language": "python"},
        "agent": {"deployment_type": "application", "environment": "demo"},
        "model": {"provider": "Anthropic", "managed": True},
        "mcp": {"transport": "streamable-http", "hosting_type": "self-hosted"},
        "read_tool": {"read_capability": True, "write_capability": False},
        "write_tool": {"read_capability": True, "write_capability": True},
        "guardrail": {"prompt_attack_filter": "high", "status": "enabled"},
        "identity": {"provider": "AWS", "principal_type": "iam_role"},
        "workload": {"runtime": "container", "environment": "demo"},
        "data": {"classification": "sensitive", "provider": "AWS"},
    }
    assets = tuple(
        AssetAssertion(
            asset=ref,
            coverage_plane="demo_inventory",
            display_name=names[key],
            assertion_type=AssertionType.EXTERNALLY_VERIFIED,
            confidence=1.0,
            evidence=_evidence(observed_at, f"asset/{key}"),
            attributes=attributes[key],
        )
        for key, ref in refs.items()
    )
    relationship_specs = (
        ("agent", "repo", RelationshipKind.DEFINED_IN),
        ("repo", "framework", RelationshipKind.USES),
        ("agent", "model", RelationshipKind.USES),
        ("agent", "mcp", RelationshipKind.CONNECTS_TO),
        ("agent", "read_tool", RelationshipKind.CAN_INVOKE),
        ("agent", "write_tool", RelationshipKind.CAN_INVOKE),
        ("write_tool", "data", RelationshipKind.CAN_WRITE),
        ("read_tool", "data", RelationshipKind.CAN_READ),
        ("agent", "identity", RelationshipKind.RUNS_AS),
        ("agent", "workload", RelationshipKind.HOSTED_ON),
        ("agent", "guardrail", RelationshipKind.PROTECTED_BY),
    )
    relationships = tuple(
        RelationshipAssertion(
            source=refs[source],
            target=refs[target],
            coverage_plane="demo_relationships",
            kind=kind,
            assertion_type=AssertionType.EXTERNALLY_VERIFIED,
            confidence=1.0,
            evidence=_evidence(observed_at, f"relationship/{source}/{kind.value}/{target}"),
            principal_ref=refs["identity"] if kind is RelationshipKind.RUNS_AS else None,
            agent_ref=refs["agent"] if kind.category.value == "capability" else None,
        )
        for source, target, kind in relationship_specs
    )
    return InventoryBatch(
        connector_id=CONNECTOR_ID,
        connection_id="local-demo",
        run_id=f"demo-{observed_at.isoformat()}",
        scope_key="inventory-preview",
        collected_at=observed_at,
        coverage=(
            Coverage("demo_inventory", CoverageState.COMPLETE, "inventory-preview"),
            Coverage("demo_relationships", CoverageState.COMPLETE, "inventory-preview"),
        ),
        assets=assets,
        relationships=relationships,
    )


def seed_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    tenant = os.environ.get("DENALI_TENANT_ID", DEFAULT_TENANT)
    migrate(dsn)
    counts = PostgresInventoryRepository(dsn).ingest(tenant, demo_batch())
    print(
        f"Seeded {counts['assets']} assets and {counts['relationships']} relationships "
        f"for tenant {tenant}"
    )


def _evidence(observed_at: datetime, locator: str) -> Evidence:
    return Evidence(
        source_type="denali_demo_fixture",
        locator=f"fixture://inventory-preview/{locator}",
        observed_at=observed_at,
        payload={"fixture": True, "scenario": "inventory-preview"},
    )


if __name__ == "__main__":
    seed_main()
