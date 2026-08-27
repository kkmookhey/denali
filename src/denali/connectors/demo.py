"""Transparent fixture connector for the local Inventory Preview experience."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from denali.domain import (
    AffectedResource,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.demo"
CAPABILITIES = ConnectorCapabilities(findings=True, inventory=True, relationships=True)
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


def demo_findings_batch(at: datetime | None = None) -> FindingBatch:
    observed_at = at or datetime.now(UTC)
    specs = (
        {
            "source_uid": "demo-finding-wildcard-agent-role",
            "rule_uid": "DENALI-DEMO-IAM-001",
            "title": "AI agent execution role carries wildcard data permissions",
            "description": (
                "The role used by the customer support agent can perform unrestricted "
                "data operations. A compromised prompt or tool path could therefore "
                "reach well beyond the records required by the agent."
            ),
            "risk": (
                "Wildcard permissions turn a narrow agent action into broad data-plane "
                "authority and materially increase the impact of prompt injection or tool abuse."
            ),
            "remediation": (
                "Replace wildcard actions and resources with the exact read and update "
                "operations required by the approved customer workflow."
            ),
            "severity": FindingSeverity.CRITICAL,
            "signal": "identity.overprivileged",
            "resource": AffectedResource(
                uid="demo:customer-agent-role",
                name="Customer Agent Role",
                resource_type="AWS IAM Role",
                provider="AWS",
                account_uid="123456789012",
                region="us-east-1",
            ),
            "compliance": {
                "OWASP Agentic": ("ASI03", "ASI05"),
                "NIST AI RMF": ("MAP 3.5", "MANAGE 2.4"),
            },
        },
        {
            "source_uid": "demo-finding-mcp-write-confirmation",
            "rule_uid": "DENALI-DEMO-MCP-002",
            "title": "Write-capable MCP tool does not require human confirmation",
            "description": (
                "The update-customer tool can change sensitive customer records without "
                "an independently enforced approval step."
            ),
            "risk": (
                "An agent can translate manipulated or ambiguous input directly into a "
                "persistent customer-data change."
            ),
            "remediation": (
                "Require confirmation for state-changing calls and enforce the decision "
                "at the tool boundary rather than in prompt text alone."
            ),
            "severity": FindingSeverity.HIGH,
            "signal": "tool.write_without_confirmation",
            "resource": AffectedResource(
                uid="demo:mcp:update-customer",
                name="Update Customer",
                resource_type="MCP Tool",
                provider="Denali demo",
            ),
            "compliance": {
                "OWASP Agentic": ("ASI02", "ASI09"),
                "OWASP LLM": ("LLM06",),
            },
        },
        {
            "source_uid": "demo-finding-guardrail-output-coverage",
            "rule_uid": "DENALI-DEMO-GRD-003",
            "title": "Guardrail output enforcement has not been independently verified",
            "description": (
                "The prompt-attack filter is configured, but this source has not observed "
                "or tested the output enforcement path."
            ),
            "risk": (
                "Configuration presence alone does not prove that unsafe generated content "
                "is blocked in the deployed path."
            ),
            "remediation": (
                "Run a non-destructive output-policy validation and retain the observed "
                "result as separate runtime evidence."
            ),
            "severity": FindingSeverity.MEDIUM,
            "signal": "guardrail.output_unverified",
            "resource": AffectedResource(
                uid="demo:customer-data-guardrail",
                name="Customer Data Guardrail",
                resource_type="AI Guardrail",
                provider="Denali demo",
            ),
            "compliance": {
                "OWASP LLM": ("LLM01",),
                "NIST AI RMF": ("MEASURE 2.7",),
            },
        },
    )
    findings = tuple(
        FindingAssertion(
            source_uid=str(spec["source_uid"]),
            rule_uid=str(spec["rule_uid"]),
            title=str(spec["title"]),
            description=str(spec["description"]),
            risk=str(spec["risk"]),
            remediation=str(spec["remediation"]),
            remediation_references=(),
            severity=spec["severity"],
            state=FindingState.OPEN,
            evaluation_result=EvaluationResult.FAIL,
            class_uid=2003,
            class_name="Compliance Finding",
            observed_at=observed_at,
            evidence=_finding_evidence(observed_at, str(spec["source_uid"])),
            affected_resources=(spec["resource"],),
            compliance=spec["compliance"],
            attributes={
                "fixture": True,
                "category": "AI Configuration",
                "product": "Denali Configuration Findings Preview",
                "denali_signal": spec["signal"],
            },
        )
        for spec in specs
    )
    return FindingBatch(
        connector_id=CONNECTOR_ID,
        connection_id="local-demo",
        run_id=f"demo-findings-{observed_at.isoformat()}",
        scope_key="configuration-preview",
        collected_at=observed_at,
        coverage=(
            Coverage(
                "demo_configuration_findings",
                CoverageState.COMPLETE,
                "configuration-preview",
            ),
        ),
        findings=findings,
        authoritative=True,
    )


def seed_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    tenant = os.environ.get("DENALI_TENANT_ID", DEFAULT_TENANT)
    migrate(dsn)
    repository = PostgresInventoryRepository(dsn)
    counts = repository.ingest(tenant, demo_batch())
    finding_counts = repository.ingest_findings(tenant, demo_findings_batch())
    issue_counts = repository.evaluate_issues(tenant)
    print(
        f"Seeded {counts['assets']} assets and {counts['relationships']} relationships "
        f"and {finding_counts['findings']} findings and "
        f"{issue_counts['confirmed_issues']} confirmed issues for tenant {tenant}"
    )


def _evidence(observed_at: datetime, locator: str) -> Evidence:
    return Evidence(
        source_type="denali_demo_fixture",
        locator=f"fixture://inventory-preview/{locator}",
        observed_at=observed_at,
        payload={"fixture": True, "scenario": "inventory-preview"},
    )


def _finding_evidence(observed_at: datetime, source_uid: str) -> Evidence:
    return Evidence(
        source_type="denali_demo_fixture",
        locator=f"fixture://configuration-preview/{source_uid}",
        observed_at=observed_at,
        payload={"fixture": True, "scenario": "configuration-preview"},
    )


if __name__ == "__main__":
    seed_main()
