"""Transparent fixture connector for the local Inventory Preview experience."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AffectedResource,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ComponentIdentity,
    ComponentScope,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    ExploitState,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
    SoftwareComponentAssertion,
    VulnerabilityAssertion,
    VulnerabilityBatch,
    VulnerabilityFixState,
    VulnerabilityMatchMethod,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.demo"
CAPABILITIES = ConnectorCapabilities(
    findings=True, inventory=True, relationships=True, activity=True
)
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


def demo_software_batch(at: datetime | None = None) -> InventoryBatch:
    observed_at = at or datetime.now(UTC)
    target = AssetRef(AssetKind.AI_WORKLOAD, "demo:eiger-api")
    specs = (
        (
            "denali-demo-model-server",
            "1.8.2",
            "pkg:pypi/denali-demo-model-server@1.8.2",
            "/app/site-packages/denali_demo_model_server",
        ),
        (
            "denali-demo-mcp-runtime",
            "1.6.0",
            "pkg:pypi/denali-demo-mcp-runtime@1.6.0",
            "/app/site-packages/denali_demo_mcp_runtime",
        ),
        (
            "denali-demo-vector-client",
            "0.9.4",
            "pkg:npm/denali-demo-vector-client@0.9.4",
            "/app/node_modules/denali-demo-vector-client",
        ),
    )
    components = tuple(
        SoftwareComponentAssertion(
            identity=ComponentIdentity(
                target=target,
                name=name,
                version=version,
                ecosystem="python" if purl.startswith("pkg:pypi") else "javascript",
                package_type="python" if purl.startswith("pkg:pypi") else "npm",
                purl=purl,
                location=location,
            ),
            coverage_plane="software_components",
            scope=ComponentScope.INSTALLED,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=Evidence(
                "denali_demo_fixture",
                f"fixture://vulnerability-preview/syft/{name}",
                observed_at,
                {"fixture": True, "scanner": "Syft", "artifact_id": f"demo-{name}"},
            ),
            licenses=("Apache-2.0",),
            attributes={
                "fixture": True,
                "syft": {"tool_version": "1.42.3-demo", "artifact_ids": [f"demo-{name}"]},
            },
        )
        for name, version, purl, location in specs
    )
    target_assertion = AssetAssertion(
        asset=target,
        coverage_plane="software_components",
        display_name="Eiger API",
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=Evidence(
            "denali_demo_fixture",
            "fixture://vulnerability-preview/syft/source",
            observed_at,
            {"fixture": True, "scanner": "Syft", "source_type": "image"},
        ),
        attributes={"fixture": True, "software_inventory": {"source": "Syft"}},
    )
    return InventoryBatch(
        connector_id="denali.demo.syft",
        connection_id="local-demo-syft",
        run_id=f"demo-syft-{observed_at.isoformat()}",
        scope_key="vulnerability-preview",
        collected_at=observed_at,
        coverage=(
            Coverage(
                "software_components",
                CoverageState.COMPLETE,
                "vulnerability-preview",
            ),
        ),
        assets=(target_assertion, *(item.asset_assertion() for item in components)),
        relationships=tuple(item.containment_assertion() for item in components),
    )


def demo_vulnerability_batch(at: datetime | None = None) -> VulnerabilityBatch:
    observed_at = at or datetime.now(UTC)
    target = AssetRef(AssetKind.AI_WORKLOAD, "demo:eiger-api")
    component_specs = (
        (
            "denali-demo-model-server",
            "1.8.2",
            "pkg:pypi/denali-demo-model-server@1.8.2",
            "/app/site-packages/denali_demo_model_server",
            "DEMO-2026-0001",
            "Unsafe model artifact deserialization in demo serving runtime",
            FindingSeverity.CRITICAL,
            9.8,
            VulnerabilityFixState.FIXED,
            ("1.8.5",),
            ExploitState.PUBLIC_EXPLOIT,
            VulnerabilityMatchMethod.EXACT_DIRECT,
            1.0,
        ),
        (
            "denali-demo-mcp-runtime",
            "1.6.0",
            "pkg:pypi/denali-demo-mcp-runtime@1.6.0",
            "/app/site-packages/denali_demo_mcp_runtime",
            "DEMO-2026-0002",
            "Authentication bypass in demo MCP transport",
            FindingSeverity.HIGH,
            8.1,
            VulnerabilityFixState.FIXED,
            ("1.8.0",),
            ExploitState.UNKNOWN,
            VulnerabilityMatchMethod.EXACT_DIRECT,
            1.0,
        ),
        (
            "denali-demo-vector-client",
            "0.9.4",
            "pkg:npm/denali-demo-vector-client@0.9.4",
            "/app/node_modules/denali-demo-vector-client",
            "DEMO-2026-0003",
            "Unbounded response parsing in demo vector client",
            FindingSeverity.MEDIUM,
            5.9,
            VulnerabilityFixState.NOT_FIXED,
            (),
            ExploitState.UNKNOWN,
            VulnerabilityMatchMethod.CPE,
            0.6,
        ),
    )
    vulnerabilities = []
    for (
        name,
        version,
        purl,
        location,
        vulnerability_id,
        title,
        severity,
        cvss_score,
        fix_state,
        fixed_versions,
        exploit_state,
        match_method,
        match_confidence,
    ) in component_specs:
        component = ComponentIdentity(
            target=target,
            name=name,
            version=version,
            ecosystem="python" if purl.startswith("pkg:pypi") else "javascript",
            package_type="python" if purl.startswith("pkg:pypi") else "npm",
            purl=purl,
            location=location,
        )
        evidence = Evidence(
            "denali_demo_fixture",
            f"fixture://vulnerability-preview/grype/{vulnerability_id}",
            observed_at,
            {
                "fixture": True,
                "scanner": "Grype",
                "match_type": match_method.value,
                "artifact": name,
            },
        )
        vulnerabilities.append(
            VulnerabilityAssertion(
                source_uid=f"demo-grype:{vulnerability_id}:{component.natural_key}",
                vulnerability_id=vulnerability_id,
                component=component.asset_ref,
                target=target,
                title=title,
                description=(
                    f"Transparent fixture: Grype matched {name} {version} in the Eiger "
                    "API image. This synthetic record exists only for product review."
                ),
                severity=severity,
                state=FindingState.OPEN,
                observed_at=observed_at,
                evidence=evidence,
                match_method=match_method,
                match_confidence=match_confidence,
                cvss_score=cvss_score,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                fix_state=fix_state,
                fixed_versions=fixed_versions,
                exploit_state=exploit_state,
                database_version="6.1.9-demo",
                database_built_at=observed_at,
                attributes={
                    "fixture": True,
                    "grype": {
                        "match_confidence_basis": "denali_derived_from_match_type",
                        "tool_version": "0.116.1-demo",
                    },
                },
            )
        )
    return VulnerabilityBatch(
        connector_id="denali.demo.grype",
        connection_id="local-demo-grype",
        run_id=f"demo-grype-{observed_at.isoformat()}",
        scope_key="vulnerability-preview",
        collected_at=observed_at,
        coverage=(Coverage("vulnerabilities", CoverageState.COMPLETE, "vulnerability-preview"),),
        vulnerabilities=tuple(vulnerabilities),
        authoritative=True,
    )


def demo_activity_batch(at: datetime | None = None) -> ActivityBatch:
    observed_at = at or datetime.now(UTC)
    refs = {
        "actor": AssetRef(AssetKind.IDENTITY, "demo:customer-agent-role"),
        "agent": AssetRef(AssetKind.AI_AGENT, "demo:customer-support-agent"),
        "model": AssetRef(AssetKind.AI_MODEL, "demo:anthropic.claude-3-5-sonnet"),
        "tool": AssetRef(AssetKind.AI_TOOL, "demo:mcp:update-customer"),
        "workload": AssetRef(AssetKind.AI_WORKLOAD, "demo:eiger-api"),
    }

    def linked(role: ActivityEntityRole, key: str, name: str) -> ActivityEntity:
        return ActivityEntity(
            role=role,
            external_uid=refs[key].natural_key,
            display_name=name,
            asset=refs[key],
            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
            confidence=1.0,
        )

    fixture_events = (
        (
            "demo-runtime-bedrock-converse",
            ActivityCategory.MODEL_INVOCATION,
            "aws.bedrock.Converse",
            "Customer Support Agent invoked Claude 3.5 Sonnet",
            ActivityOutcome.SUCCESS,
            "aws_bedrock",
            (
                linked(ActivityEntityRole.ACTOR, "actor", "Customer Agent Role"),
                linked(ActivityEntityRole.AGENT, "agent", "Customer Support Agent"),
                linked(ActivityEntityRole.MODEL, "model", "Claude 3.5 Sonnet"),
                linked(ActivityEntityRole.WORKLOAD, "workload", "Eiger API"),
            ),
        ),
        (
            "demo-runtime-tool-update",
            ActivityCategory.TOOL_INVOCATION,
            "mcp.tools.call",
            "Customer Support Agent called Update Customer",
            ActivityOutcome.SUCCESS,
            "mcp",
            (
                linked(ActivityEntityRole.ACTOR, "actor", "Customer Agent Role"),
                linked(ActivityEntityRole.AGENT, "agent", "Customer Support Agent"),
                linked(ActivityEntityRole.TOOL, "tool", "Update Customer"),
            ),
        ),
        (
            "demo-runtime-bedrock-denied",
            ActivityCategory.MODEL_INVOCATION,
            "aws.bedrock.InvokeModel",
            "Bedrock model invocation was denied",
            ActivityOutcome.FAILURE,
            "aws_bedrock",
            (
                linked(ActivityEntityRole.ACTOR, "actor", "Customer Agent Role"),
                linked(ActivityEntityRole.MODEL, "model", "Claude 3.5 Sonnet"),
            ),
        ),
    )
    activities = [
        ActivityRecord(
            source_uid=uid,
            category=category,
            activity_name=name,
            title=title,
            occurred_at=observed_at - timedelta(minutes=(index + 1) * 7),
            observed_at=observed_at,
            outcome=outcome,
            provider=provider,
            account_uid="123456789012" if provider == "aws_bedrock" else None,
            region="us-east-1" if provider == "aws_bedrock" else None,
            session_uid="demo-session-001",
            trace_uid=f"demo-trace-{index + 1:03d}",
            entities=entities,
            evidence=Evidence(
                "denali_demo_fixture",
                f"fixture://runtime-activity/{uid}",
                observed_at,
                {"fixture": True, "scenario": "runtime-activity", "event_name": name},
            ),
            attributes={"fixture": True},
        )
        for index, (uid, category, name, title, outcome, provider, entities) in enumerate(
            fixture_events
        )
    ]
    for index, (uid, provider, title, actor, app) in enumerate(
        (
            (
                "demo-runtime-vertex",
                "gcp_vertex_ai",
                "Vertex AI prediction completed",
                "analyst@example.com",
                "projects/demo/locations/us-central1/endpoints/42",
            ),
            (
                "demo-runtime-workspace",
                "google_workspace_gemini",
                "Gemini assisted content generation",
                "seller@example.com",
                "gemini_in_workspace_apps",
            ),
            (
                "demo-runtime-entra",
                "microsoft_entra",
                "Sign-in to Microsoft Copilot",
                "founder@example.com",
                "Microsoft Copilot",
            ),
        ),
        start=4,
    ):
        category = (
            ActivityCategory.MODEL_INVOCATION
            if provider == "gcp_vertex_ai"
            else ActivityCategory.AI_APP_SIGN_IN
            if provider == "microsoft_entra"
            else ActivityCategory.OTHER
        )
        activities.append(
            ActivityRecord(
                source_uid=uid,
                category=category,
                activity_name=f"{provider}.demo",
                title=title,
                occurred_at=observed_at - timedelta(minutes=index * 11),
                observed_at=observed_at,
                outcome=ActivityOutcome.SUCCESS,
                provider=provider,
                entities=(
                    ActivityEntity(ActivityEntityRole.ACTOR, actor, actor),
                    ActivityEntity(ActivityEntityRole.APPLICATION, app, app),
                ),
                evidence=Evidence(
                    "denali_demo_fixture",
                    f"fixture://runtime-activity/{uid}",
                    observed_at,
                    {"fixture": True, "scenario": "runtime-activity"},
                ),
                attributes={"fixture": True},
            )
        )
    return ActivityBatch(
        connector_id=CONNECTOR_ID,
        connection_id="local-demo-runtime",
        run_id=f"demo-runtime-{observed_at.isoformat()}",
        scope_key="runtime-preview",
        collected_at=observed_at,
        coverage=(Coverage("runtime_activity", CoverageState.COMPLETE, "runtime-preview"),),
        activities=tuple(activities),
    )


def seed_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    tenant = os.environ.get("DENALI_TENANT_ID", DEFAULT_TENANT)
    migrate(dsn)
    repository = PostgresInventoryRepository(dsn)
    counts = repository.ingest(tenant, demo_batch())
    software_counts = repository.ingest(tenant, demo_software_batch())
    finding_counts = repository.ingest_findings(tenant, demo_findings_batch())
    vulnerability_counts = repository.ingest_vulnerabilities(tenant, demo_vulnerability_batch())
    activity_counts = repository.ingest_activity(tenant, demo_activity_batch())
    issue_counts = repository.evaluate_issues(tenant)
    print(
        f"Seeded {counts['assets']} assets and {counts['relationships']} relationships "
        f"plus {software_counts['assets'] - 1} software components and "
        f"{finding_counts['findings']} findings and "
        f"{vulnerability_counts['vulnerabilities']} vulnerabilities and "
        f"{activity_counts['activities']} runtime activities and "
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
