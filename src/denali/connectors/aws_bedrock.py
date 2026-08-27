"""Native, read-only AWS Bedrock inventory for one account and region.

Coverage is deliberately split by API family. A successful ListAgents call cannot
withdraw guardrails when ListGuardrails failed, and unresolved guardrail attachments do
not become fabricated assets.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from datetime import UTC, datetime
from typing import Any

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

CONNECTOR_ID = "denali.aws_bedrock"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
AGENT_INVENTORY_PLANE = "aws_bedrock_agent_inventory"
AGENT_RELATIONSHIP_PLANE = "aws_bedrock_agent_relationships"
GUARDRAIL_INVENTORY_PLANE = "aws_bedrock_guardrail_inventory"
GUARDRAIL_RELATIONSHIP_PLANE = "aws_bedrock_guardrail_relationships"
MAX_PAGES = 1_000

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_AGENT_ID_RE = re.compile(r"^[0-9A-Za-z]{10}$")
_GUARDRAIL_ID_RE = re.compile(r"^[a-z0-9]+$")


class AwsDiscoveryError(RuntimeError):
    """A safe discovery failure that contains no SDK response or credential text."""


class AwsBedrockRegionConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        agent_client: Any,
        bedrock_client: Any,
        partition: str = "aws",
    ) -> None:
        if not _ACCOUNT_RE.fullmatch(account_id):
            raise ValueError("AWS account_id must be 12 digits")
        if not _REGION_RE.fullmatch(region):
            raise ValueError("AWS region has an invalid shape")
        if not partition or ":" in partition:
            raise ValueError("AWS partition has an invalid shape")
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.agent_client = agent_client
        self.bedrock_client = bedrock_client

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"aws:{self.account_id}"
        scope = f"account={self.account_id},region={self.region}"
        assets: dict[AssetRef, AssetAssertion] = {}
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion] = {}
        guardrail_index: dict[str, AssetRef] = {}

        guardrail_warnings: list[str] = []
        agent_warnings: list[str] = []
        attachment_warnings: list[str] = []
        guardrail_list_succeeded = False
        agent_list_succeeded = False

        try:
            summaries = _paginate(
                self.bedrock_client,
                "list_guardrails",
                "guardrails",
            )
            guardrail_list_succeeded = True
            self._collect_guardrails(
                summaries,
                observed_at=observed_at,
                assets=assets,
                index=guardrail_index,
                warnings=guardrail_warnings,
            )
        except AwsDiscoveryError as error:
            guardrail_warnings.append(str(error))

        try:
            summaries = _paginate(
                self.agent_client,
                "list_agents",
                "agentSummaries",
            )
            agent_list_succeeded = True
            self._collect_agents(
                summaries,
                observed_at=observed_at,
                assets=assets,
                relationships=relationships,
                guardrail_index=guardrail_index,
                guardrail_list_succeeded=guardrail_list_succeeded,
                warnings=agent_warnings,
                attachment_warnings=attachment_warnings,
            )
        except AwsDiscoveryError as error:
            agent_warnings.append(str(error))

        agent_state = _coverage_state(agent_list_succeeded, agent_warnings)
        guardrail_state = _coverage_state(guardrail_list_succeeded, guardrail_warnings)
        relationship_warnings = [*agent_warnings, *attachment_warnings]
        agent_relationship_state = _coverage_state(agent_list_succeeded, relationship_warnings)
        guardrail_relationship_succeeded = agent_list_succeeded and guardrail_list_succeeded
        guardrail_relationship_state = _coverage_state(
            guardrail_relationship_succeeded,
            [*agent_warnings, *guardrail_warnings, *attachment_warnings],
        )

        return InventoryBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection,
            run_id=f"aws-bedrock-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(
                    AGENT_INVENTORY_PLANE,
                    agent_state,
                    scope,
                    _detail(agent_warnings),
                ),
                Coverage(
                    AGENT_RELATIONSHIP_PLANE,
                    agent_relationship_state,
                    scope,
                    _detail(relationship_warnings),
                ),
                Coverage(
                    GUARDRAIL_INVENTORY_PLANE,
                    guardrail_state,
                    scope,
                    _detail(guardrail_warnings),
                ),
                Coverage(
                    GUARDRAIL_RELATIONSHIP_PLANE,
                    guardrail_relationship_state,
                    scope,
                    _detail([*agent_warnings, *guardrail_warnings, *attachment_warnings]),
                ),
            ),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _collect_guardrails(
        self,
        summaries: list[Any],
        *,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        index: dict[str, AssetRef],
        warnings: list[str],
    ) -> None:
        for position, raw in enumerate(summaries):
            if not isinstance(raw, dict):
                warnings.append(f"list_guardrails item {position}: expected object")
                continue
            guardrail_id = _string(raw.get("id"))
            name = _string(raw.get("name"))
            arn = _string(raw.get("arn"))
            version = _string(raw.get("version"))
            if not guardrail_id or not name or not arn or not version:
                warnings.append(f"list_guardrails item {position}: missing required identity")
                continue
            if not _valid_guardrail_arn(
                arn,
                partition=self.partition,
                account_id=self.account_id,
                region=self.region,
                guardrail_id=guardrail_id,
            ):
                warnings.append(f"list_guardrails item {position}: inconsistent guardrail ARN")
                continue

            ref = AssetRef(AssetKind.AI_GUARDRAIL, arn)
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock",
                "account_id": self.account_id,
                "region": self.region,
                "guardrail_id": guardrail_id,
                "version": version,
                "status": _string(raw.get("status")) or "UNKNOWN",
                "description": (_string(raw.get("description")) or "")[:500],
                "configuration_observed": False,
            }
            evidence = self._evidence(
                observed_at,
                service="bedrock",
                operation="ListGuardrails",
                resource_id=guardrail_id,
            )
            try:
                detail = self.bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id,
                    guardrailVersion=version,
                )
                if not isinstance(detail, dict):
                    raise AwsDiscoveryError("GetGuardrail: invalid response shape")
                detail_arn = _string(detail.get("guardrailArn"))
                detail_id = _string(detail.get("guardrailId"))
                if detail_arn != arn or detail_id != guardrail_id:
                    raise AwsDiscoveryError("GetGuardrail: identity did not match ListGuardrails")
                attributes.update(_guardrail_attributes(detail))
                attributes["configuration_observed"] = True
                evidence = self._evidence(
                    observed_at,
                    service="bedrock",
                    operation="GetGuardrail",
                    resource_id=guardrail_id,
                )
            except Exception as error:  # SDK exception text may contain request material.
                warnings.append(_safe_failure("GetGuardrail", error, guardrail_id))

            self._add_asset(
                assets,
                ref,
                display_name=name,
                plane=GUARDRAIL_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            index[guardrail_id] = ref
            index[arn] = ref

    def _collect_agents(
        self,
        summaries: list[Any],
        *,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        guardrail_index: dict[str, AssetRef],
        guardrail_list_succeeded: bool,
        warnings: list[str],
        attachment_warnings: list[str],
    ) -> None:
        for position, raw in enumerate(summaries):
            if not isinstance(raw, dict):
                warnings.append(f"list_agents item {position}: expected object")
                continue
            agent_id = _string(raw.get("agentId"))
            if not agent_id or not _AGENT_ID_RE.fullmatch(agent_id):
                warnings.append(f"list_agents item {position}: missing or invalid agentId")
                continue
            expected_arn = (
                f"arn:{self.partition}:bedrock:{self.region}:{self.account_id}:agent/{agent_id}"
            )
            ref = AssetRef(AssetKind.AI_AGENT, expected_arn)
            display_name = _string(raw.get("agentName")) or agent_id
            evidence = self._evidence(
                observed_at,
                service="bedrock-agent",
                operation="ListAgents",
                resource_id=agent_id,
            )
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock-agent",
                "account_id": self.account_id,
                "region": self.region,
                "agent_id": agent_id,
                "status": _string(raw.get("agentStatus")) or "UNKNOWN",
                "description": (_string(raw.get("description")) or "")[:500],
                "configuration_observed": False,
                "arn_source": "constructed_from_list_identity",
            }
            try:
                response = self.agent_client.get_agent(agentId=agent_id)
                detail = response.get("agent") if isinstance(response, dict) else None
                if not isinstance(detail, dict):
                    raise AwsDiscoveryError("GetAgent: invalid response shape")
                returned_arn = _string(detail.get("agentArn"))
                if returned_arn != expected_arn:
                    raise AwsDiscoveryError("GetAgent: agentArn did not match regional identity")
                attributes.update(_agent_attributes(detail))
                attributes["configuration_observed"] = True
                attributes["arn_source"] = "get_agent"
                display_name = _string(detail.get("agentName")) or display_name
                evidence = self._evidence(
                    observed_at,
                    service="bedrock-agent",
                    operation="GetAgent",
                    resource_id=agent_id,
                )
            except Exception as error:
                warnings.append(_safe_failure("GetAgent", error, agent_id))
                self._add_asset(
                    assets,
                    ref,
                    display_name=display_name,
                    plane=AGENT_INVENTORY_PLANE,
                    evidence=evidence,
                    attributes=attributes,
                )
                continue

            self._add_asset(
                assets,
                ref,
                display_name=display_name,
                plane=AGENT_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            self._agent_relationships(
                ref,
                attributes=attributes,
                observed_at=observed_at,
                assets=assets,
                relationships=relationships,
                guardrail_index=guardrail_index,
                guardrail_list_succeeded=guardrail_list_succeeded,
                warnings=warnings,
                attachment_warnings=attachment_warnings,
                evidence=evidence,
            )

    def _agent_relationships(
        self,
        agent_ref: AssetRef,
        *,
        attributes: dict[str, Any],
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        guardrail_index: dict[str, AssetRef],
        guardrail_list_succeeded: bool,
        warnings: list[str],
        attachment_warnings: list[str],
        evidence: Evidence,
    ) -> None:
        model_id = _string(attributes.get("foundation_model"))
        if model_id:
            model_ref = AssetRef(AssetKind.AI_MODEL, f"aws:bedrock:model:{model_id}")
            self._add_asset(
                assets,
                model_ref,
                display_name=model_id,
                plane=AGENT_INVENTORY_PLANE,
                evidence=evidence,
                attributes={"provider": "aws_bedrock", "model_id": model_id},
            )
            self._add_relationship(
                relationships,
                agent_ref,
                model_ref,
                RelationshipKind.USES,
                plane=AGENT_RELATIONSHIP_PLANE,
                evidence=evidence,
            )

        role_arn = _string(attributes.get("role_arn"))
        if role_arn:
            if _valid_role_arn(role_arn, self.partition, self.account_id):
                identity_ref = AssetRef(AssetKind.IDENTITY, role_arn)
                self._add_asset(
                    assets,
                    identity_ref,
                    display_name=role_arn.rsplit("/", 1)[-1],
                    plane=AGENT_INVENTORY_PLANE,
                    evidence=evidence,
                    attributes={"provider": "aws", "principal_type": "iam_role"},
                )
                self._add_relationship(
                    relationships,
                    agent_ref,
                    identity_ref,
                    RelationshipKind.RUNS_AS,
                    plane=AGENT_RELATIONSHIP_PLANE,
                    evidence=evidence,
                    principal_ref=identity_ref,
                    agent_ref=agent_ref,
                )
            else:
                warnings.append("GetAgent: execution role ARN was outside the scanned account")

        guardrail_identifier = _string(attributes.get("guardrail_identifier"))
        if guardrail_identifier:
            guardrail_ref = guardrail_index.get(guardrail_identifier)
            if guardrail_ref is None:
                if guardrail_list_succeeded:
                    attachment_warnings.append(
                        "GetAgent: guardrail attachment did not resolve to native "
                        "regional inventory"
                    )
                return
            self._add_relationship(
                relationships,
                agent_ref,
                guardrail_ref,
                RelationshipKind.PROTECTED_BY,
                plane=GUARDRAIL_RELATIONSHIP_PLANE,
                evidence=evidence,
                attributes={"guardrail_version": attributes.get("guardrail_version")},
                agent_ref=agent_ref,
            )

    def _add_asset(
        self,
        assets: dict[AssetRef, AssetAssertion],
        ref: AssetRef,
        *,
        display_name: str,
        plane: str,
        evidence: Evidence,
        attributes: dict[str, Any],
    ) -> None:
        assets.setdefault(
            ref,
            AssetAssertion(
                asset=ref,
                coverage_plane=plane,
                display_name=display_name,
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=evidence,
                attributes=attributes,
            ),
        )

    def _add_relationship(
        self,
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        source: AssetRef,
        target: AssetRef,
        kind: RelationshipKind,
        *,
        plane: str,
        evidence: Evidence,
        attributes: dict[str, Any] | None = None,
        principal_ref: AssetRef | None = None,
        agent_ref: AssetRef | None = None,
    ) -> None:
        relationships.setdefault(
            (source, target, kind),
            RelationshipAssertion(
                source=source,
                target=target,
                coverage_plane=plane,
                kind=kind,
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=evidence,
                attributes=attributes or {},
                principal_ref=principal_ref,
                agent_ref=agent_ref,
            ),
        )

    def _evidence(
        self,
        observed_at: datetime,
        *,
        service: str,
        operation: str,
        resource_id: str,
    ) -> Evidence:
        return Evidence(
            source_type="aws_control_plane",
            locator=(f"aws://{self.account_id}/{self.region}/{service}/{operation}/{resource_id}"),
            observed_at=observed_at,
            payload={
                "account_id": self.account_id,
                "region": self.region,
                "service": service,
                "operation": operation,
                "resource_id": resource_id,
            },
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Discover AWS Bedrock AI inventory")
    parser.add_argument(
        "--regions", help="comma-separated AWS regions; defaults to configured region"
    )
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
        raise SystemExit("AWS discovery requires: pip install 'denali-ai-security[aws]'") from error

    session = boto3.Session(profile_name=args.profile)
    configured_region = session.region_name
    regions = [
        item.strip()
        for item in (args.regions or configured_region or "").split(",")
        if item.strip()
    ]
    if not regions:
        raise SystemExit("--regions or an AWS configured region is required")
    config = Config(
        connect_timeout=10,
        read_timeout=30,
        retries={"max_attempts": 3, "mode": "standard"},
    )
    identity = session.client("sts", config=config).get_caller_identity()
    account_id = _string(identity.get("Account"))
    identity_arn = _string(identity.get("Arn"))
    if not account_id or not identity_arn:
        raise SystemExit("STS GetCallerIdentity returned no account identity")
    partition = identity_arn.split(":", 2)[1] if identity_arn.startswith("arn:") else "aws"

    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    failed = False
    for region in regions:
        connector = AwsBedrockRegionConnector(
            account_id=account_id,
            region=region,
            partition=partition,
            agent_client=session.client("bedrock-agent", region_name=region, config=config),
            bedrock_client=session.client("bedrock", region_name=region, config=config),
        )
        batch = connector.collect(connection_id=args.connection_id)
        result = repository.ingest(args.tenant_id, batch)
        states = ",".join(f"{item.plane}={item.state.value}" for item in batch.coverage)
        print(
            f"Scanned AWS {account_id}/{region}: {result['assets']} assets, "
            f"{result['relationships']} relationships; {states}"
        )
        failed = failed or any(item.state is not CoverageState.COMPLETE for item in batch.coverage)
    if failed:
        raise SystemExit(2)


def _paginate(client: Any, operation: str, result_key: str, **parameters: Any) -> list[Any]:
    output: list[Any] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(MAX_PAGES):
        request = dict(parameters)
        if token:
            request["nextToken"] = token
        try:
            response = getattr(client, operation)(**request)
        except Exception as error:
            raise AwsDiscoveryError(_safe_failure(operation, error)) from error
        if not isinstance(response, dict) or not isinstance(response.get(result_key), list):
            raise AwsDiscoveryError(f"{operation}: invalid response shape")
        output.extend(response[result_key])
        next_token = response.get("nextToken")
        if next_token is None:
            return output
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise AwsDiscoveryError(f"{operation}: invalid or repeated pagination token")
        seen_tokens.add(next_token)
        token = next_token
    raise AwsDiscoveryError(f"{operation}: exceeded {MAX_PAGES} page safety limit")


def _agent_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    instruction = _string(detail.get("instruction"))
    guardrail = detail.get("guardrailConfiguration")
    if not isinstance(guardrail, dict):
        guardrail = {}
    return {
        "status": _string(detail.get("agentStatus")) or "UNKNOWN",
        "description": (_string(detail.get("description")) or "")[:500],
        "foundation_model": _string(detail.get("foundationModel")),
        "role_arn": _string(detail.get("agentResourceRoleArn")),
        "guardrail_identifier": _string(guardrail.get("guardrailIdentifier")),
        "guardrail_version": _string(guardrail.get("guardrailVersion")),
        "instruction_configured": bool(instruction),
        "instruction_sha256": hashlib.sha256(instruction.encode()).hexdigest()
        if instruction
        else None,
        "instruction_length": len(instruction) if instruction else 0,
        "customer_kms_key_configured": bool(detail.get("customerEncryptionKeyArn")),
        "idle_session_ttl_seconds": detail.get("idleSessionTTLInSeconds"),
        "memory_configured": isinstance(detail.get("memoryConfiguration"), dict),
        "prompt_override_configured": isinstance(detail.get("promptOverrideConfiguration"), dict),
    }


def _guardrail_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    content_policy = detail.get("contentPolicy")
    filters = content_policy.get("filters", []) if isinstance(content_policy, dict) else []
    normalized_filters = [
        {
            key: item.get(key)
            for key in (
                "type",
                "inputStrength",
                "outputStrength",
                "inputEnabled",
                "outputEnabled",
                "inputAction",
                "outputAction",
            )
            if item.get(key) is not None
        }
        for item in filters
        if isinstance(item, dict)
    ]
    sensitive_policy = detail.get("sensitiveInformationPolicy")
    pii_entities = (
        sensitive_policy.get("piiEntities", []) if isinstance(sensitive_policy, dict) else []
    )
    topic_policy = detail.get("topicPolicy")
    topics = topic_policy.get("topics", []) if isinstance(topic_policy, dict) else []
    word_policy = detail.get("wordPolicy")
    words = word_policy.get("words", []) if isinstance(word_policy, dict) else []
    managed_lists = word_policy.get("managedWordLists", []) if isinstance(word_policy, dict) else []
    automated = detail.get("automatedReasoningPolicy")
    return {
        "version": _string(detail.get("version")) or "DRAFT",
        "status": _string(detail.get("status")) or "UNKNOWN",
        "content_filters": normalized_filters,
        "pii_entity_types": sorted(
            {
                str(item.get("type"))
                for item in pii_entities
                if isinstance(item, dict) and item.get("type")
            }
        ),
        "regex_filter_count": len(sensitive_policy.get("regexes", []))
        if isinstance(sensitive_policy, dict)
        else 0,
        "denied_topic_count": len(topics),
        "word_filter_count": len(words),
        "managed_word_list_types": sorted(
            {
                str(item.get("type"))
                for item in managed_lists
                if isinstance(item, dict) and item.get("type")
            }
        ),
        "blocked_input_message_configured": bool(detail.get("blockedInputMessaging")),
        "blocked_output_message_configured": bool(detail.get("blockedOutputsMessaging")),
        "kms_key_configured": bool(detail.get("kmsKeyArn")),
        "automated_reasoning_policy_count": len(automated.get("policies", []))
        if isinstance(automated, dict)
        else 0,
    }


def _coverage_state(succeeded: bool, warnings: list[str]) -> CoverageState:
    if not succeeded:
        return CoverageState.FAILED
    return CoverageState.PARTIAL if warnings else CoverageState.COMPLETE


def _detail(warnings: list[str]) -> str | None:
    return "; ".join(dict.fromkeys(warnings))[:2_000] if warnings else None


def _safe_failure(operation: str, error: Exception, resource_id: str | None = None) -> str:
    resource = f" for {resource_id}" if resource_id else ""
    return f"{operation}{resource}: {error.__class__.__name__}"


def _valid_guardrail_arn(
    arn: str,
    *,
    partition: str,
    account_id: str,
    region: str,
    guardrail_id: str,
) -> bool:
    parts = arn.split(":", 5)
    return (
        len(parts) == 6
        and parts[:3] == ["arn", partition, "bedrock"]
        and parts[3] == region
        and parts[4] == account_id
        and parts[5] == f"guardrail/{guardrail_id}"
        and bool(_GUARDRAIL_ID_RE.fullmatch(guardrail_id))
    )


def _valid_role_arn(arn: str, partition: str, account_id: str) -> bool:
    parts = arn.split(":", 5)
    return (
        len(parts) == 6
        and parts[:3] == ["arn", partition, "iam"]
        and parts[3] == ""
        and parts[4] == account_id
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
    )


def _string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


if __name__ == "__main__":
    scan_main()
