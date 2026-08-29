"""Bounded live Bedrock management-activity collection from CloudTrail Event History.

CloudTrail Event History retains supported management events without requiring a
customer trail.  This connector deliberately collects only Bedrock model invocation
metadata and never enables Bedrock model-invocation logging or reads prompt/response
content.  Agent Runtime and other data-event coverage remain outside this plane.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from denali.connectors.activity_json import ActivityJsonConnector
from denali.domain import ActivityBatch, ConnectorCapabilities, Coverage, CoverageState
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.aws_bedrock_activity"
CAPABILITIES = ConnectorCapabilities(activity=True)
ACTIVITY_PLANE = "bedrock_management_activity"
EVENT_NAMES = (
    "Converse",
    "ConverseStream",
    "InvokeModel",
    "InvokeModelWithResponseStream",
)
MAX_PAGES_PER_EVENT = 40
MAX_RECORDS = 5_000


class AwsBedrockActivityConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(self, *, account_id: str, region: str, cloudtrail_client: Any) -> None:
        self.account_id = _required("account_id", account_id)
        self.region = _required("region", region)
        self.cloudtrail_client = cloudtrail_client

    def collect(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        connection_id: str | None = None,
    ) -> ActivityBatch:
        start = _aware("start_time", start_time)
        end = _aware("end_time", end_time)
        if start >= end:
            raise ValueError("start_time must be earlier than end_time")
        observed_at = datetime.now(UTC)
        connection = connection_id or f"aws:{self.account_id}"
        scope = f"aws:{self.account_id}:{self.region}:cloudtrail:event-history:bedrock"
        run_id = f"aws-bedrock-activity-{self.region}-{observed_at.isoformat()}"
        try:
            records, warnings = self._lookup(start, end)
        except Exception as error:
            detail = _safe_failure("cloudtrail:LookupEvents", error)
            return ActivityBatch(
                connector_id=self.connector_id,
                connection_id=connection,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=(Coverage(ACTIVITY_PLANE, CoverageState.FAILED, scope, detail),),
            )

        normalized = ActivityJsonConnector().collect(
            {"Records": records},
            format_name="aws-bedrock-cloudtrail",
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            source_locator=f"aws://cloudtrail/{self.region}/event-history",
        )
        normalization_detail = normalized.coverage[0].detail
        if normalization_detail:
            warnings.append(normalization_detail)
        state = (
            CoverageState.PARTIAL
            if warnings or normalized.coverage[0].state is not CoverageState.COMPLETE
            else CoverageState.COMPLETE
        )
        detail_parts = [
            "Collected CloudTrail Event History management events for "
            + ", ".join(EVENT_NAMES)
            + ". Agent Runtime and other Bedrock data events are outside this coverage plane."
        ]
        detail_parts.extend(warnings)
        return ActivityBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(ACTIVITY_PLANE, state, scope, " ".join(detail_parts)[:4_000]),),
            activities=normalized.activities,
        )

    def _lookup(
        self, start_time: datetime, end_time: datetime
    ) -> tuple[list[dict[str, Any]], list[str]]:
        records: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        for event_name in EVENT_NAMES:
            token: str | None = None
            seen_tokens: set[str] = set()
            completed = False
            for _ in range(MAX_PAGES_PER_EVENT):
                request: dict[str, Any] = {
                    "LookupAttributes": [
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    "StartTime": start_time,
                    "EndTime": end_time,
                    "MaxResults": 50,
                }
                if token:
                    request["NextToken"] = token
                response = self.cloudtrail_client.lookup_events(**request)
                events = response.get("Events") if isinstance(response, dict) else None
                if not isinstance(events, list):
                    raise ValueError("invalid response shape")
                for event in events:
                    if not isinstance(event, dict):
                        warnings.append(f"{event_name}: ignored a non-object event")
                        continue
                    uid = event.get("EventId")
                    if not isinstance(uid, str) or not uid:
                        warnings.append(f"{event_name}: ignored an event without EventId")
                        continue
                    records[uid] = event
                    if len(records) >= MAX_RECORDS:
                        warnings.append(f"record safety limit reached at {MAX_RECORDS}")
                        return list(records.values()), warnings
                next_token = response.get("NextToken")
                if next_token is None:
                    completed = True
                    break
                if (
                    not isinstance(next_token, str)
                    or not next_token
                    or next_token in seen_tokens
                ):
                    warnings.append(f"{event_name}: invalid or repeated pagination token")
                    break
                seen_tokens.add(next_token)
                token = next_token
            if not completed and not any(item.startswith(f"{event_name}:") for item in warnings):
                warnings.append(f"{event_name}: page safety limit reached")
        return list(records.values()), warnings


def scan_main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect privacy-safe Bedrock runtime metadata from CloudTrail Event History"
    )
    parser.add_argument("--region", help="AWS region; defaults to configured region")
    parser.add_argument("--profile", help="AWS shared-config profile")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        parser.error("--dsn or DENALI_DSN is required")
    if not 1 <= args.lookback_hours <= 24 * 90:
        parser.error("--lookback-hours must be between 1 and 2160")
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        message = "AWS activity collection requires: pip install 'denali-ai-security[aws]'"
        raise SystemExit(message) from error

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    region = args.region or session.region_name
    if not region:
        parser.error("--region or an AWS configured region is required")
    config = Config(
        connect_timeout=10,
        read_timeout=30,
        retries={"max_attempts": 3, "mode": "standard"},
    )
    identity = session.client("sts", config=config).get_caller_identity()
    account_id = identity.get("Account") if isinstance(identity, dict) else None
    if not isinstance(account_id, str) or not account_id:
        raise SystemExit("STS GetCallerIdentity returned no account identity")
    end_time = datetime.now(UTC)
    batch = AwsBedrockActivityConnector(
        account_id=account_id,
        region=region,
        cloudtrail_client=session.client("cloudtrail", region_name=region, config=config),
    ).collect(
        start_time=end_time - timedelta(hours=args.lookback_hours),
        end_time=end_time,
        connection_id=args.connection_id,
    )
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_activity(args.tenant_id, batch)
    print(
        json.dumps(
            {
                **result,
                "coverage": batch.coverage[0].state.value,
                "scope": batch.scope_key,
            }
        )
    )
    if batch.coverage[0].state is not CoverageState.COMPLETE:
        raise SystemExit(2)


def _safe_failure(operation: str, error: Exception) -> str:
    response = getattr(error, "response", None)
    code = None
    if isinstance(response, dict):
        error_data = response.get("Error")
        if isinstance(error_data, dict):
            candidate = error_data.get("Code")
            code = candidate if isinstance(candidate, str) and candidate else None
    return f"{operation}: {code or error.__class__.__name__}"


def _required(label: str, value: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty without surrounding whitespace")
    return value


def _aware(label: str, value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value
