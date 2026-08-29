"""Bounded live Vertex AI activity collection from Google Cloud Logging."""

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

CONNECTOR_ID = "denali.gcp_vertex_activity"
CAPABILITIES = ConnectorCapabilities(activity=True)
ACTIVITY_PLANE = "vertex_cloud_audit_activity"
MAX_RECORDS = 5_000


class GcpVertexActivityConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(self, *, project_id: str, logging_client: Any) -> None:
        self.project_id = _required("project_id", project_id)
        self.logging_client = logging_client

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
        connection = connection_id or f"gcp:{self.project_id}"
        scope = f"gcp:{self.project_id}:cloud-logging:vertex-ai"
        run_id = f"gcp-vertex-activity-{observed_at.isoformat()}"
        filter_text = (
            'protoPayload.serviceName="aiplatform.googleapis.com" '
            f'AND timestamp>="{start.astimezone(UTC).isoformat()}" '
            f'AND timestamp<="{end.astimezone(UTC).isoformat()}"'
        )
        try:
            iterator = self.logging_client.list_entries(
                resource_names=[f"projects/{self.project_id}"],
                filter_=filter_text,
                order_by="timestamp asc",
                page_size=1_000,
            )
            entries: list[dict[str, Any]] = []
            truncated = False
            for entry in iterator:
                if len(entries) >= MAX_RECORDS:
                    truncated = True
                    break
                representation = entry.to_api_repr() if hasattr(entry, "to_api_repr") else entry
                if not isinstance(representation, dict):
                    raise ValueError("invalid log entry shape")
                entries.append(representation)
        except Exception as error:
            return ActivityBatch(
                connector_id=self.connector_id,
                connection_id=connection,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=(
                    Coverage(
                        ACTIVITY_PLANE,
                        CoverageState.FAILED,
                        scope,
                        _safe_failure("logging:ListEntries", error),
                    ),
                ),
            )

        normalized = ActivityJsonConnector().collect(
            {"entries": entries},
            format_name="gcp-vertex-audit",
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            source_locator=f"gcp://logging/projects/{self.project_id}/vertex-ai",
        )
        warnings: list[str] = []
        if truncated:
            warnings.append(f"record safety limit reached at {MAX_RECORDS}")
        if normalized.coverage[0].detail:
            warnings.append(normalized.coverage[0].detail)
        state = (
            CoverageState.PARTIAL
            if warnings or normalized.coverage[0].state is not CoverageState.COMPLETE
            else CoverageState.COMPLETE
        )
        detail = (
            "Queried Vertex AI Cloud Audit Log entries to completion for the declared time "
            "window. Event availability remains governed by the project's audit-log settings."
        )
        if warnings:
            detail += " " + " ".join(warnings)
        return ActivityBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(ACTIVITY_PLANE, state, scope, detail[:4_000]),),
            activities=normalized.activities,
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Vertex AI activity metadata from Google Cloud Logging"
    )
    parser.add_argument("--project-id", help="Google Cloud project; defaults to ADC project")
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
    if not 1 <= args.lookback_hours <= 24 * 30:
        parser.error("--lookback-hours must be between 1 and 720")
    try:
        import google.auth
        from google.cloud import logging as cloud_logging
    except ImportError as error:
        message = "GCP activity collection requires: pip install 'denali-ai-security[gcp]'"
        raise SystemExit(message) from error

    credentials, default_project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
    )
    project_id = args.project_id or default_project
    if not project_id:
        parser.error("--project-id is required when ADC has no default project")
    end_time = datetime.now(UTC)
    batch = GcpVertexActivityConnector(
        project_id=project_id,
        logging_client=cloud_logging.Client(project=project_id, credentials=credentials),
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
    code = getattr(error, "code", None)
    if callable(code):
        code = code()
    safe_code = str(code) if isinstance(code, (int, str)) and str(code) else None
    return f"{operation}: {safe_code or error.__class__.__name__}"


def _required(label: str, value: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty without surrounding whitespace")
    return value


def _aware(label: str, value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value
