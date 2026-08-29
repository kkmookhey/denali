"""Inventory-first Denali API."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from threading import Lock
from time import monotonic, sleep
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from denali.connections import (
    AWS_COVERAGE_AUTOMATIC,
    AWS_COVERAGE_SELECTED,
    AWS_SCOPES,
    AZURE_CLOUD_PUBLIC,
    AZURE_SCOPES,
    AwsCloudFormationLauncher,
    AwsConnectionValidator,
    AzureConnectionValidator,
    AzureSetupScriptLauncher,
    aws_connection_coverage_plan,
    azure_coverage_plan,
)
from denali.connections.aws import render_cloudformation
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DEFAULT_LOCAL_TENANT = "00000000-0000-4000-8000-000000000001"


class InventoryReader(Protocol):
    def create_connection(
        self,
        tenant_id: str,
        *,
        connection_id: str,
        provider: str,
        display_name: str,
        credential_type: str,
        credential_reference: dict[str, Any],
        declared_scopes: list[str],
        coverage_plan: list[dict[str, Any]],
        configuration: dict[str, Any],
    ) -> dict[str, Any]: ...

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None: ...

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None: ...

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def record_connection_launch(
        self, tenant_id: str, connection_id: str, launch: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def record_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None: ...

    def complete_azure_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        service_principal_id: str,
        subscriptions: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None: ...

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None: ...

    def delete_connection(self, tenant_id: str, connection_id: str) -> str: ...

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        lifecycle: str = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None: ...

    def summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None: ...

    def finding_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def list_vulnerabilities(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_vulnerability(self, tenant_id: str, vulnerability_id: str) -> dict[str, Any] | None: ...

    def vulnerability_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def list_issues(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_issue(self, tenant_id: str, issue_id: str) -> dict[str, Any] | None: ...

    def issue_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_issue_evaluations(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def code_to_cloud_deployments(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def list_activity(
        self,
        tenant_id: str,
        *,
        category: str | None = None,
        outcome: str | None = None,
        asset_id: str | None = None,
        include_fixtures: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_activity(self, tenant_id: str, activity_id: str) -> dict[str, Any] | None: ...

    def activity_summary(
        self, tenant_id: str, *, include_fixtures: bool = False
    ) -> dict[str, Any]: ...

    def list_runtime_detections(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_runtime_detection(
        self, tenant_id: str, detection_id: str
    ) -> dict[str, Any] | None: ...

    def runtime_detection_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_runtime_detection_evaluations(
        self, tenant_id: str
    ) -> list[dict[str, Any]]: ...

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None: ...


class GovernanceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern="^(approved|unreviewed|unwanted)$")
    owner: str | None = Field(default=None, max_length=256)
    notes: str | None = Field(default=None, max_length=4000)


class AwsConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["aws"] = "aws"
    display_name: str = Field(min_length=1, max_length=120)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    partition: Literal["aws", "aws-us-gov", "aws-cn"] = "aws"
    deployment_region: str = "us-east-1"
    coverage_mode: Literal["automatic", "selected"] = AWS_COVERAGE_AUTOMATIC
    regions: list[str] = Field(default_factory=list, max_length=40)
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(AWS_SCOPES), min_length=1, max_length=len(AWS_SCOPES)
    )
    role_name: str = Field(
        default="DenaliSecurityAuditRole",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9+=,.@_-]+$",
    )


class AzureConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["azure"] = "azure"
    display_name: str = Field(min_length=1, max_length=120)
    tenant_id: UUID
    cloud: Literal["AzureCloud"] = AZURE_CLOUD_PUBLIC
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(AZURE_SCOPES), min_length=1, max_length=len(AZURE_SCOPES)
    )


class AzureSetupCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    completion_code: str = Field(min_length=16, max_length=32768)


ConnectionCreate = Annotated[
    AwsConnectionCreate | AzureConnectionCreate,
    Field(discriminator="provider"),
]


def create_app(
    *,
    repository: InventoryReader | None = None,
    connection_validator: AwsConnectionValidator | None = None,
    azure_connection_validator: AzureConnectionValidator | None = None,
    cloudformation_launcher: AwsCloudFormationLauncher | None = None,
    azure_setup_launcher: AzureSetupScriptLauncher | None = None,
    onboarding_validation_timeout_seconds: int | None = None,
    onboarding_validation_retry_seconds: int | None = None,
    tenant_id: str | None = None,
    migrate_on_start: bool = True,
) -> FastAPI:
    configured_dsn = os.environ.get("DENALI_DSN")
    configured_tenant = tenant_id or os.environ.get("DENALI_TENANT_ID", DEFAULT_LOCAL_TENANT)
    configured_launcher = cloudformation_launcher or _cloudformation_launcher_from_environment()
    configured_azure_launcher = azure_setup_launcher or _azure_setup_launcher_from_environment()
    onboarding_validation_timeout = (
        onboarding_validation_timeout_seconds
        if onboarding_validation_timeout_seconds is not None
        else _bounded_environment_integer(
            "DENALI_AWS_ONBOARDING_VALIDATION_SECONDS",
            default=900,
            minimum=60,
            maximum=1800,
        )
    )
    onboarding_validation_retry = (
        onboarding_validation_retry_seconds
        if onboarding_validation_retry_seconds is not None
        else _bounded_environment_integer(
            "DENALI_AWS_ONBOARDING_RETRY_SECONDS", default=10, minimum=2, maximum=60
        )
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if repository is not None:
            app.state.repository = repository
        elif configured_dsn:
            if migrate_on_start:
                migrate(configured_dsn)
            app.state.repository = PostgresInventoryRepository(configured_dsn)
        else:
            app.state.repository = None
        app.state.tenant_id = configured_tenant
        app.state.connection_validator = connection_validator or AwsConnectionValidator()
        app.state.azure_connection_validator = (
            azure_connection_validator or AzureConnectionValidator()
        )
        app.state.cloudformation_launcher = configured_launcher
        app.state.azure_setup_launcher = configured_azure_launcher
        app.state.onboarding_validation_timeout = onboarding_validation_timeout
        app.state.onboarding_validation_retry = onboarding_validation_retry
        app.state.active_connection_validations = set()
        app.state.connection_validation_lock = Lock()
        yield

    app = FastAPI(
        title="Denali API",
        description="Open-source AI security inventory and evidence API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    def queue_validation(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
        *,
        wait_for_credentials: bool,
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        connection_key = (current_tenant, connection_id)
        validation_lock = request.app.state.connection_validation_lock
        active_validations = request.app.state.active_connection_validations
        with validation_lock:
            if connection_key in active_validations:
                return {"status": "already_running", "connection_id": connection_id}
            active_validations.add(connection_key)

        validator = (
            request.app.state.connection_validator
            if target["provider"] == "aws"
            else request.app.state.azure_connection_validator
        )
        retry_seconds = request.app.state.onboarding_validation_retry
        timeout_seconds = request.app.state.onboarding_validation_timeout

        def run_validation() -> None:
            deadline = monotonic() + timeout_seconds
            try:
                while True:
                    validation = validator.validate(target)
                    if (
                        not wait_for_credentials
                        or validation["credential_state"] == "passed"
                        or monotonic() >= deadline
                    ):
                        repo.record_connection_validation(
                            current_tenant, connection_id, validation
                        )
                        return
                    sleep(min(retry_seconds, max(0, deadline - monotonic())))
            finally:
                with validation_lock:
                    active_validations.discard(connection_key)

        background_tasks.add_task(run_validation)
        return {"status": "started", "connection_id": connection_id}

    @app.get("/", include_in_schema=False)
    def web_application() -> RedirectResponse:
        return RedirectResponse(os.environ.get("DENALI_WEB_URL", "http://127.0.0.1:3080"))

    @app.get("/healthz")
    def health(request: Request) -> dict[str, str]:
        state = "ready" if request.app.state.repository is not None else "storage_unconfigured"
        return {"status": state, "version": app.version}

    @app.get("/v1/connections")
    def list_connections(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_connections(current_tenant)
        return {
            "items": [_with_validation_state(request, current_tenant, row) for row in rows]
        }

    @app.post("/v1/connections", status_code=201)
    def create_connection(request: Request, connection: ConnectionCreate) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        display_name = connection.display_name.strip()
        if not display_name:
            raise HTTPException(status_code=422, detail="display_name must not be blank")
        if isinstance(connection, AzureConnectionCreate):
            launcher = request.app.state.azure_setup_launcher
            if launcher is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Azure onboarding is not configured; set DENALI_AZURE_CLIENT_ID, "
                        "DENALI_AZURE_ONBOARDING_BUCKET, and the consent redirect URI"
                    ),
                )
            scopes = list(dict.fromkeys(connection.declared_scopes))
            unsupported_scopes = [scope for scope in scopes if scope not in AZURE_SCOPES]
            if unsupported_scopes:
                raise HTTPException(
                    status_code=422,
                    detail=f"unsupported Azure scope: {', '.join(unsupported_scopes)}",
                )
            connection_id = str(uuid4())
            try:
                created = repo.create_connection(
                    current_tenant,
                    connection_id=connection_id,
                    provider="azure",
                    display_name=display_name,
                    credential_type="azure_multitenant_app",
                    credential_reference={"client_id": launcher.client_id},
                    declared_scopes=scopes,
                    coverage_plan=[],
                    configuration={
                        "tenant_id": str(connection.tenant_id),
                        "cloud": connection.cloud,
                        "coverage_mode": "selected-subscriptions",
                        "subscriptions": [],
                    },
                )
                return _with_validation_state(request, current_tenant, created)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error

        if not _valid_aws_region(connection.deployment_region, partition=connection.partition):
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS deployment region format: {connection.deployment_region}",
            )
        regions = list(dict.fromkeys(connection.regions))
        invalid_regions = [
            region
            for region in regions
            if not _valid_aws_region(region, partition=connection.partition)
        ]
        if invalid_regions:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS region format: {', '.join(invalid_regions)}",
            )
        if connection.coverage_mode == AWS_COVERAGE_SELECTED and not regions:
            raise HTTPException(
                status_code=422,
                detail="selected region coverage requires at least one region",
            )
        scopes = list(dict.fromkeys(connection.declared_scopes))
        unsupported_scopes = [scope for scope in scopes if scope not in AWS_SCOPES]
        if unsupported_scopes:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS scope: {', '.join(unsupported_scopes)}",
            )
        connection_id = str(uuid4())
        external_id = f"denali-{current_tenant}-{connection_id}"
        role_arn = (
            f"arn:{connection.partition}:iam::{connection.account_id}:role/{connection.role_name}"
        )
        try:
            created = repo.create_connection(
                current_tenant,
                connection_id=connection_id,
                provider="aws",
                display_name=display_name,
                credential_type="aws_assume_role",
                credential_reference={"role_arn": role_arn, "external_id": external_id},
                declared_scopes=scopes,
                coverage_plan=aws_connection_coverage_plan(
                    scopes,
                    (
                        regions
                        if connection.coverage_mode == AWS_COVERAGE_SELECTED
                        else ["all-enabled"]
                    ),
                    deployment_region=connection.deployment_region,
                    coverage_mode=connection.coverage_mode,
                ),
                configuration={
                    "account_id": connection.account_id,
                    "partition": connection.partition,
                    "deployment_region": connection.deployment_region,
                    "coverage_mode": connection.coverage_mode,
                    "regions": regions if connection.coverage_mode == AWS_COVERAGE_SELECTED else [],
                    "role_name": connection.role_name,
                    "stack_scopes": [],
                },
            )
            return _with_validation_state(request, current_tenant, created)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/v1/connections/{connection_id}")
    def connection_detail(request: Request, connection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        return _with_validation_state(request, current_tenant, row)

    @app.get("/v1/connections/{connection_id}/aws/cloudformation.yaml")
    def aws_connection_cloudformation(
        request: Request, connection_id: UUID
    ) -> PlainTextResponse:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "aws":
            raise HTTPException(status_code=404, detail="AWS connection not found")
        template = render_cloudformation(target)
        filename = f"denali-aws-{connection_id}.yaml"
        return PlainTextResponse(
            template,
            media_type="application/yaml",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/connections/{connection_id}/aws/cloudformation/launch", status_code=201)
    def launch_aws_cloudformation(
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "aws":
            raise HTTPException(status_code=404, detail="AWS connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        launcher = request.app.state.cloudformation_launcher
        if launcher is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "AWS console launch is not configured; use Download template or configure "
                    "DENALI_AWS_ONBOARDING_BUCKET and DENALI_AWS_PRINCIPAL_ARN"
                ),
            )
        try:
            launch = launcher.create_launch(
                tenant_id=current_tenant,
                connection_id=str(connection_id),
                connection=target,
            )
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Unable to prepare the AWS CloudFormation launch"
            ) from error

        recorded = repo.record_connection_launch(
            current_tenant,
            str(connection_id),
            {
                "method": "cloudformation_quick_create",
                "template_version": launch["template_version"],
                "template_sha256": launch["template_sha256"],
                "principal_arn": launch["principal_arn"],
                "published_at": launch["published_at"].isoformat(),
                "url_expires_at": launch["expires_at"].isoformat(),
            },
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        validation = queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            target,
            wait_for_credentials=True,
        )
        response.headers["Cache-Control"] = "no-store"
        return {
            "launch_url": launch["launch_url"],
            "stack_name": launch["stack_name"],
            "stack_region": launch["stack_region"],
            "template_version": launch["template_version"],
            "template_sha256": launch["template_sha256"],
            "expires_at": launch["expires_at"],
            "validation_status": validation["status"],
        }

    @app.post("/v1/connections/{connection_id}/azure/setup/launch", status_code=201)
    def launch_azure_setup(
        request: Request,
        response: Response,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "azure":
            raise HTTPException(status_code=404, detail="Azure connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        launcher = request.app.state.azure_setup_launcher
        if launcher is None:
            raise HTTPException(
                status_code=503,
                detail="Azure Cloud Shell onboarding is not configured",
            )
        try:
            launch = launcher.create_launch(
                tenant_id=current_tenant,
                connection_id=str(connection_id),
                connection=target,
            )
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Unable to prepare the Azure setup script"
            ) from error

        recorded = repo.record_connection_setup_launch(
            current_tenant,
            str(connection_id),
            launch={
                "method": "azure_cloud_shell",
                "script_version": launch["script_version"],
                "script_sha256": launch["script_sha256"],
                "client_id": launch["client_id"],
                "published_at": launch["published_at"].isoformat(),
                "url_expires_at": launch["expires_at"].isoformat(),
            },
            setup_token_sha256=launch["callback_token_sha256"],
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        response.headers["Cache-Control"] = "no-store"
        return {
            "consent_url": launch["consent_url"],
            "cloud_shell_url": launch["cloud_shell_url"],
            "script_url": launch["script_url"],
            "setup_command": launch["setup_command"],
            "script_version": launch["script_version"],
            "script_sha256": launch["script_sha256"],
            "expires_at": launch["expires_at"],
        }

    @app.post("/v1/connections/{connection_id}/azure/setup/complete", status_code=202)
    def complete_azure_setup(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
        completion: AzureSetupCompletion,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "azure":
            raise HTTPException(status_code=404, detail="Azure connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be completed")
        payload = _decode_azure_completion_code(completion.completion_code)
        expected_token_hash = target["credential_reference"].get("setup_token_sha256")
        presented_token = payload.get("token")
        token_matches = (
            bool(expected_token_hash)
            and isinstance(presented_token, str)
            and hmac.compare_digest(
                expected_token_hash, hashlib.sha256(presented_token.encode()).hexdigest()
            )
        )
        if not token_matches:
            raise HTTPException(status_code=409, detail="Azure setup completion code is invalid")
        onboarding = target["configuration"].get("onboarding", {})
        try:
            expires_at = datetime.fromisoformat(onboarding["url_expires_at"])
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="Azure setup launch is not current"
            ) from error
        if datetime.now(UTC) > expires_at:
            raise HTTPException(status_code=409, detail="Azure setup completion code has expired")
        if str(payload.get("tenant_id", "")).lower() != target["configuration"][
            "tenant_id"
        ].lower():
            raise HTTPException(status_code=409, detail="Azure tenant does not match the plan")
        service_principal_id = str(payload.get("service_principal_id", ""))
        if not _valid_uuid_text(service_principal_id):
            raise HTTPException(status_code=422, detail="Azure service principal ID is invalid")
        subscriptions = _azure_subscriptions_from_completion(payload)
        completed_at = datetime.now(UTC)
        updated = repo.complete_azure_connection_setup(
            current_tenant,
            str(connection_id),
            expected_setup_token_sha256=expected_token_hash,
            service_principal_id=service_principal_id,
            subscriptions=subscriptions,
            coverage_plan=azure_coverage_plan(target["declared_scopes"], subscriptions),
            completed_at=completed_at,
        )
        if updated is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        validation_target = repo.get_connection_validation_target(
            current_tenant, str(connection_id)
        )
        if validation_target is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        return queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            validation_target,
            wait_for_credentials=True,
        )

    @app.post("/v1/connections/{connection_id}/validate", status_code=202)
    def validate_connection(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        connection_key = (current_tenant, str(connection_id))
        target = repo.get_connection_validation_target(current_tenant, connection_key[1])
        if target is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be validated")
        if target["provider"] not in {"aws", "azure"}:
            raise HTTPException(status_code=422, detail="connection provider is not supported")
        if target["provider"] == "azure" and not target["configuration"].get("subscriptions"):
            raise HTTPException(
                status_code=409,
                detail="complete Azure subscription selection before validation",
            )
        return queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            target,
            wait_for_credentials=False,
        )

    @app.post("/v1/connections/{connection_id}/disable")
    def disable_connection(request: Request, connection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        connection_key = (current_tenant, str(connection_id))
        with request.app.state.connection_validation_lock:
            if connection_key in request.app.state.active_connection_validations:
                raise HTTPException(
                    status_code=409,
                    detail="wait for the active validation to finish before disabling",
                )
        row = repo.disable_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        return _with_validation_state(request, current_tenant, row)

    @app.delete("/v1/connections/{connection_id}", status_code=204)
    def delete_connection(
        request: Request,
        connection_id: UUID,
        confirm: str = Query(min_length=1, max_length=120),
    ) -> Response:
        repo, current_tenant = _context(request)
        row = repo.get_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if confirm != row["display_name"]:
            raise HTTPException(status_code=409, detail="confirmation name does not match")
        result = repo.delete_connection(current_tenant, str(connection_id))
        if result == "active":
            raise HTTPException(status_code=409, detail="disable the connection before deleting it")
        if result == "not_found":
            raise HTTPException(status_code=404, detail="connection not found")
        return Response(status_code=204)

    @app.get("/v1/inventory/summary")
    def inventory_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.summary(current_tenant)

    @app.get("/v1/inventory/assets")
    def list_assets(
        request: Request,
        kind: str | None = None,
        lifecycle: str = Query(default="active", pattern="^(active|withdrawn|unknown|all)$"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_assets(
            current_tenant,
            kind=kind,
            lifecycle="" if lifecycle == "all" else lifecycle,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/inventory/assets/{asset_id}")
    def asset_detail(request: Request, asset_id: str) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_asset(current_tenant, asset_id)
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return row

    @app.patch("/v1/inventory/assets/{asset_id}/governance")
    def update_governance(
        request: Request, asset_id: str, update: GovernanceUpdate
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.set_governance(
            current_tenant,
            asset_id,
            status=update.status,
            owner=update.owner,
            notes=update.notes,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return row

    @app.get("/v1/sources/coverage")
    def source_coverage(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_coverage(current_tenant)}

    @app.get("/v1/findings/summary")
    def finding_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.finding_summary(current_tenant)

    @app.get("/v1/findings")
    def list_findings(
        request: Request,
        state: str | None = Query(
            default=None,
            pattern="^(open|resolved|suppressed|unknown)$",
        ),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_findings(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/findings/{finding_id}")
    def finding_detail(request: Request, finding_id: str) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_finding(current_tenant, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return row

    @app.get("/v1/vulnerabilities/summary")
    def vulnerability_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.vulnerability_summary(current_tenant)

    @app.get("/v1/vulnerabilities")
    def list_vulnerabilities(
        request: Request,
        state: str | None = Query(
            default=None,
            pattern="^(open|resolved|suppressed|unknown)$",
        ),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_vulnerabilities(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/vulnerabilities/{vulnerability_id}")
    def vulnerability_detail(request: Request, vulnerability_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_vulnerability(current_tenant, str(vulnerability_id))
        if row is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return row

    @app.get("/v1/issues/summary")
    def issue_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.issue_summary(current_tenant)

    @app.get("/v1/issues")
    def list_issues(
        request: Request,
        state: str | None = Query(default=None, pattern="^(open|resolved|unknown)$"),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_issues(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/issues/evaluations")
    def issue_evaluations(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_issue_evaluations(current_tenant)}

    @app.get("/v1/issues/{issue_id}")
    def issue_detail(request: Request, issue_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_issue(current_tenant, str(issue_id))
        if row is None:
            raise HTTPException(status_code=404, detail="issue not found")
        return row

    @app.get("/v1/code-to-cloud/deployments")
    def code_to_cloud_deployments(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.code_to_cloud_deployments(current_tenant)}

    @app.get("/v1/activity/summary")
    def activity_summary(
        request: Request,
        include_fixtures: bool = Query(default=False),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.activity_summary(current_tenant, include_fixtures=include_fixtures)

    @app.get("/v1/activity")
    def list_activity(
        request: Request,
        category: str | None = Query(
            default=None,
            pattern="^(model_invocation|agent_invocation|retrieval|tool_invocation|ai_app_sign_in|admin_change|data_access|other)$",
        ),
        outcome: str | None = Query(default=None, pattern="^(success|failure|unknown)$"),
        asset_id: Annotated[UUID | None, Query()] = None,
        include_fixtures: bool = Query(default=False),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {
            "items": repo.list_activity(
                current_tenant,
                category=category,
                outcome=outcome,
                asset_id=str(asset_id) if asset_id is not None else None,
                include_fixtures=include_fixtures,
                limit=limit,
                offset=offset,
            ),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/activity/{activity_id}")
    def activity_detail(request: Request, activity_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_activity(current_tenant, str(activity_id))
        if row is None:
            raise HTTPException(status_code=404, detail="activity not found")
        return row

    @app.get("/v1/detections/summary")
    def runtime_detection_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.runtime_detection_summary(current_tenant)

    @app.get("/v1/detections")
    def list_runtime_detections(
        request: Request,
        state: str | None = Query(default=None, pattern="^(open|resolved|unknown)$"),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {
            "items": repo.list_runtime_detections(
                current_tenant,
                state=state,
                severity=severity,
                limit=limit,
                offset=offset,
            ),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/detections/evaluations")
    def runtime_detection_evaluations(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_runtime_detection_evaluations(current_tenant)}

    @app.get("/v1/detections/{detection_id}")
    def runtime_detection_detail(request: Request, detection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_runtime_detection(current_tenant, str(detection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="runtime detection not found")
        return row

    return app


def _context(request: Request) -> tuple[InventoryReader, str]:
    repository = request.app.state.repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Denali storage is not configured")
    return repository, request.app.state.tenant_id


def _with_validation_state(
    request: Request, tenant_id: str, row: dict[str, Any]
) -> dict[str, Any]:
    result = dict(row)
    connection_key = (tenant_id, str(result["id"]))
    with request.app.state.connection_validation_lock:
        running = connection_key in request.app.state.active_connection_validations
    result["validation_state"] = "running" if running else "idle"
    result["setup_capabilities"] = {
        "cloudformation_quick_create": (
            result["provider"] == "aws"
            and request.app.state.cloudformation_launcher is not None
        ),
        "azure_cloud_shell": (
            result["provider"] == "azure"
            and request.app.state.azure_setup_launcher is not None
        ),
    }
    return result


def _cloudformation_launcher_from_environment() -> AwsCloudFormationLauncher | None:
    bucket_name = os.environ.get("DENALI_AWS_ONBOARDING_BUCKET")
    principal_arn = os.environ.get("DENALI_AWS_PRINCIPAL_ARN")
    if not bucket_name or not principal_arn:
        return None
    expires_in_seconds = _bounded_environment_integer(
        "DENALI_AWS_ONBOARDING_URL_SECONDS", default=3600, minimum=300, maximum=3600
    )
    return AwsCloudFormationLauncher(
        bucket_name=bucket_name,
        principal_arn=principal_arn,
        expires_in_seconds=expires_in_seconds,
    )


def _azure_setup_launcher_from_environment() -> AzureSetupScriptLauncher | None:
    bucket_name = os.environ.get("DENALI_AZURE_ONBOARDING_BUCKET")
    client_id = os.environ.get("DENALI_AZURE_CLIENT_ID")
    redirect_uri = os.environ.get("DENALI_AZURE_CONSENT_REDIRECT_URI") or os.environ.get(
        "DENALI_WEB_URL", "http://127.0.0.1:3080"
    )
    if not bucket_name or not client_id:
        return None
    expires_in_seconds = _bounded_environment_integer(
        "DENALI_AZURE_ONBOARDING_URL_SECONDS",
        default=3600,
        minimum=300,
        maximum=3600,
    )
    return AzureSetupScriptLauncher(
        bucket_name=bucket_name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        expires_in_seconds=expires_in_seconds,
    )


def _decode_azure_completion_code(value: str) -> dict[str, Any]:
    encoded = value.strip()
    if encoded.startswith("DENALI_SETUP_COMPLETE="):
        encoded = encoded.split("=", 1)[1].strip()
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=422, detail="Azure setup completion code is malformed"
        ) from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Azure setup completion code is malformed")
    return payload


def _azure_subscriptions_from_completion(payload: dict[str, Any]) -> list[dict[str, str]]:
    raw_subscriptions = payload.get("subscriptions")
    if not isinstance(raw_subscriptions, list) or not 1 <= len(raw_subscriptions) <= 200:
        raise HTTPException(status_code=422, detail="select between 1 and 200 subscriptions")
    subscriptions: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_subscriptions:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="Azure subscription selection is invalid")
        subscription_id = str(item.get("id", ""))
        name = str(item.get("name", "")).strip()
        normalized_id = subscription_id.lower()
        if not _valid_uuid_text(subscription_id) or not name or len(name) > 256:
            raise HTTPException(status_code=422, detail="Azure subscription selection is invalid")
        if normalized_id not in seen:
            seen.add(normalized_id)
            subscriptions.append({"id": subscription_id, "name": name})
    return subscriptions


def _valid_uuid_text(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _bounded_environment_integer(
    name: str, *, default: int, minimum: int, maximum: int
) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


def _cors_origins() -> list[str]:
    raw = os.environ.get("DENALI_CORS_ORIGINS", "http://localhost:5173")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _valid_aws_region(region: str, *, partition: str) -> bool:
    patterns = {
        "aws": (
            r"^(af|ap|ca|eu|il|me|mx|sa|us)-"
            r"(central|east|northeast|north|northwest|south|southeast|southwest|west)-[0-9]+$"
        ),
        "aws-us-gov": r"^us-gov-(east|west)-[0-9]+$",
        "aws-cn": r"^cn-(north|northwest)-[0-9]+$",
    }
    return bool(re.fullmatch(patterns[partition], region))


app = create_app()
