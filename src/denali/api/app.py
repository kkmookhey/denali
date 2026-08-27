"""Inventory-first Denali API."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DEFAULT_LOCAL_TENANT = "00000000-0000-4000-8000-000000000001"


class InventoryReader(Protocol):
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


def create_app(
    *,
    repository: InventoryReader | None = None,
    tenant_id: str | None = None,
    migrate_on_start: bool = True,
) -> FastAPI:
    configured_dsn = os.environ.get("DENALI_DSN")
    configured_tenant = tenant_id or os.environ.get("DENALI_TENANT_ID", DEFAULT_LOCAL_TENANT)

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
        allow_methods=["GET", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    @app.get("/", include_in_schema=False)
    def web_application() -> RedirectResponse:
        return RedirectResponse(os.environ.get("DENALI_WEB_URL", "http://127.0.0.1:3080"))

    @app.get("/healthz")
    def health(request: Request) -> dict[str, str]:
        state = "ready" if request.app.state.repository is not None else "storage_unconfigured"
        return {"status": state, "version": app.version}

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

    return app


def _context(request: Request) -> tuple[InventoryReader, str]:
    repository = request.app.state.repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Denali storage is not configured")
    return repository, request.app.state.tenant_id


def _cors_origins() -> list[str]:
    raw = os.environ.get("DENALI_CORS_ORIGINS", "http://localhost:5173")
    return [item.strip() for item in raw.split(",") if item.strip()]


app = create_app()
