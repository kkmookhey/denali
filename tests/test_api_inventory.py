from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app

ASSET_ID = "11111111-1111-4111-8111-111111111111"


class RepositoryStub:
    def __init__(self):
        self.governance = "unreviewed"

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        lifecycle: str = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        return [{"id": ASSET_ID, "kind": kind or "ai_agent", "lifecycle_state": lifecycle}]

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
        if asset_id != ASSET_ID:
            return None
        return {"id": ASSET_ID, "kind": "ai_agent", "assertions": [], "relationships": []}

    def summary(self, tenant_id: str) -> dict[str, Any]:
        return {"total": 1, "by_kind": {"ai_agent": 1}, "by_governance": {self.governance: 1}}

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"connector_id": "fixture", "plane": "agents", "state": "complete"}]

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        if asset_id != ASSET_ID:
            return None
        self.governance = status
        return {"id": asset_id, "governance_status": status, "owner": owner, "notes": notes}


def client() -> TestClient:
    return TestClient(create_app(repository=RepositoryStub(), migrate_on_start=False))


def test_inventory_surface() -> None:
    with client() as test_client:
        assert test_client.get("/healthz").json()["status"] == "ready"
        assert test_client.get("/v1/inventory/summary").json()["total"] == 1
        rows = test_client.get("/v1/inventory/assets?kind=ai_agent").json()["items"]
        assert rows[0]["kind"] == "ai_agent"
        assert test_client.get(f"/v1/inventory/assets/{ASSET_ID}").status_code == 200
        assert test_client.get("/v1/sources/coverage").json()["items"][0]["state"] == "complete"


def test_missing_asset_is_404() -> None:
    with client() as test_client:
        response = test_client.get("/v1/inventory/assets/does-not-exist")
        assert response.status_code == 404


def test_governance_update_is_validated_and_persisted() -> None:
    with client() as test_client:
        response = test_client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            json={"status": "approved", "owner": "platform-security"},
        )
        assert response.status_code == 200
        assert response.json()["governance_status"] == "approved"
        invalid = test_client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            json={"status": "probably-safe"},
        )
        assert invalid.status_code == 422


def test_unconfigured_storage_fails_explicitly() -> None:
    app = create_app(repository=None, migrate_on_start=False)
    with TestClient(app) as test_client:
        assert test_client.get("/healthz").json()["status"] == "storage_unconfigured"
        assert test_client.get("/v1/inventory/summary").status_code == 503
