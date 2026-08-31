from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app

ASSET_ID = "11111111-1111-4111-8111-111111111111"
FINDING_ID = "22222222-2222-4222-8222-222222222222"
ISSUE_ID = "33333333-3333-4333-8333-333333333333"
VULNERABILITY_ID = "55555555-5555-4555-8555-555555555555"
ACTIVITY_ID = "66666666-6666-4666-8666-666666666666"
DETECTION_ID = "77777777-7777-4777-8777-777777777777"


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

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": FINDING_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None:
        if finding_id != FINDING_ID:
            return None
        return {"id": FINDING_ID, "state": "open", "resources": [], "observations": []}

    def finding_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
        }

    def list_vulnerabilities(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": VULNERABILITY_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_vulnerability(self, tenant_id: str, vulnerability_id: str) -> dict[str, Any] | None:
        if vulnerability_id != VULNERABILITY_ID:
            return None
        return {
            "id": VULNERABILITY_ID,
            "state": "open",
            "component": {},
            "target": {},
            "observations": [],
        }

    def vulnerability_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
            "open_by_exploit_state": {"known_exploited": 1},
        }

    def list_issues(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": ISSUE_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_issue(self, tenant_id: str, issue_id: str) -> dict[str, Any] | None:
        if issue_id != ISSUE_ID:
            return None
        return {"id": ISSUE_ID, "state": "open", "findings": [], "path_nodes": []}

    def issue_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
        }

    def latest_issue_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"rule_uid": "rule-1", "state": "complete", "confirmed_issues": 1}]

    def code_to_cloud_deployments(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"id": "deployment-1", "repository_name": "anna", "workload_name": "api"}]

    def code_to_cloud_observations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "connection_id": "github-fixture",
                "repository_natural_key": "github.com/acme/agent",
                "source_state": "complete",
                "analysis_state": "complete",
                "correlation_summary": {
                    "declarations": 1,
                    "proven": 0,
                    "ambiguous": 0,
                    "unmatched": 1,
                    "targets_evaluated": 0,
                },
                "correlation_candidates": [],
            }
        ]

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
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": ACTIVITY_ID,
                "category": category or "model_invocation",
                "outcome": outcome or "success",
            }
        ]

    def get_activity(self, tenant_id: str, activity_id: str) -> dict[str, Any] | None:
        if activity_id != ACTIVITY_ID:
            return None
        return {"id": ACTIVITY_ID, "category": "model_invocation", "entities": []}

    def activity_summary(self, tenant_id: str, *, include_fixtures: bool = False) -> dict[str, Any]:
        return {
            "total": 1,
            "last_24h": 1,
            "providers": 1,
            "failures": 0,
            "fixture_total": 0,
            "by_category": {"model_invocation": 1},
        }

    def list_runtime_detections(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        return [
            {
                "id": DETECTION_ID,
                "state": state or "open",
                "severity": severity or "high",
            }
        ]

    def get_runtime_detection(
        self, tenant_id: str, detection_id: str
    ) -> dict[str, Any] | None:
        if detection_id != DETECTION_ID:
            return None
        return {
            "id": DETECTION_ID,
            "state": "open",
            "severity": "high",
            "activities": [],
            "assets": [],
        }

    def runtime_detection_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"high": 1},
        }

    def latest_runtime_detection_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "rule_uid": "DENALI-RUNTIME-ENTRA-CONSENT-001",
                "state": "complete",
                "confirmed_detections": 1,
            }
        ]

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
        assert test_client.get("/", follow_redirects=False).headers["location"] == (
            "http://127.0.0.1:3080"
        )
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


def test_findings_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/findings/summary").json()["total"] == 1
        response = test_client.get("/v1/findings?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == FINDING_ID
        assert test_client.get(f"/v1/findings/{FINDING_ID}").status_code == 200
        assert test_client.get("/v1/findings/not-found").status_code == 404
        assert test_client.get("/v1/findings?state=probably-open").status_code == 422


def test_activity_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/activity/summary").json()["last_24h"] == 1
        response = test_client.get("/v1/activity?category=model_invocation&outcome=success")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == ACTIVITY_ID
        assert test_client.get(f"/v1/activity?asset_id={ASSET_ID}").status_code == 200
        assert test_client.get("/v1/activity?asset_id=not-a-uuid").status_code == 422
        assert test_client.get(f"/v1/activity/{ACTIVITY_ID}").status_code == 200
        assert test_client.get("/v1/activity/not-a-uuid").status_code == 422
        assert test_client.get("/v1/activity?category=threat").status_code == 422
        assert test_client.get("/v1/activity?include_fixtures=true").status_code == 200
        assert test_client.get("/v1/activity/summary?include_fixtures=true").status_code == 200


def test_runtime_detections_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/detections/summary").json()["total"] == 1
        response = test_client.get("/v1/detections?state=open&severity=high")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == DETECTION_ID
        evaluations = test_client.get("/v1/detections/evaluations").json()["items"]
        assert evaluations[0]["state"] == "complete"
        assert test_client.get(f"/v1/detections/{DETECTION_ID}").status_code == 200
        assert (
            test_client.get("/v1/detections/44444444-4444-4444-8444-444444444444").status_code
            == 404
        )
        assert test_client.get("/v1/detections/not-a-uuid").status_code == 422
        assert test_client.get("/v1/detections?state=probably-open").status_code == 422
        assert test_client.get("/v1/detections?severity=catastrophic").status_code == 422


def test_issues_surface_and_evaluation_coverage() -> None:
    with client() as test_client:
        assert test_client.get("/v1/issues/summary").json()["total"] == 1
        response = test_client.get("/v1/issues?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == ISSUE_ID
        assert test_client.get("/v1/issues/evaluations").json()["items"][0]["state"] == "complete"
        assert test_client.get(f"/v1/issues/{ISSUE_ID}").status_code == 200
        assert test_client.get("/v1/issues/44444444-4444-4444-8444-444444444444").status_code == 404
        assert test_client.get("/v1/issues/not-a-uuid").status_code == 422
        assert test_client.get("/v1/issues?state=probably-open").status_code == 422


def test_code_to_cloud_surface() -> None:
    with client() as test_client:
        response = test_client.get("/v1/code-to-cloud/deployments")
        assert response.status_code == 200
        assert response.json()["items"][0]["repository_name"] == "anna"
        observations = test_client.get("/v1/code-to-cloud/observations")
        assert observations.status_code == 200
        assert observations.json()["items"][0]["correlation_summary"]["unmatched"] == 1


def test_vulnerability_surface_and_filters() -> None:
    with client() as test_client:
        summary = test_client.get("/v1/vulnerabilities/summary").json()
        assert summary["open_by_exploit_state"] == {"known_exploited": 1}
        response = test_client.get("/v1/vulnerabilities?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == VULNERABILITY_ID
        assert test_client.get(f"/v1/vulnerabilities/{VULNERABILITY_ID}").status_code == 200
        assert (
            test_client.get("/v1/vulnerabilities/44444444-4444-4444-8444-444444444444").status_code
            == 404
        )
        assert test_client.get("/v1/vulnerabilities/not-a-uuid").status_code == 422
        assert test_client.get("/v1/vulnerabilities?severity=catastrophic").status_code == 422


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
