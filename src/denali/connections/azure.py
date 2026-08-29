"""Bounded Azure multi-tenant application onboarding and validation."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

AZURE_CLOUD_PUBLIC = "AzureCloud"
AZURE_SCOPE_AI_SERVICES = "azure.ai_services"
AZURE_SCOPE_AI_PLATFORM = "azure.ai_platform"
AZURE_SCOPE_AI_ACTIVITY = "azure.ai_activity"
AZURE_SCOPES = (
    AZURE_SCOPE_AI_SERVICES,
    AZURE_SCOPE_AI_PLATFORM,
    AZURE_SCOPE_AI_ACTIVITY,
)
AZURE_READER_ROLE_DEFINITION_ID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
AZURE_MANAGEMENT_SCOPE = "https://management.azure.com/.default"
AZURE_MANAGEMENT_ENDPOINT = "https://management.azure.com"
AZURE_RESOURCE_GRAPH_API_VERSION = "2022-10-01"
AZURE_SUBSCRIPTION_API_VERSION = "2022-12-01"
AZURE_ACTIVITY_API_VERSION = "2015-04-01"

_SCOPE_METADATA = {
    AZURE_SCOPE_AI_SERVICES: (
        {
            "plane": "azure_ai_services_accounts",
            "label": "Azure AI services account inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.cognitiveservices/accounts' "
                "| summarize resourceCount=count()"
            ),
        },
        {
            "plane": "azure_ai_search_services",
            "label": "Azure AI Search inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.search/searchservices' "
                "| summarize resourceCount=count()"
            ),
        },
    ),
    AZURE_SCOPE_AI_PLATFORM: (
        {
            "plane": "azure_machine_learning_workspaces",
            "label": "Azure Machine Learning workspace inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.machinelearningservices/workspaces' "
                "| summarize resourceCount=count()"
            ),
        },
        {
            "plane": "azure_bot_services",
            "label": "Azure Bot Service inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.botservice/botservices' "
                "| summarize resourceCount=count()"
            ),
        },
    ),
    AZURE_SCOPE_AI_ACTIVITY: (
        {
            "plane": "azure_ai_management_activity",
            "label": "Azure AI management activity",
            "permission": "Microsoft.Insights/eventtypes/values/read",
            "query": None,
        },
    ),
}


class AzureAccessToken(Protocol):
    token: str


class AzureTokenCredential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> AzureAccessToken: ...


class AzureHttpResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


AzureRequest = Callable[..., AzureHttpResponse]
CredentialFactory = Callable[[str], AzureTokenCredential]


def azure_coverage_plan(
    scopes: list[str], subscriptions: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Expand Azure scopes across the exact selected subscriptions."""

    return [
        {
            "scope": f"/subscriptions/{subscription['id']}",
            "declared_scope": scope,
            "plane": plane["plane"],
            "label": plane["label"],
            "region": "all-locations",
            "subscription_id": subscription["id"],
            "subscription_name": subscription["name"],
            "permissions": [plane["permission"]],
            "validation_state": "not_validated",
            "coverage_mode": "selected-subscriptions",
        }
        for subscription in subscriptions
        for scope in scopes
        for plane in _SCOPE_METADATA[scope]
    ]


class AzureConnectionValidator:
    """Validate every selected subscription and declared Azure control-plane entrypoint."""

    def __init__(
        self,
        credential_factory: CredentialFactory | None = None,
        request: AzureRequest | None = None,
    ):
        self._credential_factory = credential_factory or _default_credential
        self._request = request or _httpx_request

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        configuration = connection["configuration"]
        subscriptions = configuration.get("subscriptions", [])
        if not subscriptions:
            return _credential_failure(connection, started_at, "subscriptions_not_selected")
        customer_tenant_id = configuration["tenant_id"]
        try:
            credential = self._credential_factory(customer_tenant_id)
            token = credential.get_token(AZURE_MANAGEMENT_SCOPE).token
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        except Exception as error:
            return _credential_failure(connection, started_at, _azure_error_code(error))

        results: list[dict[str, Any]] = []
        observed_subscriptions: list[str] = []
        credential_failed = False
        for subscription in subscriptions:
            subscription_id = subscription["id"]
            try:
                response = self._request(
                    "GET",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}",
                    headers=headers,
                    params={"api-version": AZURE_SUBSCRIPTION_API_VERSION},
                    timeout=10.0,
                )
                response.raise_for_status()
                observed = response.json()
                observed_subscription = str(observed.get("subscriptionId", ""))
                observed_tenant = str(observed.get("tenantId", ""))
                if observed_subscription.lower() != subscription_id.lower():
                    raise AzureBindingError("subscription_mismatch")
                if observed_tenant.lower() != customer_tenant_id.lower():
                    raise AzureBindingError("tenant_mismatch")
                observed_subscriptions.append(observed_subscription)
            except Exception as error:
                credential_failed = True
                results.extend(
                    _unknown_subscription_results(
                        connection,
                        subscription_id,
                        f"Credential or subscription binding failed ({_azure_error_code(error)}).",
                    )
                )
                continue

            plans = azure_coverage_plan(connection["declared_scopes"], [subscription])
            results.extend(
                self._validate_plane(planned, subscription_id, headers) for planned in plans
            )

        failed_count = sum(item["state"] in {"failed", "unknown"} for item in results)
        if not observed_subscriptions:
            health = "unhealthy"
            credential_state = "failed"
        else:
            health = "healthy" if failed_count == 0 else "partial"
            credential_state = "failed" if credential_failed else "passed"
        if health == "healthy":
            summary = (
                f"Credentials and tenant binding validated; every declared Azure control-plane "
                f"check passed across all locations in {len(observed_subscriptions)} selected "
                "subscription(s)."
            )
        else:
            summary = (
                f"Azure validation reached {len(observed_subscriptions)} of {len(subscriptions)} "
                f"selected subscription(s); {failed_count} coverage check(s) failed or remain "
                "unknown."
            )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": credential_state,
            "account_id_observed": ",".join(sorted(observed_subscriptions)) or None,
            "results": results,
            "summary": summary,
        }

    def _validate_plane(
        self,
        planned: dict[str, Any],
        subscription_id: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        result = {
            "scope": planned["scope"],
            "plane": planned["plane"],
            "label": planned["label"],
            "region": "all-locations",
            "subscription_id": subscription_id,
            "subscription_name": planned["subscription_name"],
        }
        try:
            metadata = _plane_metadata(planned["declared_scope"], planned["plane"])
            if metadata["query"] is None:
                end = datetime.now(UTC)
                start = end - timedelta(hours=1)
                response = self._request(
                    "GET",
                    (
                        f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}/providers/"
                        "microsoft.insights/eventtypes/management/values"
                    ),
                    headers=headers,
                    params={
                        "api-version": AZURE_ACTIVITY_API_VERSION,
                        "$filter": (
                            f"eventTimestamp ge '{start.isoformat()}' and "
                            f"eventTimestamp le '{end.isoformat()}'"
                        ),
                        "$top": "1",
                    },
                    timeout=10.0,
                )
            else:
                response = self._request(
                    "POST",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/providers/Microsoft.ResourceGraph/resources",
                    headers=headers,
                    params={"api-version": AZURE_RESOURCE_GRAPH_API_VERSION},
                    json={
                        "subscriptions": [subscription_id],
                        "query": metadata["query"],
                        "options": {"$top": 1, "resultFormat": "objectArray"},
                    },
                    timeout=10.0,
                )
            response.raise_for_status()
            response.json()
            result.update(
                state="passed",
                detail=(
                    "The subscription-wide read-only entrypoint succeeded. Resource-specific "
                    "reads and locations are verified during collection when resources exist."
                ),
            )
        except Exception as error:
            result.update(
                state="failed",
                detail=f"Validation call failed ({_azure_error_code(error)}).",
            )
        return result


class AzureBindingError(RuntimeError):
    pass


def _credential_failure(
    connection: dict[str, Any], started_at: datetime, code: str
) -> dict[str, Any]:
    return {
        "started_at": started_at,
        "completed_at": datetime.now(UTC),
        "health_state": "unhealthy",
        "credential_state": "failed",
        "account_id_observed": None,
        "results": [
            {
                "scope": item["scope"],
                "plane": item["plane"],
                "label": item["label"],
                "region": item["region"],
                "state": "unknown",
                "detail": "Not attempted because credential or subscription binding failed.",
                **(
                    {"subscription_id": item["subscription_id"]}
                    if item.get("subscription_id")
                    else {}
                ),
            }
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the Azure connection ({code}).",
    }


def _unknown_subscription_results(
    connection: dict[str, Any], subscription_id: str, detail: str
) -> list[dict[str, Any]]:
    return [
        {
            "scope": item["scope"],
            "plane": item["plane"],
            "label": item["label"],
            "region": item["region"],
            "subscription_id": subscription_id,
            "subscription_name": item.get("subscription_name", subscription_id),
            "state": "unknown",
            "detail": detail,
        }
        for item in connection["coverage_plan"]
        if item.get("subscription_id") == subscription_id
    ]


def _plane_metadata(scope: str, plane: str) -> dict[str, Any]:
    return next(item for item in _SCOPE_METADATA[scope] if item["plane"] == plane)


def _azure_error_code(error: Exception) -> str:
    if isinstance(error, AzureBindingError):
        return str(error)
    response = getattr(error, "response", None)
    if response is not None:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            nested = payload.get("error")
            if isinstance(nested, dict) and nested.get("code"):
                return str(nested["code"])
    return error.__class__.__name__


def valid_azure_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _default_credential(customer_tenant_id: str) -> AzureTokenCredential:
    client_id = os.environ.get("DENALI_AZURE_CLIENT_ID")
    client_secret = os.environ.get("DENALI_AZURE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError("Denali Azure application credentials are not configured")
    try:
        from azure.identity import ClientSecretCredential
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("install Denali with the azure extra to validate Azure") from error
    return ClientSecretCredential(
        tenant_id=customer_tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def _httpx_request(method: str, url: str, **kwargs: Any) -> AzureHttpResponse:
    try:
        import httpx
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("httpx is required for Azure validation") from error
    return httpx.request(method, url, **kwargs)
