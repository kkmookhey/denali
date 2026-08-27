"""Read-only inventory observation of MCP Streamable HTTP servers.

The observer completes the MCP lifecycle and lists tools, including pagination. It never
calls a tool. Authentication material is accepted only from an environment variable and
is never emitted as inventory, attributes, evidence, logs, or command-line arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

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

CONNECTOR_ID = "denali.mcp_http"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
INVENTORY_PLANE = "mcp_live_inventory"
RELATIONSHIP_PLANE = "mcp_live_relationships"
LATEST_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2025-03-26", "2025-06-18", "2025-11-25"})
MAX_RESPONSE_BYTES = 2_000_000
MAX_PAGES = 100
MAX_TOOLS = 5_000
_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")
_SENSITIVE_TEXT_RE = re.compile(
    r"(?i)(bearer\s+|access[_-]?token[=: ]+|api[_-]?key[=: ]+|password[=: ]+)"
    r"[^\s,;]+"
)


class McpObservationError(RuntimeError):
    """A bounded, user-safe failure while observing an MCP server."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: dict[str, str]
    messages: tuple[dict[str, Any], ...]


class McpTransport(Protocol):
    endpoint: str

    def post(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> TransportResponse: ...

    def close(
        self,
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> None: ...


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise McpObservationError("MCP endpoint redirects are not followed")


class StreamableHttpTransport:
    """Small dependency-free transport for one explicitly configured MCP endpoint."""

    def __init__(
        self,
        endpoint: str,
        *,
        bearer_token: str | None = None,
        timeout: float = 10.0,
        allow_insecure_http: bool = False,
    ) -> None:
        self.endpoint = _validate_endpoint(endpoint, allow_insecure_http=allow_insecure_http)
        self._bearer_token = bearer_token
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_RejectRedirects())

    def post(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> TransportResponse:
        body = json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers=self._headers(session_id=session_id, protocol_version=protocol_version),
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = _bounded_read(response)
                headers = {key.lower(): value for key, value in response.headers.items()}
                return TransportResponse(
                    status=response.status,
                    headers=headers,
                    messages=_decode_messages(raw, headers.get("content-type", "")),
                )
        except McpObservationError:
            raise
        except urllib.error.HTTPError as error:
            raise McpObservationError(f"MCP endpoint returned HTTP {error.code}") from error
        except (OSError, TimeoutError) as error:
            raise McpObservationError(
                f"MCP endpoint request failed: {error.__class__.__name__}"
            ) from error

    def close(
        self,
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> None:
        if not session_id:
            return
        request = urllib.request.Request(
            self.endpoint,
            headers=self._headers(session_id=session_id, protocol_version=protocol_version),
            method="DELETE",
        )
        try:
            with self._opener.open(request, timeout=self._timeout):
                pass
        except (McpObservationError, OSError, urllib.error.HTTPError):
            # Session termination is optional and cannot change inventory coverage.
            return

    def _headers(self, *, session_id: str | None, protocol_version: str | None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": "denali-ai-security/0.1",
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if protocol_version:
            headers["MCP-Protocol-Version"] = protocol_version
        return headers


class McpHttpObserver:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        endpoint: str,
        *,
        app_id: str | None = None,
        bearer_token: str | None = None,
        timeout: float = 10.0,
        allow_insecure_http: bool = False,
        transport: McpTransport | None = None,
    ) -> None:
        self.transport = transport or StreamableHttpTransport(
            endpoint,
            bearer_token=bearer_token,
            timeout=timeout,
            allow_insecure_http=allow_insecure_http,
        )
        self.endpoint = _public_endpoint(self.transport.endpoint)
        parsed = urlsplit(self.endpoint)
        self.app_id = _normalize_name(app_id or parsed.hostname or "mcp")
        self.authenticated = bool(bearer_token)

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or self.endpoint
        scope = f"mcp-endpoint:{self.endpoint}"
        assets: list[AssetAssertion] = []
        relationships: list[RelationshipAssertion] = []
        session_id: str | None = None
        protocol_version: str | None = None
        error: str | None = None
        initialized = False
        server_ref: AssetRef | None = None

        try:
            response = self.transport.post(_initialize_request())
            session_id = response.headers.get("mcp-session-id")
            result = _rpc_result(response, 1)
            protocol_version = _required_string(result, "protocolVersion")
            if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
                raise McpObservationError(
                    f"server selected unsupported MCP protocol {protocol_version!r}"
                )
            server_info = _required_mapping(result, "serverInfo")
            server_name = _required_string(server_info, "name")
            server_ref = self._server_ref(server_name)
            evidence = self._evidence(
                observed_at,
                method="initialize",
                payload={
                    "protocol_version": protocol_version,
                    "server_name": server_name,
                    "server_version": _optional_string(server_info, "version"),
                },
            )
            capabilities = result.get("capabilities")
            if not isinstance(capabilities, dict):
                raise McpObservationError("initialize result has no capabilities object")
            assets.append(
                AssetAssertion(
                    asset=server_ref,
                    coverage_plane=INVENTORY_PLANE,
                    display_name=_optional_string(server_info, "title") or server_name,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "transport": "streamable_http",
                        "endpoint": self.endpoint,
                        "protocol_version": protocol_version,
                        "server_version": _optional_string(server_info, "version"),
                        "capabilities": sorted(str(key) for key in capabilities),
                        "instructions_present": bool(result.get("instructions")),
                        "authentication_configured": self.authenticated,
                    },
                )
            )

            initialized_response = self.transport.post(
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                session_id=session_id,
                protocol_version=protocol_version,
            )
            if initialized_response.status != 202:
                raise McpObservationError(
                    "server did not acknowledge notifications/initialized with HTTP 202"
                )
            initialized = True

            if "tools" in capabilities:
                if not isinstance(capabilities["tools"], dict):
                    raise McpObservationError("server tools capability must be an object")
                self._collect_tools(
                    server_ref=server_ref,
                    observed_at=observed_at,
                    session_id=session_id,
                    protocol_version=protocol_version,
                    assets=assets,
                    relationships=relationships,
                )
        except (McpObservationError, ValueError, TypeError) as exception:
            error = _safe_detail(str(exception))[:500] or exception.__class__.__name__
        finally:
            self.transport.close(session_id=session_id, protocol_version=protocol_version)

        state = (
            CoverageState.COMPLETE
            if error is None
            else (CoverageState.PARTIAL if initialized or server_ref else CoverageState.FAILED)
        )
        coverage = (
            Coverage(INVENTORY_PLANE, state, scope, error),
            Coverage(RELATIONSHIP_PLANE, state, scope, error),
        )
        return InventoryBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection,
            run_id=f"mcp-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=coverage,
            assets=tuple(assets),
            relationships=tuple(relationships),
        )

    def _collect_tools(
        self,
        *,
        server_ref: AssetRef,
        observed_at: datetime,
        session_id: str | None,
        protocol_version: str,
        assets: list[AssetAssertion],
        relationships: list[RelationshipAssertion],
    ) -> None:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_names: set[str] = set()
        normalized_names: dict[str, str] = {}
        request_id = 2

        for page in range(1, MAX_PAGES + 1):
            params = {"cursor": cursor} if cursor else {}
            response = self.transport.post(
                {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params},
                session_id=session_id,
                protocol_version=protocol_version,
            )
            result = _rpc_result(response, request_id)
            tools = result.get("tools")
            if not isinstance(tools, list):
                raise McpObservationError("tools/list result has no tools array")

            for tool in tools:
                if not isinstance(tool, dict):
                    raise McpObservationError("tools/list returned a non-object tool")
                name = _required_string(tool, "name")
                if name in seen_names:
                    continue
                if len(seen_names) >= MAX_TOOLS:
                    raise McpObservationError(f"tool count exceeds safety limit {MAX_TOOLS}")
                normalized = _normalize_name(name)
                if not normalized:
                    raise McpObservationError("tool name has no canonical characters")
                previous = normalized_names.get(normalized)
                if previous is not None and previous != name:
                    raise McpObservationError(
                        f"tool names {previous!r} and {name!r} collide after canonicalization"
                    )
                normalized_names[normalized] = name
                seen_names.add(name)
                tool_ref = AssetRef(
                    AssetKind.AI_TOOL,
                    f"{server_ref.natural_key}:tool:{normalized}",
                )
                description = _optional_string(tool, "description") or ""
                input_schema = tool.get("inputSchema")
                if not isinstance(input_schema, dict):
                    raise McpObservationError(f"tool {name!r} has no inputSchema object")
                schema_digest = hashlib.sha256(
                    json.dumps(input_schema, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                evidence = self._evidence(
                    observed_at,
                    method="tools/list",
                    payload={
                        "page": page,
                        "name": name,
                        "description": description[:1_000],
                        "input_schema_sha256": schema_digest,
                    },
                )
                annotations = tool.get("annotations")
                assets.append(
                    AssetAssertion(
                        asset=tool_ref,
                        coverage_plane=INVENTORY_PLANE,
                        display_name=_optional_string(tool, "title") or name,
                        assertion_type=AssertionType.OBSERVED,
                        confidence=1.0,
                        evidence=evidence,
                        attributes={
                            "protocol_name": name,
                            "description": description[:8_000],
                            "input_schema": input_schema,
                            "output_schema_present": isinstance(tool.get("outputSchema"), dict),
                            "annotations": annotations if isinstance(annotations, dict) else {},
                        },
                    )
                )
                relationships.append(
                    RelationshipAssertion(
                        source=server_ref,
                        target=tool_ref,
                        coverage_plane=RELATIONSHIP_PLANE,
                        kind=RelationshipKind.EXPOSES,
                        assertion_type=AssertionType.OBSERVED,
                        confidence=1.0,
                        evidence=evidence,
                    )
                )

            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return
            if not isinstance(next_cursor, str) or not next_cursor:
                raise McpObservationError("tools/list returned an invalid nextCursor")
            if next_cursor in seen_cursors:
                raise McpObservationError("tools/list repeated a pagination cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
            request_id += 1

        raise McpObservationError(f"tools/list exceeds page safety limit {MAX_PAGES}")

    def _server_ref(self, server_name: str) -> AssetRef:
        canonical_name = _normalize_server(server_name)
        if not canonical_name:
            canonical_name = hashlib.sha256(self.endpoint.encode()).hexdigest()[:16]
        return AssetRef(AssetKind.MCP_SERVER, f"app:{self.app_id}:mcp:{canonical_name}")

    def _evidence(self, observed_at: datetime, *, method: str, payload: dict[str, Any]) -> Evidence:
        return Evidence(
            source_type="mcp_protocol_observation",
            locator=f"{_locator_endpoint(self.endpoint)}#{method}",
            observed_at=observed_at,
            payload=MappingProxyType(payload),
        )


def observe_main() -> None:
    parser = argparse.ArgumentParser(description="Observe one MCP Streamable HTTP endpoint")
    parser.add_argument("endpoint")
    parser.add_argument("--app-id", help="application namespace shared with repository discovery")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--token-env",
        default="DENALI_MCP_BEARER_TOKEN",
        help="environment variable containing a bearer token (never pass the token itself)",
    )
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="allow cleartext HTTP to non-loopback hosts",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")

    token = os.environ.get(args.token_env) if args.token_env else None
    observer = McpHttpObserver(
        args.endpoint,
        app_id=args.app_id,
        bearer_token=token,
        timeout=args.timeout,
        allow_insecure_http=args.allow_insecure_http,
    )
    batch = observer.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest(args.tenant_id, batch)
    state = batch.coverage[0].state
    print(
        f"Observed {observer.endpoint}: {result['assets']} assets, "
        f"{result['relationships']} relationships, coverage={state.value}"
    )
    if batch.coverage[0].detail:
        print(f"Coverage detail: {batch.coverage[0].detail}")
    if state is not CoverageState.COMPLETE:
        raise SystemExit(2)


def _initialize_request() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "denali-ai-security",
                "title": "Denali AI Security",
                "version": "0.1.0",
            },
        },
    }


def _rpc_result(response: TransportResponse, request_id: int) -> dict[str, Any]:
    for message in response.messages:
        if message.get("id") != request_id:
            continue
        error = message.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            detail = str(error.get("message", "JSON-RPC error"))[:300]
            raise McpObservationError(f"JSON-RPC {code}: {detail}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise McpObservationError(f"JSON-RPC response {request_id} has no result object")
        return result
    raise McpObservationError(f"MCP response omitted JSON-RPC id {request_id}")


def _required_mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    result = value.get(key)
    if not isinstance(result, dict):
        raise McpObservationError(f"MCP response field {key!r} must be an object")
    return result


def _required_string(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result.strip():
        raise McpObservationError(f"MCP response field {key!r} must be a non-empty string")
    return result.strip()


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    result = value.get(key)
    return result.strip() if isinstance(result, str) and result.strip() else None


def _decode_messages(raw: bytes, content_type: str) -> tuple[dict[str, Any], ...]:
    if not raw:
        return ()
    text = raw.decode("utf-8", errors="strict")
    values: list[Any]
    if content_type.lower().startswith("text/event-stream"):
        values = []
        data_lines: list[str] = []
        for line in text.splitlines() + [""]:
            if not line:
                if data_lines:
                    values.append(json.loads("\n".join(data_lines)))
                    data_lines = []
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
    else:
        values = [json.loads(text)]
    if not all(isinstance(value, dict) for value in values):
        raise McpObservationError("MCP transport returned a non-object JSON-RPC message")
    return tuple(values)


def _bounded_read(response) -> bytes:  # type: ignore[no-untyped-def]
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise McpObservationError(f"MCP response exceeds {MAX_RESPONSE_BYTES} byte safety limit")
    return raw


def _validate_endpoint(endpoint: str, *, allow_insecure_http: bool) -> str:
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("MCP endpoint must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("MCP endpoint must not contain credentials")
    if parsed.fragment:
        raise ValueError("MCP endpoint must not contain a fragment")
    if parsed.scheme == "http" and not allow_insecure_http and not _is_loopback(parsed.hostname):
        raise ValueError("cleartext MCP endpoints are allowed only on loopback hosts")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _locator_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return urlunsplit((f"mcp+{parsed.scheme}", parsed.netloc, parsed.path, "", ""))


def _public_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_detail(value: str) -> str:
    return _SENSITIVE_TEXT_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", value)


def _normalize_server(value: str) -> str:
    normalized = value.lower().strip()
    if normalized.startswith("mcp-") or normalized.startswith("mcp_"):
        normalized = normalized[4:]
    return _normalize_name(normalized)


def _normalize_name(value: str) -> str:
    return _NORMALIZE_RE.sub("_", value.lower()).strip("_")


if __name__ == "__main__":
    observe_main()
