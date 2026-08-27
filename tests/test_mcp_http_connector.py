import json
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

import pytest

from denali.connectors.mcp_http import (
    INVENTORY_PLANE,
    RELATIONSHIP_PLANE,
    McpHttpObserver,
    McpObservationError,
    StreamableHttpTransport,
    TransportResponse,
    _decode_messages,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind


class FakeTransport:
    endpoint = "https://mcp.example.test/mcp"

    def __init__(
        self,
        responses: list[TransportResponse | Exception],
        *,
        endpoint: str | None = None,
    ) -> None:
        if endpoint:
            self.endpoint = endpoint
        self.responses = deque(responses)
        self.calls: list[tuple[dict[str, Any], str | None, str | None]] = []
        self.closed: tuple[str | None, str | None] | None = None

    def post(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> TransportResponse:
        self.calls.append((payload, session_id, protocol_version))
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response

    def close(
        self,
        *,
        session_id: str | None = None,
        protocol_version: str | None = None,
    ) -> None:
        self.closed = (session_id, protocol_version)


def response(message: dict[str, Any], **headers: str) -> TransportResponse:
    return TransportResponse(status=200, headers=headers, messages=(message,))


def initialize(*, capabilities: dict[str, Any] | None = None) -> TransportResponse:
    return response(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": capabilities or {},
                "serverInfo": {"name": "mcp-core-banking", "version": "1.4.0"},
            },
        },
        **{"mcp-session-id": "session-secret"},
    )


def accepted() -> TransportResponse:
    return TransportResponse(status=202, headers={}, messages=())


def test_live_observer_initializes_and_paginates_without_calling_tools() -> None:
    transport = FakeTransport(
        [
            initialize(capabilities={"tools": {"listChanged": True}}),
            accepted(),
            response(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {
                                "name": "get_balance",
                                "description": "Return account balance",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"account_id": {"type": "string"}},
                                },
                            }
                        ],
                        "nextCursor": "opaque-page-2",
                    },
                }
            ),
            response(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "result": {
                        "tools": [
                            {
                                "name": "transfer_funds",
                                "title": "Transfer Funds",
                                "description": "Move funds between accounts",
                                "inputSchema": {"type": "object"},
                                "annotations": {"destructiveHint": True},
                            }
                        ]
                    },
                }
            ),
        ]
    )

    batch = McpHttpObserver(
        transport.endpoint,
        app_id="Eiger",
        bearer_token="must-never-be-stored",
        transport=transport,
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert batch.may_withdraw(INVENTORY_PLANE)
    assert batch.may_withdraw(RELATIONSHIP_PLANE)
    assert [item.asset.kind for item in batch.assets].count(AssetKind.MCP_SERVER) == 1
    assert [item.asset.kind for item in batch.assets].count(AssetKind.AI_TOOL) == 2
    assert {item.kind for item in batch.relationships} == {RelationshipKind.EXPOSES}
    assert all(call[0].get("method") != "tools/call" for call in transport.calls)
    assert transport.calls[1][0]["method"] == "notifications/initialized"
    assert transport.calls[2][1:] == ("session-secret", "2025-11-25")
    assert transport.calls[3][0]["params"] == {"cursor": "opaque-page-2"}
    assert transport.closed == ("session-secret", "2025-11-25")
    assert "must-never-be-stored" not in str(batch)
    assert "session-secret" not in str(batch)


def test_server_without_tools_is_complete_inventory() -> None:
    transport = FakeTransport([initialize(), accepted()])

    batch = McpHttpObserver(transport.endpoint, transport=transport).collect()

    assert len(batch.assets) == 1
    assert batch.assets[0].asset.kind is AssetKind.MCP_SERVER
    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}


def test_failed_tool_page_is_partial_and_cannot_withdraw() -> None:
    transport = FakeTransport(
        [
            initialize(capabilities={"tools": {}}),
            accepted(),
            McpObservationError("timed out while listing tools"),
        ]
    )

    batch = McpHttpObserver(transport.endpoint, transport=transport).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert not batch.may_withdraw(INVENTORY_PLANE)
    assert not batch.may_withdraw(RELATIONSHIP_PLANE)
    assert batch.assets[0].asset.kind is AssetKind.MCP_SERVER
    assert "timed out" in (batch.coverage[0].detail or "")


def test_colliding_tool_names_are_not_silently_merged() -> None:
    transport = FakeTransport(
        [
            initialize(capabilities={"tools": {}}),
            accepted(),
            response(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {"name": "read-file", "inputSchema": {"type": "object"}},
                            {"name": "read_file", "inputSchema": {"type": "object"}},
                        ]
                    },
                }
            ),
        ]
    )

    batch = McpHttpObserver(transport.endpoint, transport=transport).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "collide after canonicalization" in (batch.coverage[0].detail or "")


def test_transport_rejects_credentials_and_cleartext_remote_hosts() -> None:
    with pytest.raises(ValueError, match="must not contain credentials"):
        StreamableHttpTransport("https://user:secret@example.com/mcp")
    with pytest.raises(ValueError, match="only on loopback"):
        StreamableHttpTransport("http://example.com/mcp")

    transport = StreamableHttpTransport("http://127.0.0.1:7777/mcp")
    assert transport.endpoint == "http://127.0.0.1:7777/mcp"


def test_endpoint_query_tokens_and_error_secrets_are_not_persisted() -> None:
    transport = FakeTransport(
        [McpObservationError("Bearer server-secret-token was rejected")],
        endpoint="https://mcp.example.test/mcp?access_token=query-secret",
    )

    batch = McpHttpObserver(transport.endpoint, transport=transport).collect()

    rendered = str(batch)
    assert "query-secret" not in rendered
    assert "server-secret-token" not in rendered
    assert "[REDACTED]" in (batch.coverage[0].detail or "")


def test_sse_transport_response_extracts_json_rpc_messages() -> None:
    raw = (
        b"event: message\n"
        b'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
        b"event: message\n"
        b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
    )

    messages = _decode_messages(raw, "text/event-stream; charset=utf-8")

    assert len(messages) == 2
    assert messages[1]["id"] == 1


def test_real_streamable_http_round_trip() -> None:
    calls: list[tuple[str, str | None, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            method = request["method"]
            calls.append(
                (
                    method,
                    self.headers.get("Mcp-Session-Id"),
                    self.headers.get("MCP-Protocol-Version"),
                )
            )
            if method == "initialize":
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "round-trip"},
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Mcp-Session-Id", "round-trip-session")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if method == "notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (
                b'data: {"jsonrpc":"2.0","id":2,"result":{"tools":['
                b'{"name":"ping","inputSchema":{"type":"object"}}]}}\n\n'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_DELETE(self) -> None:  # noqa: N802
            calls.append(
                (
                    "DELETE",
                    self.headers.get("Mcp-Session-Id"),
                    self.headers.get("MCP-Protocol-Version"),
                )
            )
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/mcp"
        batch = McpHttpObserver(endpoint, app_id="round-trip").collect()
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert [call[0] for call in calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "DELETE",
    ]
    assert all(call[1] == "round-trip-session" for call in calls[1:])
    assert all(call[2] == "2025-11-25" for call in calls[1:])
