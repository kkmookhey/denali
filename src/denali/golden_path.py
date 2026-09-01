"""Manifest-driven reset and acceptance checks for bounded demo tenants."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import psycopg
import yaml
from psycopg.rows import dict_row

DEFAULT_TENANT_ID = "00000000-0000-4000-8000-000000000001"

_TENANT_TABLES = (
    "issue",
    "issue_rule_evaluation",
    "runtime_detection",
    "runtime_detection_rule_evaluation",
    "vulnerability",
    "activity_event",
    "finding",
    "relationship_assertion",
    "asset",
    "collection_run",
    "connection_validation",
)


class GoldenPathError(ValueError):
    """A safe, actionable Golden Path configuration error."""


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    payload = yaml.safe_load(manifest_path.read_text())
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise GoldenPathError("manifest version must be 1")
    if not isinstance(payload.get("name"), str) or not payload["name"].strip():
        raise GoldenPathError("manifest name is required")
    connections = payload.get("connections")
    if not isinstance(connections, list) or not connections:
        raise GoldenPathError("manifest connections must be a non-empty list")
    connection_ids: set[str] = set()
    for connection in connections:
        if not isinstance(connection, dict):
            raise GoldenPathError("every connection must be an object")
        connection_id = connection.get("id")
        if not isinstance(connection_id, str) or connection_id in connection_ids:
            raise GoldenPathError("connection IDs must be unique strings")
        connection_ids.add(connection_id)
        if connection.get("provider") not in {"aws", "gcp", "github"}:
            raise GoldenPathError(f"unsupported provider for {connection_id}")
        if not isinstance(connection.get("declared_scopes"), list):
            raise GoldenPathError(f"declared_scopes must be a list for {connection_id}")
    expected = payload.get("expected")
    if not isinstance(expected, dict):
        raise GoldenPathError("manifest expected section is required")
    for key in ("repositories", "ai_workloads", "deployed_by"):
        if not isinstance(expected.get(key), list):
            raise GoldenPathError(f"expected.{key} must be a list")
    budgets = payload.get("budgets", {})
    if not isinstance(budgets, dict) or any(
        not isinstance(value, int) or value < 0 for value in budgets.values()
    ):
        raise GoldenPathError("budgets must contain non-negative integers")
    return payload


def reset_tenant(
    dsn: str,
    tenant_id: str,
    manifest: dict[str, Any],
    *,
    apply: bool,
    confirmation: str | None,
) -> dict[str, Any]:
    if apply and confirmation != tenant_id:
        raise GoldenPathError("--confirm-tenant must exactly match --tenant-id")
    keep_connections = {item["id"] for item in manifest["connections"]}
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        counts = {
            table: int(
                connection.execute(
                    f"SELECT count(*) AS count FROM {table} WHERE tenant_id = %s",
                    (tenant_id,),
                ).fetchone()["count"]
            )
            for table in _TENANT_TABLES
        }
        counts["provider_connection_removed"] = int(
            connection.execute(
                "SELECT count(*) AS count FROM provider_connection "
                "WHERE tenant_id = %s AND NOT (id = ANY(%s::uuid[]))",
                (tenant_id, sorted(keep_connections)),
            ).fetchone()["count"]
        )
        if apply:
            for table in _TENANT_TABLES:
                connection.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))
            connection.execute(
                "DELETE FROM provider_connection "
                "WHERE tenant_id = %s AND NOT (id = ANY(%s::uuid[]))",
                (tenant_id, sorted(keep_connections)),
            )
    return {
        "manifest": manifest["name"],
        "tenant_id": tenant_id,
        "mode": "applied" if apply else "dry-run",
        "preserved_connection_ids": sorted(keep_connections),
        "rows": counts,
    }


def verify_tenant(dsn: str, tenant_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        actual_connections = connection.execute(
            "SELECT id::text, provider, display_name, lifecycle_state, declared_scopes, "
            "configuration FROM provider_connection WHERE tenant_id = %s ORDER BY id",
            (tenant_id,),
        ).fetchall()
        expected_connections = {item["id"]: item for item in manifest["connections"]}
        actual_ids = {item["id"] for item in actual_connections}
        if actual_ids != set(expected_connections):
            failures.append(
                f"connection IDs differ: expected {sorted(expected_connections)}, "
                f"observed {sorted(actual_ids)}"
            )
        for actual in actual_connections:
            expected = expected_connections.get(actual["id"])
            if expected is None:
                continue
            for key in ("provider", "display_name"):
                if actual[key] != expected[key]:
                    failures.append(
                        f"connection {actual['id']} {key}: expected {expected[key]!r}, "
                        f"observed {actual[key]!r}"
                    )
            if actual["lifecycle_state"] != "active":
                failures.append(f"connection {actual['id']} is not active")
            if sorted(actual["declared_scopes"]) != sorted(expected["declared_scopes"]):
                failures.append(f"connection {actual['id']} declared scopes differ")
            _verify_connection_boundary(actual, expected, failures)

        active_assets = connection.execute(
            "SELECT kind, natural_key FROM asset "
            "WHERE tenant_id = %s AND lifecycle_state = 'active' ORDER BY kind, natural_key",
            (tenant_id,),
        ).fetchall()
        by_kind: dict[str, set[str]] = {}
        for item in active_assets:
            by_kind.setdefault(item["kind"], set()).add(item["natural_key"])
        expected = manifest["expected"]
        for key, kind in (("repositories", "code_repository"), ("ai_workloads", "ai_workload")):
            observed = by_kind.get(kind, set())
            required = set(expected[key])
            if observed != required:
                failures.append(
                    f"active {kind} set differs: expected {sorted(required)}, "
                    f"observed {sorted(observed)}"
                )

        edges = connection.execute(
            "SELECT source.natural_key AS source, target.natural_key AS target "
            "FROM relationship_assertion edge "
            "JOIN asset source ON source.id = edge.source_asset_id "
            "JOIN asset target ON target.id = edge.target_asset_id "
            "WHERE edge.tenant_id = %s AND edge.kind = 'deployed_by' "
            "AND edge.withdrawn_at IS NULL",
            (tenant_id,),
        ).fetchall()
        observed_edges = {(item["source"], item["target"]) for item in edges}
        for required in expected["deployed_by"]:
            edge = (required["workload"], required["repository"])
            if edge not in observed_edges:
                failures.append(f"missing deployed_by edge {edge[0]} -> {edge[1]}")

        forbidden_connectors = set(manifest.get("forbidden_connectors", []))
        observed_forbidden = connection.execute(
            "SELECT DISTINCT connector_id FROM collection_run "
            "WHERE tenant_id = %s AND connector_id = ANY(%s::text[]) ORDER BY connector_id",
            (tenant_id, sorted(forbidden_connectors)),
        ).fetchall()
        if observed_forbidden:
            failures.append(
                "forbidden connectors present: "
                + ", ".join(item["connector_id"] for item in observed_forbidden)
            )

        counts = _tenant_counts(connection, tenant_id)
        for key, limit in manifest.get("budgets", {}).items():
            observed = counts.get(key)
            if observed is None:
                failures.append(f"unknown budget key {key}")
            elif observed > limit:
                failures.append(f"{key} budget exceeded: {observed} > {limit}")

    return {
        "manifest": manifest["name"],
        "tenant_id": tenant_id,
        "status": "passed" if not failures else "failed",
        "failures": failures,
        "counts": counts,
    }


def _verify_connection_boundary(
    actual: dict[str, Any], expected: dict[str, Any], failures: list[str]
) -> None:
    configuration = actual["configuration"]
    boundary = expected.get("boundary", {})
    provider = actual["provider"]
    if provider == "github":
        observed = sorted(
            item.get("full_name")
            for item in configuration.get("repositories", [])
            if isinstance(item, dict)
        )
        wanted = sorted(boundary.get("repositories", []))
        if observed != wanted:
            failures.append(f"GitHub repository boundary differs: {observed}")
    elif provider == "aws":
        if configuration.get("account_id") != boundary.get("account_id"):
            failures.append("AWS account boundary differs")
        if sorted(configuration.get("regions", [])) != sorted(boundary.get("regions", [])):
            failures.append("AWS region boundary differs")
    elif provider == "gcp":
        observed_projects = sorted(
            item.get("id")
            for item in configuration.get("projects", [])
            if isinstance(item, dict)
        )
        if observed_projects != sorted(boundary.get("projects", [])):
            failures.append("GCP project boundary differs")
        if sorted(configuration.get("resource_names", [])) != sorted(
            boundary.get("resource_names", [])
        ):
            failures.append("GCP exact resource-name boundary differs")


def _tenant_counts(connection: Any, tenant_id: str) -> dict[str, int]:
    table_to_key = {
        "asset": "assets",
        "finding": "findings",
        "issue": "issues",
        "activity_event": "activities",
        "vulnerability": "vulnerabilities",
        "runtime_detection": "detections",
        "collection_run": "collection_runs",
    }
    return {
        key: int(
            connection.execute(
                f"SELECT count(*) AS count FROM {table} WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()["count"]
        )
        for table, key in table_to_key.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset or verify a manifest-bounded Denali Golden Path tenant"
    )
    parser.add_argument("command", choices=("reset", "verify"))
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    parser.add_argument(
        "--tenant-id", default=os.environ.get("DENALI_TENANT_ID", DEFAULT_TENANT_ID)
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-tenant")
    args = parser.parse_args()
    if not args.dsn:
        parser.error("--dsn or DENALI_DSN is required")
    manifest = load_manifest(args.manifest)
    if args.command == "verify":
        if args.apply or args.confirm_tenant:
            parser.error("--apply and --confirm-tenant are only valid with reset")
        result = verify_tenant(args.dsn, args.tenant_id, manifest)
    else:
        result = reset_tenant(
            args.dsn,
            args.tenant_id,
            manifest,
            apply=args.apply,
            confirmation=args.confirm_tenant,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result.get("status") == "failed":
        raise SystemExit(1)
