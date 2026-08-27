"""Transactional Postgres repository for canonical inventory assertions."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

from denali.domain import (
    AssetAssertion,
    AssetRef,
    CoverageState,
    FindingAssertion,
    FindingBatch,
    InventoryBatch,
    RelationshipAssertion,
)

_ASSERTION_RANK_SQL = """
CASE aa.assertion_type
  WHEN 'externally_verified' THEN 4
  WHEN 'observed' THEN 3
  WHEN 'declared' THEN 2
  WHEN 'inferred' THEN 1
  ELSE 0
END
"""


class PostgresInventoryRepository:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]:
        """Persist a batch atomically and reconcile only completely covered planes."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                asset_ids: dict[AssetRef, str] = {}
                for assertion in batch.assets:
                    asset_id = self._ensure_asset(
                        connection,
                        tenant_id,
                        assertion.asset,
                        batch.collected_at,
                    )
                    asset_ids[assertion.asset] = asset_id
                    self._upsert_asset_assertion(connection, tenant_id, batch, asset_id, assertion)

                for assertion in batch.relationships:
                    source_id = asset_ids.get(assertion.source)
                    if source_id is None:
                        source_id = self._ensure_asset(
                            connection, tenant_id, assertion.source, batch.collected_at
                        )
                        asset_ids[assertion.source] = source_id
                    target_id = asset_ids.get(assertion.target)
                    if target_id is None:
                        target_id = self._ensure_asset(
                            connection, tenant_id, assertion.target, batch.collected_at
                        )
                        asset_ids[assertion.target] = target_id
                    principal_id = self._optional_asset(
                        connection, tenant_id, assertion.principal_ref, batch.collected_at
                    )
                    agent_id = self._optional_asset(
                        connection, tenant_id, assertion.agent_ref, batch.collected_at
                    )
                    self._upsert_relationship(
                        connection,
                        tenant_id,
                        batch,
                        assertion,
                        source_id,
                        target_id,
                        principal_id,
                        agent_id,
                    )

                withdrawn_assets = 0
                withdrawn_relationships = 0
                for coverage in batch.coverage:
                    if coverage.state is not CoverageState.COMPLETE:
                        continue
                    withdrawn_assets += self._withdraw_missing_assets(
                        connection, tenant_id, batch, coverage.plane
                    )
                    withdrawn_relationships += self._withdraw_missing_relationships(
                        connection, tenant_id, batch, coverage.plane
                    )

                self._refresh_asset_lifecycle(connection, tenant_id)

        return {
            "assets": len(batch.assets),
            "relationships": len(batch.relationships),
            "withdrawn_assets": withdrawn_assets,
            "withdrawn_relationships": withdrawn_relationships,
        }

    def ingest_findings(self, tenant_id: str, batch: FindingBatch) -> dict[str, int]:
        """Persist finding observations without manufacturing inventory assets."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                persisted_findings = 0
                for finding in batch.findings:
                    if finding.evaluation_result.value == "pass" and not self._finding_exists(
                        connection, tenant_id, batch, finding
                    ):
                        continue
                    finding_id = self._upsert_finding(
                        connection,
                        tenant_id,
                        batch,
                        finding,
                    )
                    persisted_findings += 1
                    self._replace_finding_resources(
                        connection,
                        tenant_id,
                        finding_id,
                        finding,
                    )
                    self._replace_finding_compliance(
                        connection,
                        tenant_id,
                        finding_id,
                        finding,
                    )
                    self._insert_finding_observation(
                        connection,
                        tenant_id,
                        finding_id,
                        batch,
                        finding,
                    )

                resolved_missing = 0
                if batch.may_resolve_missing:
                    result = connection.execute(
                        """
                        UPDATE finding
                        SET state = 'resolved',
                            evaluation_result = 'unknown',
                            resolution_reason = 'absent_from_authoritative_snapshot',
                            last_changed_at = %s
                        WHERE tenant_id = %s::uuid
                          AND connector_id = %s
                          AND connection_id = %s
                          AND scope_key = %s
                          AND last_observed_run_id <> %s
                          AND state IN ('open', 'unknown')
                        """,
                        (
                            batch.collected_at,
                            tenant_id,
                            batch.connector_id,
                            batch.connection_id,
                            batch.scope_key,
                            batch.run_id,
                        ),
                    )
                    resolved_missing = result.rowcount

        return {"findings": persisted_findings, "resolved_missing": resolved_missing}

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT f.*,
                       (SELECT count(*) FROM finding_resource fr
                        WHERE fr.tenant_id = f.tenant_id AND fr.finding_id = f.id)
                           AS resource_count
                FROM finding f
                WHERE f.tenant_id = %s::uuid
                  AND (%s::text IS NULL OR f.state = %s::text)
                  AND (%s::text IS NULL OR f.severity = %s::text)
                ORDER BY
                  CASE f.state WHEN 'open' THEN 0 WHEN 'unknown' THEN 1
                               WHEN 'suppressed' THEN 2 ELSE 3 END,
                  CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                  WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                  WHEN 'informational' THEN 4 ELSE 5 END,
                  f.last_seen_at DESC, f.source_uid
                LIMIT %s OFFSET %s
                """,
                (tenant_id, state, state, severity, severity, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            finding = connection.execute(
                "SELECT * FROM finding WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, finding_id),
            ).fetchone()
            if finding is None:
                return None
            resources = connection.execute(
                """
                SELECT resource_uid AS uid, resource_name AS name,
                       resource_type, provider, account_uid, region
                FROM finding_resource
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY resource_uid
                """,
                (tenant_id, finding_id),
            ).fetchall()
            compliance = connection.execute(
                """
                SELECT framework, control
                FROM finding_compliance
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY framework, control
                """,
                (tenant_id, finding_id),
            ).fetchall()
            observations = connection.execute(
                """
                SELECT run_id, scope_key, collected_at, source_observed_at,
                       severity, state, evaluation_result, evidence, attributes,
                       affected_resources, compliance
                FROM finding_observation
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY collected_at DESC
                LIMIT 50
                """,
                (tenant_id, finding_id),
            ).fetchall()
        result = dict(finding)
        result["resources"] = [dict(row) for row in resources]
        grouped: dict[str, list[str]] = {}
        for row in compliance:
            grouped.setdefault(row["framework"], []).append(row["control"])
        result["compliance"] = grouped
        result["observations"] = [dict(row) for row in observations]
        return result

    def finding_summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_state = connection.execute(
                """
                SELECT state, count(*) AS count
                FROM finding WHERE tenant_id = %s::uuid
                GROUP BY state ORDER BY state
                """,
                (tenant_id,),
            ).fetchall()
            open_by_severity = connection.execute(
                """
                SELECT severity, count(*) AS count
                FROM finding WHERE tenant_id = %s::uuid AND state = 'open'
                GROUP BY severity ORDER BY severity
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_state),
            "by_state": {row["state"]: row["count"] for row in by_state},
            "open_by_severity": {row["severity"]: row["count"] for row in open_by_severity},
        }

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        lifecycle: str = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        query = f"""
        SELECT a.id, a.kind, a.natural_key, a.governance_status, a.lifecycle_state,
               a.owner, a.first_seen_at, a.last_seen_at, a.last_changed_at,
               winner.display_name, winner.attributes, winner.assertion_type,
               winner.confidence, winner.connector_id, winner.connection_id
        FROM asset a
        LEFT JOIN LATERAL (
            SELECT aa.display_name, aa.attributes, aa.assertion_type, aa.confidence,
                   aa.connector_id, aa.connection_id
            FROM asset_assertion aa
            WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
              AND aa.withdrawn_at IS NULL
            ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC,
                     aa.connector_id, aa.connection_id
            LIMIT 1
        ) winner ON true
        WHERE a.tenant_id = %s::uuid
          AND (%s::text IS NULL OR a.kind = %s::text)
          AND (%s::text IS NULL OR a.lifecycle_state = %s::text)
        ORDER BY COALESCE(winner.display_name, a.natural_key), a.kind, a.natural_key
        LIMIT %s OFFSET %s
        """
        lifecycle_filter = lifecycle or None
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                query,
                (tenant_id, kind, kind, lifecycle_filter, lifecycle_filter, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            asset = connection.execute(
                "SELECT * FROM asset WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, asset_id),
            ).fetchone()
            if asset is None:
                return None
            assertions = connection.execute(
                """
                SELECT connector_id, connection_id, scope_key, coverage_plane,
                       assertion_type, confidence, display_name, attributes, evidence,
                       lifecycle_state, first_seen_at, last_seen_at, withdrawn_at
                FROM asset_assertion
                WHERE tenant_id = %s::uuid AND asset_id = %s::uuid
                ORDER BY withdrawn_at NULLS FIRST, last_seen_at DESC
                """,
                (tenant_id, asset_id),
            ).fetchall()
            relationships = connection.execute(
                """
                SELECT r.id, r.kind, r.category, r.assertion_type, r.confidence,
                       r.attributes, r.evidence, r.withdrawn_at,
                       s.id AS source_id, s.kind AS source_kind,
                       s.natural_key AS source_natural_key,
                       t.id AS target_id, t.kind AS target_kind,
                       t.natural_key AS target_natural_key
                FROM relationship_assertion r
                JOIN asset s ON s.id = r.source_asset_id
                JOIN asset t ON t.id = r.target_asset_id
                WHERE r.tenant_id = %s::uuid
                  AND (r.source_asset_id = %s::uuid OR r.target_asset_id = %s::uuid)
                ORDER BY r.withdrawn_at NULLS FIRST, r.kind, s.natural_key, t.natural_key
                """,
                (tenant_id, asset_id, asset_id),
            ).fetchall()
        result = dict(asset)
        result["assertions"] = [dict(row) for row in assertions]
        result["relationships"] = [dict(row) for row in relationships]
        return result

    def summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_kind = connection.execute(
                """
                SELECT kind, count(*) AS count
                FROM asset
                WHERE tenant_id = %s::uuid AND lifecycle_state = 'active'
                GROUP BY kind ORDER BY kind
                """,
                (tenant_id,),
            ).fetchall()
            governance = connection.execute(
                """
                SELECT governance_status, count(*) AS count
                FROM asset
                WHERE tenant_id = %s::uuid AND lifecycle_state = 'active'
                GROUP BY governance_status ORDER BY governance_status
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_kind),
            "by_kind": {row["kind"]: row["count"] for row in by_kind},
            "by_governance": {row["governance_status"]: row["count"] for row in governance},
        }

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT ON (connector_id, connection_id, plane, scope)
                       connector_id, connection_id, plane, scope, state, detail,
                       run_id, collected_at
                FROM collection_coverage
                WHERE tenant_id = %s::uuid
                ORDER BY connector_id, connection_id, plane, scope, collected_at DESC
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        if status not in {"approved", "unreviewed", "unwanted"}:
            raise ValueError("unsupported governance status")
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                UPDATE asset
                SET governance_status = %s, owner = %s, notes = %s
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                RETURNING id, governance_status, owner, notes
                """,
                (status, owner, notes, tenant_id, asset_id),
            ).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _finding_exists(
        connection,
        tenant_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM finding
                WHERE tenant_id = %s::uuid AND connector_id = %s
                  AND connection_id = %s AND source_uid = %s
                """,
                (
                    tenant_id,
                    batch.connector_id,
                    batch.connection_id,
                    finding.source_uid,
                ),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _upsert_finding(
        connection,
        tenant_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> str:
        evidence = _evidence_json(finding.evidence)
        resolution_reason = "source_status" if finding.state.value == "resolved" else None
        row = connection.execute(
            """
            INSERT INTO finding
              (tenant_id, connector_id, connection_id, scope_key, source_uid, rule_uid,
               title, description, risk, remediation, remediation_references, severity,
               state, evaluation_result, class_uid, class_name, source_observed_at,
               evidence, attributes, resolution_reason, first_seen_at, last_seen_at,
               last_changed_at, last_observed_run_id)
            VALUES
              (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s,
               %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, connector_id, connection_id, source_uid)
            DO UPDATE SET
              last_changed_at = CASE WHEN
                (finding.scope_key, finding.rule_uid, finding.title, finding.description,
                 finding.risk, finding.remediation, finding.remediation_references,
                 finding.severity, finding.state, finding.evaluation_result,
                 finding.class_uid, finding.class_name, finding.attributes)
                IS DISTINCT FROM
                (EXCLUDED.scope_key, EXCLUDED.rule_uid, EXCLUDED.title,
                 EXCLUDED.description, EXCLUDED.risk, EXCLUDED.remediation,
                 EXCLUDED.remediation_references, EXCLUDED.severity, EXCLUDED.state,
                 EXCLUDED.evaluation_result, EXCLUDED.class_uid, EXCLUDED.class_name,
                 EXCLUDED.attributes)
                THEN EXCLUDED.last_seen_at ELSE finding.last_changed_at END,
              scope_key = EXCLUDED.scope_key,
              rule_uid = EXCLUDED.rule_uid,
              title = EXCLUDED.title,
              description = EXCLUDED.description,
              risk = EXCLUDED.risk,
              remediation = EXCLUDED.remediation,
              remediation_references = EXCLUDED.remediation_references,
              severity = EXCLUDED.severity,
              state = EXCLUDED.state,
              evaluation_result = EXCLUDED.evaluation_result,
              class_uid = EXCLUDED.class_uid,
              class_name = EXCLUDED.class_name,
              source_observed_at = EXCLUDED.source_observed_at,
              evidence = EXCLUDED.evidence,
              attributes = EXCLUDED.attributes,
              resolution_reason = EXCLUDED.resolution_reason,
              last_seen_at = EXCLUDED.last_seen_at,
              last_observed_run_id = EXCLUDED.last_observed_run_id
            RETURNING id
            """,
            (
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                finding.source_uid,
                finding.rule_uid,
                finding.title,
                finding.description,
                finding.risk,
                finding.remediation,
                json.dumps(finding.remediation_references),
                finding.severity.value,
                finding.state.value,
                finding.evaluation_result.value,
                finding.class_uid,
                finding.class_name,
                finding.observed_at,
                json.dumps(evidence),
                json.dumps(dict(finding.attributes)),
                resolution_reason,
                batch.collected_at,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        ).fetchone()
        return str(row["id"])

    @staticmethod
    def _replace_finding_resources(
        connection,
        tenant_id: str,
        finding_id: str,
        finding: FindingAssertion,
    ) -> None:
        connection.execute(
            "DELETE FROM finding_resource WHERE tenant_id = %s::uuid AND finding_id = %s::uuid",
            (tenant_id, finding_id),
        )
        for resource in finding.affected_resources:
            connection.execute(
                """
                INSERT INTO finding_resource
                  (tenant_id, finding_id, resource_uid, resource_name, resource_type,
                   provider, account_uid, region)
                VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tenant_id,
                    finding_id,
                    resource.uid,
                    resource.name,
                    resource.resource_type,
                    resource.provider,
                    resource.account_uid,
                    resource.region,
                ),
            )

    @staticmethod
    def _replace_finding_compliance(
        connection,
        tenant_id: str,
        finding_id: str,
        finding: FindingAssertion,
    ) -> None:
        connection.execute(
            "DELETE FROM finding_compliance WHERE tenant_id = %s::uuid AND finding_id = %s::uuid",
            (tenant_id, finding_id),
        )
        for framework, controls in finding.compliance.items():
            for control in controls:
                connection.execute(
                    """
                    INSERT INTO finding_compliance
                      (tenant_id, finding_id, framework, control)
                    VALUES (%s::uuid, %s::uuid, %s, %s)
                    """,
                    (tenant_id, finding_id, framework, control),
                )

    @staticmethod
    def _insert_finding_observation(
        connection,
        tenant_id: str,
        finding_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> None:
        resources = [
            {
                "uid": resource.uid,
                "name": resource.name,
                "resource_type": resource.resource_type,
                "provider": resource.provider,
                "account_uid": resource.account_uid,
                "region": resource.region,
            }
            for resource in finding.affected_resources
        ]
        connection.execute(
            """
            INSERT INTO finding_observation
              (tenant_id, finding_id, connector_id, connection_id, run_id, scope_key,
               collected_at, source_observed_at, severity, state, evaluation_result,
               evidence, attributes, affected_resources, compliance)
            VALUES
              (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s,
               %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
            ON CONFLICT
              (tenant_id, finding_id, connector_id, connection_id, run_id)
            DO UPDATE SET
              collected_at = EXCLUDED.collected_at,
              source_observed_at = EXCLUDED.source_observed_at,
              severity = EXCLUDED.severity,
              state = EXCLUDED.state,
              evaluation_result = EXCLUDED.evaluation_result,
              evidence = EXCLUDED.evidence,
              attributes = EXCLUDED.attributes,
              affected_resources = EXCLUDED.affected_resources,
              compliance = EXCLUDED.compliance
            """,
            (
                tenant_id,
                finding_id,
                batch.connector_id,
                batch.connection_id,
                batch.run_id,
                batch.scope_key,
                batch.collected_at,
                finding.observed_at,
                finding.severity.value,
                finding.state.value,
                finding.evaluation_result.value,
                json.dumps(_evidence_json(finding.evidence)),
                json.dumps(dict(finding.attributes)),
                json.dumps(resources),
                json.dumps(dict(finding.compliance)),
            ),
        )

    @staticmethod
    def _insert_run(connection, tenant_id: str, batch: InventoryBatch | FindingBatch) -> None:
        connection.execute(
            """
            INSERT INTO collection_run
              (tenant_id, connector_id, connection_id, run_id, scope_key, collected_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, connector_id, connection_id, run_id) DO NOTHING
            """,
            (
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.run_id,
                batch.scope_key,
                batch.collected_at,
            ),
        )
        for coverage in batch.coverage:
            connection.execute(
                """
                INSERT INTO collection_coverage
                  (tenant_id, connector_id, connection_id, run_id, plane, scope, state,
                   detail, collected_at)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, connector_id, connection_id, run_id, plane, scope)
                DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail,
                              collected_at = EXCLUDED.collected_at
                """,
                (
                    tenant_id,
                    batch.connector_id,
                    batch.connection_id,
                    batch.run_id,
                    coverage.plane,
                    coverage.scope,
                    coverage.state.value,
                    coverage.detail,
                    batch.collected_at,
                ),
            )

    @staticmethod
    def _ensure_asset(connection, tenant_id: str, ref: AssetRef, seen_at: datetime) -> str:
        row = connection.execute(
            """
            INSERT INTO asset
              (tenant_id, kind, natural_key, first_seen_at, last_seen_at, last_changed_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, kind, natural_key)
            DO UPDATE SET last_seen_at = GREATEST(asset.last_seen_at, EXCLUDED.last_seen_at)
            RETURNING id
            """,
            (tenant_id, ref.kind.value, ref.natural_key, seen_at, seen_at, seen_at),
        ).fetchone()
        return str(row["id"])

    def _optional_asset(
        self, connection, tenant_id: str, ref: AssetRef | None, seen_at: datetime
    ) -> str | None:
        return None if ref is None else self._ensure_asset(connection, tenant_id, ref, seen_at)

    @staticmethod
    def _upsert_asset_assertion(
        connection,
        tenant_id: str,
        batch: InventoryBatch,
        asset_id: str,
        assertion: AssetAssertion,
    ) -> None:
        evidence = _evidence_json(assertion.evidence)
        connection.execute(
            """
            INSERT INTO asset_assertion
              (tenant_id, asset_id, connector_id, connection_id, scope_key,
               coverage_plane, assertion_type, confidence, display_name, attributes,
               evidence, lifecycle_state, first_seen_at, last_seen_at,
               last_observed_run_id, withdrawn_at)
            VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s::jsonb,
                    %s::jsonb, %s, %s, %s, %s, NULL)
            ON CONFLICT
              (tenant_id, asset_id, connector_id, connection_id, scope_key,
               coverage_plane, assertion_type)
            DO UPDATE SET confidence = EXCLUDED.confidence,
                          display_name = EXCLUDED.display_name,
                          attributes = EXCLUDED.attributes,
                          evidence = EXCLUDED.evidence,
                          lifecycle_state = EXCLUDED.lifecycle_state,
                          last_seen_at = EXCLUDED.last_seen_at,
                          last_observed_run_id = EXCLUDED.last_observed_run_id,
                          withdrawn_at = NULL
            """,
            (
                tenant_id,
                asset_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                assertion.coverage_plane,
                assertion.assertion_type.value,
                assertion.confidence,
                assertion.display_name,
                json.dumps(dict(assertion.attributes)),
                json.dumps(evidence),
                assertion.lifecycle.value,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        )

    @staticmethod
    def _upsert_relationship(
        connection,
        tenant_id: str,
        batch: InventoryBatch,
        assertion: RelationshipAssertion,
        source_id: str,
        target_id: str,
        principal_id: str | None,
        agent_id: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO relationship_assertion
              (tenant_id, source_asset_id, target_asset_id, kind, category,
               connector_id, connection_id, scope_key, coverage_plane, assertion_type,
               confidence, attributes, evidence, principal_asset_id, agent_asset_id,
               first_seen_at, last_seen_at, last_observed_run_id, withdrawn_at)
            VALUES (%s::uuid, %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::uuid, %s::uuid, %s, %s, %s, NULL)
            ON CONFLICT
              (tenant_id, source_asset_id, target_asset_id, kind, connector_id,
               connection_id, scope_key, coverage_plane, assertion_type)
            DO UPDATE SET confidence = EXCLUDED.confidence,
                          attributes = EXCLUDED.attributes,
                          evidence = EXCLUDED.evidence,
                          principal_asset_id = EXCLUDED.principal_asset_id,
                          agent_asset_id = EXCLUDED.agent_asset_id,
                          last_seen_at = EXCLUDED.last_seen_at,
                          last_observed_run_id = EXCLUDED.last_observed_run_id,
                          withdrawn_at = NULL
            """,
            (
                tenant_id,
                source_id,
                target_id,
                assertion.kind.value,
                assertion.category.value,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                assertion.coverage_plane,
                assertion.assertion_type.value,
                assertion.confidence,
                json.dumps(dict(assertion.attributes)),
                json.dumps(_evidence_json(assertion.evidence)),
                principal_id,
                agent_id,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        )

    @staticmethod
    def _withdraw_missing_assets(
        connection, tenant_id: str, batch: InventoryBatch, plane: str
    ) -> int:
        result = connection.execute(
            """
            UPDATE asset_assertion
            SET withdrawn_at = %s, lifecycle_state = 'withdrawn'
            WHERE tenant_id = %s::uuid AND connector_id = %s AND connection_id = %s
              AND scope_key = %s AND coverage_plane = %s AND withdrawn_at IS NULL
              AND last_observed_run_id <> %s
            """,
            (
                batch.collected_at,
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                plane,
                batch.run_id,
            ),
        )
        return result.rowcount

    @staticmethod
    def _withdraw_missing_relationships(
        connection, tenant_id: str, batch: InventoryBatch, plane: str
    ) -> int:
        result = connection.execute(
            """
            UPDATE relationship_assertion
            SET withdrawn_at = %s
            WHERE tenant_id = %s::uuid AND connector_id = %s AND connection_id = %s
              AND scope_key = %s AND coverage_plane = %s AND withdrawn_at IS NULL
              AND last_observed_run_id <> %s
            """,
            (
                batch.collected_at,
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                plane,
                batch.run_id,
            ),
        )
        return result.rowcount

    @staticmethod
    def _refresh_asset_lifecycle(connection, tenant_id: str) -> None:
        connection.execute(
            """
            UPDATE asset a
            SET lifecycle_state = CASE WHEN
                EXISTS (
                    SELECT 1 FROM asset_assertion aa
                    WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
                      AND aa.withdrawn_at IS NULL
                ) OR EXISTS (
                    SELECT 1 FROM relationship_assertion ra
                    WHERE ra.tenant_id = a.tenant_id
                      AND (ra.source_asset_id = a.id OR ra.target_asset_id = a.id)
                      AND ra.withdrawn_at IS NULL
                ) THEN 'active' ELSE 'withdrawn' END
            WHERE a.tenant_id = %s::uuid
            """,
            (tenant_id,),
        )


def _evidence_json(evidence) -> dict[str, Any]:
    return {
        "source_type": evidence.source_type,
        "locator": evidence.locator,
        "observed_at": evidence.observed_at.isoformat(),
        "payload": dict(evidence.payload),
    }
