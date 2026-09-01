"""PostgreSQL contract for the destructive Golden Path boundary."""

from __future__ import annotations

import os
import uuid

import psycopg
import pytest

from denali.connectors.demo import demo_batch
from denali.golden_path import GoldenPathError, reset_tenant
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_reset_requires_exact_confirmation_and_preserves_only_manifest_connections() -> None:
    assert DSN
    migrate(DSN)
    tenant_id = str(uuid.uuid4())
    keep_id = str(uuid.uuid4())
    remove_id = str(uuid.uuid4())
    repository = PostgresInventoryRepository(DSN)
    for connection_id, name in ((keep_id, "Keep"), (remove_id, "Remove")):
        repository.create_connection(
            tenant_id,
            connection_id=connection_id,
            provider="aws",
            display_name=name,
            credential_type="aws_assume_role",
            credential_reference={
                "role_arn": "arn:aws:iam::123456789012:role/Reader",
                "external_id": f"external-{connection_id}",
            },
            declared_scopes=["aws.code_to_cloud"],
            coverage_plan=[],
            configuration={"account_id": "123456789012", "regions": ["us-east-1"]},
        )
    repository.ingest(tenant_id, demo_batch())
    manifest = {
        "version": 1,
        "name": "test",
        "connections": [{"id": keep_id}],
    }

    preview = reset_tenant(
        DSN, tenant_id, manifest, apply=False, confirmation=None
    )
    assert preview["rows"]["asset"] > 0
    assert preview["rows"]["provider_connection_removed"] == 1

    with pytest.raises(GoldenPathError, match="exactly match"):
        reset_tenant(DSN, tenant_id, manifest, apply=True, confirmation="wrong")

    reset_tenant(DSN, tenant_id, manifest, apply=True, confirmation=tenant_id)
    with psycopg.connect(DSN) as connection:
        assert connection.execute(
            "SELECT id::text FROM provider_connection WHERE tenant_id = %s", (tenant_id,)
        ).fetchall() == [(keep_id,)]
        assert connection.execute(
            "SELECT count(*) FROM asset WHERE tenant_id = %s", (tenant_id,)
        ).fetchone() == (0,)
