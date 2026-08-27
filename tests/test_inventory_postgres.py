"""Postgres contract tests.

Set ``DENALI_TEST_DSN`` to run them. The local Compose DSN uses port 55450; a skip
is expected in the dependency-free unit target and is not accepted in the DB gate.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def assertion(key: str, observed_at: datetime) -> AssetAssertion:
    return AssetAssertion(
        asset=AssetRef(AssetKind.AI_AGENT, key),
        coverage_plane="agents",
        display_name=key,
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=Evidence("fixture", f"fixture://{key}", observed_at),
    )


def inventory_batch(
    *, run_id: str, state: CoverageState, assets: tuple[AssetAssertion, ...], at: datetime
) -> InventoryBatch:
    return InventoryBatch(
        connector_id="fixture",
        connection_id="fixture-connection",
        run_id=run_id,
        scope_key="fixture-scope",
        collected_at=at,
        coverage=(Coverage("agents", state, "fixture-scope"),),
        assets=assets,
    )


@pytest.fixture
def repository():
    assert DSN
    migrate(DSN)
    tenant = str(uuid.uuid4())
    return tenant, PostgresInventoryRepository(DSN)


def test_complete_empty_snapshot_withdraws_but_partial_does_not(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    first = assertion("agent-one", now)
    repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-1", state=CoverageState.COMPLETE, assets=(first,), at=now
        ),
    )

    partial = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-2",
            state=CoverageState.PARTIAL,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert partial["withdrawn_assets"] == 0
    assert repo.summary(tenant)["total"] == 1

    complete = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-3",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=2),
        ),
    )
    assert complete["withdrawn_assets"] == 1
    assert repo.summary(tenant)["total"] == 0


def test_one_source_cannot_withdraw_another_sources_asset(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    shared = assertion("shared-agent", now)
    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-run", state=CoverageState.COMPLETE, assets=(shared,), at=now
        ),
    )
    second_source = InventoryBatch(
        connector_id="other-source",
        connection_id="other-connection",
        run_id="other-run",
        scope_key="fixture-scope",
        collected_at=now,
        coverage=(Coverage("agents", CoverageState.COMPLETE, "fixture-scope"),),
        assets=(shared,),
    )
    repo.ingest(tenant, second_source)

    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-empty",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert repo.summary(tenant)["total"] == 1
    detail = repo.get_asset(tenant, str(repo.list_assets(tenant)[0]["id"]))
    assert detail is not None
    active = [row for row in detail["assertions"] if row["withdrawn_at"] is None]
    assert {row["connector_id"] for row in active} == {"other-source"}
