"""Small operational commands for the local and hosted distributions."""

from __future__ import annotations

import os

from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository


def migrate_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    migrate(dsn)


def evaluate_issues_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    tenant_id = os.environ.get(
        "DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"
    )
    migrate(dsn)
    result = PostgresInventoryRepository(dsn).evaluate_issues(tenant_id)
    print(
        f"Evaluated issues: {result['confirmed_issues']} confirmed; "
        f"coverage={result['evaluation_state']}; "
        f"incomplete={result['incomplete_candidates']}; "
        f"ambiguous={result['ambiguous_resource_references']}"
    )
