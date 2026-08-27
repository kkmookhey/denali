"""Small operational commands for the local and hosted distributions."""

from __future__ import annotations

import os

from denali.store.db import migrate


def migrate_main() -> None:
    dsn = os.environ.get("DENALI_DSN")
    if not dsn:
        raise SystemExit("DENALI_DSN is required")
    migrate(dsn)
