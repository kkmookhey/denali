"""Database migration helpers."""

from __future__ import annotations

from importlib.resources import files

import psycopg


def migrate(dsn: str) -> None:
    migration_dir = files("denali.store").joinpath("migrations")
    with psycopg.connect(dsn) as connection:
        # The transaction-scoped lock also works with managed Postgres poolers when
        # migrations are accidentally started concurrently.
        connection.execute("SELECT pg_advisory_xact_lock(hashtext('denali-schema-migrations'))")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migration (
                version text PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        applied = {
            row[0] for row in connection.execute("SELECT version FROM schema_migration").fetchall()
        }
        for item in sorted(migration_dir.iterdir(), key=lambda path: path.name):
            if item.name.endswith(".sql") and item.name not in applied:
                connection.execute(item.read_text())
                connection.execute(
                    "INSERT INTO schema_migration (version) VALUES (%s) "
                    "ON CONFLICT (version) DO NOTHING",
                    (item.name,),
                )
