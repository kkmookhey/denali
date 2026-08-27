"""Database migration helpers."""

from __future__ import annotations

from importlib.resources import files

import psycopg


def migrate(dsn: str) -> None:
    migration_dir = files("denali.store").joinpath("migrations")
    with psycopg.connect(dsn) as connection:
        for item in sorted(migration_dir.iterdir(), key=lambda path: path.name):
            if item.name.endswith(".sql"):
                connection.execute(item.read_text())
                connection.execute(
                    "INSERT INTO schema_migration (version) VALUES (%s) "
                    "ON CONFLICT (version) DO NOTHING",
                    (item.name,),
                )
