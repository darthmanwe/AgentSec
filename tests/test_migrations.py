"""Alembic migration tests (AS-005).

These need a real PostgreSQL, because the failure they exist to catch is dialect-specific.
The first version of the ``was_executed`` check constraint was written as
``was_executed = 0`` — valid on SQLite, rejected by PostgreSQL, which has no
boolean-to-integer comparison. A SQLite-only test suite would have shipped it.

Skipped automatically when the database is unreachable, so `uv run task test` stays green
without a container. Run the stack first to exercise them:

    docker compose up -d postgres
    uv run pytest -m integration
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy
from sqlalchemy import text

# Imported for its side effect: declaring the models is what populates Base.metadata.
# Without it the expectations below are built from empty metadata, and the whole module
# passes against an empty database by comparing nothing to nothing. It only appeared to
# work because another test module imported the models first, so a green result here
# depended on collection order.
import agentsec.db.models  # noqa: F401  the import is the point
from agentsec.config import load_settings
from agentsec.db.base import Base

REPO_ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.integration

EXPECTED_TABLES = set(Base.metadata.tables)
assert EXPECTED_TABLES, "models were not imported; these tests would compare nothing"


def sync_url() -> str:
    """Alembic runs async, but these checks use a plain sync connection."""
    return load_settings().database_url.get_secret_value().replace("+asyncpg", "+psycopg2")


def database_reachable() -> bool:
    try:
        engine = sqlalchemy.create_engine(
            sync_url(), connect_args={"connect_timeout": 3}, poolclass=sqlalchemy.pool.NullPool
        )
        with engine.connect():
            return True
    except Exception:
        return False


requires_db = pytest.mark.skipif(
    not database_reachable(), reason="PostgreSQL not reachable (docker compose up -d postgres)"
)


def alembic(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def table_names() -> set[str]:
    engine = sqlalchemy.create_engine(sync_url(), poolclass=sqlalchemy.pool.NullPool)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "select tablename from pg_tables "
                "where schemaname='public' and tablename <> 'alembic_version'"
            )
        )
        return {r[0] for r in rows}


@requires_db
def test_upgrade_creates_every_table() -> None:
    result = alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr
    assert table_names() == EXPECTED_TABLES


@requires_db
def test_downgrade_removes_every_table() -> None:
    assert alembic("upgrade", "head").returncode == 0
    result = alembic("downgrade", "base")
    assert result.returncode == 0, result.stderr
    assert table_names() == set()
    # Leave the database usable for the next test and for interactive work.
    assert alembic("upgrade", "head").returncode == 0


@requires_db
def test_schema_matches_the_models() -> None:
    """Autogenerate must produce nothing: if it does, a model changed without a migration
    and a fresh database would not match a migrated one."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    assert alembic("upgrade", "head").returncode == 0
    engine = sqlalchemy.create_engine(sync_url(), poolclass=sqlalchemy.pool.NullPool)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models and migrations disagree: {diff}"


@requires_db
def test_timestamps_are_timezone_aware() -> None:
    """SQLite cannot represent this, so it can only be checked here. A naive timestamp in
    an audit trail cannot be compared across a DST boundary or another machine's zone."""
    assert alembic("upgrade", "head").returncode == 0
    engine = sqlalchemy.create_engine(sync_url(), poolclass=sqlalchemy.pool.NullPool)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "select table_name, column_name, data_type from information_schema.columns "
                "where table_schema='public' and data_type like 'timestamp%'"
            )
        ).fetchall()
    assert rows, "no timestamp columns found"
    naive = [(t, c) for t, c, d in rows if "with time zone" not in d]
    assert not naive, f"naive timestamp columns: {naive}"
