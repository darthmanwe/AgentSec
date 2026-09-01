"""Declarative base and shared column types (AS-005).

Two choices worth explaining:

**Explicit constraint naming.** Without a naming convention, SQLAlchemy lets the database
invent constraint names, and Alembic then cannot generate a working ``downgrade`` because
it does not know what to drop. The AS-005 acceptance criterion requires upgrade *and*
downgrade to work, so names are deterministic.

**JSONB with a SQLite variant.** The production database is PostgreSQL and JSONB is the
right type there. But binding the schema to Postgres would mean every model and constraint
test needs a running container, and the S1 gate requires the authorization kernel to be
provable with nothing else running. The variant lets constraint behaviour be tested
in-memory while production still gets JSONB.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import DateTime, MetaData, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy.types import JSON, TypeEngine

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: JSONB on PostgreSQL, plain JSON elsewhere so the suite runs without a container.
JSONColumn: TypeEngine[Any] = postgresql.JSONB().with_variant(JSON(), "sqlite")

#: A SHA-256 hex digest. Fixed width because every digest in this system is SHA-256, and
#: a wrong-length value is a bug worth rejecting at the column rather than discovering
#: during an approval comparison.
DIGEST_LENGTH = 64
DigestColumn = String(DIGEST_LENGTH)

#: Timezone-aware throughout. A naive timestamp in an audit trail is a timestamp that
#: cannot be compared across a DST boundary or a machine in another zone.
TimestampColumn = DateTime(timezone=True)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {  # noqa: RUF012
        dict[str, Any]: JSONColumn,
        list[str]: JSONColumn,
        dt.datetime: TimestampColumn,
    }


def digest_column(**kwargs: Any) -> Any:
    """A SHA-256 digest column."""
    return mapped_column(DigestColumn, **kwargs)


__all__ = [
    "DIGEST_LENGTH",
    "NAMING_CONVENTION",
    "Base",
    "DigestColumn",
    "JSONColumn",
    "TimestampColumn",
    "digest_column",
]
