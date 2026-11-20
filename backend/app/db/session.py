"""Engine/session factory plus tenant context propagation for PostgreSQL Row-Level Security.

The request's verified organization and user IDs are stored in ``Session.info``. Every time the
session begins a transaction, they are written into transaction-local PostgreSQL settings
(``app.current_org_id`` / ``app.current_user_id``) that the RLS policies read, together with
``app.current_context = 'api'`` which gates access to the shared identity tables. Because the
settings are transaction-local (``set_config(..., true)``) they can never leak between pooled
connections.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

TENANT_ORG_KEY = "tenant_org_id"
TENANT_USER_KEY = "tenant_user_id"


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    if settings.is_sqlite:
        engine = create_engine(
            settings.database_url,
            echo=settings.db_echo,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

        return engine
    return create_engine(
        settings.database_url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_recycle=1800,
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def _apply_tenant_settings(session: Session, connection) -> None:  # type: ignore[no-untyped-def]
    if connection.dialect.name != "postgresql":
        return
    org_id = session.info.get(TENANT_ORG_KEY)
    user_id = session.info.get(TENANT_USER_KEY)
    connection.execute(
        text(
            "SELECT set_config('app.current_context', 'api', true), "
            "set_config('app.current_org_id', :org, true), "
            "set_config('app.current_user_id', :usr, true)"
        ),
        {"org": str(org_id) if org_id else "", "usr": str(user_id) if user_id else ""},
    )


@event.listens_for(Session, "after_begin")
def _on_begin(session: Session, _transaction, connection) -> None:  # type: ignore[no-untyped-def]
    _apply_tenant_settings(session, connection)


def set_tenant_context(
    session: Session, *, org_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None
) -> None:
    """Bind the verified tenant to this session (current and all future transactions)."""
    if org_id is not None:
        session.info[TENANT_ORG_KEY] = org_id
    if user_id is not None:
        session.info[TENANT_USER_KEY] = user_id
    if session.in_transaction():
        _apply_tenant_settings(session, session.connection())


def get_db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()
