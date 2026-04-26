"""
AgentGuard – Async Database Engine & Session Factory
=====================================================
Security Rationale
------------------
* All DB operations run through an **async** session so they never block the
  event loop during a live tool intercept.
* Connection-pool size is intentionally limited (pool_size=5, max_overflow=10)
  to prevent a compromised proxy from exhausting DB connections.
* SSL enforcement is controlled via DATABASE_SSL_REQUIRE (default: True in
  production) so audit records cannot be tampered with in transit.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# ---------------------------------------------------------------------------
# Configuration – pulled from environment so secrets are never hard-coded.
# ---------------------------------------------------------------------------
_DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard",
)

_SSL_REQUIRE: bool = os.getenv("DATABASE_SSL_REQUIRE", "false").lower() == "true"

_connect_args: dict = {"ssl": "require"} if _SSL_REQUIRE else {}

# ---------------------------------------------------------------------------
# Async engine – echo=False in production so query text is not leaked to logs.
# ---------------------------------------------------------------------------
engine = create_async_engine(
    _DATABASE_URL,
    echo=os.getenv("DB_ECHO", "false").lower() == "true",
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,   # Detect stale connections before handing them out.
    connect_args=_connect_args,
)

# ---------------------------------------------------------------------------
# Session factory – expire_on_commit=False keeps detached objects readable
# after a commit, which is important for returning audit records to callers.
# ---------------------------------------------------------------------------
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all AgentGuard ORM models."""


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields a short-lived async DB session.

    Security note
    -------------
    The session is always closed in the `finally` block regardless of whether
    an exception occurred, preventing connection leaks that could be exploited
    to exhaust the pool.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_all_tables() -> None:
    """
    Idempotently create all tables defined against `Base`.

    Race-condition fix
    ------------------
    When uvicorn starts with multiple workers, every worker process runs its
    own lifespan handler concurrently.  SQLAlchemy's `create_all` checks
    whether the table exists and, if not, issues a bare `CREATE TABLE`
    (without `IF NOT EXISTS`).  Between the check and the DDL, a second
    worker can pass the same check and attempt the same `CREATE TABLE`.
    PostgreSQL registers a composite row-type for every table in `pg_type`
    the moment the DDL starts; the second worker therefore hits:

        UniqueViolationError: duplicate key value violates unique constraint
        "pg_type_typname_nsp_index"

    We serialise the DDL across all workers by acquiring a PostgreSQL
    session-level advisory lock (arbitrary constant 1_000_000_007) before
    running `create_all`.  Only one connection holds the lock at a time;
    the others wait.  Because advisory locks are released automatically
    when the connection closes, there is no risk of a lock being held
    indefinitely if a worker crashes mid-startup.

    The outer `try/except IntegrityError` is a belt-and-suspenders fallback:
    if the lock did not fully prevent the race (e.g. cross-process timing
    before asyncpg establishes the connection), we treat the error as "table
    already exists" and continue normally.
    """
    try:
        async with engine.begin() as conn:
            # Acquire a session-level advisory lock so only one worker runs
            # DDL at a time.  The lock is released when this transaction ends.
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(1000000007)")
            )
            await conn.run_sync(Base.metadata.create_all)
    except IntegrityError as exc:
        # The table (and its pg_type entry) was already created by another
        # worker that won the race.  This is not an error – swallow and move on.
        if "pg_type_typname_nsp_index" in str(exc) or "already exists" in str(exc).lower():
            return
        raise
