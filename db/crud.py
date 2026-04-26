"""
AgentGuard – Async CRUD Operations for the Audit Ledger
========================================================
Security Rationale
------------------
* All writes go through `create_handshake`, which is called via a FastAPI
  `BackgroundTask` so that DB latency is **off the critical path** of tool
  execution.  An adversary cannot stall a tool call by flooding the DB.

* `get_handshakes_by_agent` and `get_high_risk_handshakes` are read-only
  helpers for the security dashboard; they use `LIMIT` / `OFFSET` pagination
  to prevent accidental full-table scans that could expose excessive audit
  data in a single response.

* There are intentionally **no update or delete helpers** – the audit ledger
  must remain append-only.  The DB user should be granted INSERT + SELECT only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Handshake, HandshakeStatus


async def create_handshake(
    session: AsyncSession,
    *,
    agent_identity: str,
    tool_name: str,
    input_payload: dict,
    output_payload: dict | None,
    status: HandshakeStatus,
    risk_score: float,
    reasoning: str | None = None,
    session_id: str | None = None,
    latency_ms: float | None = None,
) -> Handshake:
    """
    Persist one governed tool-call record to the immutable audit ledger.

    Parameters
    ----------
    session:
        Async SQLAlchemy session (injected by FastAPI dependency or passed
        explicitly from a background task).
    agent_identity:
        Stable identifier for the calling agent (JWT subject, API-key hash…).
    tool_name:
        The MCP tool that was invoked.
    input_payload:
        **Already-redacted** tool arguments – the caller is responsible for
        stripping secrets before passing them here.
    output_payload:
        **Masked** tool response, or None if the call was blocked before
        execution.
    status:
        Governance decision from the PolicyEngine.
    risk_score:
        Floating-point danger score in [0.0, 1.0].
    reasoning:
        Explanation text produced by the PolicyEngine.
    session_id:
        Optional correlation token linking multiple calls in one conversation.
    latency_ms:
        End-to-end wall time in milliseconds.

    Returns
    -------
    Handshake
        The freshly persisted ORM object (already committed by the session
        dependency's `finally` block or explicitly committed by the caller).
    """
    record = Handshake(
        id=uuid.uuid4(),
        timestamp=datetime.now(tz=timezone.utc),
        agent_identity=agent_identity,
        tool_name=tool_name,
        input_payload=input_payload,
        output_payload=output_payload,
        status=status.value,
        risk_score=float(risk_score),
        reasoning=reasoning,
        session_id=session_id,
        latency_ms=latency_ms,
    )
    session.add(record)
    await session.flush()   # Assign DB-generated defaults without a full commit.
    return record


async def get_handshake_by_id(
    session: AsyncSession,
    handshake_id: uuid.UUID,
) -> Handshake | None:
    """
    Retrieve a single audit record by its primary key.

    Security note: returns None instead of raising so callers cannot use
    timing differences to confirm whether an ID exists.
    """
    result = await session.execute(
        select(Handshake).where(Handshake.id == handshake_id)
    )
    return result.scalar_one_or_none()


async def get_handshakes_by_agent(
    session: AsyncSession,
    agent_identity: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> Sequence[Handshake]:
    """
    Return a paginated list of audit records for a given agent.

    The default `limit=50` prevents accidentally dumping the full history of
    a prolific agent in a single query.
    """
    result = await session.execute(
        select(Handshake)
        .where(Handshake.agent_identity == agent_identity)
        .order_by(Handshake.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


async def get_high_risk_handshakes(
    session: AsyncSession,
    *,
    threshold: float = 0.7,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[Handshake]:
    """
    Surface high-risk events for the security dashboard.

    Parameters
    ----------
    threshold:
        Minimum `risk_score` to include (default 0.7 – clearly dangerous).
    limit / offset:
        Pagination guard to prevent excessive data exposure.
    """
    result = await session.execute(
        select(Handshake)
        .where(Handshake.risk_score >= threshold)
        .order_by(Handshake.risk_score.desc(), Handshake.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


async def get_blocked_handshakes(
    session: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[Handshake]:
    """Return all BLOCKED audit records ordered by most recent first."""
    result = await session.execute(
        select(Handshake)
        .where(Handshake.status == HandshakeStatus.BLOCKED.value)
        .order_by(Handshake.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()
