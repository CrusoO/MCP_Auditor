"""
AgentGuard – Dashboard API Router
==================================
Provides read-only aggregation endpoints consumed by the React dashboard.
All queries are paginated and use indexed columns so they never do full
table scans against the audit ledger.
"""

from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db_session
from db.models import Handshake

router = APIRouter(prefix="/v1/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class StatsResponse(BaseModel):
    total_calls: int
    blocked: int
    allowed: int
    redacted: int
    error: int
    avg_risk_score: float
    high_risk_count: int
    block_rate: float


class HandshakeSummary(BaseModel):
    id: str
    timestamp: str
    agent_identity: str
    tool_name: str
    status: str
    risk_score: float
    reasoning: str | None
    latency_ms: float | None
    session_id: str | None
    input_payload: dict[str, Any]
    output_payload: dict[str, Any] | None


class PaginatedAudit(BaseModel):
    items: list[HandshakeSummary]
    total: int
    page: int
    pages: int
    limit: int


class AgentStat(BaseModel):
    agent_identity: str
    total_calls: int
    blocked_calls: int
    avg_risk_score: float
    block_rate: float


class RiskPoint(BaseModel):
    timestamp: str
    risk_score: float
    status: str
    tool_name: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serialize(h: Handshake) -> HandshakeSummary:
    return HandshakeSummary(
        id=str(h.id),
        timestamp=h.timestamp.isoformat() if h.timestamp else "",
        agent_identity=h.agent_identity,
        tool_name=h.tool_name,
        status=h.status,
        risk_score=round(h.risk_score, 4),
        reasoning=h.reasoning,
        latency_ms=h.latency_ms,
        session_id=h.session_id,
        input_payload=h.input_payload or {},
        output_payload=h.output_payload,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    session: AsyncSession = Depends(get_db_session),
) -> StatsResponse:
    """Aggregated governance statistics across all audit records."""
    row = (
        await session.execute(
            select(
                func.count().label("total"),
                func.coalesce(
                    func.sum(case((Handshake.status == "BLOCKED", 1), else_=0)), 0
                ).label("blocked"),
                func.coalesce(
                    func.sum(case((Handshake.status == "ALLOWED", 1), else_=0)), 0
                ).label("allowed"),
                func.coalesce(
                    func.sum(case((Handshake.status == "REDACTED", 1), else_=0)), 0
                ).label("redacted"),
                func.coalesce(
                    func.sum(case((Handshake.status == "ERROR", 1), else_=0)), 0
                ).label("error"),
                func.coalesce(func.avg(Handshake.risk_score), 0.0).label("avg_risk"),
                func.coalesce(
                    func.sum(case((Handshake.risk_score >= 0.7, 1), else_=0)), 0
                ).label("high_risk"),
            )
        )
    ).one()

    total = int(row.total or 0)
    blocked = int(row.blocked or 0)
    block_rate = round((blocked / total * 100) if total > 0 else 0.0, 1)

    return StatsResponse(
        total_calls=total,
        blocked=blocked,
        allowed=int(row.allowed or 0),
        redacted=int(row.redacted or 0),
        error=int(row.error or 0),
        avg_risk_score=round(float(row.avg_risk or 0), 3),
        high_risk_count=int(row.high_risk or 0),
        block_rate=block_rate,
    )


@router.get("/audit", response_model=PaginatedAudit)
async def list_audit(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    agent: str | None = Query(None),
    tool: str | None = Query(None),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedAudit:
    """Paginated, filterable list of audit records."""
    q = select(Handshake)

    if status:
        q = q.where(Handshake.status == status.upper())
    if agent:
        q = q.where(Handshake.agent_identity.ilike(f"%{agent}%"))
    if tool:
        q = q.where(Handshake.tool_name.ilike(f"%{tool}%"))

    total: int = (
        await session.execute(
            select(func.count()).select_from(q.subquery())
        )
    ).scalar_one()

    rows = (
        await session.execute(
            q.order_by(Handshake.timestamp.desc())
            .limit(limit)
            .offset((page - 1) * limit)
        )
    ).scalars().all()

    return PaginatedAudit(
        items=[_serialize(r) for r in rows],
        total=total,
        page=page,
        pages=max(1, math.ceil(total / limit)),
        limit=limit,
    )


@router.get("/agents", response_model=list[AgentStat])
async def top_agents(
    limit: int = Query(10, ge=1, le=50),
    session: AsyncSession = Depends(get_db_session),
) -> list[AgentStat]:
    """Per-agent call statistics ordered by total calls descending."""
    rows = (
        await session.execute(
            select(
                Handshake.agent_identity,
                func.count().label("total_calls"),
                func.coalesce(
                    func.sum(case((Handshake.status == "BLOCKED", 1), else_=0)), 0
                ).label("blocked_calls"),
                func.coalesce(func.avg(Handshake.risk_score), 0.0).label("avg_risk"),
            )
            .group_by(Handshake.agent_identity)
            .order_by(func.count().desc())
            .limit(limit)
        )
    ).all()

    result = []
    for r in rows:
        total = int(r.total_calls or 0)
        blocked = int(r.blocked_calls or 0)
        result.append(
            AgentStat(
                agent_identity=r.agent_identity,
                total_calls=total,
                blocked_calls=blocked,
                avg_risk_score=round(float(r.avg_risk or 0), 3),
                block_rate=round((blocked / total * 100) if total > 0 else 0.0, 1),
            )
        )
    return result


@router.get("/risk-trend", response_model=list[RiskPoint])
async def risk_trend(
    limit: int = Query(60, ge=10, le=200),
    session: AsyncSession = Depends(get_db_session),
) -> list[RiskPoint]:
    """Latest N records as a time-series for the risk-score sparkline."""
    rows = (
        await session.execute(
            select(
                Handshake.timestamp,
                Handshake.risk_score,
                Handshake.status,
                Handshake.tool_name,
            )
            .order_by(Handshake.timestamp.desc())
            .limit(limit)
        )
    ).all()

    # Return chronological order for the chart
    return [
        RiskPoint(
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            risk_score=round(float(r.risk_score), 4),
            status=r.status,
            tool_name=r.tool_name,
        )
        for r in reversed(rows)
    ]
