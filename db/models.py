"""
AgentGuard – Audit Ledger ORM Models
=====================================
Security Rationale
------------------
* The `Handshake` table is an **append-only** audit ledger.  No UPDATE or
  DELETE permissions should be granted to the application DB user – only
  INSERT and SELECT.  This prevents a compromised proxy from erasing evidence
  of malicious tool calls.

* `input_payload` stores the **redacted** version of arguments supplied by
  the agent; the raw payload is never persisted to disk.

* `output_payload` stores the **masked** tool response so that secrets
  scrubbed by the RedactionPipeline never land in the ledger.

* `risk_score` (0.0–1.0) is written by the PolicyEngine and is indexed so
  that security dashboards can quickly surface high-risk events.

* `status` uses a server-side `CHECK` constraint (enforced at DB level) to
  guarantee only valid values are stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


class HandshakeStatus(str, Enum):
    """Finite set of outcomes for a governed tool invocation."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    REDACTED = "REDACTED"
    ERROR = "ERROR"


class Handshake(Base):
    """
    Immutable audit record created for every tool call intercepted by the
    AgentGuard proxy.

    Each row answers the forensic questions:
    * WHO  called the tool? (`agent_identity`)
    * WHAT did they ask?   (`tool_name`, `input_payload`)
    * WHEN did it happen?  (`timestamp`)
    * WHY was it allowed/blocked? (`reasoning`, `risk_score`)
    * WHAT came back?      (`output_payload` – always masked)
    """

    __tablename__ = "handshakes"

    __table_args__ = (
        CheckConstraint(
            "status IN ('ALLOWED', 'BLOCKED', 'REDACTED', 'ERROR')",
            name="ck_handshake_status",
        ),
        CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 1.0",
            name="ck_risk_score_range",
        ),
        # Fast lookups by agent and time for dashboards.
        Index("ix_handshake_agent_ts", "agent_identity", "timestamp"),
        # Fast lookups for high-risk events.
        Index("ix_handshake_risk", "risk_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Immutable surrogate key – never reused.",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="UTC wall-clock time when the intercept occurred.",
    )

    agent_identity: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="JWT sub, API-key fingerprint, or IP of the calling agent.",
    )

    tool_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
        comment="The MCP tool that was invoked (e.g. 'read_file', 'run_sql').",
    )

    input_payload: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Redacted tool arguments – secrets stripped before persistence.",
    )

    output_payload: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Masked tool response – PII and secrets removed.",
    )

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Final governance decision: ALLOWED | BLOCKED | REDACTED | ERROR.",
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="PolicyEngine score in [0.0, 1.0]; higher means more dangerous.",
    )

    reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable explanation produced by the PolicyEngine.",
    )

    session_id: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        index=True,
        comment="Correlates multiple tool calls within one LLM conversation.",
    )

    latency_ms: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="End-to-end wall time (ms) for the governed invocation.",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Handshake id={self.id} tool={self.tool_name!r} "
            f"status={self.status} risk={self.risk_score:.2f}>"
        )
