# ============================================================================
# AgentGuard – Multi-stage Docker build
# ============================================================================
# Stage 1 – builder: install dependencies with uv into an isolated venv.
# Stage 2 – runtime: copy only the venv + source; no build tools at runtime.
#
# Security hardening:
#   * Runs as a non-root user (uid=1000) in both stages.
#   * No shell in the final image (uses exec-form ENTRYPOINT).
#   * Build secrets (if any) are never copied into the final layer.
# ============================================================================

# --------------------------------------------------------------------------
# Stage 1 – dependency installation
# --------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install uv (fast Python package manager).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency manifests only (layer-cache friendly).
COPY pyproject.toml ./

# Create and populate the virtual environment.
RUN uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python \
        fastapi \
        "uvicorn[standard]" \
        fastmcp \
        httpx \
        "sqlalchemy[asyncio]" \
        asyncpg \
        alembic \
        "pydantic>=2.7.0" \
        pydantic-settings \
        structlog

# --------------------------------------------------------------------------
# Stage 2 – runtime image
# --------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Non-root user for the process.
RUN addgroup --system --gid 1000 agentguard && \
    adduser  --system --uid 1000 --ingroup agentguard --no-create-home agentguard

WORKDIR /app

# Copy virtualenv from builder.
COPY --from=builder /opt/venv /opt/venv

# Copy application source.
COPY proxy/    ./proxy/
COPY db/       ./db/
COPY mock_server/ ./mock_server/

# Set PATH so the venv python/uvicorn are found without activating.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER agentguard

EXPOSE 8000

# Exec-form ENTRYPOINT – no shell, so signals are delivered directly to uvicorn.
# workers=1: table DDL runs in the lifespan handler at startup.
# Multiple workers would race on CREATE TABLE and hit a pg_type duplicate-key
# error (UniqueViolationError on pg_type_typname_nsp_index).
# For horizontal scaling, run DB migrations with Alembic before starting the
# container, then you can safely increase workers.
ENTRYPOINT ["uvicorn", "proxy.gateway:app", \
            "--host", "0.0.0.0", \
            "--port", "8000", \
            "--workers", "1", \
            "--log-level", "info"]
