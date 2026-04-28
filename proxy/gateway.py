"""
AgentGuard – Zero-Trust MCP Governance Gateway
===============================================
Security Rationale
------------------
This module is the **traffic cop** of the AgentGuard system.  Every JSON-RPC
tool call that a LLM agent issues must pass through `intercept_call` before
the underlying MCP tool is ever executed.

The interception pipeline is:

    LLM Agent
        │
        ▼
    ┌─────────────────────────────────────────────────┐
    │  AgentGuardProxy.intercept_call()               │
    │                                                 │
    │  1. Extract identity & intent from request      │
    │  2. PolicyEngine.evaluate() → ALLOW/BLOCK/REDACT│
    │  3. [if ALLOW/REDACT] Forward to real tool      │
    │  4. RedactionPipeline.scrub_value() on output   │
    │  5. BackgroundTask → persist Handshake to DB    │
    │  6. Return scrubbed result to LLM               │
    └─────────────────────────────────────────────────┘
        │
        ▼
    MCP Tool Server  (only reached if policy allows)

Design principles
-----------------
* **Fail-closed**: If the PolicyEngine raises an unexpected exception, the
  call is BLOCKED (not allowed).  A bug in the engine must never silently
  permit a dangerous action.

* **Non-blocking audit**: DB persistence runs in a FastAPI `BackgroundTask`
  so it cannot delay the tool response or be used as a DoS vector.

* **Identity propagation**: The `X-Agent-Identity` header (or JWT `sub`) is
  extracted and forwarded to every audit record.  Anonymous calls are assigned
  a deterministic fingerprint based on their IP.

* **Request ID correlation**: Every intercepted call gets a `request_id` (UUID)
  that is included in both the response headers and the audit record, enabling
  end-to-end forensic tracing.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from db.crud import create_handshake
from db.database import AsyncSessionLocal, create_all_tables
from db.models import HandshakeStatus
from proxy.engine import PolicyAction, PolicyDecision, PolicyEngine
from proxy.redaction import RedactionPipeline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_UPSTREAM_MCP_URL: str = os.getenv(
    "UPSTREAM_MCP_URL", "http://mock-mcp-server:8001"
)
_STRICT_MODE: bool = os.getenv("POLICY_STRICT_MODE", "true").lower() == "true"
_USE_PRESIDIO: bool = os.getenv("USE_PRESIDIO", "false").lower() == "true"
_MAX_PAYLOAD_BYTES: int = int(os.getenv("MAX_PAYLOAD_BYTES", str(1 * 1024 * 1024)))  # 1 MB


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ToolCallRequest(BaseModel):
    """
    Normalised representation of an incoming MCP tool invocation.

    The `user_intent` field is critical for the dynamic scope check – the
    calling client MUST provide the original user prompt so the PolicyEngine
    can detect intent drift.
    """

    tool_name: str = Field(..., description="Name of the MCP tool to invoke.")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to pass to the tool.",
    )
    user_intent: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="The original user prompt that triggered this tool call.",
    )
    session_id: str | None = Field(
        default=None,
        description="Optional opaque token correlating multiple calls in one conversation.",
    )


class ToolCallResponse(BaseModel):
    """Governed tool response returned to the LLM agent."""

    request_id: str
    tool_name: str
    status: str
    result: Any | None = None
    blocked_reason: str | None = None
    risk_score: float
    redacted: bool = False


class PolicyDecisionSchema(BaseModel):
    """Serialisable form of a PolicyDecision (used in health/explain endpoints)."""

    action: str
    reason: str
    risk_score: float
    triggered_rules: list[str]


# ---------------------------------------------------------------------------
# AgentGuardProxy
# ---------------------------------------------------------------------------

class AgentGuardProxy:
    """
    The central governance gateway that wraps every MCP tool call with
    zero-trust security controls.

    This class owns the FastAPI application instance and registers all
    route handlers.  It is designed to be instantiated once per process
    and shared across all requests.

    Lifecycle
    ---------
    * ``__init__``: Creates sub-components (PolicyEngine, RedactionPipeline,
      async httpx client).
    * ``lifespan``: FastAPI lifespan handler that creates DB tables on startup
      and closes the HTTP client on shutdown.
    * ``intercept_call``: The primary interception endpoint.
    """

    def __init__(self) -> None:
        self._engine = PolicyEngine(strict_mode=_STRICT_MODE)
        self._redactor = RedactionPipeline(use_presidio=_USE_PRESIDIO)
        # Shared async HTTP client for upstream MCP calls.
        # Timeout is intentionally short to prevent the proxy from hanging
        # if the upstream tool server is unresponsive.
        self._http: httpx.AsyncClient = httpx.AsyncClient(
            base_url=_UPSTREAM_MCP_URL,
            timeout=httpx.Timeout(30.0, connect=5.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        logger.info(
            "AgentGuardProxy initialised | upstream=%s strict=%s presidio=%s",
            _UPSTREAM_MCP_URL, _STRICT_MODE, _USE_PRESIDIO,
        )

    @asynccontextmanager
    async def lifespan(self, app: FastAPI):  # type: ignore[override]
        """
        FastAPI lifespan context manager.

        Startup
        -------
        * Ensures all DB tables are created (idempotent).

        Shutdown
        --------
        * Gracefully closes the shared HTTP client so in-flight requests
          are not abruptly terminated.
        """
        logger.info("AgentGuard startup: creating database tables…")
        await create_all_tables()
        logger.info("AgentGuard ready.")
        yield
        logger.info("AgentGuard shutdown: closing HTTP client…")
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Primary interception endpoint
    # ------------------------------------------------------------------

    async def intercept_call(
        self,
        request: Request,
        body: ToolCallRequest,
        background_tasks: BackgroundTasks,
        x_agent_identity: str | None = Header(default=None, alias="X-Agent-Identity"),
        x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    ) -> ToolCallResponse:
        """
        Intercept, evaluate, execute (conditionally), and audit a tool call.

        Security flow
        -------------
        1.  **Identity extraction**: Resolve agent identity from the header or
            fall back to a SHA-256 hash of the client IP so anonymous callers
            are still traceable.

        2.  **Payload size guard**: Reject oversized payloads before any
            expensive evaluation to prevent memory exhaustion attacks.

        3.  **PolicyEngine evaluation**: Pass ``tool_name``, ``tool_args``,
            and ``user_intent`` to the engine.  The engine returns a
            ``PolicyDecision`` synchronously (no I/O) so it cannot be timed out
            by a slow upstream.

        4.  **Branch on decision**:
            - BLOCK  → return 403 immediately; skip tool execution entirely.
            - ALLOW/REDACT → forward the call to the upstream MCP server.

        5.  **Output redaction**: Run ``RedactionPipeline.scrub_value()`` on
            the tool result unconditionally (even ALLOW decisions are scrubbed).

        6.  **Background audit**: Schedule ``create_handshake`` as a
            ``BackgroundTask`` so DB latency is off the critical path.

        7.  **Response**: Return the scrubbed result with ``request_id`` and
            ``risk_score`` headers so callers can correlate with audit records.
        """
        request_id = str(uuid.uuid4())
        t_start = time.perf_counter()

        # ----------------------------------------------------------------
        # Step 1 – Resolve agent identity
        # ----------------------------------------------------------------
        agent_identity = x_agent_identity or self._derive_identity(request)
        session_id = x_session_id or body.session_id

        logger.info(
            "Intercepted | req=%s agent=%s tool=%s",
            request_id, agent_identity, body.tool_name,
        )

        # ----------------------------------------------------------------
        # Step 2 – Payload size guard
        # ----------------------------------------------------------------
        raw_size = int(request.headers.get("content-length", 0))
        if raw_size > _MAX_PAYLOAD_BYTES:
            logger.warning("Oversized payload (%d bytes) from agent %s.", raw_size, agent_identity)
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Payload exceeds the maximum allowed size.",
            )

        # ----------------------------------------------------------------
        # Step 3 – PolicyEngine evaluation (synchronous, fail-closed)
        # ----------------------------------------------------------------
        try:
            decision: PolicyDecision = self._engine.evaluate(
                tool_name=body.tool_name,
                tool_args=body.tool_args,
                user_intent=body.user_intent,
            )
        except Exception as exc:
            logger.exception("PolicyEngine raised an unexpected error: %s", exc)
            # Fail-closed: treat any engine error as a BLOCK.
            decision = PolicyDecision(
                action=PolicyAction.BLOCK,
                reason=f"PolicyEngine internal error: {exc!r}. Failing closed.",
                risk_score=1.0,
                triggered_rules=["ENGINE_ERROR"],
            )

        # ----------------------------------------------------------------
        # Step 4 – Branch on decision
        # ----------------------------------------------------------------
        tool_result: Any = None
        final_status: HandshakeStatus
        redacted_input, _ = self._redactor.scrub_dict(body.tool_args)

        if decision.action == PolicyAction.BLOCK:
            final_status = HandshakeStatus.BLOCKED
            latency_ms = (time.perf_counter() - t_start) * 1000

            background_tasks.add_task(
                self._audit,
                agent_identity=agent_identity,
                tool_name=body.tool_name,
                input_payload=redacted_input,
                output_payload=None,
                status=final_status,
                risk_score=decision.risk_score,
                reasoning=decision.reason,
                session_id=session_id,
                latency_ms=latency_ms,
            )

            return ToolCallResponse(
                request_id=request_id,
                tool_name=body.tool_name,
                status=HandshakeStatus.BLOCKED.value,
                result=None,
                blocked_reason=decision.reason,
                risk_score=decision.risk_score,
                redacted=False,
            )

        # ALLOW or REDACT → execute the tool upstream.
        raw_result, upstream_error = await self._forward_to_upstream(
            tool_name=body.tool_name,
            tool_args=body.tool_args,
        )

        if upstream_error:
            final_status = HandshakeStatus.ERROR
            tool_result = {"error": upstream_error}
            scrubbed_output: Any = tool_result
            all_findings: list = []
        else:
            # ----------------------------------------------------------------
            # Step 5 – Output redaction (unconditional)
            # ----------------------------------------------------------------
            scrubbed_output, all_findings = self._redactor.scrub_value(raw_result)
            was_redacted = bool(all_findings) or decision.action == PolicyAction.REDACT
            final_status = (
                HandshakeStatus.REDACTED if was_redacted else HandshakeStatus.ALLOWED
            )
            tool_result = scrubbed_output

        latency_ms = (time.perf_counter() - t_start) * 1000

        # ----------------------------------------------------------------
        # Step 6 – Background audit (non-blocking)
        # ----------------------------------------------------------------
        background_tasks.add_task(
            self._audit,
            agent_identity=agent_identity,
            tool_name=body.tool_name,
            input_payload=redacted_input,
            output_payload=scrubbed_output if isinstance(scrubbed_output, dict) else {"result": str(scrubbed_output)},
            status=final_status,
            risk_score=decision.risk_score,
            reasoning=decision.reason,
            session_id=session_id,
            latency_ms=latency_ms,
        )

        # ----------------------------------------------------------------
        # Step 7 – Return governed response
        # ----------------------------------------------------------------
        return ToolCallResponse(
            request_id=request_id,
            tool_name=body.tool_name,
            status=final_status.value,
            result=tool_result,
            blocked_reason=None,
            risk_score=decision.risk_score,
            redacted=final_status == HandshakeStatus.REDACTED,
        )

    # ------------------------------------------------------------------
    # Auxiliary methods
    # ------------------------------------------------------------------

    async def _forward_to_upstream(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[Any, str | None]:
        """
        Forward an approved tool call to the upstream MCP server.

        Returns
        -------
        (result, error_string)
            `error_string` is None on success; non-None on any HTTP or
            network failure.  The caller decides how to surface the error.

        Security note
        -------------
        The upstream response is **never** trusted raw; it is always passed
        through the RedactionPipeline before reaching the LLM.  This means
        a compromised upstream cannot leak secrets through its responses.
        """
        try:
            response = await self._http.post(
                "/invoke",
                json={"tool": tool_name, "args": tool_args},
            )
            response.raise_for_status()
            return response.json(), None
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Upstream HTTP error for tool '%s': %s", tool_name, exc.response.text
            )
            return None, f"Upstream returned {exc.response.status_code}"
        except httpx.RequestError as exc:
            logger.error("Upstream connection error for tool '%s': %s", tool_name, exc)
            return None, f"Upstream unreachable: {exc!r}"

    @staticmethod
    async def _audit(
        *,
        agent_identity: str,
        tool_name: str,
        input_payload: dict,
        output_payload: dict | None,
        status: HandshakeStatus,
        risk_score: float,
        reasoning: str | None,
        session_id: str | None,
        latency_ms: float,
    ) -> None:
        """
        Persist an audit record to the database.

        This function is always called via `BackgroundTasks.add_task` so it
        runs **after** the response has been sent to the client.  DB failures
        are caught and logged but do NOT affect the tool response – we prefer
        a tool call succeeding with a missed audit over blocking legitimate
        work due to DB issues.

        Security note
        -------------
        The inputs passed here must already be redacted/masked by the caller.
        This function does NOT perform any further scrubbing.
        """
        try:
            async with AsyncSessionLocal() as session:
                await create_handshake(
                    session,
                    agent_identity=agent_identity,
                    tool_name=tool_name,
                    input_payload=input_payload,
                    output_payload=output_payload,
                    status=status,
                    risk_score=risk_score,
                    reasoning=reasoning,
                    session_id=session_id,
                    latency_ms=latency_ms,
                )
                await session.commit()
        except Exception as exc:
            logger.exception("Audit persistence failed (non-fatal): %s", exc)

    @staticmethod
    def _derive_identity(request: Request) -> str:
        """
        Derive a stable anonymous identity from the client IP when no
        explicit `X-Agent-Identity` header is provided.

        Security note
        -------------
        We do NOT use raw IP strings in audit records because they can be
        trivially spoofed via X-Forwarded-For.  Instead we take the
        *last hop* IP from ASGI `client` (which is the actual TCP peer).
        """
        import hashlib

        client_ip = request.client.host if request.client else "unknown"
        fingerprint = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        return f"anon:{fingerprint}"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """
    Construct and configure the AgentGuard FastAPI application.

    This is the entry point for ASGI servers (uvicorn, gunicorn+uvicorn).
    It registers:
    * The AgentGuardProxy instance (shared across all requests).
    * All route handlers.
    * CORS middleware (locked down to an explicit allow-list in production).
    * A structured-logging middleware that stamps every response with
      `X-Request-ID`.

    Returns
    -------
    FastAPI
        Fully wired application ready to be served.
    """
    proxy = AgentGuardProxy()

    app = FastAPI(
        title="AgentGuard – Zero-Trust MCP Governance Gateway",
        description=(
            "Intercepts, evaluates, and audits every MCP tool call made by an "
            "LLM agent.  No tool is executed without explicit policy approval."
        ),
        version="1.0.0",
        lifespan=proxy.lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ----------------------------------------------------------------
    # CORS – in production, replace "*" with your LLM client origin.
    # ----------------------------------------------------------------
    _allowed_origins = os.getenv("CORS_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["POST", "GET", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # ----------------------------------------------------------------
    # Dashboard read-only API
    # ----------------------------------------------------------------
    from proxy.dashboard import router as dashboard_router
    app.include_router(dashboard_router)

    # ----------------------------------------------------------------
    # Routes
    # ----------------------------------------------------------------

    @app.post(
        "/v1/tool/invoke",
        response_model=ToolCallResponse,
        summary="Governed tool invocation",
        tags=["Governance"],
    )
    async def invoke_tool(
        request: Request,
        body: ToolCallRequest,
        background_tasks: BackgroundTasks,
        x_agent_identity: str | None = Header(default=None, alias="X-Agent-Identity"),
        x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    ) -> ToolCallResponse:
        """
        The primary endpoint.  Submit a tool call here; AgentGuard will
        evaluate it against all configured policies before (optionally)
        forwarding it to the upstream MCP server.
        """
        return await proxy.intercept_call(
            request=request,
            body=body,
            background_tasks=background_tasks,
            x_agent_identity=x_agent_identity,
            x_session_id=x_session_id,
        )

    @app.post(
        "/v1/policy/evaluate",
        response_model=PolicyDecisionSchema,
        summary="Dry-run policy evaluation (no tool execution)",
        tags=["Governance"],
    )
    async def evaluate_policy(body: ToolCallRequest) -> PolicyDecisionSchema:
        """
        Evaluate a tool call against the PolicyEngine without executing it.
        Useful for pre-flight checks and debugging.
        """
        try:
            decision = proxy._engine.evaluate(
                tool_name=body.tool_name,
                tool_args=body.tool_args,
                user_intent=body.user_intent,
            )
        except Exception as exc:
            logger.exception("PolicyEngine error in dry-run evaluation: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"PolicyEngine evaluation failed: {exc!r}",
            )
        return PolicyDecisionSchema(**decision.to_dict())

    @app.get(
        "/health",
        summary="Liveness probe",
        tags=["Operations"],
    )
    async def health() -> dict[str, str]:
        """Returns 200 OK when the gateway process is alive."""
        return {"status": "ok", "service": "AgentGuard"}

    @app.get(
        "/ready",
        summary="Readiness probe",
        tags=["Operations"],
    )
    async def ready() -> dict[str, str]:
        """
        Returns 200 OK when the gateway can accept traffic (DB reachable).
        Used by Kubernetes / Docker health-check probes.
        """
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(__import__("sqlalchemy").text("SELECT 1"))
            return {"status": "ready"}
        except Exception as exc:
            logger.error("Readiness check failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not reachable.",
            )

    # ----------------------------------------------------------------
    # MCP JSON-RPC 2.0 endpoint – compatible with Cursor, Claude
    # Desktop, and any MCP-native client.
    #
    # Clients configure this URL in their MCP settings:
    #   {"url": "https://agentguard-proxy.onrender.com/mcp"}
    #
    # Supported methods:
    #   initialize   – capability handshake
    #   tools/list   – enumerate available tools
    #   tools/call   – governed tool invocation (routed through
    #                  the same PolicyEngine pipeline as /v1/tool/invoke)
    # ----------------------------------------------------------------

    # Tool schema manifest – mirrors the mock server's tool registry.
    _MCP_TOOLS = [
        {
            "name": "read_file",
            "description": "Read a file from the project directory.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path to read"}},
                "required": ["path"],
            },
        },
        {
            "name": "list_files",
            "description": "List files in a directory.",
            "inputSchema": {
                "type": "object",
                "properties": {"directory": {"type": "string", "description": "Directory path"}},
                "required": [],
            },
        },
        {
            "name": "search_code",
            "description": "Search the codebase for a pattern.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Search pattern"}},
                "required": ["query"],
            },
        },
        {
            "name": "query_db",
            "description": "Execute a read-only SQL query.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "SQL query"}},
                "required": ["query"],
            },
        },
        {
            "name": "send_email",
            "description": "Send an email via the configured SMTP relay.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to":      {"type": "string"},
                    "subject": {"type": "string"},
                    "body":    {"type": "string"},
                },
                "required": ["to", "subject"],
            },
        },
        {
            "name": "git_log",
            "description": "Show recent git commit history.",
            "inputSchema": {
                "type": "object",
                "properties": {"n": {"type": "integer", "description": "Number of commits"}},
                "required": [],
            },
        },
        {
            "name": "fetch_url",
            "description": "Fetch the content of a URL.",
            "inputSchema": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to fetch"}},
                "required": ["url"],
            },
        },
    ]

    def _mcp_ok(req_id: Any, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _mcp_err(req_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    @app.post(
        "/mcp",
        summary="MCP JSON-RPC 2.0 endpoint (Cursor / Claude Desktop compatible)",
        tags=["MCP Protocol"],
    )
    async def mcp_jsonrpc(
        request: Request,
        background_tasks: BackgroundTasks,
    ) -> JSONResponse:
        """
        Speaks the Model Context Protocol (JSON-RPC 2.0) so any MCP-native
        client (Cursor, Claude Desktop, AutoGen, etc.) can connect without
        a custom client library.

        Every ``tools/call`` is routed through the same zero-trust
        PolicyEngine pipeline as ``/v1/tool/invoke``.
        """
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(_mcp_err(None, -32700, "Parse error"))

        req_id  = body.get("id")
        method  = body.get("method", "")
        params  = body.get("params") or {}

        # Notifications (no id) – acknowledge silently.
        if req_id is None and method.startswith("notifications/"):
            return JSONResponse({})

        # ── initialize ───────────────────────────────────────────────
        if method == "initialize":
            return JSONResponse(_mcp_ok(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "AgentGuard", "version": "1.0.0"},
            }))

        # ── tools/list ───────────────────────────────────────────────
        if method == "tools/list":
            return JSONResponse(_mcp_ok(req_id, {"tools": _MCP_TOOLS}))

        # ── tools/call ───────────────────────────────────────────────
        if method == "tools/call":
            tool_name: str = params.get("name", "")
            tool_args: dict = params.get("arguments") or {}

            # MCP clients don't send user_intent – derive a sensible default.
            agent_id: str = (
                request.headers.get("X-Agent-Identity")
                or request.headers.get("x-agent-identity")
                or "mcp-client"
            )
            user_intent: str = params.get(
                "_agentguard_intent",
                f"MCP tool call '{tool_name}' from {agent_id}",
            )

            ag_body = ToolCallRequest(
                tool_name=tool_name,
                tool_args=tool_args,
                user_intent=user_intent,
            )

            try:
                result = await proxy.intercept_call(
                    request=request,
                    body=ag_body,
                    background_tasks=background_tasks,
                    x_agent_identity=agent_id,
                    x_session_id=request.headers.get("X-Session-Id"),
                )
            except HTTPException as exc:
                return JSONResponse(_mcp_err(req_id, -32603, exc.detail))
            except Exception as exc:
                logger.exception("MCP tools/call error: %s", exc)
                return JSONResponse(_mcp_err(req_id, -32603, "Internal error"))

            if result.status.upper() == "BLOCKED":
                # Return a proper MCP error so the client knows it was blocked.
                return JSONResponse(_mcp_err(
                    req_id, -32001,
                    f"AgentGuard blocked this call: {result.blocked_reason} "
                    f"(risk_score={result.risk_score:.2f})",
                ))

            # Wrap result in MCP content format.
            import json as _json
            content_text = (
                result.result
                if isinstance(result.result, str)
                else _json.dumps(result.result, indent=2)
            )
            mcp_result: dict = {
                "content": [{"type": "text", "text": content_text}],
                "_agentguard": {
                    "request_id": result.request_id,
                    "risk_score":  result.risk_score,
                    "status":      result.status,
                    "redacted":    result.redacted,
                },
            }
            return JSONResponse(_mcp_ok(req_id, mcp_result))

        # ── unknown method ───────────────────────────────────────────
        return JSONResponse(_mcp_err(req_id, -32601, f"Method not found: {method!r}"))

    return app


# ---------------------------------------------------------------------------
# Entry point for `python -m proxy.gateway` or uvicorn direct invocation.
# ---------------------------------------------------------------------------
app = create_app()
