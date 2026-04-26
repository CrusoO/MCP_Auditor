"""
AgentGuard – Mock MCP Tool Server
===================================
Purpose
-------
This server simulates a real MCP tool server for local development and
integration testing.  It intentionally includes tools that carry sensitive
data (credentials, PII) so the test suite can verify that:

1. The PolicyEngine correctly blocks dangerous requests.
2. The RedactionPipeline strips secrets from responses before they reach the
   LLM, even when the tool itself returns raw secrets.
3. The audit ledger captures masked payloads, not the raw secret values.

It is **not** intended for production use.  Deploy it only behind the
AgentGuard proxy; never expose it directly to untrusted clients.

Endpoints
---------
POST /invoke   – Execute a named tool with JSON args.
GET  /tools    – List all available tools (capability discovery).
GET  /health   – Liveness probe.
"""

from __future__ import annotations

import asyncio
import os
import random
import string
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Mock MCP Tool Server",
    description="Fake tool server for AgentGuard integration tests.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class InvokeRequest(BaseModel):
    tool: str
    args: dict[str, Any] = {}


class InvokeResponse(BaseModel):
    tool: str
    result: Any
    metadata: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Simulated tool implementations
# Each function takes the raw args dict and returns the tool output.
# Some deliberately return PII / secrets to exercise the redaction pipeline.
# ---------------------------------------------------------------------------

async def _tool_read_file(args: dict[str, Any]) -> Any:
    """
    Simulate reading a file.

    For testing, returns different content depending on the requested path:
    - 'config.py'         → contains a fake API key (should be REDACTED)
    - 'README.md'         → benign markdown
    - any other path      → generic fake content
    """
    path: str = args.get("path", "unknown")

    if "config" in path.lower():
        return {
            "path": path,
            "content": (
                "# Application config  *** SIMULATED DATA – NOT REAL CREDENTIALS ***\n"
                "DATABASE_URL = 'postgresql://admin:<DB-PASS-REDACTED>@db:5432/prod'\n"
                "STRIPE_SECRET_KEY = 'sk_live_FAKE-KEY-NOT-REAL-DO-NOT-USE'\n"
                "AWS_ACCESS_KEY_ID = 'FAKE-AWS-KEY-ID-NOT-REAL'\n"
                "AWS_SECRET_ACCESS_KEY = 'FAKE-AWS-SECRET-NOT-REAL-DO-NOT-USE'\n"
                "SENDGRID_API_KEY = 'SG.FAKE-TOKEN-NOT-REAL-DO-NOT-USE'\n"
            ),
        }

    if "readme" in path.lower():
        return {
            "path": path,
            "content": "# My Project\nA sample Python project for demonstration.\n",
        }

    return {
        "path": path,
        "content": f"Simulated file content for: {path}",
    }


async def _tool_list_files(args: dict[str, Any]) -> Any:
    """Return a fake directory listing."""
    directory: str = args.get("directory", ".")
    return {
        "directory": directory,
        "files": [
            "main.py",
            "config.py",
            "README.md",
            "tests/test_main.py",
            ".env",
        ],
    }


async def _tool_search_code(args: dict[str, Any]) -> Any:
    """Simulate searching the codebase for a pattern."""
    query: str = args.get("query", "")
    return {
        "query": query,
        "matches": [
            {"file": "main.py", "line": 42, "snippet": f"result = compute({query})"},
            {"file": "utils.py", "line": 17, "snippet": f"# TODO: handle {query}"},
        ],
    }


async def _tool_query_db(args: dict[str, Any]) -> Any:
    """
    Simulate a database query.

    Returns fake rows that include PII (email, phone) to exercise redaction.
    """
    query: str = args.get("query", "SELECT 1")
    return {
        "query": query,
        "rows": [
            {
                "id": 1,
                "name": "Alice Johnson",
                "email": "alice.johnson@example.com",
                "phone": "+1-555-867-5309",
                "ssn": "123-45-6789",
            },
            {
                "id": 2,
                "name": "Bob Smith",
                "email": "bob.smith@company.org",
                "phone": "555.234.5678",
                "ssn": "987-65-4321",
            },
        ],
        "count": 2,
    }


async def _tool_send_email(args: dict[str, Any]) -> Any:
    """Simulate sending an email."""
    to_addr: str = args.get("to", "unknown@example.com")
    subject: str = args.get("subject", "(no subject)")
    return {
        "status": "sent",
        "to": to_addr,
        "subject": subject,
        "message_id": "fake-msg-" + "".join(random.choices(string.hexdigits, k=12)),
    }


async def _tool_git_log(args: dict[str, Any]) -> Any:
    """Return a fake git log."""
    n: int = int(args.get("n", 5))
    return {
        "commits": [
            {
                "hash": "a1b2c3d",
                "author": "dev@example.com",
                "message": f"chore: update dependency #{i}",
                "timestamp": f"2026-04-{20 - i:02d}T10:00:00Z",
            }
            for i in range(n)
        ]
    }


async def _tool_fetch_url(args: dict[str, Any]) -> Any:
    """Simulate fetching a URL."""
    url: str = args.get("url", "https://example.com")
    return {
        "url": url,
        "status_code": 200,
        "body": f"<html><body>Simulated response from {url}</body></html>",
    }


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
_TOOLS: dict[str, Any] = {
    "read_file":   _tool_read_file,
    "list_files":  _tool_list_files,
    "search_code": _tool_search_code,
    "query_db":    _tool_query_db,
    "send_email":  _tool_send_email,
    "git_log":     _tool_git_log,
    "fetch_url":   _tool_fetch_url,
}

_TOOL_DESCRIPTIONS: list[dict[str, str]] = [
    {"name": "read_file",   "description": "Read a file from the project directory."},
    {"name": "list_files",  "description": "List files in a directory."},
    {"name": "search_code", "description": "Search the codebase for a pattern."},
    {"name": "query_db",    "description": "Execute a read-only SQL query."},
    {"name": "send_email",  "description": "Send an email via the configured SMTP relay."},
    {"name": "git_log",     "description": "Show recent git commit history."},
    {"name": "fetch_url",   "description": "Fetch the content of a URL."},
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/invoke", response_model=InvokeResponse)
async def invoke(req: InvokeRequest) -> InvokeResponse:
    """
    Execute the named tool with the supplied arguments.

    404 is returned for unknown tools so the proxy can surface a clear
    error to the agent rather than silently returning null.
    """
    handler = _TOOLS.get(req.tool)
    if handler is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown tool: {req.tool!r}. Available: {list(_TOOLS.keys())}",
        )

    # Simulate network/processing latency (10–80 ms).
    await asyncio.sleep(random.uniform(0.01, 0.08))

    result = await handler(req.args)
    return InvokeResponse(
        tool=req.tool,
        result=result,
        metadata={"mock": True, "server": "AgentGuard-MockMCP/1.0"},
    )


@app.get("/tools")
async def list_tools() -> dict[str, Any]:
    """Return capability manifest – what tools this server exposes."""
    return {"tools": _TOOL_DESCRIPTIONS}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "MockMCPServer"}
