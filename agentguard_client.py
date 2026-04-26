"""
AgentGuard Client — Drop-in Python wrapper
==========================================
Copy this single file into any project.
No installation required beyond the `requests` library.

Quickstart
----------
    from agentguard_client import AgentGuard

    ag = AgentGuard(
        proxy_url="https://agentguard-proxy.onrender.com",
        agent_identity="my-agent-v1",
    )

    result = ag.call(
        tool_name="read_file",
        tool_args={"path": "/tmp/data.txt"},
        user_intent="Read the data file to answer user's question",
    )

    print(result)
"""

from __future__ import annotations

import uuid
from typing import Any

try:
    import requests
except ImportError:
    raise ImportError("Run: pip install requests")


class AgentGuardError(Exception):
    """Raised when AgentGuard blocks or rejects a tool call."""
    def __init__(self, message: str, risk_score: float = 0.0, reason: str = ""):
        super().__init__(message)
        self.risk_score = risk_score
        self.reason = reason


class AgentGuard:
    """
    Wraps every MCP tool call with AgentGuard's zero-trust security gateway.

    Parameters
    ----------
    proxy_url : str
        Base URL of your deployed AgentGuard proxy.
        Example: "https://agentguard-proxy.onrender.com"

    agent_identity : str
        A name/ID for your agent — appears in audit logs.
        Example: "my-chatbot-v1", "finance-agent", "customer-support-bot"

    raise_on_block : bool
        If True (default), raise AgentGuardError when a call is blocked.
        If False, return the raw response dict instead.

    timeout : int
        HTTP timeout in seconds (default: 30).
    """

    def __init__(
        self,
        proxy_url: str,
        agent_identity: str = "unnamed-agent",
        raise_on_block: bool = True,
        timeout: int = 30,
    ):
        self.proxy_url = proxy_url.rstrip("/")
        self.agent_identity = agent_identity
        self.raise_on_block = raise_on_block
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-Agent-Identity": self.agent_identity,
        })

    def call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_intent: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a tool call through AgentGuard.

        Parameters
        ----------
        tool_name : str
            The MCP tool to invoke. Example: "read_file", "send_email"

        tool_args : dict
            Arguments for the tool. Example: {"path": "/tmp/file.txt"}

        user_intent : str
            The original user message that triggered this call.
            Example: "Show me the contents of the config file"

        session_id : str, optional
            Optional ID to group multiple calls in one conversation.

        Returns
        -------
        dict with keys:
            - request_id   : Unique ID for this call (for audit tracing)
            - tool_name    : Name of the tool
            - status       : "allowed", "blocked", or "redacted"
            - result       : Tool output (None if blocked)
            - blocked_reason: Why it was blocked (None if allowed)
            - risk_score   : 0.0 to 1.0 (higher = more dangerous)
            - redacted     : True if PII was removed from output

        Raises
        ------
        AgentGuardError
            If the call is blocked and raise_on_block=True.
        requests.exceptions.ConnectionError
            If the AgentGuard proxy is unreachable.
        """
        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "user_intent": user_intent,
        }
        if session_id:
            payload["session_id"] = session_id

        response = self._session.post(
            f"{self.proxy_url}/v1/tool/invoke",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        if self.raise_on_block and data.get("status") == "blocked":
            raise AgentGuardError(
                f"Tool call '{tool_name}' was blocked by AgentGuard policy.",
                risk_score=data.get("risk_score", 0.0),
                reason=data.get("blocked_reason", "Policy violation"),
            )

        return data

    def check_policy(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_intent: str,
    ) -> dict[str, Any]:
        """
        Dry-run: check if a call would be allowed WITHOUT executing it.

        Returns
        -------
        dict with keys:
            - action          : "ALLOW", "BLOCK", or "REDACT"
            - reason          : Human-readable explanation
            - risk_score      : 0.0 to 1.0
            - triggered_rules : List of policy rules that fired
        """
        payload = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "user_intent": user_intent,
        }
        response = self._session.post(
            f"{self.proxy_url}/v1/policy/evaluate",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> bool:
        """Returns True if the AgentGuard proxy is reachable and healthy."""
        try:
            r = self._session.get(f"{self.proxy_url}/health", timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def new_session(self) -> "AgentGuardSession":
        """
        Start a tracked session — groups all calls under one session_id
        so they appear together in the audit log.

        Usage
        -----
            with ag.new_session() as session:
                session.call("read_file", {"path": "/tmp/x"}, "Read file")
                session.call("send_email", {...}, "Send summary")
        """
        return AgentGuardSession(client=self, session_id=str(uuid.uuid4()))


class AgentGuardSession:
    """
    Context manager that groups tool calls under one session_id.
    All calls in this session appear together in the audit dashboard.
    """

    def __init__(self, client: AgentGuard, session_id: str):
        self._client = client
        self.session_id = session_id

    def call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_intent: str,
    ) -> dict[str, Any]:
        return self._client.call(
            tool_name=tool_name,
            tool_args=tool_args,
            user_intent=user_intent,
            session_id=self.session_id,
        )

    def __enter__(self) -> "AgentGuardSession":
        return self

    def __exit__(self, *_: Any) -> None:
        pass


# ---------------------------------------------------------------------------
# Quick test — run this file directly to verify your connection
# python agentguard_client.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    PROXY_URL = "https://agentguard-proxy.onrender.com"

    print(f"Connecting to AgentGuard at {PROXY_URL}...\n")

    ag = AgentGuard(proxy_url=PROXY_URL, agent_identity="test-runner")

    # 1. Health check
    print("1. Health check...")
    ok = ag.health()
    print(f"   {'OK' if ok else 'FAILED — is the proxy deployed?'}\n")

    if not ok:
        print("Cannot reach proxy. Check your PROXY_URL.")
        exit(1)

    # 2. Policy dry-run
    print("2. Policy dry-run (no execution)...")
    decision = ag.check_policy(
        tool_name="read_file",
        tool_args={"path": "/tmp/test.txt"},
        user_intent="Check the log file",
    )
    print(f"   Decision: {decision['action']}  |  Risk: {decision['risk_score']}\n")

    # 3. Allowed call
    print("3. Sending an ALLOWED tool call...")
    result = ag.call(
        tool_name="read_file",
        tool_args={"path": "/tmp/test.txt"},
        user_intent="Read config file for user",
    )
    print(f"   Status: {result['status']}  |  Risk: {result['risk_score']}\n")

    # 4. Blocked call
    print("4. Sending a BLOCKED tool call (dangerous)...")
    ag_no_raise = AgentGuard(proxy_url=PROXY_URL, agent_identity="test-runner", raise_on_block=False)
    result = ag_no_raise.call(
        tool_name="delete_file",
        tool_args={"path": "/etc/passwd"},
        user_intent="Delete system files",
    )
    print(f"   Status: {result['status']}  |  Reason: {result['blocked_reason']}\n")

    # 5. Session grouping
    print("5. Grouped session (3 calls under one session_id)...")
    with ag.new_session() as session:
        for tool in ["list_files", "read_file", "summarize"]:
            r = session.call(tool, {"path": "/tmp"}, "Summarize files for user")
            print(f"   {tool}: {r['status']}")

    print(f"\nAll done. Check your dashboard: {PROXY_URL.replace('proxy', 'dashboard')}")
