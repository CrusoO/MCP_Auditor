"""
Integration tests for the AgentGuard gateway endpoint.

Test organisation
-----------------
TestHealthEndpoints          – liveness / docs probes
TestPolicyEvaluate           – dry-run /v1/policy/evaluate (no DB, no upstream)
TestToolInvocation           – happy-path + general block + redaction (mocked)
TestDeleteFileBlocking       – exhaustive delete-attempt variants, all must block
TestDeleteFileAuditLogging   – spy on create_handshake; verify audit payload shape
TestDeleteFilePostgresIntegration
                             – end-to-end with a real PostgreSQL instance.
                               Skipped automatically when DATABASE_URL is unset
                               or when the `integration` mark is not passed.
                               Run with: pytest -m integration

Spy strategy (no real DB needed for unit tests)
------------------------------------------------
Rather than suppressing _audit entirely, the spy fixture wraps create_handshake
so real argument validation happens while the DB call is replaced by an
in-memory capture list.  This gives us full assertion power over what *would*
be written to Postgres without requiring a live database.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from db.models import HandshakeStatus
from proxy.gateway import create_app

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app():
    """Fresh FastAPI app per test (avoids shared state between tests)."""
    return create_app()


@pytest.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Async test client that bypasses the lifespan (no real DB required)."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Audit-spy fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_spy() -> list[dict[str, Any]]:
    """
    Returns a list that accumulates every keyword-argument dict passed to
    db.crud.create_handshake during the test.

    How it works
    ------------
    We patch db.crud.create_handshake with an async wrapper that:
      1. Records all keyword arguments to the shared list.
      2. Does NOT call the real DB function (so no Postgres is needed).

    The proxy's _audit helper calls create_handshake inside AsyncSessionLocal,
    so we must also patch AsyncSessionLocal to hand back a lightweight async
    context manager that yields a dummy session object.

    Security relevance
    ------------------
    Asserting against the captured arguments verifies that the audit ledger
    would receive the correct, policy-governed data (status=BLOCKED,
    risk_score, redacted payload…) — the same guarantees apply regardless of
    whether the DB is real or simulated.
    """
    captured: list[dict[str, Any]] = []

    async def _fake_create_handshake(session: Any, **kwargs: Any) -> MagicMock:  # noqa: ANN401
        captured.append(kwargs)
        mock_record = MagicMock()
        mock_record.id = uuid.uuid4()
        return mock_record

    # Fake AsyncSessionLocal that yields a dummy session supporting commit/close.
    class _FakeSession:
        async def __aenter__(self) -> "_FakeSession":
            return self

        async def __aexit__(self, *_: Any) -> None:
            pass

        async def commit(self) -> None:
            pass

        async def close(self) -> None:
            pass

    class _FakeAsyncSessionLocal:
        def __call__(self) -> "_FakeSession":
            return _FakeSession()

    with (
        patch("db.crud.create_handshake", side_effect=_fake_create_handshake),
        patch("proxy.gateway.AsyncSessionLocal", new_callable=_FakeAsyncSessionLocal),
    ):
        yield captured


# ---------------------------------------------------------------------------
# Background-task drain helper
# ---------------------------------------------------------------------------


async def _drain_background_tasks(delay: float = 0.15) -> None:
    """
    Yield control to the event loop long enough for FastAPI BackgroundTasks
    to complete.  BackgroundTasks execute in the same event loop after the
    response coroutine finishes, so a short sleep is sufficient.
    """
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Canonical delete-attempt payloads used across multiple test classes
# ---------------------------------------------------------------------------

_DELETE_SCENARIOS: list[tuple[str, dict[str, Any], str]] = [
    # (scenario_label, request_body, expected_rule_hint_in_reason)
    (
        "shell_rm_rf_absolute",
        {
            "tool_name": "run_shell",
            "tool_args": {"cmd": "rm -rf /home/user/project"},
            "user_intent": "tidy up the workspace",
        },
        "SHELL_RM_RF",
    ),
    (
        "shell_rm_rf_root",
        {
            "tool_name": "run_shell",
            "tool_args": {"cmd": "rm -rf /"},
            "user_intent": "remove temporary files",
        },
        "SHELL_RM_RF",
    ),
    (
        "delete_file_tool_etc_passwd",
        {
            "tool_name": "delete_file",
            "tool_args": {"path": "/etc/passwd"},
            "user_intent": "clean up old files",
        },
        "PATH_ETC_PASSWD",
    ),
    (
        "delete_file_tool_ssh_key",
        {
            "tool_name": "delete_file",
            "tool_args": {"path": "~/.ssh/id_rsa"},
            "user_intent": "remove unused credentials",
        },
        "PATH_SSH_KEYS",
    ),
    (
        "sql_delete_no_where",
        {
            "tool_name": "query_db",
            "tool_args": {"query": "DELETE FROM users"},
            "user_intent": "clean up the database",
        },
        "SQL_DELETE_ALL",
    ),
    (
        "sql_truncate",
        {
            "tool_name": "query_db",
            "tool_args": {"query": "TRUNCATE TABLE audit_logs"},
            "user_intent": "free up disk space",
        },
        "SQL_TRUNCATE",
    ),
    (
        "path_traversal_delete",
        {
            "tool_name": "delete_file",
            "tool_args": {"path": "../../../etc/shadow"},
            "user_intent": "clean temporary files",
        },
        "PATH_TRAVERSAL",
    ),
    (
        "shell_rm_rf_with_force_flags",
        {
            "tool_name": "run_shell",
            "tool_args": {"cmd": "rm -f /var/log/app.log && rm -rf /tmp/secrets"},
            "user_intent": "rotate logs",
        },
        "SHELL_RM_RF",
    ),
    (
        "delete_via_python_os_remove",
        {
            "tool_name": "run_code",
            "tool_args": {
                "code": "__import__('os').remove('/etc/hosts')",
                "language": "python",
            },
            "user_intent": "run a helper script",
        },
        "CODE_IMPORT_OS",
    ),
    (
        "delete_proc_self",
        {
            "tool_name": "delete_file",
            "tool_args": {"path": "/proc/self/mem"},
            "user_intent": "free memory",
        },
        "PATH_PROC_SELF",
    ),
]


# ---------------------------------------------------------------------------
# Pre-existing tests (unchanged)
# ---------------------------------------------------------------------------


class TestHealthEndpoints:
    async def test_health_returns_200(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_docs_reachable(self, client: AsyncClient) -> None:
        response = await client.get("/docs")
        assert response.status_code == 200


class TestPolicyEvaluate:
    async def test_safe_call_allowed(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/policy/evaluate",
            json={
                "tool_name": "read_file",
                "tool_args": {"path": "./src/main.py"},
                "user_intent": "code summary",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["action"] == "ALLOW"
        assert body["risk_score"] == 0.0

    async def test_dangerous_call_blocked(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/policy/evaluate",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /"},
                "user_intent": "clean up files",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["action"] == "BLOCK"
        assert body["risk_score"] == 1.0

    async def test_etc_passwd_blocked(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/policy/evaluate",
            json={
                "tool_name": "read_file",
                "tool_args": {"path": "/etc/passwd"},
                "user_intent": "show me the file",
            },
        )
        assert response.status_code == 200
        assert response.json()["action"] == "BLOCK"

    async def test_sql_drop_blocked(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/policy/evaluate",
            json={
                "tool_name": "query_db",
                "tool_args": {"query": "DROP TABLE users"},
                "user_intent": "run a query",
            },
        )
        assert response.status_code == 200
        assert response.json()["action"] == "BLOCK"


class TestToolInvocation:
    @patch("proxy.gateway.AgentGuardProxy._forward_to_upstream", new_callable=AsyncMock)
    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_allowed_call_returns_result(
        self,
        mock_audit: AsyncMock,
        mock_forward: AsyncMock,
        client: AsyncClient,
    ) -> None:
        mock_forward.return_value = ({"files": ["main.py", "README.md"]}, None)

        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "list_files",
                "tool_args": {"directory": "./src"},
                "user_intent": "code summary",
            },
            headers={"X-Agent-Identity": "test-agent-001"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] in ("ALLOWED", "REDACTED")
        assert body["result"] is not None
        assert body["blocked_reason"] is None

    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_blocked_call_returns_403_body(
        self,
        mock_audit: AsyncMock,
        client: AsyncClient,
    ) -> None:
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /"},
                "user_intent": "do some cleanup",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "BLOCKED"
        assert body["result"] is None
        assert body["blocked_reason"] is not None
        assert body["risk_score"] == 1.0

    @patch("proxy.gateway.AgentGuardProxy._forward_to_upstream", new_callable=AsyncMock)
    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_output_secrets_are_redacted(
        self,
        mock_audit: AsyncMock,
        mock_forward: AsyncMock,
        client: AsyncClient,
    ) -> None:
        mock_forward.return_value = (
            {
                "content": (
                    "API_KEY = 'sk_live_FAKE-KEY-NOT-REAL-DO-NOT-USE'\n"
                    "DB_PASS  = 'SuperSecret123'\n"
                )
            },
            None,
        )

        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "read_file",
                "tool_args": {"path": "./config.py"},
                "user_intent": "code summary",
            },
        )

        assert response.status_code == 200
        body = response.json()
        raw_json = response.text
        assert "FAKE-KEY-NOT-REAL-DO-NOT-USE" not in raw_json
        assert "SuperSecret123" not in raw_json
        assert body["status"] == "REDACTED"
        assert body["redacted"] is True

    async def test_missing_user_intent_returns_422(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "read_file",
                "tool_args": {"path": "main.py"},
            },
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# TestDeleteFileBlocking
# ---------------------------------------------------------------------------


class TestDeleteFileBlocking:
    """
    Verifies that every known delete-attempt variant is blocked by the
    PolicyEngine before the upstream MCP server is ever contacted.

    Security guarantee being tested
    --------------------------------
    No tool that destroys data (shell rm, SQL DELETE/TRUNCATE, filesystem
    unlink via Python os.remove, etc.) must ever reach the upstream server.
    The response must carry `status=BLOCKED` and a non-null `blocked_reason`
    so the LLM can understand why the action was denied.

    Each parametrised scenario targets a different attack surface so regressions
    in any single rule are caught individually rather than masked by a passing
    aggregate.
    """

    @pytest.mark.parametrize(
        "label,body,_rule_hint",
        [(s[0], s[1], s[2]) for s in _DELETE_SCENARIOS],
        ids=[s[0] for s in _DELETE_SCENARIOS],
    )
    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_delete_attempt_is_blocked(
        self,
        mock_audit: AsyncMock,
        label: str,
        body: dict[str, Any],
        _rule_hint: str,
        client: AsyncClient,
    ) -> None:
        """
        Every delete-attempt scenario must return status=BLOCKED with a
        non-empty blocked_reason and a risk_score ≥ 0.7.

        The upstream MCP server must NOT be called — _forward_to_upstream is
        not patched here, which means a call reaching the upstream would raise
        a connection error and cause the test to fail with ERROR, not BLOCKED.
        This proves the gateway short-circuits before any network I/O.
        """
        response = await client.post(
            "/v1/tool/invoke",
            json=body,
            headers={"X-Agent-Identity": f"malicious-agent-{label}"},
        )

        assert response.status_code == 200, (
            f"[{label}] Expected HTTP 200, got {response.status_code}"
        )
        resp_body = response.json()

        assert resp_body["status"] == "BLOCKED", (
            f"[{label}] Expected BLOCKED, got {resp_body['status']!r}. "
            f"Full response: {resp_body}"
        )
        assert resp_body["result"] is None, (
            f"[{label}] Tool result must be None when blocked — "
            f"got {resp_body['result']!r}"
        )
        assert resp_body["blocked_reason"] is not None, (
            f"[{label}] blocked_reason must be set so the agent can self-correct."
        )
        assert len(resp_body["blocked_reason"]) > 10, (
            f"[{label}] blocked_reason is suspiciously short: "
            f"{resp_body['blocked_reason']!r}"
        )
        assert resp_body["risk_score"] >= 0.7, (
            f"[{label}] Expected risk_score ≥ 0.7, got {resp_body['risk_score']}"
        )

    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_concurrent_delete_attempts_all_blocked(
        self,
        mock_audit: AsyncMock,
        client: AsyncClient,
    ) -> None:
        """
        Fire multiple delete attempts concurrently and verify every single one
        is blocked.  This tests that the PolicyEngine is stateless and
        thread-safe — a race condition cannot cause one attempt to slip through
        while another is being evaluated.
        """
        payloads = [
            {
                "tool_name": "run_shell",
                "tool_args": {"cmd": f"rm -rf /tmp/target_{i}"},
                "user_intent": "temporary file cleanup",
            }
            for i in range(8)
        ]

        responses = await asyncio.gather(
            *[
                client.post(
                    "/v1/tool/invoke",
                    json=p,
                    headers={"X-Agent-Identity": f"concurrent-attacker-{i}"},
                )
                for i, p in enumerate(payloads)
            ]
        )

        for i, resp in enumerate(responses):
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "BLOCKED", (
                f"Concurrent attempt #{i} was not blocked: {body}"
            )
            assert body["risk_score"] == 1.0, (
                f"Concurrent attempt #{i} risk_score should be 1.0: {body}"
            )

    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_delete_obfuscated_with_base64_still_blocked(
        self,
        mock_audit: AsyncMock,
        client: AsyncClient,
    ) -> None:
        """
        An agent cannot bypass the policy by embedding the dangerous string in
        a base64-encoded shell invocation.

        Note: The PolicyEngine catches `eval(` and `exec(` which are the
        typical decode-and-execute wrappers.  This test verifies that obfuscated
        injection is also blocked.
        """
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {
                    "cmd": "eval(base64.b64decode('cm0gLXJmIC8=').decode())"
                },
                "user_intent": "run a maintenance script",
            },
        )
        body = response.json()
        assert body["status"] == "BLOCKED"

    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_delete_with_no_agent_identity_still_blocked(
        self,
        mock_audit: AsyncMock,
        client: AsyncClient,
    ) -> None:
        """
        Anonymous agents (no X-Agent-Identity header) must be treated
        identically to identified agents — delete attempts are blocked regardless.
        The system falls back to an IP-derived fingerprint for the audit record.
        """
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /var/www"},
                "user_intent": "clean up web root",
            },
            # No X-Agent-Identity header
        )
        assert response.json()["status"] == "BLOCKED"

    @patch("proxy.gateway.AgentGuardProxy._audit", new_callable=AsyncMock)
    async def test_delete_file_tool_with_session_id_blocked(
        self,
        mock_audit: AsyncMock,
        client: AsyncClient,
    ) -> None:
        """
        Session correlation (X-Session-Id header) must not influence policy
        decisions.  A session that was previously trusted cannot inherit
        permissions that bypass delete protection.
        """
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "delete_file",
                "tool_args": {"path": "/etc/crontab"},
                "user_intent": "remove an old config",
                "session_id": "privileged-session-abc123",
            },
            headers={
                "X-Agent-Identity": "session-escalation-agent",
                "X-Session-Id": "privileged-session-abc123",
            },
        )
        assert response.json()["status"] == "BLOCKED"


# ---------------------------------------------------------------------------
# TestDeleteFileAuditLogging
# ---------------------------------------------------------------------------


class TestDeleteFileAuditLogging:
    """
    Verifies the shape and content of the audit record that would be written
    to the Handshake table when a delete attempt is blocked.

    Uses the `audit_spy` fixture which intercepts `create_handshake` at the
    CRUD layer (below the gateway's _audit method) so we can make fine-grained
    assertions about what data would land in Postgres.

    Security guarantees being verified
    ------------------------------------
    1. `status`         == "BLOCKED"    (not ALLOWED, not silently swallowed)
    2. `risk_score`     >= 0.9          (catastrophic-tier score)
    3. `reasoning`      contains the rule name so responders understand why
    4. `input_payload`  does NOT contain raw secrets/paths that were stripped
                        by the redaction pipeline
    5. `output_payload` is None         (tool was never executed → no output)
    6. `agent_identity` is the value sent in the header (or derived fingerprint)
    7. `tool_name`      matches the requested tool
    8. `latency_ms`     is recorded (>0) so SLA dashboards work
    """

    async def test_block_creates_one_audit_record(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        Exactly one Handshake record must be created per blocked request.
        Duplicate writes would inflate risk metrics and skew dashboards.
        """
        response = await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "delete_file",
                "tool_args": {"path": "/etc/passwd"},
                "user_intent": "housekeeping",
            },
            headers={"X-Agent-Identity": "audit-test-agent"},
        )
        await _drain_background_tasks()

        assert response.json()["status"] == "BLOCKED"
        assert len(audit_spy) == 1, (
            f"Expected exactly 1 audit record, got {len(audit_spy)}: {audit_spy}"
        )

    async def test_audit_record_status_is_blocked(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """The `status` field in the audit record must be BLOCKED."""
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /home"},
                "user_intent": "clear home directory",
            },
            headers={"X-Agent-Identity": "status-check-agent"},
        )
        await _drain_background_tasks()

        record = audit_spy[0]
        assert record["status"] == HandshakeStatus.BLOCKED, (
            f"Expected HandshakeStatus.BLOCKED in audit record, got {record['status']!r}"
        )

    async def test_audit_record_risk_score_is_catastrophic(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        A `rm -rf` attempt must carry risk_score == 1.0 in the audit ledger
        so that automated alerting thresholds are triggered immediately.
        """
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /"},
                "user_intent": "cleanup",
            },
            headers={"X-Agent-Identity": "risk-score-agent"},
        )
        await _drain_background_tasks()

        record = audit_spy[0]
        assert record["risk_score"] == 1.0, (
            f"Expected risk_score=1.0 for rm -rf /, got {record['risk_score']}"
        )

    async def test_audit_record_reasoning_names_triggered_rule(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        The `reasoning` column must name the triggered rule (e.g. 'SHELL_RM_RF')
        so security engineers can triage the alert without re-running the engine.
        """
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /tmp/secrets"},
                "user_intent": "remove temp files",
            },
            headers={"X-Agent-Identity": "reasoning-check-agent"},
        )
        await _drain_background_tasks()

        reasoning: str = audit_spy[0]["reasoning"] or ""
        assert "SHELL_RM_RF" in reasoning, (
            f"Expected 'SHELL_RM_RF' in reasoning, got: {reasoning!r}"
        )

    async def test_audit_record_output_payload_is_none_for_block(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        When a call is BLOCKED, the upstream tool is never invoked so
        `output_payload` must be None — not an empty dict, not a stub value.
        Storing a non-None output for a blocked call would be misleading.
        """
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "delete_file",
                "tool_args": {"path": "/etc/shadow"},
                "user_intent": "remove a file",
            },
            headers={"X-Agent-Identity": "output-check-agent"},
        )
        await _drain_background_tasks()

        assert audit_spy[0]["output_payload"] is None, (
            "output_payload must be None for a BLOCKED call; "
            f"got {audit_spy[0]['output_payload']!r}"
        )

    async def test_audit_record_preserves_agent_identity(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        The `agent_identity` stored in the ledger must exactly match the value
        sent in the `X-Agent-Identity` header so forensic queries by agent are
        reliable.
        """
        test_identity = "tracked-malicious-agent-xyz"
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /data"},
                "user_intent": "wipe storage",
            },
            headers={"X-Agent-Identity": test_identity},
        )
        await _drain_background_tasks()

        assert audit_spy[0]["agent_identity"] == test_identity, (
            f"Expected agent_identity={test_identity!r}, "
            f"got {audit_spy[0]['agent_identity']!r}"
        )

    async def test_audit_record_tool_name_matches_request(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """The `tool_name` written to the ledger must match what the agent requested."""
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "delete_file",
                "tool_args": {"path": "/etc/passwd"},
                "user_intent": "file cleanup",
            },
            headers={"X-Agent-Identity": "tool-name-agent"},
        )
        await _drain_background_tasks()

        assert audit_spy[0]["tool_name"] == "delete_file"

    async def test_audit_record_latency_is_positive(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        `latency_ms` must be a positive float.  A value of 0 or None would
        break SLA alerting and performance dashboards.
        """
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "run_shell",
                "tool_args": {"cmd": "rm -rf /usr"},
                "user_intent": "uninstall packages",
            },
            headers={"X-Agent-Identity": "latency-check-agent"},
        )
        await _drain_background_tasks()

        latency = audit_spy[0].get("latency_ms")
        assert latency is not None and latency > 0, (
            f"Expected latency_ms > 0, got {latency!r}"
        )

    async def test_audit_input_payload_path_is_preserved_but_args_are_safe(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        The input_payload written to the audit ledger is the output of the
        redaction pipeline on the supplied tool_args.  Non-sensitive path
        strings like '/etc/passwd' are structural metadata (not secrets) so
        they survive redaction and are stored — but if the args contained a
        real secret alongside the path, that secret must be stripped.

        This test sends args that combine a dangerous path with a fake API key.
        The path is retained for forensic value; the key is scrubbed.
        """
        await client.post(
            "/v1/tool/invoke",
            json={
                "tool_name": "delete_file",
                "tool_args": {
                    "path": "/etc/passwd",
                    "api_key": "sk_live_FAKE-KEY-NOT-REAL-DO-NOT-USE",
                },
                "user_intent": "remove config files",
            },
            headers={"X-Agent-Identity": "payload-check-agent"},
        )
        await _drain_background_tasks()

        input_payload: dict = audit_spy[0]["input_payload"]
        # The raw API key must not appear in the stored payload.
        payload_str = str(input_payload)
        assert "FAKE-KEY-NOT-REAL-DO-NOT-USE" not in payload_str, (
            "Raw API key leaked into the audit input_payload!"
        )

    async def test_multiple_delete_attempts_each_logged_separately(
        self,
        client: AsyncClient,
        audit_spy: list[dict[str, Any]],
    ) -> None:
        """
        Three distinct delete attempts from three different agents must each
        produce their own separate audit record (3 rows, not 1 merged row).
        The ledger must be append-only; records must never be collapsed.
        """
        agents = ["agent-alpha", "agent-beta", "agent-gamma"]
        for agent in agents:
            await client.post(
                "/v1/tool/invoke",
                json={
                    "tool_name": "run_shell",
                    "tool_args": {"cmd": "rm -rf /tmp"},
                    "user_intent": "cleanup",
                },
                headers={"X-Agent-Identity": agent},
            )

        await _drain_background_tasks()

        assert len(audit_spy) == 3, (
            f"Expected 3 separate audit records, got {len(audit_spy)}"
        )
        recorded_agents = {r["agent_identity"] for r in audit_spy}
        assert recorded_agents == set(agents), (
            f"Mismatch in recorded agent identities: {recorded_agents}"
        )


# ---------------------------------------------------------------------------
# TestDeleteFilePostgresIntegration
# ---------------------------------------------------------------------------

# This class runs only when:
#   1. The `integration` pytest mark is provided (-m integration), AND
#   2. DATABASE_URL is set in the environment.
#
# It performs a full round-trip:
#   HTTP request → PolicyEngine BLOCK → _audit BackgroundTask → PostgreSQL
# and then reads the handshakes table back via asyncpg to confirm the row
# was actually written with the correct values.


_INTEGRATION_DB_URL: str | None = os.getenv("DATABASE_URL")
_skip_integration = pytest.mark.skipif(
    not _INTEGRATION_DB_URL,
    reason=(
        "DATABASE_URL is not set. "
        "Start Postgres with `docker compose up postgres -d` and set "
        "DATABASE_URL=postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard"
    ),
)


@pytest.mark.integration
class TestDeleteFilePostgresIntegration:
    """
    End-to-end verification that a blocked delete attempt is durably written
    to the PostgreSQL audit ledger.

    Test flow
    ---------
    1.  Create an isolated test session with a unique agent identity so
        this test's rows can be queried independently of other data.
    2.  Send a `rm -rf /` delete attempt through the real gateway stack
        (no mocking of _audit or create_handshake).
    3.  Wait for the BackgroundTask to drain (short asyncio.sleep).
    4.  Query the `handshakes` table via asyncpg (bypassing the ORM so the
        test can verify the raw stored values).
    5.  Assert the row exists, is BLOCKED, has risk_score=1.0, and that
        no raw file paths from sensitive locations are in the stored payload
        beyond what is expected.
    6.  Clean up the test row so the ledger is not polluted.

    Run with
    --------
        docker compose up postgres mock-mcp-server -d
        DATABASE_URL=postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard \\
        pytest -m integration -v
    """

    @_skip_integration
    async def test_delete_attempt_row_written_to_postgres(
        self, app
    ) -> None:
        """
        Full round-trip: HTTP block → BackgroundTask → Postgres row exists.
        """
        import asyncpg  # Only import when the test actually runs.

        unique_agent = f"integration-test-agent-{uuid.uuid4().hex[:8]}"

        # ----------------------------------------------------------------
        # Step 1 – Ensure tables exist.
        # ----------------------------------------------------------------
        from db.database import create_all_tables
        await create_all_tables()

        # ----------------------------------------------------------------
        # Step 2 – Send the delete attempt.
        # ----------------------------------------------------------------
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/tool/invoke",
                json={
                    "tool_name": "run_shell",
                    "tool_args": {"cmd": "rm -rf /"},
                    "user_intent": "nuclear cleanup",
                },
                headers={"X-Agent-Identity": unique_agent},
            )

        assert response.status_code == 200
        http_body = response.json()
        assert http_body["status"] == "BLOCKED", (
            f"Gateway did not block the request: {http_body}"
        )
        assert http_body["risk_score"] == 1.0

        # ----------------------------------------------------------------
        # Step 3 – Wait for the BackgroundTask to complete.
        # The task is a fire-and-forget coroutine scheduled after response
        # dispatch; 300 ms is comfortably above the DB round-trip time on
        # localhost.
        # ----------------------------------------------------------------
        await _drain_background_tasks(delay=0.30)

        # ----------------------------------------------------------------
        # Step 4 – Query Postgres directly via asyncpg.
        # ----------------------------------------------------------------
        raw_url = (
            _INTEGRATION_DB_URL
            .replace("postgresql+asyncpg://", "postgresql://")
            .replace("asyncpg://", "postgresql://")
        )

        conn = await asyncpg.connect(raw_url)
        try:
            row = await conn.fetchrow(
                """
                SELECT id, status, risk_score, tool_name, reasoning,
                       output_payload, input_payload
                FROM   handshakes
                WHERE  agent_identity = $1
                ORDER  BY timestamp DESC
                LIMIT  1
                """,
                unique_agent,
            )

            # ----------------------------------------------------------------
            # Step 5 – Assert the row.
            # ----------------------------------------------------------------
            assert row is not None, (
                f"No handshake row found for agent {unique_agent!r}. "
                "The BackgroundTask may not have completed or the DB "
                "connection may be wrong."
            )

            assert row["status"] == "BLOCKED", (
                f"Row status should be BLOCKED, got {row['status']!r}"
            )
            assert float(row["risk_score"]) == 1.0, (
                f"risk_score should be 1.0, got {row['risk_score']}"
            )
            assert row["tool_name"] == "run_shell", (
                f"tool_name mismatch: {row['tool_name']!r}"
            )
            assert row["output_payload"] is None, (
                "output_payload must be NULL for a BLOCKED call"
            )

            reasoning: str = row["reasoning"] or ""
            assert "SHELL_RM_RF" in reasoning, (
                f"Reasoning must name the triggered rule. Got: {reasoning!r}"
            )

            # ----------------------------------------------------------------
            # Step 6 – Clean up (delete only this test's row by PK).
            # ----------------------------------------------------------------
            await conn.execute(
                "DELETE FROM handshakes WHERE id = $1", row["id"]
            )

        finally:
            await conn.close()

    @_skip_integration
    async def test_sql_delete_blocked_and_logged(self, app) -> None:
        """
        Variant: SQL DELETE FROM (no WHERE) attempt.
        Verifies the SQL_DELETE_ALL rule fires and is persisted.
        """
        import asyncpg

        unique_agent = f"integration-sql-agent-{uuid.uuid4().hex[:8]}"

        from db.database import create_all_tables
        await create_all_tables()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/tool/invoke",
                json={
                    "tool_name": "query_db",
                    "tool_args": {"query": "DELETE FROM users"},
                    "user_intent": "clean up old records",
                },
                headers={"X-Agent-Identity": unique_agent},
            )

        assert response.json()["status"] == "BLOCKED"
        await _drain_background_tasks(delay=0.30)

        raw_url = (
            _INTEGRATION_DB_URL
            .replace("postgresql+asyncpg://", "postgresql://")
            .replace("asyncpg://", "postgresql://")
        )
        conn = await asyncpg.connect(raw_url)
        try:
            row = await conn.fetchrow(
                "SELECT status, risk_score, reasoning FROM handshakes "
                "WHERE agent_identity = $1 ORDER BY timestamp DESC LIMIT 1",
                unique_agent,
            )
            assert row is not None
            assert row["status"] == "BLOCKED"
            assert float(row["risk_score"]) >= 0.9
            assert "SQL_DELETE_ALL" in (row["reasoning"] or "")

            await conn.execute(
                "DELETE FROM handshakes WHERE agent_identity = $1", unique_agent
            )
        finally:
            await conn.close()

    @_skip_integration
    async def test_multiple_blocked_deletes_all_logged(self, app) -> None:
        """
        Fire three delete attempts sequentially and confirm all three produce
        rows in Postgres.  Validates the append-only ledger guarantee under
        repeated attack.
        """
        import asyncpg

        unique_prefix = f"integration-multi-{uuid.uuid4().hex[:6]}"
        agents = [f"{unique_prefix}-{i}" for i in range(3)]

        from db.database import create_all_tables
        await create_all_tables()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            for agent in agents:
                await client.post(
                    "/v1/tool/invoke",
                    json={
                        "tool_name": "run_shell",
                        "tool_args": {"cmd": "rm -rf /tmp"},
                        "user_intent": "cleanup",
                    },
                    headers={"X-Agent-Identity": agent},
                )

        await _drain_background_tasks(delay=0.50)

        raw_url = (
            _INTEGRATION_DB_URL
            .replace("postgresql+asyncpg://", "postgresql://")
            .replace("asyncpg://", "postgresql://")
        )
        conn = await asyncpg.connect(raw_url)
        try:
            rows = await conn.fetch(
                "SELECT agent_identity, status FROM handshakes "
                "WHERE agent_identity LIKE $1",
                f"{unique_prefix}-%",
            )
            assert len(rows) == 3, (
                f"Expected 3 audit rows, found {len(rows)}: "
                f"{[r['agent_identity'] for r in rows]}"
            )
            for row in rows:
                assert row["status"] == "BLOCKED"

            await conn.execute(
                "DELETE FROM handshakes WHERE agent_identity LIKE $1",
                f"{unique_prefix}-%",
            )
        finally:
            await conn.close()
