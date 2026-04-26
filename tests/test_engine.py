"""
Tests for the PolicyEngine – static rules and dynamic scope checks.
"""

from __future__ import annotations

import pytest

from proxy.engine import PolicyAction, PolicyEngine


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(strict_mode=True)


@pytest.fixture
def lenient_engine() -> PolicyEngine:
    return PolicyEngine(strict_mode=False)


# ---------------------------------------------------------------------------
# Static rule tests
# ---------------------------------------------------------------------------

class TestStaticRules:
    def test_rm_rf_is_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="run_shell",
            tool_args={"cmd": "rm -rf /"},
            user_intent="clean up temp files",
        )
        assert decision.action == PolicyAction.BLOCK
        assert decision.risk_score == 1.0
        assert "SHELL_RM_RF" in decision.triggered_rules

    def test_drop_table_is_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="query_db",
            tool_args={"query": "DROP TABLE users;"},
            user_intent="run a report",
        )
        assert decision.action == PolicyAction.BLOCK
        assert "SQL_DROP" in decision.triggered_rules

    def test_eval_injection_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="run_code",
            tool_args={"code": "eval(input())"},
            user_intent="run a script",
        )
        assert decision.action == PolicyAction.BLOCK

    def test_etc_passwd_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="read_file",
            tool_args={"path": "/etc/passwd"},
            user_intent="summarise the codebase",
        )
        assert decision.action == PolicyAction.BLOCK
        assert decision.risk_score == 1.0

    def test_jwt_token_in_args_redacted(self, lenient_engine: PolicyEngine) -> None:
        """
        JWT tokens in args should raise the risk score but not necessarily BLOCK
        in lenient mode (the redaction pipeline will scrub the value).
        """
        decision = lenient_engine.evaluate(
            tool_name="fetch_url",
            tool_args={"headers": {"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"}},
            user_intent="fetch some data from the API",
        )
        # In lenient mode with a mid-range score it should be REDACT or ALLOW.
        assert decision.action in (PolicyAction.REDACT, PolicyAction.ALLOW)

    def test_safe_call_is_allowed(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="list_files",
            tool_args={"directory": "./src"},
            user_intent="code summary",
        )
        assert decision.action == PolicyAction.ALLOW
        assert decision.risk_score == 0.0

    def test_ssh_key_path_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="read_file",
            tool_args={"path": "~/.ssh/id_rsa"},
            user_intent="check the config files",
        )
        assert decision.action == PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# Dynamic scope tests
# ---------------------------------------------------------------------------

class TestDynamicScope:
    def test_out_of_scope_path_blocked(self, engine: PolicyEngine) -> None:
        """Agent tries to read /proc/self/environ during a 'code summary' intent."""
        decision = engine.evaluate(
            tool_name="read_file",
            tool_args={"path": "/proc/self/environ"},
            user_intent="give me a code summary",
        )
        assert decision.action == PolicyAction.BLOCK

    def test_tool_outside_intent_category_blocked(self, engine: PolicyEngine) -> None:
        """
        User's intent is 'code summary' but the agent is trying to call
        'query_db', which is not in the allowed tools for that category.
        """
        decision = engine.evaluate(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM users"},
            user_intent="code summary of the project",
        )
        assert decision.action == PolicyAction.BLOCK
        assert "INTENT_MISMATCH" in decision.triggered_rules

    def test_aligned_intent_is_allowed(self, engine: PolicyEngine) -> None:
        """read_file is valid for 'code summary' intent."""
        decision = engine.evaluate(
            tool_name="read_file",
            tool_args={"path": "./src/main.py"},
            user_intent="give me a code summary",
        )
        assert decision.action == PolicyAction.ALLOW

    def test_send_email_for_database_query_intent_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="send_email",
            tool_args={"to": "admin@example.com", "subject": "DB dump"},
            user_intent="database query results",
        )
        assert decision.action == PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# Risk score tests
# ---------------------------------------------------------------------------

class TestRiskScores:
    def test_catastrophic_score_is_1(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="run_shell",
            tool_args={"cmd": "rm -rf /tmp && __import__('os').system('cat /etc/passwd')"},
            user_intent="anything",
        )
        assert decision.risk_score == 1.0

    def test_benign_score_is_0(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate(
            tool_name="search_code",
            tool_args={"query": "def main"},
            user_intent="code summary",
        )
        assert decision.risk_score == 0.0

    def test_decision_to_dict(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("read_file", {"path": "./main.py"}, "code review")
        d = decision.to_dict()
        assert "action" in d
        assert "reason" in d
        assert "risk_score" in d
        assert isinstance(d["triggered_rules"], list)
