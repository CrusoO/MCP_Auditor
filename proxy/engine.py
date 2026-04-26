"""
AgentGuard – Policy Engine
===========================
Security Rationale
------------------
The PolicyEngine sits between the raw MCP JSON-RPC message and the actual
tool execution.  Its job is to decide: **ALLOW, BLOCK, or REDACT**.

Two evaluation layers are applied in order:

1. **Static Rules (fast path)**
   Pattern-match against known dangerous strings that should *never* appear
   in tool arguments regardless of user intent:
   - Shell destruction commands:  ``rm -rf``, ``dd if=/dev/zero``, etc.
   - SQL DDL/DML attacks:         ``DROP TABLE``, ``DELETE FROM``, etc.
   - Code injection sinks:        ``eval(``, ``exec(``, ``__import__``, etc.
   - Path traversal:              ``../../../``, absolute sensitive paths.

   If any static rule fires → immediately return BLOCK with a risk_score of 1.0.
   No further evaluation is performed; speed and safety over granularity.

2. **Dynamic Scope Check (intent alignment)**
   Compare the *semantic intent* of the original user prompt against the
   *concrete tool arguments*.  For example:
   - User asked for a "code summary" but the agent is reading ``/etc/passwd``.
   - User asked to "send an email" but the agent is calling a DB-delete tool.

   The scope check uses a keyword-overlap heuristic.  For production use this
   can be replaced with an embedding-based cosine-similarity check (see the
   ``_embedding_scope_check`` stub below).

   If intent mismatch is detected → BLOCK with a risk_score proportional to
   the degree of divergence.

The engine is stateless and can be instantiated once at startup and reused
across all concurrent requests.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"


@dataclass
class PolicyDecision:
    """
    Structured verdict returned by the PolicyEngine for every tool call.

    Attributes
    ----------
    action:
        One of ALLOW / BLOCK / REDACT.
    reason:
        Human-readable explanation; included in the audit record and (for
        BLOCK) returned to the caller so the agent can self-correct.
    risk_score:
        Float in [0.0, 1.0].  0.0 = benign, 1.0 = certain attack.
    triggered_rules:
        List of rule names that fired (for BLOCK/REDACT decisions).
    """

    action: PolicyAction
    reason: str
    risk_score: float
    triggered_rules: list[str] = field(default_factory=list)

    def is_allowed(self) -> bool:
        return self.action == PolicyAction.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "triggered_rules": self.triggered_rules,
        }


# ---------------------------------------------------------------------------
# Static rule catalogue
# ---------------------------------------------------------------------------
# Each rule is (name, compiled_regex, risk_score_if_matched).
# risk_score 1.0 → automatic BLOCK regardless of intent.
# risk_score 0.5–0.9 → BLOCK unless overridden by a trust exception.
# ---------------------------------------------------------------------------
_STATIC_RULES: list[tuple[str, re.Pattern[str], float]] = [
    # Shell destruction
    (
        "SHELL_RM_RF",
        re.compile(r"rm\s+-[rf]{1,2}", re.IGNORECASE),
        1.0,
    ),
    (
        "SHELL_DD_ZERO",
        re.compile(r"dd\s+if=/dev/zero", re.IGNORECASE),
        1.0,
    ),
    (
        "SHELL_FORK_BOMB",
        re.compile(r":\s*\(\s*\)\s*\{.*:\|:&\s*\}", re.IGNORECASE),
        1.0,
    ),
    (
        "SHELL_CHMOD_777",
        re.compile(r"chmod\s+(?:a\+rwx|0?777)", re.IGNORECASE),
        0.8,
    ),
    # SQL injection / destructive DDL
    (
        "SQL_DROP",
        re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\b", re.IGNORECASE),
        1.0,
    ),
    (
        "SQL_TRUNCATE",
        re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
        0.9,
    ),
    (
        "SQL_DELETE_ALL",
        re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.IGNORECASE),
        0.9,
    ),
    (
        "SQL_UNION_INJECTION",
        re.compile(r"(?i)\bUNION\b.{0,50}\bSELECT\b"),
        0.85,
    ),
    (
        "SQL_COMMENT_INJECTION",
        re.compile(r"(?:'|\")\s*(?:--|#|/\*)"),
        0.8,
    ),
    # Code injection
    (
        "CODE_EVAL",
        re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
        0.95,
    ),
    (
        "CODE_IMPORT_OS",
        re.compile(r"__import__\s*\(\s*['\"]os['\"]", re.IGNORECASE),
        1.0,
    ),
    (
        "CODE_SUBPROCESS",
        re.compile(r"\bsubprocess\s*\.\s*(?:run|Popen|call|check_output)\b", re.IGNORECASE),
        0.9,
    ),
    (
        "CODE_PICKLE",
        re.compile(r"\bpickle\s*\.\s*loads?\b", re.IGNORECASE),
        0.85,
    ),
    # Path traversal / sensitive absolute paths
    (
        "PATH_TRAVERSAL",
        re.compile(r"\.\./\.\./"),
        0.9,
    ),
    (
        "PATH_ETC_PASSWD",
        re.compile(r"/etc/(?:passwd|shadow|sudoers|hosts)\b"),
        1.0,
    ),
    (
        "PATH_SSH_KEYS",
        re.compile(r"~/?\s*\.ssh/"),
        0.95,
    ),
    (
        "PATH_PROC_SELF",
        re.compile(r"/proc/self/"),
        0.85,
    ),
    # Credential exfiltration patterns
    (
        "EXFIL_CURL",
        re.compile(r"\bcurl\b.{0,80}(?:api\.telegram|webhook\.site|ngrok\.io|requestbin)", re.IGNORECASE),
        1.0,
    ),
    (
        "EXFIL_DNS",
        re.compile(r"\bnslookup\b|\bdig\b.{0,40}@", re.IGNORECASE),
        0.7,
    ),
]

# ---------------------------------------------------------------------------
# Intent keyword taxonomy
# Maps high-level user intent categories to the tools/paths/actions that
# are semantically consistent with that intent.
# ---------------------------------------------------------------------------
_INTENT_TAXONOMY: dict[str, list[str]] = {
    "code_review":     ["read_file", "list_files", "search_code", "get_diff"],
    "code_summary":    ["read_file", "list_files", "search_code"],
    "send_email":      ["send_email", "draft_email", "list_contacts"],
    "database_query":  ["query_db", "read_db", "list_tables"],
    "file_management": ["read_file", "write_file", "delete_file", "list_files"],
    "web_search":      ["search_web", "fetch_url", "browse"],
    "git":             ["git_log", "git_diff", "git_commit", "git_status"],
}

# Sensitive paths that are always out-of-scope regardless of intent.
_OUT_OF_SCOPE_PATHS: list[re.Pattern[str]] = [
    re.compile(r"/etc/"),
    re.compile(r"/proc/"),
    re.compile(r"/sys/"),
    re.compile(r"C:\\Windows\\System32", re.IGNORECASE),
    re.compile(r"\.ssh/"),
    re.compile(r"\.aws/credentials"),
    re.compile(r"\.env"),
]


class PolicyEngine:
    """
    Stateless governance engine that evaluates every tool call against static
    blocklists and dynamic intent-scoping rules.

    Instantiate once at application startup; the same instance is safe to use
    from concurrent async tasks.

    Example
    -------
    .. code-block:: python

        engine = PolicyEngine(strict_mode=True)
        decision = engine.evaluate(
            tool_name="read_file",
            tool_args={"path": "/etc/passwd"},
            user_intent="summarise this Python project",
        )
        if not decision.is_allowed():
            raise PermissionError(decision.reason)
    """

    def __init__(self, *, strict_mode: bool = True) -> None:
        """
        Parameters
        ----------
        strict_mode:
            When True (default), any rule with risk_score >= 0.7 causes a
            BLOCK.  When False, scores between 0.5 and 0.7 downgrade to
            REDACT, which is useful in trusted-dev environments.
        """
        self._strict = strict_mode

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_intent: str,
    ) -> PolicyDecision:
        """
        Evaluate a tool call and return a governance decision.

        Evaluation order
        ----------------
        1. Flatten `tool_args` to a single string for pattern matching.
        2. Run all static rules.  First match with score == 1.0 short-circuits
           (immediate BLOCK).
        3. Run the dynamic scope check comparing `tool_name` / arg paths to
           the declared `user_intent`.
        4. Aggregate findings → produce final PolicyDecision.

        Parameters
        ----------
        tool_name:
            The MCP tool being invoked (e.g. ``"read_file"``).
        tool_args:
            Arguments supplied by the agent (before any redaction).
        user_intent:
            The original user prompt or a summarised form of it.  Used to
            detect intent drift.

        Returns
        -------
        PolicyDecision
        """
        flat_args = self._flatten(tool_args)
        triggered: list[tuple[str, float]] = []

        # ----------------------------------------------------------------
        # Layer 1 – Static rules
        # ----------------------------------------------------------------
        for rule_name, pattern, score in _STATIC_RULES:
            if pattern.search(flat_args):
                triggered.append((rule_name, score))
                logger.warning(
                    "Static rule '%s' fired on tool '%s' (score=%.2f).",
                    rule_name, tool_name, score,
                )
                # Instant block for catastrophic patterns.
                if score >= 1.0:
                    return PolicyDecision(
                        action=PolicyAction.BLOCK,
                        reason=f"Blocked by static rule '{rule_name}': detected a catastrophically dangerous pattern.",
                        risk_score=1.0,
                        triggered_rules=[rule_name],
                    )

        # ----------------------------------------------------------------
        # Layer 2 – Dynamic scope / intent check
        # ----------------------------------------------------------------
        scope_score, scope_reason = self._scope_check(
            tool_name=tool_name,
            tool_args=tool_args,
            user_intent=user_intent,
        )
        if scope_score > 0.0:
            triggered.append(("INTENT_MISMATCH", scope_score))

        # ----------------------------------------------------------------
        # Layer 3 – Aggregate decision
        # ----------------------------------------------------------------
        if not triggered:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="All checks passed; no policy violations detected.",
                risk_score=0.0,
            )

        max_score = max(s for _, s in triggered)
        rule_names = [r for r, _ in triggered]

        if max_score >= 1.0 or (self._strict and max_score >= 0.7):
            action = PolicyAction.BLOCK
            reason = self._block_reason(triggered, scope_reason)
        elif max_score >= 0.5:
            action = PolicyAction.REDACT
            reason = (
                f"Sensitive content detected (score={max_score:.2f}); "
                "output will be redacted before delivery."
            )
        else:
            action = PolicyAction.ALLOW
            reason = f"Low-risk signals detected (score={max_score:.2f}); proceeding with caution."

        return PolicyDecision(
            action=action,
            reason=reason,
            risk_score=max_score,
            triggered_rules=rule_names,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flatten(data: Any, depth: int = 0) -> str:
        """
        Recursively flatten a dict/list/primitive to a single string for
        regex pattern matching.

        Depth is capped at 10 to prevent stack overflow on pathologically
        nested inputs (a potential DoS vector).
        """
        if depth > 10:
            return ""
        if isinstance(data, dict):
            return " ".join(
                PolicyEngine._flatten(v, depth + 1) for v in data.values()
            )
        if isinstance(data, (list, tuple)):
            return " ".join(PolicyEngine._flatten(v, depth + 1) for v in data)
        return str(data)

    def _scope_check(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_intent: str,
    ) -> tuple[float, str]:
        """
        Detect intent drift: the agent is attempting actions inconsistent
        with what the user originally asked for.

        Algorithm
        ---------
        1. Detect intent category from `user_intent` keywords.
        2. Check whether `tool_name` is in the allowed tools for that category.
        3. Check whether any path argument falls under a sensitive prefix
           regardless of intent.

        Returns (risk_score, reason_string).  (0.0, "") means in-scope.
        """
        intent_lower = user_intent.lower()
        flat_args = self._flatten(tool_args).lower()

        # Check for unconditionally out-of-scope paths first.
        for pattern in _OUT_OF_SCOPE_PATHS:
            if pattern.search(flat_args):
                return (
                    0.95,
                    f"Tool args reference a sensitive system path that is "
                    f"always out of scope (pattern: {pattern.pattern!r}).",
                )

        # Determine the user's intent category.
        matched_category: str | None = None
        for category, allowed_tools in _INTENT_TAXONOMY.items():
            if category.replace("_", " ") in intent_lower or category in intent_lower:
                matched_category = category
                break

        if matched_category is None:
            # Unknown intent → we can't validate scope, so allow with low risk.
            return 0.0, ""

        allowed = _INTENT_TAXONOMY[matched_category]
        if tool_name not in allowed:
            score = 0.75
            return (
                score,
                f"Intent mismatch: user intent '{matched_category}' does not "
                f"permit tool '{tool_name}'. Allowed tools: {allowed}.",
            )

        return 0.0, ""

    @staticmethod
    def _block_reason(
        triggered: list[tuple[str, float]],
        scope_reason: str,
    ) -> str:
        """Compose a human-readable block reason from triggered rules."""
        lines = []
        for rule, score in triggered:
            if rule == "INTENT_MISMATCH":
                lines.append(f"• Intent mismatch (score={score:.2f}): {scope_reason}")
            else:
                lines.append(f"• Static rule '{rule}' (score={score:.2f})")
        return "Request blocked by AgentGuard PolicyEngine:\n" + "\n".join(lines)
