"""
AgentGuard – PII & Secret Redaction Pipeline
=============================================
Security Rationale
------------------
This module forms the **last line of defence** before a tool result is handed
back to the LLM.  Even if the PolicyEngine granted access to a tool, the raw
output is scrubbed here so that:

1. **Secrets-in-transit** (API keys, DB passwords, private keys) are masked
   before the LLM can memorise or echo them in subsequent turns.

2. **PII** (emails, phone numbers, IPv4 addresses, names) is redacted in
   compliance with GDPR / HIPAA requirements and to prevent the agent from
   leaking personal data through prompt injection.

3. The **original value is never stored**; only the redacted form reaches the
   audit ledger, the LLM response, and any downstream systems.

Design decisions
----------------
* Multi-pass regex scanning is used as a fast, dependency-free baseline.
* An optional `presidio` pass can be enabled when the `presidio-analyzer` and
  `presidio-anonymizer` packages are installed.  The code gracefully degrades
  to regex-only if they are absent (e.g. in lightweight deployments).
* Each matched span is replaced with a deterministic placeholder of the form
  ``<TYPE_REDACTED>`` so the LLM can still reason about the *structure* of a
  response without seeing sensitive values.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex catalogue
# Each entry: (label, compiled_pattern)
# Order matters – more specific patterns first.
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # ---- Credentials & Secrets ------------------------------------------------
    (
        "API_KEY",
        re.compile(
            r"""(?xi)
            (?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)
            \s*[:=]\s*
            ["']?([A-Za-z0-9\-_\.]{20,})["']?
            """,
        ),
    ),
    (
        "AWS_KEY",
        re.compile(r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b"),
    ),
    (
        "AWS_SECRET",
        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "JWT",
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    ),
    (
        "GENERIC_SECRET",
        re.compile(
            r"""(?xi)
            (?:password|passwd|pwd|secret|token|credential)
            \s*[:=]\s*
            ["']?([^\s"']{8,})["']?
            """,
        ),
    ),
    # ---- PII ------------------------------------------------------------------
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "PHONE_US",
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    ),
    (
        "SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"),
    ),
    (
        "IPV4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
]


@dataclass
class RedactionResult:
    """
    Outcome of one redaction pass.

    Attributes
    ----------
    redacted_text:
        The sanitised string with all detected sensitive spans replaced by
        ``<TYPE_REDACTED>`` placeholders.
    findings:
        List of ``(label, original_snippet)`` tuples describing every match.
        Used for audit logging – the snippet is truncated to 8 chars for safety.
    was_modified:
        True if at least one replacement was made.
    """

    redacted_text: str
    findings: list[tuple[str, str]] = field(default_factory=list)
    was_modified: bool = False


class RedactionPipeline:
    """
    Multi-pass text and structured-data scrubber.

    Usage
    -----
    .. code-block:: python

        pipeline = RedactionPipeline(use_presidio=True)
        result = pipeline.scrub_text(raw_output)
        safe_dict = pipeline.scrub_dict(raw_dict)

    Security guarantees
    -------------------
    * The original text is **never mutated in place**; scrubbing always returns
      a new object.
    * Findings (partial snippets) are only logged at DEBUG level; they are
      never sent to the LLM or stored in full.
    * The pipeline is stateless and thread-safe – the same instance can be
      shared across concurrent request handlers.
    """

    def __init__(self, *, use_presidio: bool = False) -> None:
        """
        Initialise the pipeline.

        Parameters
        ----------
        use_presidio:
            When True, attempt to import and use `presidio-analyzer` for
            NLP-based named-entity redaction (names, locations, orgs).
            Falls back silently to regex-only if the package is not installed.
        """
        self._use_presidio = use_presidio
        self._presidio_analyzer: Any = None
        self._presidio_anonymizer: Any = None

        if use_presidio:
            self._presidio_analyzer = self._try_load_presidio()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scrub_text(self, text: str) -> RedactionResult:
        """
        Scan `text` for all registered PII / secret patterns and replace
        every match with a ``<TYPE_REDACTED>`` placeholder.

        This is the primary entry point for scrubbing tool output strings.

        Security note
        -------------
        Multi-pass scanning with overlapping patterns could theoretically
        skip a secret that spans two pattern groups.  To mitigate this,
        patterns are ordered from most-specific (private keys) to least-
        specific (generic secrets), and the scan is run twice if a
        replacement was made (since one redaction may expose another).
        """
        if not isinstance(text, str):
            text = str(text)

        findings: list[tuple[str, str]] = []
        current = text
        changed = True
        passes = 0

        # Double-pass: a second sweep catches secrets exposed after the first.
        while changed and passes < 2:
            changed = False
            passes += 1
            for label, pattern in _PATTERNS:
                new, n = pattern.subn(f"<{label}_REDACTED>", current)
                if n > 0:
                    # Capture a safe snippet (first 8 chars) for audit logging.
                    for match in pattern.finditer(current):
                        snippet = match.group()[:8] + "…"
                        findings.append((label, snippet))
                    current = new
                    changed = True

        # Optional: NLP-based pass for names / orgs / locations.
        # _presidio_anonymizer is lazily initialised inside _presidio_scrub,
        # so we only gate on the analyzer being available.
        if self._presidio_analyzer:
            current, presidio_findings = self._presidio_scrub(current)
            findings.extend(presidio_findings)

        was_modified = current != text
        if was_modified:
            logger.debug("Redaction made %d finding(s) in %d pass(es).", len(findings), passes)

        return RedactionResult(
            redacted_text=current,
            findings=findings,
            was_modified=was_modified,
        )

    def scrub_dict(self, data: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        """
        Recursively scrub a nested dictionary (e.g. a JSON tool response).

        Returns
        -------
        (sanitised_dict, all_findings)
            The first element is safe to return to the LLM and to persist in
            the audit ledger.  The second is the aggregated findings list for
            audit purposes.
        """
        all_findings: list[tuple[str, str]] = []
        sanitised = self._walk(data, all_findings)
        return sanitised, all_findings

    def scrub_value(self, value: Any) -> tuple[Any, list[tuple[str, str]]]:
        """
        Scrub an arbitrary Python value (str, dict, list, or primitive).

        Convenience wrapper used by the gateway when the tool result type is
        not known ahead of time.
        """
        if isinstance(value, dict):
            return self.scrub_dict(value)
        if isinstance(value, list):
            findings: list[tuple[str, str]] = []
            sanitised_list = [self._walk(item, findings) for item in value]
            return sanitised_list, findings
        if isinstance(value, str):
            result = self.scrub_text(value)
            return result.redacted_text, result.findings
        # Primitive – no scrubbing needed.
        return value, []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk(self, node: Any, findings: list[tuple[str, str]]) -> Any:
        """
        Depth-first traversal that scrubs every string leaf in a nested
        dict / list structure.
        """
        if isinstance(node, dict):
            return {k: self._walk(v, findings) for k, v in node.items()}
        if isinstance(node, list):
            return [self._walk(item, findings) for item in node]
        if isinstance(node, str):
            result = self.scrub_text(node)
            findings.extend(result.findings)
            return result.redacted_text
        return node

    @staticmethod
    def _try_load_presidio() -> Any:
        """
        Attempt to import `presidio_analyzer`.  Returns None silently on
        ImportError so deployments without the heavy NLP stack still work.
        """
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore[import]

            engine = AnalyzerEngine()
            logger.info("Presidio NLP analyzer loaded successfully.")
            return engine
        except ImportError:
            logger.info(
                "presidio-analyzer not installed; using regex-only redaction."
            )
            return None

    def _presidio_scrub(
        self, text: str
    ) -> tuple[str, list[tuple[str, str]]]:
        """
        Run the Presidio NLP analysis + anonymisation pass.

        Detects PERSON, LOCATION, and ORGANIZATION entities and replaces
        them with ``<PERSON_REDACTED>`` etc.
        """
        try:
            from presidio_anonymizer import AnonymizerEngine  # type: ignore[import]
            from presidio_anonymizer.entities import RecognizerResult  # type: ignore[import]

            if self._presidio_anonymizer is None:
                self._presidio_anonymizer = AnonymizerEngine()

            results = self._presidio_analyzer.analyze(
                text=text,
                entities=["PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME"],
                language="en",
            )
            if not results:
                return text, []

            anonymised = self._presidio_anonymizer.anonymize(
                text=text, analyzer_results=results
            )
            findings = [
                (r.entity_type, text[r.start : r.start + 8] + "…") for r in results
            ]
            return anonymised.text, findings
        except Exception as exc:
            logger.warning("Presidio scrub failed (%s); continuing without NLP pass.", exc)
            return text, []
