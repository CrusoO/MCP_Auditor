"""
Tests for the RedactionPipeline.
"""

from __future__ import annotations

import pytest

from proxy.redaction import RedactionPipeline


@pytest.fixture
def pipeline() -> RedactionPipeline:
    return RedactionPipeline(use_presidio=False)


class TestScrubText:
    def test_email_redacted(self, pipeline: RedactionPipeline) -> None:
        result = pipeline.scrub_text("Contact us at alice@example.com for help.")
        assert "alice@example.com" not in result.redacted_text
        assert "<EMAIL_REDACTED>" in result.redacted_text
        assert result.was_modified is True

    def test_aws_key_redacted(self, pipeline: RedactionPipeline) -> None:
        result = pipeline.scrub_text("Key: AKIAFAKEACCESSKEYID00 secret here")
        assert "AKIAFAKEACCESSKEYID00" not in result.redacted_text
        assert result.was_modified is True

    def test_jwt_redacted(self, pipeline: RedactionPipeline) -> None:
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.fakesignature"
        result = pipeline.scrub_text(f"Authorization: Bearer {jwt}")
        assert jwt not in result.redacted_text
        assert result.was_modified is True

    def test_private_key_redacted(self, pipeline: RedactionPipeline) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"
        result = pipeline.scrub_text(pem)
        assert "BEGIN RSA PRIVATE KEY" not in result.redacted_text

    def test_benign_text_unchanged(self, pipeline: RedactionPipeline) -> None:
        text = "def hello_world():\n    return 'Hello, World!'"
        result = pipeline.scrub_text(text)
        assert result.redacted_text == text
        assert result.was_modified is False
        assert result.findings == []

    def test_multiple_emails_all_redacted(self, pipeline: RedactionPipeline) -> None:
        text = "Send to alice@a.com and bob@b.org immediately."
        result = pipeline.scrub_text(text)
        assert "alice@a.com" not in result.redacted_text
        assert "bob@b.org" not in result.redacted_text

    def test_ssn_redacted(self, pipeline: RedactionPipeline) -> None:
        result = pipeline.scrub_text("SSN: 123-45-6789 on file.")
        assert "123-45-6789" not in result.redacted_text

    def test_credit_card_redacted(self, pipeline: RedactionPipeline) -> None:
        result = pipeline.scrub_text("Card: 4111111111111111 expiry 12/28")
        assert "4111111111111111" not in result.redacted_text


class TestScrubDict:
    def test_nested_dict_scrubbed(self, pipeline: RedactionPipeline) -> None:
        data = {
            "user": {
                "name": "Alice",
                "email": "alice@example.com",
                "phone": "555-123-4567",
            },
            "config": {
                "api_key": "sk_live_FAKE-KEY-NOT-REAL-DO-NOT-USE",
            },
        }
        sanitised, findings = pipeline.scrub_dict(data)
        assert sanitised["user"]["email"] != "alice@example.com"
        assert len(findings) > 0

    def test_list_values_scrubbed(self, pipeline: RedactionPipeline) -> None:
        data = {"emails": ["a@x.com", "b@y.org", "plain text"]}
        sanitised, findings = pipeline.scrub_dict(data)
        assert "a@x.com" not in sanitised["emails"]
        assert "b@y.org" not in sanitised["emails"]
        assert "plain text" in sanitised["emails"]

    def test_non_string_primitives_untouched(self, pipeline: RedactionPipeline) -> None:
        data = {"count": 42, "active": True, "ratio": 3.14}
        sanitised, findings = pipeline.scrub_dict(data)
        assert sanitised == data
        assert findings == []


class TestScrubValue:
    def test_string_value(self, pipeline: RedactionPipeline) -> None:
        val, findings = pipeline.scrub_value("Call me at 555-867-5309.")
        assert "555-867-5309" not in val

    def test_dict_value(self, pipeline: RedactionPipeline) -> None:
        val, findings = pipeline.scrub_value({"secret": "password: hunter2"})
        assert "hunter2" not in str(val)

    def test_integer_value(self, pipeline: RedactionPipeline) -> None:
        val, findings = pipeline.scrub_value(42)
        assert val == 42
        assert findings == []
