"""Redaction tests (AS-003).

Two halves, and the second matters more than the first:

* secrets are redacted;
* **non-secrets are preserved.** Over-redaction destroys the audit trail and the usage
  accounting, and it fails silently - nobody notices that `input_tokens` went missing
  until the cost report is empty.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from agentsec.redaction import REDACTED, is_sensitive_key, redact, redact_text

FAKE_ANTHROPIC = "sk-ant-api03-FAKENOTREAL0123456789abcdefXYZ"
FAKE_GITHUB = "ghp_FAKENOTREAL0123456789abcdefghij"
FAKE_GITHUB_PAT = "github_pat_FAKENOTREAL0123456789_abcdefghij"
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAA\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


# --------------------------------------------------------------------------- key matching


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "passwd",
        "api_key",
        "apiKey",
        "API_KEY",
        "x-api-key",
        "anthropic_api_key",
        "authorization",
        "Authorization",
        "auth",
        "github_token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "private_key",
        "cookie",
        "Set-Cookie",
        "credential",
    ],
)
def test_sensitive_keys_are_detected(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "token_count",
        "max_tokens",
        "cache_read_input_tokens",
        "auth_decision",
        "auth_reason",
        "auth_outcome",
        "requires_credentials",
        "credential_type",
        "has_credentials",
        "run_id",
        "workflow_id",
        "action_digest",
        "tool",
        "principal",
        "resource",
    ],
)
def test_non_sensitive_keys_are_preserved(key: str) -> None:
    """Regression guard. `token` is a substring of `input_tokens`, and redacting usage
    accounting would break the cost ceiling that keeps the eval inside budget."""
    assert not is_sensitive_key(key)


def test_sensitive_key_redacts_its_value() -> None:
    out = redact({"api_key": "anything at all", "run_id": "run-123"})
    assert out["api_key"] == REDACTED
    assert out["run_id"] == "run-123"


# --------------------------------------------------------------------------- value patterns


@pytest.mark.parametrize(
    "secret",
    [FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_GITHUB_PAT, FAKE_AWS, FAKE_JWT, FAKE_PEM],
)
def test_recognisable_secrets_redact_under_any_key(secret: str) -> None:
    """A credential pasted into a free-text field, or quoted in an error message, is still
    a credential."""
    out = redact({"note": f"the call failed using {secret} as the credential"})
    assert secret not in out["note"]
    assert REDACTED in out["note"]


def test_bearer_header_value_is_redacted() -> None:
    out = redact_text("Authorization: Bearer abcdefghijklmnop1234567890")
    assert "abcdefghijklmnop1234567890" not in out


def test_url_embedded_password_is_redacted_but_structure_survives() -> None:
    """The database URL is exactly this shape, making it the most likely accidental leak.
    Host and user stay visible because they are what makes the log line useful."""
    out = redact_text("postgresql+asyncpg://agentsec:hunter2secret@db.internal:5432/agentsec")
    assert "hunter2secret" not in out
    assert "agentsec:" in out
    assert "db.internal:5432" in out


def test_no_partial_reveal() -> None:
    """Not even a prefix. A fingerprint would help correlation but enables offline
    brute-force against low-entropy secrets."""
    out = redact({"password": "correct-horse-battery-staple"})
    assert out["password"] == REDACTED
    assert "correct" not in str(out)


# --------------------------------------------------------------------------- recursion


def test_nested_structures_are_redacted_at_every_level() -> None:
    payload = {
        "request": {
            "headers": {"Authorization": "Bearer secrettokenvalue123456"},
            "body": {"nested": [{"api_key": FAKE_ANTHROPIC}, {"safe": "keep me"}]},
        },
        "run_id": "run-42",
    }
    out = redact(payload)
    assert out["request"]["headers"]["Authorization"] == REDACTED
    assert out["request"]["body"]["nested"][0]["api_key"] == REDACTED
    assert out["request"]["body"]["nested"][1]["safe"] == "keep me"
    assert out["run_id"] == "run-42"
    assert FAKE_ANTHROPIC not in str(out)


def test_input_is_not_mutated() -> None:
    """Log processors run on live application data; a redactor with side effects would
    corrupt the state it is reporting on."""
    original = {"password": "secret", "nested": {"token": "abc"}}
    redact(original)
    assert original["password"] == "secret"
    assert original["nested"]["token"] == "abc"


def test_cycles_do_not_hang() -> None:
    payload: dict[str, object] = {"name": "root"}
    payload["self"] = payload
    out = redact(payload)
    assert out["name"] == "root"
    assert "cycle" in str(out["self"])


def test_excessive_depth_is_truncated() -> None:
    payload: dict[str, object] = {"leaf": "value"}
    for _ in range(40):
        payload = {"deeper": payload}
    assert "max-depth" in str(redact(payload))


def test_secret_str_is_redacted() -> None:
    assert redact({"anything": SecretStr("nested-secret-value")})["anything"] == REDACTED


@pytest.mark.parametrize("container", [list, tuple, set])
def test_sequence_types_are_traversed(container: type) -> None:
    out = redact({"items": container([FAKE_GITHUB, "safe"])})
    assert FAKE_GITHUB not in str(out)
    assert "safe" in str(out)


def test_scalars_pass_through_untouched() -> None:
    payload = {"count": 42, "ratio": 0.5, "ok": True, "missing": None}
    assert redact(payload) == payload
