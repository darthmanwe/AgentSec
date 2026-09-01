"""Structured logging tests (AS-003)."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest
import structlog

from agentsec.log import bind_context, clear_context, configure_logging, get_logger, run_context
from agentsec.redaction import REDACTED

FAKE_KEY = "sk-ant-api03-FAKENOTREAL0123456789abcdefXYZ"


@pytest.fixture
def captured() -> Any:
    """Configure logging to an in-memory stream and yield a parsed-line reader."""
    stream = io.StringIO()
    configure_logging(level="DEBUG", renderer="json", stream=stream)
    clear_context()
    yield stream
    clear_context()
    structlog.reset_defaults()


def lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_emits_structured_json(captured: io.StringIO) -> None:
    get_logger("test").info("policy decision recorded", outcome="DENY", tool="fixture_repo")
    (record,) = lines(captured)
    assert record["event"] == "policy decision recorded"
    assert record["outcome"] == "DENY"
    assert record["tool"] == "fixture_repo"
    assert record["level"] == "info"
    assert record["timestamp"].endswith("Z")


def test_sensitive_field_is_redacted(captured: io.StringIO) -> None:
    get_logger("test").info("calling provider", api_key=FAKE_KEY, model="claude-opus-5")
    (record,) = lines(captured)
    assert record["api_key"] == REDACTED
    assert record["model"] == "claude-opus-5"
    assert FAKE_KEY not in captured.getvalue()


def test_secret_inside_the_message_is_redacted(captured: io.StringIO) -> None:
    """The message is where credentials leak in practice - an f-string in an error path,
    not a deliberately named field."""
    get_logger("test").error(f"auth failed for key {FAKE_KEY}")
    assert FAKE_KEY not in captured.getvalue()
    assert REDACTED in lines(captured)[0]["event"]


def test_secret_in_exception_text_is_redacted(captured: io.StringIO) -> None:
    """The exception path is the one most likely to be forgotten, which is why redaction
    is a processor in the chain rather than something callers opt into."""
    try:
        raise ValueError(f"bad credential: {FAKE_KEY}")
    except ValueError:
        get_logger("test").exception("provider call failed")
    assert FAKE_KEY not in captured.getvalue()


def test_usage_accounting_survives_redaction(captured: io.StringIO) -> None:
    """`token` is a substring of `input_tokens`; over-redaction here would silently break
    the cost ceiling."""
    get_logger("test").info("usage", input_tokens=1200, output_tokens=340, total_tokens=1540)
    record = lines(captured)[0]
    assert record["input_tokens"] == 1200
    assert record["output_tokens"] == 340
    assert record["total_tokens"] == 1540


def test_correlation_context_appears_on_records(captured: io.StringIO) -> None:
    bind_context(run_id="run-abc", workflow_id="wf-123")
    get_logger("test").info("collecting context")
    record = lines(captured)[0]
    assert record["run_id"] == "run-abc"
    assert record["workflow_id"] == "wf-123"


def test_run_context_restores_previous_values(captured: io.StringIO) -> None:
    """Nesting must not orphan the outer context, or a workflow's later log lines lose
    their correlation and audit replay breaks."""
    bind_context(run_id="outer")
    with run_context(run_id="inner", action_digest="deadbeef"):
        get_logger("test").info("inside")
    get_logger("test").info("outside")

    inside, outside = lines(captured)
    assert inside["run_id"] == "inner"
    assert inside["action_digest"] == "deadbeef"
    assert outside["run_id"] == "outer"
    assert "action_digest" not in outside


def test_level_filtering_applies(captured: io.StringIO) -> None:
    configure_logging(level="WARNING", renderer="json", stream=captured)
    log = get_logger("test")
    log.info("should not appear")
    log.warning("should appear")
    records = lines(captured)
    assert len(records) == 1
    assert records[0]["event"] == "should appear"


def test_json_output_keys_are_sorted(captured: io.StringIO) -> None:
    """Deterministic ordering keeps committed log fixtures diff-stable."""
    get_logger("test").info("event", zeta=1, alpha=2, mu=3)
    raw = captured.getvalue().strip()
    parsed = json.loads(raw)
    assert list(parsed) == sorted(parsed)
