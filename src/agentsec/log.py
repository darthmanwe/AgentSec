"""Structured logging with correlation context and mandatory redaction (AS-003).

Every log record passes through the AS-003 redactor before rendering. The processor is
installed in the chain rather than offered as a helper, because a redaction step that
callers have to remember is one that eventually gets forgotten in the exception path,
which is precisely where credentials tend to appear.

Correlation identifiers (``run_id``, ``workflow_id``, ``action_digest``) are bound to
context variables rather than threaded through call signatures, so a log line emitted deep
inside a tool adapter still joins up with the workflow that caused it. This is what makes
the AS-041 audit replay possible.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final, Literal

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from agentsec.redaction import redact, redact_text

_CONFIGURED = False

#: Keys carried on every record when bound. Named here so the audit replay in AS-041 and
#: the log schema cannot drift apart silently.
CORRELATION_KEYS: Final = ("run_id", "workflow_id", "action_digest", "tool", "principal")


def _redaction_processor(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """Redact every value in the record, including the message and exception text."""
    redacted: EventDict = redact(dict(event_dict))
    # `event` is the message itself and is frequently an f-string containing a value that
    # was never intended as a field.
    if isinstance(redacted.get("event"), str):
        redacted["event"] = redact_text(redacted["event"])
    if isinstance(redacted.get("exception"), str):
        redacted["exception"] = redact_text(redacted["exception"])
    return redacted


def configure_logging(
    *,
    level: str = "INFO",
    renderer: Literal["json", "console"] = "json",
    stream: Any | None = None,
) -> None:
    """Install the processor chain. Idempotent within a process.

    ``json`` is the default because these logs are meant to be queried and replayed, not
    read. ``console`` exists for interactive development only.
    """
    global _CONFIGURED

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        # No add_logger_name: it reads `.name` off the underlying logger, which
        # PrintLoggerFactory does not provide. get_logger() binds `logger` explicitly
        # instead. PrintLogger is deliberate - these records go to stdout as JSON with
        # no stdlib logging configuration to inherit or fight with.
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        # Redaction runs last among the enrichers and before any renderer, so that
        # everything added above - including formatted exception text - is covered.
        _redaction_processor,
    ]

    if renderer == "json":
        processors.append(structlog.processors.JSONRenderer(sort_keys=True))
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stdout),
        cache_logger_on_first_use=False,
    )
    _CONFIGURED = True


def get_logger(name: str | None = None) -> Any:
    """Return a bound logger, configuring with defaults if nobody has yet."""
    if not _CONFIGURED:
        configure_logging()
    logger = structlog.get_logger()
    if name is not None:
        logger = logger.bind(logger=name)
    return logger


def bind_context(**kwargs: Any) -> None:
    """Bind correlation identifiers for the current context."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Drop all bound correlation identifiers."""
    structlog.contextvars.clear_contextvars()


@contextmanager
def run_context(**kwargs: Any) -> Iterator[None]:
    """Scope correlation identifiers to a block.

    Restores the previous values on exit rather than clearing outright, so nesting a run
    context inside a workflow context does not silently orphan the outer one.
    """
    tokens = structlog.contextvars.bind_contextvars(**kwargs)
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)


__all__ = [
    "CORRELATION_KEYS",
    "bind_context",
    "clear_context",
    "configure_logging",
    "get_logger",
    "run_context",
]
