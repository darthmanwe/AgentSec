"""Failure classification and retry for a paid run (AS-040 hardening).

A single funded evaluation run gets one attempt. It may make hundreds of API calls over
tens of minutes, and the ways that goes wrong are not exotic: a rate limit, a brief
overload, a connection reset, one slow request that never returns. None of those is a
reason to lose the run, and none of them is the same as a reason to stop.

So failures are **classified**, not merely caught:

``RETRYABLE``
    Transient. Retry with exponential backoff and jitter. Rate limits, overload,
    connection resets, timeouts, 5xx.

``TERMINAL``
    Retrying cannot help and would spend money learning that. A bad request, a rejected
    model parameter, an authentication failure. Stop the cell, record why, continue the
    run — one malformed cell must not abort a run that has already cost money.

``FATAL``
    Stop the whole run. Authentication that was working and now is not, or a budget
    ceiling reached. Continuing would either fail identically every time or spend past a
    limit the operator set.

The classification is by SDK exception type rather than by parsing messages. Message
matching breaks silently on an SDK upgrade, and the failure mode is a retry storm against
an error that will never clear.

**Jitter is not decoration.** Ten cells retrying a rate limit on the same schedule
re-collide on every attempt. Full jitter is what turns a thundering herd into a queue.
"""

from __future__ import annotations

import asyncio
import enum
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Final

from agentsec.log import get_logger

log = get_logger("agentsec.eval.resilience")


#: Retry schedule. Six attempts over roughly two minutes of backoff, which covers a
#: rate-limit window without letting one stuck cell hold a funded run open indefinitely.
MAX_ATTEMPTS: Final = 6
BASE_DELAY_SECONDS: Final = 2.0
MAX_DELAY_SECONDS: Final = 60.0

#: Hard ceiling on a single request. The SDK has its own timeout, but a hung socket that
#: the SDK does not notice would stall a cell forever, and a funded run cannot afford to
#: discover that at the end.
REQUEST_TIMEOUT_SECONDS: Final = 300.0


class Severity(enum.StrEnum):
    """What to do about a failure."""

    RETRYABLE = "retryable"
    TERMINAL = "terminal"
    FATAL = "fatal"


#: SDK exception names by severity. Matched on the class name so this module never imports
#: the SDK - the mock path must not drag in an HTTP client, and the classification has to
#: work in a test process that has no credentials.
_RETRYABLE_NAMES: Final = frozenset(
    {
        "RateLimitError",
        "OverloadedError",
        "APITimeoutError",
        "APIConnectionError",
        "InternalServerError",
        "ServiceUnavailableError",
        "RetryableError",
        "ConflictError",
        "DeadlineExceededError",
        "APIConnectionTimeoutError",
        "TimeoutError",
        "ConnectionError",
        "ConnectionResetError",
    }
)

_FATAL_NAMES: Final = frozenset(
    {
        "AuthenticationError",
        "PermissionDeniedError",
        "WorkloadIdentityError",
    }
)

#: Status codes, for an exception whose type name was not recognised. 408 request
#: timeout, 409 conflict, 429 rate limit; 5xx is the server's problem and may clear.
_RETRYABLE_STATUS: Final = frozenset({408, 409, 429})
_SERVER_ERROR: Final = 500
#: Credentials. Retrying these burns the retry budget learning nothing.
_FATAL_STATUS: Final = frozenset({401, 403})

_TERMINAL_NAMES: Final = frozenset(
    {
        "BadRequestError",
        "NotFoundError",
        "UnprocessableEntityError",
        "RequestTooLargeError",
        "APIResponseValidationError",
    }
)


def classify(error: BaseException) -> Severity:
    """Decide what a failure means.

    By type name, walking the MRO so a subclass of a known error is classified with its
    parent. Unknown errors are TERMINAL rather than RETRYABLE: retrying something nobody
    has classified spends money to learn nothing, and the conservative default on a funded
    run is to stop the cell and say so.
    """
    for klass in type(error).__mro__:
        name = klass.__name__
        if name in _FATAL_NAMES:
            return Severity.FATAL
        if name in _RETRYABLE_NAMES:
            return Severity.RETRYABLE
        if name in _TERMINAL_NAMES:
            return Severity.TERMINAL

    # Status codes, when the exception carries one and the name was not recognised.
    status = getattr(error, "status_code", None)
    if isinstance(status, int):
        if status in _RETRYABLE_STATUS or status >= _SERVER_ERROR:
            return Severity.RETRYABLE
        if status in _FATAL_STATUS:
            return Severity.FATAL
        return Severity.TERMINAL

    return Severity.TERMINAL


class FatalRunError(Exception):
    """Stop the whole run. Continuing would fail identically or overspend."""


class TerminalCallError(Exception):
    """This call cannot succeed. Record it and move on."""


@dataclass
class RetryLog:
    """What went wrong and what was done about it.

    Kept because a run that quietly retried forty times is a materially different result
    from one that ran clean, and an artifact that does not say so is hiding the most
    useful diagnostic it has.
    """

    attempts: int = 0
    retries: int = 0
    waited_seconds: float = 0.0
    by_kind: dict[str, int] = field(default_factory=dict)
    terminal: list[str] = field(default_factory=list)

    def record_retry(self, error: BaseException, delay: float) -> None:
        self.retries += 1
        self.waited_seconds += delay
        name = type(error).__name__
        self.by_kind[name] = self.by_kind.get(name, 0) + 1

    def record_terminal(self, error: BaseException) -> None:
        self.terminal.append(f"{type(error).__name__}: {error}"[:300])

    def as_row(self) -> dict[str, Any]:
        return {
            "attempts": self.attempts,
            "retries": self.retries,
            "waited_seconds": round(self.waited_seconds, 2),
            "retries_by_kind": dict(sorted(self.by_kind.items())),
            "terminal_failures": list(self.terminal),
        }


def backoff_delay(attempt: int, *, rng: random.Random | None = None) -> float:
    """Exponential backoff with full jitter.

    Full jitter rather than a fixed schedule because ten cells hitting the same rate limit
    would otherwise retry in lockstep and re-collide on every attempt. Randomising the
    whole interval is what turns a thundering herd into a queue.
    """
    ceiling = min(MAX_DELAY_SECONDS, BASE_DELAY_SECONDS * (2 ** (attempt - 1)))
    source = rng or random
    return source.uniform(0.0, ceiling)


async def with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    what: str,
    retry_log: RetryLog | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    sleeper: Callable[[float], Awaitable[None]] | None = None,
    rng: random.Random | None = None,
) -> T:
    """Run an operation, retrying transient failures.

    A hard timeout wraps every attempt. The SDK has its own, but a socket that hangs
    without the SDK noticing would stall a cell indefinitely, and a funded run cannot
    afford to discover that after an hour.
    """
    record = retry_log or RetryLog()
    sleep = sleeper or asyncio.sleep
    last: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        record.attempts += 1
        try:
            async with asyncio.timeout(timeout_seconds):
                return await operation()
        except asyncio.CancelledError:
            # Never swallowed. A cancellation is the operator stopping the run, and
            # retrying through it would ignore them.
            raise
        except BaseException as error:  # classified on the next line, not swallowed
            last = error
            severity = classify(error)

            if severity is Severity.FATAL:
                record.record_terminal(error)
                raise FatalRunError(f"{what}: {type(error).__name__}: {error}") from error
            if severity is Severity.TERMINAL:
                record.record_terminal(error)
                raise TerminalCallError(f"{what}: {type(error).__name__}: {error}") from error
            if attempt >= max_attempts:
                record.record_terminal(error)
                raise TerminalCallError(
                    f"{what}: gave up after {attempt} attempts; last was "
                    f"{type(error).__name__}: {error}"
                ) from error

            delay = backoff_delay(attempt, rng=rng)
            record.record_retry(error, delay)
            log.warning(
                "retrying after a transient failure",
                what=what,
                attempt=attempt,
                kind=type(error).__name__,
                delay_seconds=round(delay, 2),
            )
            await sleep(delay)

    # Unreachable: the loop either returns or raises.
    raise TerminalCallError(f"{what}: exhausted retries") from last  # pragma: no cover


class Deadline:
    """A wall-clock budget for a whole run.

    Separate from the money ceiling and just as necessary. A run that is still going after
    six hours has almost certainly hit something the retry logic cannot see, and the honest
    response is to stop with the results already captured rather than keep paying.
    """

    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._limit = seconds
        self._clock = clock
        self._started = clock()

    @property
    def elapsed(self) -> float:
        return self._clock() - self._started

    @property
    def remaining(self) -> float:
        return max(0.0, self._limit - self.elapsed)

    @property
    def expired(self) -> bool:
        return self.remaining <= 0

    def check(self) -> None:
        if self.expired:
            raise FatalRunError(
                f"run deadline of {self._limit:.0f}s reached after {self.elapsed:.0f}s; "
                "stopping with results captured so far"
            )


__all__ = [
    "BASE_DELAY_SECONDS",
    "MAX_ATTEMPTS",
    "MAX_DELAY_SECONDS",
    "REQUEST_TIMEOUT_SECONDS",
    "Deadline",
    "FatalRunError",
    "RetryLog",
    "Severity",
    "TerminalCallError",
    "backoff_delay",
    "classify",
    "with_retry",
]
