"""Deterministic fault injection for durable execution (AS-023).

The durability claims this project makes — a workflow resumes after its worker dies, a
retried activity produces one logical effect, a policy denial is not retried into a storm
— are only claims until something breaks on purpose and they still hold. This module
breaks things on purpose.

**Faults are scheduled, never random.** A fault fires on named attempt ordinals of a named
activity, so a run reproduces exactly and the same subset is safe in CI. Randomised chaos
finds problems too, but it cannot be a gate: a suite that fails one run in twenty gets
disabled, and the guarantee goes with it.

**The ordinal comes from Temporal, not from a counter here.** ``activity.info().attempt``
is durable and survives the worker process; a local counter resets exactly when the worker
is killed, which is the scenario under test. A harness that mis-numbers attempts precisely
during a crash would report recovery it never observed.

**Injection is an interceptor, so no production code carries a test hook.** The activities
have no idea this exists. That matters beyond tidiness: a fault switch reachable from
production code is a fault switch an attacker can look for.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import enum
import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Final

from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.worker import ActivityInboundInterceptor, ExecuteActivityInput, Interceptor

from agentsec.log import get_logger

log = get_logger("agentsec.faults")

ANY_ACTIVITY: Final = "*"
"""Target every activity. Useful for timeout sweeps; too blunt for anything else."""


class FaultKind(enum.StrEnum):
    """What goes wrong.

    Each maps to a failure the system genuinely has to survive, not to an abstract
    category. ``NON_RETRYABLE`` is the odd one out: it is not a fault to recover from but
    a decision to respect, and the harness induces it to prove the retry policy tells the
    difference.
    """

    TRANSIENT_ERROR = "transient_error"
    """A backend that failed and will work on retry: a 500, a dropped connection."""

    NON_RETRYABLE = "non_retryable"
    """A refusal. Retrying one turns a single denial into a stream of identical denials,
    inflating the attempt count and telling us nothing new."""

    TIMEOUT = "timeout"
    """The activity hangs past its start-to-close timeout. Distinct from an error: the
    work may well have happened, which is what makes it dangerous."""

    MALFORMED_RESULT = "malformed_result"
    """A backend returns something structurally wrong. Everything from a backend is
    untrusted, and this is where that stops being a slogan."""

    DUPLICATE_EXECUTION = "duplicate_execution"
    """The activity body runs twice for one logical operation - a duplicated delivery, or
    a retry whose first response was merely lost. The execution ledger (AS-022) is what is
    actually under test here."""


@dataclass(frozen=True, slots=True)
class Fault:
    """One scheduled failure."""

    activity: str
    kind: FaultKind
    attempts: tuple[int, ...] = (1,)
    """Which attempt ordinals fail, 1-based. ``(1, 2)`` means the third attempt succeeds,
    which is how "retryable errors retry" is stated as a fact rather than a hope."""

    detail: str = ""
    hang_seconds: float = 30.0
    """Only meaningful for TIMEOUT. Must exceed the activity's start-to-close timeout."""

    def applies_to(self, name: str, attempt: int) -> bool:
        return (self.activity in (name, ANY_ACTIVITY)) and attempt in self.attempts


@dataclass(frozen=True, slots=True)
class InducedFailure:
    """A fault that actually fired."""

    activity: str
    attempt: int
    kind: FaultKind
    detail: str
    at: str


@dataclass(frozen=True, slots=True)
class Completion:
    """An activity that finished, and how many attempts it took."""

    activity: str
    attempts: int
    recovered: bool
    """True when it took more than one attempt, i.e. the system recovered from something."""


@dataclass
class RecoveryReport:
    """What was broken and what happened next.

    Pairs induced failures with outcomes, which is the acceptance criterion for AS-023 and
    also the only honest way to report this. "The suite passed" says nothing about whether
    any fault fired; a run where the injector silently matched nothing looks identical.
    :meth:`assert_fired` exists so a test can refuse that outcome.
    """

    induced: list[InducedFailure] = field(default_factory=list)
    completions: list[Completion] = field(default_factory=list)

    def failures_for(self, name: str) -> list[InducedFailure]:
        return [f for f in self.induced if f.activity == name]

    def attempts_for(self, name: str) -> int:
        return max((c.attempts for c in self.completions if c.activity == name), default=0)

    def assert_fired(self, expected: int | None = None) -> None:
        """Refuse a green result produced by injecting nothing.

        A fault plan that matches no activity - a renamed activity, a typo in the target -
        makes every durability test pass by testing an unbroken system.
        """
        if not self.induced:
            raise AssertionError("no faults were injected; the plan matched nothing")
        if expected is not None and len(self.induced) != expected:
            raise AssertionError(
                f"expected {expected} induced failures, got {len(self.induced)}: "
                f"{[f.activity for f in self.induced]}"
            )

    def summary(self) -> dict[str, Any]:
        return {
            "induced_failures": len(self.induced),
            "by_kind": {
                kind.value: sum(1 for f in self.induced if f.kind is kind) for kind in FaultKind
            },
            "recovered_activities": sorted({c.activity for c in self.completions if c.recovered}),
            "max_attempts": {
                name: self.attempts_for(name)
                for name in sorted({c.activity for c in self.completions})
            },
        }

    def to_json(self) -> str:
        return json.dumps(
            {
                "summary": self.summary(),
                # asdict, not vars: these are slotted dataclasses and have no __dict__.
                "induced": [asdict(f) for f in self.induced],
                "completions": [asdict(c) for c in self.completions],
            },
            indent=2,
            sort_keys=True,
        )


class MalformedResultError(ApplicationError):
    """A backend returned something structurally wrong."""


class TransientBackendError(ApplicationError):
    """A failure that a retry is expected to clear."""


class FaultInjector:
    """Decides which fault, if any, applies to an attempt, and records what fired."""

    def __init__(self, faults: Iterable[Fault] = ()) -> None:
        self._faults = tuple(faults)
        self.report = RecoveryReport()

    @property
    def faults(self) -> tuple[Fault, ...]:
        return self._faults

    def select(self, name: str, attempt: int) -> Fault | None:
        """First matching fault wins, so an activity-specific plan beats a wildcard."""
        specific = [f for f in self._faults if f.activity == name and f.applies_to(name, attempt)]
        if specific:
            return specific[0]
        return next((f for f in self._faults if f.applies_to(name, attempt)), None)

    def record_injection(self, fault: Fault, name: str, attempt: int) -> None:
        self.report.induced.append(
            InducedFailure(
                activity=name,
                attempt=attempt,
                kind=fault.kind,
                detail=fault.detail or fault.kind.value,
                at=dt.datetime.now(dt.UTC).isoformat(),
            )
        )
        log.warning("fault injected", activity=name, attempt=attempt, kind=fault.kind.value)

    def record_completion(self, name: str, attempt: int) -> None:
        self.report.completions.append(
            Completion(activity=name, attempts=attempt, recovered=attempt > 1)
        )


class _FaultyActivity(ActivityInboundInterceptor):
    def __init__(self, next: ActivityInboundInterceptor, injector: FaultInjector) -> None:  # noqa: A002
        super().__init__(next)
        self._injector = injector

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:  # noqa: A002
        info = activity.info()
        name, attempt = info.activity_type, info.attempt
        fault = self._injector.select(name, attempt)

        if fault is None:
            result = await self.next.execute_activity(input)
            self._injector.record_completion(name, attempt)
            return result

        self._injector.record_injection(fault, name, attempt)

        if fault.kind is FaultKind.TRANSIENT_ERROR:
            raise TransientBackendError(f"induced transient failure in {name}", type="Transient")

        if fault.kind is FaultKind.NON_RETRYABLE:
            # Typed to match the workflow's non-retryable list, and deliberately *not*
            # flagged non_retryable on the error itself. Setting that flag would stop the
            # retry regardless of how the workflow is configured, so the test would pass
            # even if someone emptied NON_RETRYABLE. Leaving it off means the workflow's
            # own retry policy is the only thing that can hold, which is what is under test.
            raise ApplicationError(f"induced policy denial in {name}", type="PolicyDenied")

        if fault.kind is FaultKind.TIMEOUT:
            await asyncio.sleep(fault.hang_seconds)
            return await self.next.execute_activity(input)

        if fault.kind is FaultKind.MALFORMED_RESULT:
            raise MalformedResultError(
                f"induced malformed result from {name}", type="MalformedResult"
            )

        # DUPLICATE_EXECUTION: run the body twice for one logical operation. Nothing here
        # prevents the second effect - the execution ledger does, or the test fails.
        first = await self.next.execute_activity(input)
        await self.next.execute_activity(input)
        self._injector.record_completion(name, attempt)
        return first


class FaultInterceptor(Interceptor):
    """Worker interceptor that applies a fault plan to activity executions.

    Passed to ``Worker(interceptors=[...])``. Production workers are constructed without
    it, so the injection path does not exist outside a test process.
    """

    def __init__(self, injector: FaultInjector) -> None:
        self.injector = injector

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:  # noqa: A002
        return _FaultyActivity(next, self.injector)


def plan(*faults: Fault) -> FaultInjector:
    """Build an injector from a fault plan."""
    return FaultInjector(faults)


def transient(name: str, *, attempts: Sequence[int] = (1,)) -> Fault:
    return Fault(activity=name, kind=FaultKind.TRANSIENT_ERROR, attempts=tuple(attempts))


def denial(name: str, *, attempts: Sequence[int] = (1, 2, 3, 4, 5)) -> Fault:
    """A refusal, scheduled across every attempt the retry policy could make.

    Scheduling it on attempt 1 alone would make "a denial is not retried" untestable: the
    assertion counts injections, and with only attempt 1 armed the count is 1 whether the
    policy respected the non-retryable type or retried four more times into an activity
    the fault no longer targets.
    """
    return Fault(activity=name, kind=FaultKind.NON_RETRYABLE, attempts=tuple(attempts))


def duplicate(name: str) -> Fault:
    return Fault(activity=name, kind=FaultKind.DUPLICATE_EXECUTION, attempts=(1,))


def malformed(name: str, *, attempts: Sequence[int] = (1,)) -> Fault:
    return Fault(activity=name, kind=FaultKind.MALFORMED_RESULT, attempts=tuple(attempts))


def hang(name: str, *, seconds: float = 30.0, attempts: Sequence[int] = (1,)) -> Fault:
    return Fault(
        activity=name,
        kind=FaultKind.TIMEOUT,
        attempts=tuple(attempts),
        hang_seconds=seconds,
    )


__all__ = [
    "ANY_ACTIVITY",
    "Completion",
    "Fault",
    "FaultInjector",
    "FaultInterceptor",
    "FaultKind",
    "InducedFailure",
    "MalformedResultError",
    "RecoveryReport",
    "TransientBackendError",
    "denial",
    "duplicate",
    "hang",
    "malformed",
    "plan",
    "transient",
]
