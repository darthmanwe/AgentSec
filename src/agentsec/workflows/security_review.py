"""SecurityReviewWorkflow: the durable outer state machine (AS-020).

**This module performs no I/O.** No database, LLM, OPA, MCP, filesystem, wall clock or
randomness. Every one of those is an activity call.

That is not stylistic. Workflow code is re-executed from history on every replay — after
a worker restart, during a deploy, when Temporal recovers a task. A workflow that read the
clock directly would take a different branch the second time, and the divergence surfaces
as a non-determinism error in the middle of the crash-recovery demo this project exists to
show off. ``tests/test_workflow_determinism.py`` walks this module's AST and fails if a
banned construct appears, so the rule is checked rather than remembered.

Where the safe equivalents live:

===========================  ==================================
Forbidden                    Use instead
===========================  ==================================
``datetime.now()``           ``workflow.now()``
``uuid.uuid4()``             ``workflow.uuid4()``
``random``                   ``workflow.random()``
``asyncio.sleep``            ``workflow.sleep``
``logging`` / ``structlog``  ``workflow.logger``
any direct I/O               ``workflow.execute_activity``
===========================  ==================================
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    # Imported outside the sandbox because they are pure data definitions. Anything with
    # side effects at import time must NOT be added here.
    from agentsec.workflows.activities import ActivityContext
    from agentsec.workflows.shared import (
        ContextCollection,
        ReviewRequest,
        ReviewResult,
        ReviewState,
        StateTransition,
    )

#: Short activities: persistence and bookkeeping.
QUICK_TIMEOUT = timedelta(seconds=30)

#: Longer activities: context collection, planning.
WORK_TIMEOUT = timedelta(minutes=5)

#: A policy denial is a decision, not a transient fault. Retrying one would turn a single
#: refusal into a stream of identical refused attempts, inflating the attempt count and
#: telling us nothing new.
NON_RETRYABLE = ["PolicyDenied", "CapabilityRejected", "ApprovalDenied"]

DEFAULT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=5,
    non_retryable_error_types=NON_RETRYABLE,
)


@workflow.defn(name="SecurityReviewWorkflow")
class SecurityReviewWorkflow:
    """Drives one security review from request to report."""

    def __init__(self) -> None:
        self._state = ReviewState.RECEIVED
        self._run_id: str = ""
        self._detail: str | None = None

    @workflow.query(name="state")
    def current_state(self) -> str:
        """Queryable so the UI and tests can observe progress without touching the
        database. Queries must not mutate; this only reads."""
        return self._state.value

    @workflow.query(name="detail")
    def current_detail(self) -> str | None:
        return self._detail

    @workflow.run
    async def run(self, request: ReviewRequest) -> ReviewResult:
        self._run_id = request.run_id
        try:
            return await self._execute(request)
        except asyncio.CancelledError:
            # Cancellation must leave a record. A run that vanishes without a terminal
            # state is indistinguishable from one that is still going.
            await self._transition(ReviewState.CANCELLED, "cancelled")
            raise
        except ActivityError as exc:
            await self._transition(ReviewState.FAILED, _describe(exc))
            raise
        except ApplicationError as exc:
            await self._transition(ReviewState.FAILED, str(exc))
            raise

    async def _execute(self, request: ReviewRequest) -> ReviewResult:
        context = ActivityContext  # bound by the worker; referenced for activity typing

        await workflow.execute_activity_method(
            context.create_run,
            request,
            start_to_close_timeout=QUICK_TIMEOUT,
            retry_policy=DEFAULT_RETRY,
        )
        await self._transition(ReviewState.PREPARING)

        await self._transition(ReviewState.COLLECTING_CONTEXT)
        collection: ContextCollection = await workflow.execute_activity_method(
            context.collect_context,
            request,
            start_to_close_timeout=WORK_TIMEOUT,
            retry_policy=DEFAULT_RETRY,
        )

        await self._transition(ReviewState.PLANNING)
        plan = await workflow.execute_activity_method(
            context.plan_actions,
            collection,
            start_to_close_timeout=WORK_TIMEOUT,
            retry_policy=DEFAULT_RETRY,
        )

        # AS-028 wires authorization, approval and execution in here. The states exist
        # now so the machine is observable end to end before the intelligence arrives.
        await self._transition(ReviewState.AUTHORIZING)
        await self._transition(ReviewState.VALIDATING)
        await self._transition(ReviewState.REPORTING)
        await self._transition(ReviewState.COMPLETED)

        return ReviewResult(
            run_id=request.run_id,
            state=ReviewState.COMPLETED,
            attempted_actions=len(plan),
            executed_actions=0,
            metadata={
                "untrusted_context_items": collection.untrusted_count,
                "control_profile": request.control_profile,
                "planner_kind": request.planner_kind,
            },
        )

    async def _transition(self, state: ReviewState, detail: str | None = None) -> None:
        """Move to a new state and persist it.

        Persistence goes through an activity because it is I/O. The in-memory field is
        updated first so a query reflects the intended state even if the activity is
        still retrying.
        """
        self._state = state
        self._detail = detail
        workflow.logger.info("state transition", extra={"state": state.value, "detail": detail})
        await workflow.execute_activity_method(
            ActivityContext.record_transition,
            StateTransition(run_id=self._run_id, state=state, detail=detail),
            start_to_close_timeout=QUICK_TIMEOUT,
            retry_policy=DEFAULT_RETRY,
        )


def _describe(error: BaseException) -> str:
    """A short, stable description for the persisted failure detail."""
    cause = error.__cause__ or error
    return f"{type(cause).__name__}: {cause}"[:500]


__all__ = ["DEFAULT_RETRY", "NON_RETRYABLE", "SecurityReviewWorkflow"]
