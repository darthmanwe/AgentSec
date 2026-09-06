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
import contextlib
from collections.abc import Callable
from datetime import datetime, timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    # Imported outside the sandbox because they are pure data definitions. Anything with
    # side effects at import time must NOT be added here.
    from agentsec.workflows.activities import ActivityContext
    from agentsec.workflows.shared import (
        ApprovalHandle,
        ApprovalNudge,
        ApprovalOutcome,
        ApprovalRequest,
        ContextCollection,
        PlannedAction,
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
        self._pending: ApprovalHandle | None = None
        self._nudges = 0

    @workflow.query(name="state")
    def current_state(self) -> str:
        """Queryable so the UI and tests can observe progress without touching the
        database. Queries must not mutate; this only reads."""
        return self._state.value

    @workflow.query(name="detail")
    def current_detail(self) -> str | None:
        return self._detail

    @workflow.query(name="pending_approval")
    def pending_approval(self) -> str | None:
        """Which approval this run is blocked on, if any. Lets the CLI and the AS-042 UI
        show a waiting run without joining Temporal state against the database."""
        return self._pending.approval_id if self._pending else None

    # ------------------------------------------------------------------ approval

    @workflow.update(name="approval_decided")
    def approval_decided(self, nudge: ApprovalNudge) -> str:
        """Wake this workflow because a decision was recorded.

        **This grants nothing.** It increments a counter; the workflow then re-reads the
        decision from the database through an activity, and the database is where operator
        authentication and decision terminality are enforced (AS-010). Anyone who can reach
        the Temporal namespace can call this, and calling it approves nothing at all.

        Deliberately synchronous: the handler must not block, because a handler still
        running when the workflow completes produces a warning and, worse, an update that
        appears to have been accepted while its effect was discarded.
        """
        self._nudges += 1
        workflow.logger.info(
            "approval nudge accepted",
            extra={"approval_id": nudge.approval_id, "nudges": self._nudges},
        )
        return self._state.value

    @approval_decided.validator
    def _validate_nudge(self, nudge: ApprovalNudge) -> None:
        """Reject a nudge aimed at something this run is not waiting on.

        **Pure by requirement.** Validators run on every replay and must not perform I/O;
        one that queried the database would make replay depend on the state of the world
        at replay time, which is the exact failure the determinism boundary exists to
        prevent. Everything checked here is already in workflow memory.

        A rejected update never enters workflow history, so a wrong-digest decision leaves
        no trace on the run and cannot unblock it.
        """
        if self._pending is None:
            raise ValueError(f"run {self._run_id} is not waiting on an approval")
        if nudge.approval_id != self._pending.approval_id:
            raise ValueError(
                f"run {self._run_id} is waiting on approval {self._pending.approval_id}, "
                f"not {nudge.approval_id}"
            )
        if nudge.action_digest != self._pending.action_digest:
            # The digest is what the approval binds to (AS-007). A mismatch means the
            # decision was made against a different action than the one being waited on.
            raise ValueError("approval digest does not match the pending action")

    @workflow.signal(name="approval_nudge")
    def approval_nudge(self, nudge: ApprovalNudge) -> None:
        """Fire-and-forget variant for callers that do not want to block.

        Signals cannot be validated, so this accepts anything and simply wakes the wait
        loop. That is safe precisely because the nudge carries no authority: an unmatched
        signal costs one database read and changes no decision.
        """
        self._nudges += 1

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

        # AS-028 wires policy evaluation and execution in here. The approval gate below
        # is real; what surrounds it is still the skeleton.
        await self._transition(ReviewState.AUTHORIZING)

        denied: list[str] = []
        for action in plan:
            if not action.requires_approval:
                continue
            outcome = await self._await_approval(request, action)

            if outcome.expired:
                # Terminal for the run, not just the action. A denial means an operator
                # looked and said no - the system worked, and the remaining actions are
                # still worth attempting. An expiry means nobody looked at all, and
                # continuing to act on a plan built from hours-old evidence is exactly
                # what a human-in-the-loop control is supposed to prevent.
                await self._transition(
                    ReviewState.DENIED_EXPIRED,
                    f"approval {outcome.approval_id} expired without a decision",
                )
                return ReviewResult(
                    run_id=request.run_id,
                    state=ReviewState.DENIED_EXPIRED,
                    attempted_actions=len(plan),
                    executed_actions=0,
                    detail=f"approval {outcome.approval_id} expired",
                    metadata=self._metadata(request, collection, denied),
                )

            if not outcome.permitted:
                denied.append(action.action_id)

        await self._transition(ReviewState.VALIDATING)
        await self._transition(ReviewState.REPORTING)
        await self._transition(ReviewState.COMPLETED)

        return ReviewResult(
            run_id=request.run_id,
            state=ReviewState.COMPLETED,
            attempted_actions=len(plan),
            executed_actions=0,
            metadata=self._metadata(request, collection, denied),
        )

    def _metadata(
        self, request: ReviewRequest, collection: ContextCollection, denied: list[str]
    ) -> dict[str, object]:
        return {
            "untrusted_context_items": collection.untrusted_count,
            "control_profile": request.control_profile,
            "planner_kind": request.planner_kind,
            "denied_actions": list(denied),
        }

    async def _await_approval(
        self, request: ReviewRequest, action: PlannedAction
    ) -> ApprovalOutcome:
        """Block durably until an operator decides, or until the approval lapses.

        Two properties matter more than the mechanics.

        **The wait is bounded.** ``expires_at`` comes back from the database rather than
        being re-derived here, so the workflow and the approval record agree on the exact
        instant a decision stops counting. Without a deadline a run parks forever holding
        a plan nobody will ever act on.

        **Every wake re-reads the database.** The update handler only bumps a counter. If
        the notification is lost the poll interval picks the decision up anyway, so a
        dropped signal costs latency rather than correctness - and, in the other
        direction, a *forged* signal buys nothing, because the answer never comes from the
        message.
        """
        handle: ApprovalHandle = await workflow.execute_activity_method(
            ActivityContext.open_approval,
            ApprovalRequest(
                run_id=request.run_id,
                action_digest=action.action_digest,
                summary=action.summary,
                ttl_seconds=request.approval_ttl_seconds,
            ),
            start_to_close_timeout=QUICK_TIMEOUT,
            retry_policy=DEFAULT_RETRY,
        )
        self._pending = handle
        await self._transition(
            ReviewState.WAITING_APPROVAL,
            f"awaiting approval {handle.approval_id} for {action.action_id}",
        )

        deadline = datetime.fromisoformat(handle.expires_at)
        try:
            while True:
                remaining = (deadline - workflow.now()).total_seconds()
                if remaining <= 0:
                    break

                # A timeout here is not an error: the poll interval elapsed, so fall
                # through and ask the database anyway. That is what makes a lost
                # notification survivable rather than fatal.
                with contextlib.suppress(TimeoutError):
                    await workflow.wait_condition(
                        self._nudged_since(self._nudges),
                        timeout=timedelta(seconds=min(remaining, request.approval_poll_seconds)),
                    )

                outcome: ApprovalOutcome = await workflow.execute_activity_method(
                    ActivityContext.resolve_approval,
                    handle,
                    start_to_close_timeout=QUICK_TIMEOUT,
                    retry_policy=DEFAULT_RETRY,
                )
                if outcome.decided:
                    await self._transition(
                        ReviewState.AUTHORIZING,
                        f"approval {handle.approval_id}: {outcome.reason}",
                    )
                    return outcome

            expired: ApprovalOutcome = await workflow.execute_activity_method(
                ActivityContext.expire_approval,
                handle,
                start_to_close_timeout=QUICK_TIMEOUT,
                retry_policy=DEFAULT_RETRY,
            )
            return expired
        finally:
            # Cleared on every path, including cancellation. A stale handle would let the
            # validator accept a nudge for an approval this run has stopped waiting on.
            self._pending = None

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

    def _nudged_since(self, seen: int) -> Callable[[], bool]:
        """A wait condition bound to the nudge count observed before waiting.

        Built by a factory rather than written inline so the count is captured by value.
        A lambda closing over a loop variable reads whatever that variable holds when the
        condition is finally evaluated, which here would mean comparing the counter
        against itself and waiting through a nudge that had already arrived.
        """
        return lambda: self._nudges > seen


def _describe(error: BaseException) -> str:
    """A short, stable description for the persisted failure detail."""
    cause = error.__cause__ or error
    return f"{type(cause).__name__}: {cause}"[:500]


__all__ = ["DEFAULT_RETRY", "NON_RETRYABLE", "SecurityReviewWorkflow"]
