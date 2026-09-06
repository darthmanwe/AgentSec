"""Activities: everything that touches the outside world (AS-019, AS-020).

**All I/O lives here.** Database, LLM, OPA, MCP, filesystem, wall clock, randomness — if
it can return a different answer on a second call, it belongs in an activity, not in
workflow code. Workflow functions are replayed from history, and a non-deterministic one
produces a different execution the second time, which surfaces as corrupted replay under
exactly the crash-recovery demo this project is built to show off.

That rule is enforced structurally by ``tests/test_workflow_determinism.py``, which walks
the workflow module's AST rather than trusting a comment.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from temporalio import activity

from agentsec.authz.approvals import ApprovalReason, ApprovalService
from agentsec.db.models import ApprovalState, Run, RunStatus
from agentsec.log import get_logger
from agentsec.workflows.shared import (
    ApprovalHandle,
    ApprovalOutcome,
    ApprovalRequest,
    ContextCollection,
    PlannedAction,
    ReviewRequest,
    ReviewState,
    StateTransition,
)

log = get_logger("agentsec.workflows.activities")


class ActionPlanner(Protocol):
    """Supplies the action plan for a run.

    A protocol rather than a concrete import so AS-026 can drop in the LangGraph planner,
    and AS-028B the adversarial one, without workflow or activity code changing. It also
    makes the two planners interchangeable at exactly the seam the evaluation varies,
    which is what turns an ablation cell into a configuration rather than a code path.
    """

    async def plan(self, collection: ContextCollection) -> list[PlannedAction]: ...


@dataclass
class ActivityContext:
    """Live dependencies for the activity implementations.

    Held by the worker and bound at startup. Activities are methods on this rather than
    module-level functions with globals, so a test can construct one with an in-memory
    database instead of monkeypatching.
    """

    session_factory: async_sessionmaker[AsyncSession]
    planner: ActionPlanner | None = None
    """Produces the action plan. ``None`` yields an empty plan until AS-026 lands a real
    one. Injected rather than imported: the planner is the component the evaluation swaps,
    and a hard import here would make that a code change instead of a configuration."""

    # ---------------------------------------------------------------- persistence

    @activity.defn(name="create_run")
    async def create_run(self, request: ReviewRequest) -> str:
        async with self.session_factory() as session:
            session.add(
                Run(
                    id=request.run_id,
                    workflow_id=activity.info().workflow_id,
                    status=RunStatus.RECEIVED,
                    principal=request.principal,
                    task=request.task,
                    repository=request.repository,
                    control_profile=request.control_profile,
                    planner_kind=request.planner_kind,
                )
            )
            await session.commit()
        log.info("run created", run_id=request.run_id, task=request.task)
        return request.run_id

    @activity.defn(name="record_transition")
    async def record_transition(self, transition: StateTransition) -> None:
        """Persist a state change.

        Idempotent by construction: writing the same state twice is a no-op update, so a
        Temporal retry of this activity cannot corrupt the product view.
        """
        async with self.session_factory() as session:
            run = await session.get(Run, transition.run_id)
            if run is None:
                # A missing run means create_run has not committed yet, which Temporal
                # will resolve by retrying. Raising is right; inventing a row is not.
                raise RuntimeError(f"run {transition.run_id} does not exist")
            run.status = RunStatus(transition.state.value)
            if transition.state in _TERMINAL:
                run.finished_at = dt.datetime.now(dt.UTC)
            await session.commit()
        log.info(
            "run state changed",
            run_id=transition.run_id,
            state=transition.state.value,
            detail=transition.detail,
        )

    # ---------------------------------------------------------------- placeholders

    @activity.defn(name="collect_context")
    async def collect_context(self, request: ReviewRequest) -> ContextCollection:
        """Gather context for the run.

        A placeholder in AS-020, which the issue permits. AS-028 replaces the body with
        real gateway-mediated collection. The *shape* is already right: references and
        hashes, never content, so untrusted repository text never enters workflow history.
        """
        log.info("collecting context", run_id=request.run_id, repository=request.repository)
        return ContextCollection(item_ids=[], content_hashes=[], untrusted_count=0)

    @activity.defn(name="plan_actions")
    async def plan_actions(self, collection: ContextCollection) -> list[PlannedAction]:
        """Produce an action plan.

        Returns proposals, never anything executable: a plan is a request to act, and even
        the empty placeholder should not look like a licence. With no planner injected the
        plan is empty, which is the correct behaviour for a runtime whose reasoning
        component has not been wired in yet.
        """
        if self.planner is None:
            log.info("planning skipped: no planner configured")
            return []
        plan = await self.planner.plan(collection)
        log.info(
            "planned",
            actions=len(plan),
            requiring_approval=sum(1 for action in plan if action.requires_approval),
            untrusted_context=collection.untrusted_count,
        )
        return plan

    # ---------------------------------------------------------------- approval

    @activity.defn(name="open_approval")
    async def open_approval(self, request: ApprovalRequest) -> ApprovalHandle:
        """Open a pending approval and return the record the workflow will wait on."""
        async with self.session_factory() as session:
            approval = await ApprovalService(session).create(
                run_id=request.run_id,
                action_digest=request.action_digest,
                ttl_seconds=request.ttl_seconds,
                evidence_refs={"summary": request.summary},
            )
            handle = ApprovalHandle(
                approval_id=approval.id,
                action_digest=approval.action_digest,
                expires_at=_as_utc(approval.expires_at).isoformat(),
            )
            await session.commit()
        return handle

    @activity.defn(name="resolve_approval")
    async def resolve_approval(self, handle: ApprovalHandle) -> ApprovalOutcome:
        """Read the authoritative decision.

        Called on every wake, including a wake caused by an update. **The update payload
        is never trusted.** Operator authentication and decision terminality live in
        :class:`~agentsec.authz.approvals.ApprovalService`, so reaching the Temporal
        namespace lets an attacker wake a workflow and nothing more.
        """
        async with self.session_factory() as session:
            resolution = await ApprovalService(session).resolve(action_digest=handle.action_digest)
            await session.commit()

        return ApprovalOutcome(
            approval_id=resolution.approval_id or handle.approval_id,
            decided=resolution.state in _DECIDED,
            permitted=resolution.permitted,
            reason=resolution.reason.value,
            approver_principal=resolution.approver_principal,
            expired=resolution.reason is ApprovalReason.EXPIRED,
        )

    @activity.defn(name="expire_approval")
    async def expire_approval(self, handle: ApprovalHandle) -> ApprovalOutcome:
        """Mark a lapsed approval expired once the workflow stops waiting.

        The stored state has to match reality even though :meth:`resolve_approval` already
        evaluates expiry on read: the approval UI reads this table directly, and a row left
        PENDING forever reads as a decision somebody still owes.
        """
        async with self.session_factory() as session:
            expired = await ApprovalService(session).expire_lapsed()
            await session.commit()
        log.info("approval expired", approval_id=handle.approval_id, rows_expired=expired)
        return ApprovalOutcome(
            approval_id=handle.approval_id,
            decided=True,
            permitted=False,
            reason=ApprovalReason.EXPIRED.value,
            expired=True,
        )


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Attach UTC to a naive timestamp read back from storage.

    SQLite has no timezone type and hands values back naive; PostgreSQL returns them
    aware. Values are only ever written as UTC, so this restores the original meaning
    rather than guessing at one. Without it the ISO string in the handle would carry an
    unlabelled instant, and the workflow would compute its deadline against it.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


#: States an approval will never leave, so continuing to wait would be pointless.
_DECIDED = {ApprovalState.APPROVED, ApprovalState.DENIED, ApprovalState.EXPIRED}


_TERMINAL = {
    ReviewState.COMPLETED,
    ReviewState.FAILED,
    ReviewState.CANCELLED,
    ReviewState.DENIED_EXPIRED,
}


__all__ = ["ActionPlanner", "ActivityContext"]
