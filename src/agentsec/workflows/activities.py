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

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from temporalio import activity

from agentsec.db.models import Run, RunStatus
from agentsec.log import get_logger
from agentsec.workflows.shared import (
    ContextCollection,
    ReviewRequest,
    ReviewState,
    StateTransition,
)

log = get_logger("agentsec.workflows.activities")


@dataclass
class ActivityContext:
    """Live dependencies for the activity implementations.

    Held by the worker and bound at startup. Activities are methods on this rather than
    module-level functions with globals, so a test can construct one with an in-memory
    database instead of monkeypatching.
    """

    session_factory: async_sessionmaker[AsyncSession]

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
    async def plan_actions(self, collection: ContextCollection) -> list[str]:
        """Produce an action plan. Placeholder until AS-026/AS-028.

        Returns identifiers rather than executable anything: a plan is a proposal, and
        even the placeholder should not look like a licence to act.
        """
        log.info("planning", untrusted_context=collection.untrusted_count)
        return []


_TERMINAL = {
    ReviewState.COMPLETED,
    ReviewState.FAILED,
    ReviewState.CANCELLED,
    ReviewState.DENIED_EXPIRED,
}


__all__ = ["ActivityContext"]
