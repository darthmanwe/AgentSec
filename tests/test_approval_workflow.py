"""Durable approval gate tests (AS-021).

These need the real Temporal server. A mock would happily let a workflow "resume" without
ever replaying its history, and replay is the whole point: the acceptance criterion is that
an approval survives a worker restart, which is only meaningful against an engine that
actually reconstructs workflow state from an event log.

    docker compose up -d
    uv run pytest -m integration

The test that matters most is ``test_a_nudge_alone_approves_nothing``. Every other test
here checks that the gate works; that one checks it cannot be walked around.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from temporalio.client import Client, WorkflowHandle, WorkflowUpdateFailedError
from temporalio.worker import Worker

from agentsec.authz.approvals import ApprovalService
from agentsec.authz.models import Principal, PrincipalKind
from agentsec.db.base import Base
from agentsec.db.models import Approval, ApprovalState, Run, RunStatus
from agentsec.workflows.activities import ActivityContext
from agentsec.workflows.security_review import SecurityReviewWorkflow
from agentsec.workflows.shared import (
    ApprovalNudge,
    ContextCollection,
    PlannedAction,
    ReviewRequest,
    ReviewResult,
    ReviewState,
)

pytestmark = pytest.mark.integration

TEMPORAL_ADDRESS = "localhost:7233"
NAMESPACE = "agentsec"
OPERATOR = Principal(id="kutlu", kind=PrincipalKind.OPERATOR)

#: A stand-in for a real canonical digest. AS-007 produces these from an action; here the
#: only property that matters is that the same string reaches the approval and the nudge.
DIGEST = "d" * 64


def temporal_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 7233), timeout=2):
            return True
    except OSError:
        return False


requires_temporal = pytest.mark.skipif(
    not temporal_reachable(), reason="Temporal not reachable (docker compose up -d)"
)


@dataclass
class GatedPlanner:
    """A planner that proposes exactly one action needing human approval.

    Stands in for AS-026 at the seam the ``ActionPlanner`` protocol defines. The approval
    machinery has to be driven by *something* proposing a mutating action, and using the
    injection point rather than a monkeypatch means these tests exercise the same wiring
    the real planner will use.
    """

    digest: str = DIGEST
    actions: list[PlannedAction] = field(default_factory=list)

    async def plan(self, collection: ContextCollection) -> list[PlannedAction]:
        return self.actions or [
            PlannedAction(
                action_id="act-1",
                action_digest=self.digest,
                tool="fake_jira",
                resource="jira://PROJ",
                summary="open an issue for the SQL injection finding",
                requires_approval=True,
            )
        ]


@dataclass
class Environment:
    client: Client
    context: ActivityContext
    queue: str
    sessions: async_sessionmaker[AsyncSession]


@pytest_asyncio.fixture
async def environment(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Environment]:
    """A client, file-backed SQLite, and a task queue unique to this test.

    File-backed rather than in-memory because the worker is restarted in one of these
    tests and a new engine must see the same rows. Per-test queue so a worker left over
    from an earlier run cannot pick up this test's workflow.
    """
    path = tmp_path_factory.mktemp("approval") / "agentsec.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    client = await Client.connect(TEMPORAL_ADDRESS, namespace=NAMESPACE)
    yield Environment(
        client=client,
        context=ActivityContext(session_factory=sessions, planner=GatedPlanner()),
        queue=f"test-{uuid.uuid4().hex[:8]}",
        sessions=sessions,
    )
    await engine.dispose()


def build(environment: Environment) -> Worker:
    context = environment.context
    return Worker(
        environment.client,
        task_queue=environment.queue,
        workflows=[SecurityReviewWorkflow],
        activities=[
            context.create_run,
            context.record_transition,
            context.collect_context,
            context.plan_actions,
            context.open_approval,
            context.resolve_approval,
            context.expire_approval,
        ],
    )


def request(run_id: str, *, ttl: int = 120, poll: float = 1.0) -> ReviewRequest:
    return ReviewRequest(
        run_id=run_id,
        principal="planner",
        task="review repo-a for injection risks",
        repository="fixture://repo-a",
        approval_ttl_seconds=ttl,
        approval_poll_seconds=poll,
    )


#: How long a run may take to reach its approval before the test gives up. Generous,
#: because a cold worker's first task poll dominates it.
PENDING_TIMEOUT = 20.0


async def wait_for_pending(
    handle: WorkflowHandle[SecurityReviewWorkflow, ReviewResult],
) -> str:
    """Block until the run is parked on an approval, and return its id."""
    async with asyncio.timeout(PENDING_TIMEOUT):
        while True:
            pending = await handle.query(SecurityReviewWorkflow.pending_approval)
            if pending:
                return str(pending)
            await asyncio.sleep(0.1)


async def decide(environment: Environment, approval_id: str, *, approved: bool) -> None:
    """Record a decision the way the CLI does: through the authenticated service."""
    async with environment.sessions() as session:
        await ApprovalService(session).decide(approval_id, approver=OPERATOR, approved=approved)
        await session.commit()


# ------------------------------------------------------------------ the gate works


@requires_temporal
async def test_an_approved_action_resumes_the_run(environment: Environment) -> None:
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)
        assert await handle.query(SecurityReviewWorkflow.current_state) == "WAITING_APPROVAL"

        await decide(environment, approval_id, approved=True)
        await handle.execute_update(
            "approval_decided", ApprovalNudge(approval_id=approval_id, action_digest=DIGEST)
        )
        result = await handle.result()

    assert result.state is ReviewState.COMPLETED
    assert result.metadata["denied_actions"] == []
    assert result.executed_actions == 0, "AS-021 gates the action; AS-028 executes it"


@requires_temporal
async def test_a_denied_action_completes_the_run_without_executing(
    environment: Environment,
) -> None:
    """A denial is a correct outcome, not a failure.

    The operator looked and said no - the control worked exactly as designed. Failing the
    run would turn every successful refusal into an incident, which is how a
    human-in-the-loop gate gets switched off.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)
        await decide(environment, approval_id, approved=False)
        await handle.execute_update(
            "approval_decided", ApprovalNudge(approval_id=approval_id, action_digest=DIGEST)
        )
        result = await handle.result()

    assert result.state is ReviewState.COMPLETED
    assert result.metadata["denied_actions"] == ["act-1"]
    assert result.executed_actions == 0


@requires_temporal
async def test_a_lost_notification_is_recovered_by_polling(environment: Environment) -> None:
    """No nudge is ever sent here. The decision is recorded and nothing tells the run.

    This is the failure mode the poll interval exists for: a dropped signal, a CLI that
    crashed after committing, a Temporal blip. It must cost latency, not correctness.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)
        await decide(environment, approval_id, approved=True)
        async with asyncio.timeout(30):
            result = await handle.result()

    assert result.state is ReviewState.COMPLETED


# ------------------------------------------------------------------ it cannot be bypassed


@requires_temporal
async def test_a_nudge_alone_approves_nothing(environment: Environment) -> None:
    """The security property of this whole design.

    The update handler is a wake-up, not an authority. Anyone who can reach the Temporal
    namespace can call it; the workflow re-reads the decision from the database, where
    operator authentication and decision terminality live (AS-010). So a nudge sent while
    the approval is still PENDING wakes the run and leaves it exactly where it was.

    Sending the *correct* approval id and the *correct* digest matters here: this is not
    testing that malformed input is rejected, it is testing that perfectly well-formed
    input still grants nothing.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)

        for _ in range(3):
            await handle.execute_update(
                "approval_decided", ApprovalNudge(approval_id=approval_id, action_digest=DIGEST)
            )

        assert await handle.query(SecurityReviewWorkflow.current_state) == "WAITING_APPROVAL"
        async with environment.sessions() as session:
            approval = await session.get(Approval, approval_id)
            assert approval is not None
            assert approval.state is ApprovalState.PENDING
            assert approval.approver_principal is None

        # And it still works once an authenticated operator actually decides.
        await decide(environment, approval_id, approved=True)
        async with asyncio.timeout(30):
            result = await handle.result()

    assert result.state is ReviewState.COMPLETED


@requires_temporal
async def test_a_nudge_for_a_different_approval_is_rejected(environment: Environment) -> None:
    """Rejected by the update validator, so it never enters workflow history at all."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)

        with pytest.raises(WorkflowUpdateFailedError):
            await handle.execute_update(
                "approval_decided",
                ApprovalNudge(approval_id="ap-somebody-elses", action_digest=DIGEST),
            )

        assert await handle.query(SecurityReviewWorkflow.current_state) == "WAITING_APPROVAL"
        await decide(environment, approval_id, approved=True)
        async with asyncio.timeout(30):
            await handle.result()


@requires_temporal
async def test_a_nudge_with_the_wrong_digest_is_rejected(environment: Environment) -> None:
    """The digest is what an approval binds to (AS-007). A decision recorded against a
    different action must not unblock this one, even with the right approval id."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)

        with pytest.raises(WorkflowUpdateFailedError):
            await handle.execute_update(
                "approval_decided",
                ApprovalNudge(approval_id=approval_id, action_digest="e" * 64),
            )

        assert await handle.query(SecurityReviewWorkflow.current_state) == "WAITING_APPROVAL"
        await decide(environment, approval_id, approved=True)
        async with asyncio.timeout(30):
            await handle.result()


# ------------------------------------------------------------------ durability


@requires_temporal
async def test_the_wait_survives_a_worker_restart(environment: Environment) -> None:
    """The acceptance criterion, and the reason any of this runs on Temporal.

    The worker is stopped while the run is parked on an approval, the decision is recorded
    with nothing running, and a *new* worker process picks the run up from history. If the
    wait lived in process memory rather than in the event log, the run would be lost here.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)

    # No worker is running now. The approval is decided against the database alone.
    await decide(environment, approval_id, approved=True)

    async with build(environment), asyncio.timeout(45):
        result = await handle.result()

    assert result.state is ReviewState.COMPLETED
    async with environment.sessions() as session:
        run = await session.get(Run, run_id)
        assert run is not None
        assert run.status is RunStatus.COMPLETED


@requires_temporal
async def test_an_expired_approval_ends_the_run_as_denied_expired(
    environment: Environment,
) -> None:
    """A bounded wait, and a terminal state that names what happened.

    Nobody decided. That is different from a denial (an operator looked and said no) and
    different from a failure (something broke), and an operator triaging a queue needs to
    tell them apart. Collapsing this into FAILED would hide an unattended queue behind
    what looks like a bug.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment), asyncio.timeout(60):
        result = await environment.client.execute_workflow(
            SecurityReviewWorkflow.run,
            request(run_id, ttl=3, poll=1.0),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )

    assert result.state is ReviewState.DENIED_EXPIRED
    assert result.executed_actions == 0

    async with environment.sessions() as session:
        run = await session.get(Run, run_id)
        assert run is not None
        assert run.status is RunStatus.DENIED_EXPIRED
        assert run.finished_at is not None, "a terminal run must record when it ended"


@requires_temporal
async def test_the_approval_path_replays_without_non_determinism(
    environment: Environment,
) -> None:
    """The determinism boundary, checked against a history that includes a durable wait.

    Timers, updates and conditional waits are where non-determinism usually enters. This
    replays a completed approval history through the workflow code and fails if the code
    would take a different branch the second time.
    """
    from temporalio.worker import Replayer

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    async with build(environment):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        approval_id = await wait_for_pending(handle)
        await decide(environment, approval_id, approved=True)
        await handle.execute_update(
            "approval_decided", ApprovalNudge(approval_id=approval_id, action_digest=DIGEST)
        )
        await handle.result()

    history = await handle.fetch_history()
    await Replayer(workflows=[SecurityReviewWorkflow]).replay_workflow(history)
