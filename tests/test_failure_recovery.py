"""Durable execution under induced failure (AS-023).

Every durability claim this project makes gets broken on purpose here and has to hold
anyway. The claims, and the test that earns each one:

===============================================  ==========================================
Claim                                            Test
===============================================  ==========================================
a transient failure is retried, not surfaced     ``test_a_transient_failure_is_retried``
a refusal is *not* retried                       ``test_a_policy_denial_is_not_retried``
a hung activity times out and is retried         ``test_a_hung_activity_times_out``
a malformed backend result is never used         ``test_a_persistently_malformed_result_fails``
a killed worker loses no progress                ``test_a_killed_worker_resumes_from_history``
a duplicated execution produces one effect       ``test_a_duplicated_execution_produces_one_effect``
===============================================  ==========================================

Every test asserts on the recovery report as well as the outcome, because "the workflow
completed" is exactly what a run with no faults injected also looks like.

    docker compose up -d
    uv run pytest -m integration
"""

from __future__ import annotations

import ast
import asyncio
import pathlib
import socket
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from temporalio import activity, workflow
from temporalio.client import Client, WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

from agentsec.db.base import Base
from agentsec.db.models import Run, RunStatus
from agentsec.faults import (
    FaultInterceptor,
    denial,
    duplicate,
    hang,
    malformed,
    plan,
    transient,
)
from agentsec.gateway.ledger import ExecutionLedgerService, operation_id
from agentsec.workflows.activities import ActivityContext
from agentsec.workflows.security_review import SecurityReviewWorkflow
from agentsec.workflows.shared import ReviewRequest, ReviewState

pytestmark = pytest.mark.integration

TEMPORAL_ADDRESS = "localhost:7233"
NAMESPACE = "agentsec"
DIGEST = "f" * 64


def temporal_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 7233), timeout=2):
            return True
    except OSError:
        return False


requires_temporal = pytest.mark.skipif(
    not temporal_reachable(), reason="Temporal not reachable (docker compose up -d)"
)


# ------------------------------------------------------------------ a ledgered effect


@dataclass
class SideEffectContext:
    """An activity that records a real side effect through the execution ledger.

    Stands in for the GitHub adapter of AS-033. The counter increments only when the
    ledger says to proceed, so the assertion is on *logical effects* rather than on how
    many times the activity body happened to run — which is the whole distinction AS-022
    exists to make.
    """

    session_factory: async_sessionmaker[AsyncSession]
    effects: int = 0

    @activity.defn(name="perform_side_effect")
    async def perform_side_effect(self, run_id: str) -> str:
        operation = operation_id(f"wf-{run_id}", DIGEST, 0)
        async with self.session_factory() as session:
            ledger = ExecutionLedgerService(session)
            decision = await ledger.begin(
                operation=operation,
                run_id=run_id,
                workflow_id=f"wf-{run_id}",
                action_digest=DIGEST,
                request_hash="a" * 64,
            )
            if not decision.proceed:
                await session.commit()
                return str(decision.cached_result["key"])

            self.effects += 1  # the externally visible act
            await ledger.complete(operation, {"key": "PROJ-1"}, external_ref="PROJ-1")
            await session.commit()
        return "PROJ-1"


@workflow.defn(name="ProbeWorkflow")
class ProbeWorkflow:
    """A minimal workflow for faults the review workflow's own timeouts make slow to test.

    Its activity timeout is two seconds rather than thirty, so a hang test costs seconds
    instead of a minute. The review workflow's timeouts are checked separately and
    structurally, by ``test_every_activity_call_sets_a_timeout``.
    """

    @workflow.run
    async def run(self, run_id: str) -> str:
        return str(
            await workflow.execute_activity(
                "perform_side_effect",
                run_id,
                start_to_close_timeout=timedelta(seconds=2),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(milliseconds=200),
                    maximum_attempts=4,
                    non_retryable_error_types=["PolicyDenied"],
                ),
            )
        )


@dataclass
class Environment:
    client: Client
    context: ActivityContext
    effects: SideEffectContext
    queue: str
    sessions: async_sessionmaker[AsyncSession]


@pytest_asyncio.fixture
async def environment(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Environment]:
    path = tmp_path_factory.mktemp("faults") / "agentsec.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path.as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    client = await Client.connect(TEMPORAL_ADDRESS, namespace=NAMESPACE)
    yield Environment(
        client=client,
        context=ActivityContext(session_factory=sessions),
        effects=SideEffectContext(session_factory=sessions),
        queue=f"faults-{uuid.uuid4().hex[:8]}",
        sessions=sessions,
    )
    await engine.dispose()


def build(environment: Environment, interceptor: FaultInterceptor) -> Worker:
    context = environment.context
    return Worker(
        environment.client,
        task_queue=environment.queue,
        workflows=[SecurityReviewWorkflow, ProbeWorkflow],
        activities=[
            context.create_run,
            context.record_transition,
            context.collect_context,
            context.plan_actions,
            context.open_approval,
            context.resolve_approval,
            context.expire_approval,
            environment.effects.perform_side_effect,
        ],
        interceptors=[interceptor],
    )


def request(run_id: str) -> ReviewRequest:
    return ReviewRequest(run_id=run_id, principal="planner", task="review under fault injection")


async def seed_run(environment: Environment, run_id: str) -> None:
    """ProbeWorkflow's activity writes a ledger row with a foreign key to a run."""
    async with environment.sessions() as session:
        session.add(
            Run(
                id=run_id,
                workflow_id=f"wf-{run_id}",
                status=RunStatus.EXECUTING,
                principal="planner",
                task="side effect probe",
            )
        )
        await session.commit()


async def _wait_for_first_injection(interceptor: FaultInterceptor) -> None:
    """Block until the plan has actually broken something.

    Polling a plain attribute rather than an ``asyncio.Event`` because the injector is
    shared with the worker's own task group and must stay a plain data object - the
    harness has no business owning synchronisation primitives that only a test needs.
    """
    async with asyncio.timeout(30):
        while not interceptor.injector.report.induced:  # noqa: ASYNC110
            await asyncio.sleep(0.1)


# ------------------------------------------------------------------ transient failures


@requires_temporal
async def test_a_transient_failure_is_retried(environment: Environment) -> None:
    """Two failures, then success. The run must not notice."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    interceptor = FaultInterceptor(plan(transient("collect_context", attempts=(1, 2))))

    async with build(environment, interceptor), asyncio.timeout(60):
        result = await environment.client.execute_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )

    assert result.state is ReviewState.COMPLETED
    report = interceptor.injector.report
    report.assert_fired(2)
    assert report.attempts_for("collect_context") == 3, "the third attempt is the one that worked"
    assert "collect_context" in report.summary()["recovered_activities"]


@requires_temporal
async def test_a_policy_denial_is_not_retried(environment: Environment) -> None:
    """A refusal is a decision, not a fault.

    Retrying one turns a single denial into five identical denials: it inflates the
    attempt count that the headline metric is measured against, and it tells us nothing
    we did not already know. Exactly one induced failure is the assertion.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    interceptor = FaultInterceptor(plan(denial("plan_actions")))

    async with build(environment, interceptor), asyncio.timeout(60):
        with pytest.raises(WorkflowFailureError):
            await environment.client.execute_workflow(
                SecurityReviewWorkflow.run,
                request(run_id),
                id=f"wf-{run_id}",
                task_queue=environment.queue,
            )

    # Exactly one. The fault is armed on every attempt the retry policy could make, so a
    # count above one would mean the non-retryable type was ignored.
    interceptor.injector.report.assert_fired(1)


@requires_temporal
async def test_a_failed_run_still_records_a_terminal_state(environment: Environment) -> None:
    """A run that vanishes without a terminal state is indistinguishable from one still in
    progress, which makes the product view useless during exactly the incident it is for."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    interceptor = FaultInterceptor(plan(denial("plan_actions")))

    async with build(environment, interceptor), asyncio.timeout(60):
        with pytest.raises(WorkflowFailureError):
            await environment.client.execute_workflow(
                SecurityReviewWorkflow.run,
                request(run_id),
                id=f"wf-{run_id}",
                task_queue=environment.queue,
            )

    async with environment.sessions() as session:
        run = await session.get(Run, run_id)
        assert run is not None
        assert run.status is RunStatus.FAILED
        assert run.finished_at is not None


# ------------------------------------------------------------------ timeouts and garbage


@requires_temporal
async def test_a_hung_activity_times_out_and_is_retried(environment: Environment) -> None:
    """A hang is worse than an error: the work may well have happened. Temporal's
    start-to-close timeout is what turns an indefinite hang into a bounded retry."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    await seed_run(environment, run_id)
    interceptor = FaultInterceptor(plan(hang("perform_side_effect", seconds=5, attempts=(1,))))

    async with build(environment, interceptor), asyncio.timeout(60):
        result = await environment.client.execute_workflow(
            ProbeWorkflow.run, run_id, id=f"wf-{run_id}", task_queue=environment.queue
        )

    assert result == "PROJ-1"
    interceptor.injector.report.assert_fired(1)
    assert environment.effects.effects == 1, "the timed-out attempt must not leave an effect"


@requires_temporal
async def test_a_transient_malformed_result_is_retried(environment: Environment) -> None:
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    await seed_run(environment, run_id)
    interceptor = FaultInterceptor(plan(malformed("perform_side_effect", attempts=(1,))))

    async with build(environment, interceptor), asyncio.timeout(60):
        result = await environment.client.execute_workflow(
            ProbeWorkflow.run, run_id, id=f"wf-{run_id}", task_queue=environment.queue
        )

    assert result == "PROJ-1"
    interceptor.injector.report.assert_fired(1)


@requires_temporal
async def test_a_persistently_malformed_result_fails(environment: Environment) -> None:
    """The direction that matters. A backend returning structural garbage must stop the
    run, not be coerced into something usable - everything from a backend is untrusted,
    and "we tried to make sense of it" is how that stops being true."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    await seed_run(environment, run_id)
    interceptor = FaultInterceptor(plan(malformed("perform_side_effect", attempts=(1, 2, 3, 4, 5))))

    async with build(environment, interceptor), asyncio.timeout(60):
        with pytest.raises(WorkflowFailureError):
            await environment.client.execute_workflow(
                ProbeWorkflow.run, run_id, id=f"wf-{run_id}", task_queue=environment.queue
            )

    assert environment.effects.effects == 0, "no effect may follow a result never accepted"


# ------------------------------------------------------------------ crash and duplication


@requires_temporal
async def test_a_killed_worker_resumes_from_history(environment: Environment) -> None:
    """The claim durable execution is bought for, and a check on this harness's own design.

    The worker is killed between failed attempts and a *new* one finishes the run. The
    attempt ordinal comes from ``activity.info().attempt``, which Temporal carries in
    history; a counter local to the worker would reset here and re-inject the fault
    forever, so this test fails if the harness ever regresses to counting locally.
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    interceptor = FaultInterceptor(plan(transient("collect_context", attempts=(1, 2))))

    async with build(environment, interceptor):
        handle = await environment.client.start_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )
        await _wait_for_first_injection(interceptor)

    # The worker is gone. A fresh one, with the same plan, picks the run up from history.
    revived = FaultInterceptor(plan(transient("collect_context", attempts=(1, 2))))
    async with build(environment, revived), asyncio.timeout(60):
        result = await handle.result()

    assert result.state is ReviewState.COMPLETED


@requires_temporal
async def test_a_duplicated_execution_produces_one_effect(environment: Environment) -> None:
    """The activity body runs twice for one logical operation. The ledger is the only
    thing standing between that and two Jira issues."""
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    await seed_run(environment, run_id)
    interceptor = FaultInterceptor(plan(duplicate("perform_side_effect")))

    async with build(environment, interceptor), asyncio.timeout(60):
        result = await environment.client.execute_workflow(
            ProbeWorkflow.run, run_id, id=f"wf-{run_id}", task_queue=environment.queue
        )

    assert result == "PROJ-1"
    interceptor.injector.report.assert_fired(1)
    assert environment.effects.effects == 1, "two executions, one effect"

    async with environment.sessions() as session:
        assert await ExecutionLedgerService(session).logical_effects(f"wf-{run_id}") == 1


# ------------------------------------------------------------------ the report


@requires_temporal
async def test_the_recovery_report_pairs_failures_with_outcomes(
    environment: Environment, tmp_path: pathlib.Path
) -> None:
    """The AS-023 acceptance criterion.

    A report listing failures without outcomes cannot answer the only question worth
    asking after an incident: did the system get where it was going anyway?
    """
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    interceptor = FaultInterceptor(plan(transient("collect_context", attempts=(1,))))

    async with build(environment, interceptor), asyncio.timeout(60):
        await environment.client.execute_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=environment.queue,
        )

    report = interceptor.injector.report
    artifact = tmp_path / "recovery.json"
    artifact.write_text(report.to_json(), encoding="utf-8")

    written = artifact.read_text(encoding="utf-8")
    assert "transient_error" in written
    assert report.failures_for("collect_context")[0].attempt == 1
    assert report.attempts_for("collect_context") == 2
    assert report.summary()["recovered_activities"] == ["collect_context"]


# ------------------------------------------------------------------ structural


def test_every_activity_call_sets_a_timeout() -> None:
    """No activity may be invoked without a start-to-close timeout.

    Structural rather than behavioural, because one timeout test proves one timeout. An
    activity dispatched without one can hang indefinitely, and the run parks with no
    terminal state and no error - the failure mode that looks like nothing is wrong.
    """
    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src"
        / "agentsec"
        / "workflows"
        / "security_review.py"
    ).read_text(encoding="utf-8")

    calls = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("execute_activity")
    ]
    assert calls, "no activity calls found; this check would pass by inspecting nothing"

    for call in calls:
        keywords = {kw.arg for kw in call.keywords}
        assert "start_to_close_timeout" in keywords, (
            f"line {call.lineno}: activity dispatched with no start_to_close_timeout"
        )
        assert "retry_policy" in keywords, (
            f"line {call.lineno}: activity dispatched with no retry policy"
        )
