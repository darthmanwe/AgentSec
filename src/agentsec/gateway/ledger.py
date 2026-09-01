"""Logical-execution ledger (AS-022).

Guarantees that a retry does not duplicate an externally visible side effect, and — just
as importantly — that a retry is not *blocked* by the single-use capability it already
spent.

Those two requirements pull against each other, and the tension is the whole design. A
capability is single use (AS-011): redeeming the same ``jti`` twice violates a database
constraint. But Temporal retries an activity whose response was lost, and that retry
presents the same capability. Naively, the retry is denied and the workflow can never
finish — a correctness bug that only appears under exactly the fault the durable execution
story is meant to survive.

The resolution is ordering. **The ledger is consulted before redemption.** A retry whose
logical operation already completed returns the cached result and never reaches the
``jti`` check. A first attempt passes through to redemption normally.

``operation_id`` is ``workflow_id : action_digest : plan_step_occurrence``. The occurrence
ordinal matters: two *intentionally* identical actions in one workflow — commenting the
same text on two files, say — are different operations, and keying on workflow plus digest
alone would silently merge them and lose the second effect.

**What this does not provide.** External APIs with no idempotency key cannot give
exactly-once. The guarantee is *at-most-once with reconciliation*: the effect happens zero
or one times, and ``external_ref`` lets a lost acknowledgement be reconciled rather than
retried blindly. See docs/THREAT_MODEL.md section 6.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentsec.db.models import ExecutionLedger as ExecutionLedgerRow
from agentsec.db.models import ExecutionState
from agentsec.log import get_logger

log = get_logger("agentsec.gateway.ledger")

SEPARATOR: Final = ":"

Clock = Callable[[], dt.datetime]


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def operation_id(workflow_id: str, action_digest: str, plan_step_occurrence: int = 0) -> str:
    """Build the stable identity of one logical operation.

    The occurrence ordinal is not decoration. Two intentionally identical actions in one
    workflow are different operations; keying on workflow plus digest alone would merge
    them and lose the second effect.
    """
    return f"{workflow_id}{SEPARATOR}{action_digest}{SEPARATOR}{plan_step_occurrence}"


class ReconciliationRequiredError(Exception):
    """Raised when an operation is stuck in PENDING.

    A previous attempt reached the backend and never recorded an outcome, so whether the
    effect happened is genuinely unknown. Retrying blindly could duplicate it; failing
    silently could lose it. The honest answer is to stop and reconcile against
    ``external_ref``, which is why this is an exception rather than a quiet retry.
    """

    def __init__(self, entry: ExecutionLedgerRow) -> None:
        super().__init__(
            f"operation {entry.operation_id} is PENDING after {entry.attempt_count} attempts; "
            "the previous outcome is unknown and must be reconciled"
        )
        self.entry = entry


@dataclass(frozen=True, slots=True)
class LedgerDecision:
    """What the gateway should do with this attempt."""

    proceed: bool
    cached_result: Any | None = None
    attempt: int = 1
    replayed: bool = False


class ExecutionLedgerService:
    """Durable at-most-once bookkeeping for side effects."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        clock: Clock = _utc_now,
        max_pending_attempts: int = 3,
    ) -> None:
        self._session = session
        self._clock = clock
        self._max_pending_attempts = max_pending_attempts

    async def begin(
        self,
        *,
        operation: str,
        run_id: str,
        workflow_id: str,
        action_digest: str,
        request_hash: str,
        plan_step_occurrence: int = 0,
    ) -> LedgerDecision:
        """Claim an operation, or report that it is already done.

        Called **before** capability redemption. That ordering is what lets single-use
        grants and durable retries coexist.
        """
        entry = await self._session.get(ExecutionLedgerRow, operation)

        if entry is None:
            return await self._claim(
                operation=operation,
                run_id=run_id,
                workflow_id=workflow_id,
                action_digest=action_digest,
                request_hash=request_hash,
                plan_step_occurrence=plan_step_occurrence,
            )

        if entry.request_hash != request_hash:
            # Same operation id, different request body. Either a bug in id construction
            # or an attempt to smuggle different arguments under a completed operation's
            # identity. Neither is something to proceed through.
            raise ValueError(
                f"operation {operation} was claimed with a different request; "
                "refusing to reuse its identity"
            )

        if entry.state is ExecutionState.COMPLETED:
            log.info("operation already completed", operation_id=operation, replayed=True)
            return LedgerDecision(
                proceed=False,
                cached_result=entry.result,
                attempt=entry.attempt_count,
                replayed=True,
            )

        if entry.state is ExecutionState.FAILED:
            # A recorded failure means the backend was reached and said no. Retrying is
            # legitimate: the effect did not happen.
            entry.attempt_count += 1
            await self._session.flush()
            return LedgerDecision(proceed=True, attempt=entry.attempt_count)

        entry.attempt_count += 1
        await self._session.flush()
        if entry.attempt_count > self._max_pending_attempts:
            raise ReconciliationRequiredError(entry)

        log.warning(
            "retrying an operation left pending",
            operation_id=operation,
            attempt=entry.attempt_count,
        )
        return LedgerDecision(proceed=True, attempt=entry.attempt_count)

    async def _claim(
        self,
        *,
        operation: str,
        run_id: str,
        workflow_id: str,
        action_digest: str,
        request_hash: str,
        plan_step_occurrence: int,
    ) -> LedgerDecision:
        self._session.add(
            ExecutionLedgerRow(
                operation_id=operation,
                run_id=run_id,
                workflow_id=workflow_id,
                action_digest=action_digest,
                plan_step_occurrence=plan_step_occurrence,
                request_hash=request_hash,
                state=ExecutionState.PENDING,
                attempt_count=1,
            )
        )
        try:
            await self._session.flush()
        except IntegrityError:
            # Two concurrent attempts raced to claim. The database picked a winner; this
            # one re-reads and takes the completed/pending path rather than proceeding.
            await self._session.rollback()
            entry = await self._session.get(ExecutionLedgerRow, operation)
            if entry is None:  # pragma: no cover - the row must exist after a PK conflict
                raise
            if entry.state is ExecutionState.COMPLETED:
                return LedgerDecision(
                    proceed=False,
                    cached_result=entry.result,
                    attempt=entry.attempt_count,
                    replayed=True,
                )
            raise ReconciliationRequiredError(entry) from None

        return LedgerDecision(proceed=True, attempt=1)

    async def complete(
        self, operation: str, result: Any, *, external_ref: str | None = None
    ) -> None:
        """Record that the effect happened.

        ``external_ref`` is the backend's own identifier — a Jira key, a comment id. It is
        what makes reconciliation possible after a lost acknowledgement: without it, the
        only way to answer "did this land?" is to look and guess.
        """
        entry = await self._require(operation)
        entry.state = ExecutionState.COMPLETED
        entry.result = result if isinstance(result, dict) else {"value": result}
        entry.external_ref = external_ref
        entry.completed_at = self._clock()
        await self._session.flush()
        log.info(
            "operation completed",
            operation_id=operation,
            attempts=entry.attempt_count,
            external_ref=external_ref,
        )

    async def fail(self, operation: str, error: str) -> None:
        """Record that the backend was reached and refused. Retrying is then legitimate."""
        entry = await self._require(operation)
        entry.state = ExecutionState.FAILED
        entry.error = error[:2000]
        await self._session.flush()

    async def _require(self, operation: str) -> ExecutionLedgerRow:
        entry = await self._session.get(ExecutionLedgerRow, operation)
        if entry is None:
            raise ValueError(f"operation {operation} was never claimed")
        return entry

    # ------------------------------------------------------------------ reporting

    async def logical_effects(self, workflow_id: str) -> int:
        """How many operations actually completed for a workflow.

        The idempotency evidence: compare this with the total attempt count. A gap means
        retries happened and produced one effect each, which is the claim.
        """
        rows = (
            await self._session.execute(
                select(ExecutionLedgerRow).where(
                    ExecutionLedgerRow.workflow_id == workflow_id,
                    ExecutionLedgerRow.state == ExecutionState.COMPLETED,
                )
            )
        ).scalars()
        return len(list(rows))

    async def total_attempts(self, workflow_id: str) -> int:
        rows = (
            await self._session.execute(
                select(ExecutionLedgerRow).where(ExecutionLedgerRow.workflow_id == workflow_id)
            )
        ).scalars()
        return sum(row.attempt_count for row in rows)


class GatewayLedgerAdapter:
    """Adapts the service to the gateway's ``ExecutionLedger`` protocol (AS-014).

    The gateway wants a two-method view — "is this done?" and "it is now" — while the
    service exposes the fuller lifecycle the workflow layer needs. Keeping them separate
    means the gateway cannot accidentally use the reconciliation paths.
    """

    def __init__(
        self, service: ExecutionLedgerService, *, claim: LedgerDecision | None = None
    ) -> None:
        self._service = service
        self._claim = claim

    async def completed_result(self, operation_id: str) -> Any | None:
        entry = await self._service._session.get(ExecutionLedgerRow, operation_id)
        if entry is None or entry.state is not ExecutionState.COMPLETED:
            return None
        return entry.result

    async def record_completion(self, operation_id: str, result: Any) -> None:
        entry = await self._service._session.get(ExecutionLedgerRow, operation_id)
        if entry is None:
            return
        await self._service.complete(operation_id, result)


__all__ = [
    "ExecutionLedgerService",
    "GatewayLedgerAdapter",
    "LedgerDecision",
    "ReconciliationRequiredError",
    "operation_id",
]
