"""Budget enforcement for live model calls (AS-024).

**Worst-case cost is reserved before the request, and reconciled after.**

The obvious design is to add up what each call cost and stop when the total crosses the
ceiling. That design cannot work: by the time it notices, the money is gone. Worse, it
fails hardest exactly where it matters — a run that fans out will have many requests in
flight when the total finally crosses, and every one of them is already billable.

So a reservation is taken first, priced at the maximum the request could possibly cost
(full input, ``max_tokens`` of output). If the reservation does not fit under the ceiling,
the request is never made. Afterwards the reservation is released and replaced by the
actual usage, which is almost always smaller — so the ceiling is conservative in the safe
direction and the headroom returns immediately.

The accounting is under a lock. Concurrency is the case the naive version gets wrong:
two callers can each read a total below the ceiling and both proceed, and the ceiling
becomes advisory. ``tests/test_accounting.py`` runs many concurrent reservations against
a ceiling that admits few of them and asserts the count.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from agentsec.agent.provider import Usage, capabilities_for
from agentsec.log import get_logger

log = get_logger("agentsec.agent.accounting")


class BudgetExceededError(Exception):
    """The request was refused because it could not fit under the ceiling.

    Refused, not truncated: a smaller version of a planned call is a different call, and
    silently substituting one would corrupt an evaluation cell rather than stop it.
    """

    def __init__(self, model: str, needed: float, remaining: float, ceiling: float) -> None:
        super().__init__(
            f"refusing a {model} call needing up to ${needed:.4f}; "
            f"${remaining:.4f} remains of a ${ceiling:.2f} ceiling"
        )
        self.needed = needed
        self.remaining = remaining
        self.ceiling = ceiling


@dataclass(frozen=True, slots=True)
class Reservation:
    """A hold placed before a request is sent."""

    id: str
    model: str
    worst_case_usd: float
    purpose: str = ""


@dataclass
class Ledger:
    """What has been spent and what is held. Plain data, for reporting."""

    settled_usd: float = 0.0
    reserved_usd: float = 0.0
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    per_model: dict[str, float] = field(default_factory=dict)

    @property
    def committed_usd(self) -> float:
        """Spent plus held. The number the ceiling is actually compared against."""
        return self.settled_usd + self.reserved_usd


class UsageAccountant:
    """Enforces a hard ceiling on live spend."""

    def __init__(self, max_usd: float, *, ceiling_name: str = "AGENTSEC_BUDGET_MAX_USD") -> None:
        if max_usd <= 0:
            raise ValueError("a budget ceiling must be positive")
        self._ceiling = max_usd
        self._ceiling_name = ceiling_name
        self._ledger = Ledger()
        self._lock = asyncio.Lock()
        self._open: dict[str, Reservation] = {}

    @property
    def ceiling_usd(self) -> float:
        return self._ceiling

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self._ceiling - self._ledger.committed_usd)

    async def reserve(
        self,
        model: str,
        *,
        input_tokens: int,
        max_output_tokens: int,
        purpose: str = "",
    ) -> Reservation:
        """Hold the worst case this request could cost, or refuse it.

        ``input_tokens`` is the caller's estimate of the prompt size. Under-estimating it
        weakens the ceiling, so callers should count rather than guess; the reconciliation
        afterwards corrects the ledger either way, but a reservation that was too small
        cannot un-spend the difference.
        """
        capabilities = capabilities_for(model)
        worst_case = capabilities.cost_usd(input_tokens, max_output_tokens)

        async with self._lock:
            if self._ledger.committed_usd + worst_case > self._ceiling:
                log.warning(
                    "budget refusal",
                    model=model,
                    needed_usd=round(worst_case, 4),
                    remaining_usd=round(self.remaining_usd, 4),
                )
                raise BudgetExceededError(model, worst_case, self.remaining_usd, self._ceiling)

            reservation = Reservation(
                id=uuid.uuid4().hex[:16],
                model=model,
                worst_case_usd=worst_case,
                purpose=purpose,
            )
            self._ledger.reserved_usd += worst_case
            self._open[reservation.id] = reservation
            return reservation

    async def settle(self, reservation: Reservation, usage: Usage) -> float:
        """Release the hold and record what was actually spent."""
        capabilities = capabilities_for(reservation.model)
        actual = capabilities.cost_usd(usage.input_tokens, usage.output_tokens)

        async with self._lock:
            held = self._open.pop(reservation.id, None)
            if held is None:
                # Settling twice would credit the hold back twice and inflate the
                # remaining budget - a bookkeeping bug that spends real money.
                raise ValueError(f"reservation {reservation.id} is not open")
            self._ledger.reserved_usd -= held.worst_case_usd
            self._ledger.settled_usd += actual
            self._ledger.calls += 1
            self._ledger.input_tokens += usage.input_tokens
            self._ledger.output_tokens += usage.output_tokens
            self._ledger.per_model[reservation.model] = (
                self._ledger.per_model.get(reservation.model, 0.0) + actual
            )

        log.info(
            "model call settled",
            model=reservation.model,
            purpose=reservation.purpose,
            actual_usd=round(actual, 6),
            reserved_usd=round(held.worst_case_usd, 6),
            spent_usd=round(self._ledger.settled_usd, 4),
            remaining_usd=round(self.remaining_usd, 4),
        )
        return actual

    async def release(self, reservation: Reservation) -> None:
        """Return a hold whose request never happened.

        A failed request costs nothing, and a hold left behind after one would shrink the
        budget for the rest of the run — a sweep that hit a few transient errors would
        quietly stop early with money unspent.
        """
        async with self._lock:
            held = self._open.pop(reservation.id, None)
            if held is not None:
                self._ledger.reserved_usd -= held.worst_case_usd

    def report(self) -> dict[str, object]:
        """A summary for the evaluation artifact."""
        return {
            "ceiling_usd": self._ceiling,
            "ceiling_source": self._ceiling_name,
            "spent_usd": round(self._ledger.settled_usd, 6),
            "reserved_usd": round(self._ledger.reserved_usd, 6),
            "remaining_usd": round(self.remaining_usd, 6),
            "calls": self._ledger.calls,
            "input_tokens": self._ledger.input_tokens,
            "output_tokens": self._ledger.output_tokens,
            "per_model_usd": {k: round(v, 6) for k, v in sorted(self._ledger.per_model.items())},
        }


__all__ = ["BudgetExceededError", "Ledger", "Reservation", "UsageAccountant"]
