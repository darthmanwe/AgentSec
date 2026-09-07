"""Fault injection against the paid code path (AS-040 hardening).

The evaluation gets **one funded run**. These tests break it on purpose, in the ways a
real run breaks, and assert that money and results survive.

Every test drives the *same* ``AnthropicProvider`` a live run uses, against a fake client
that injects failures. Nothing here contacts the network or needs a key — the point is to
exercise the exact code that will spend money, not a parallel implementation of it.

The tests worth reading first:

``test_a_crash_midway_keeps_everything_bought_so_far``
    The whole reason the cache exists. A run that dies at 80% must not cost 100% and
    deliver nothing.

``test_a_resume_re_buys_nothing``
    The other half. If a resume re-purchased what the first attempt already paid for, the
    cache would be a performance optimisation instead of a budget control.

``test_a_dead_policy_engine_is_refused``
    The most dangerous failure available: OPA fails closed, so a run against a dead engine
    denies every action and reports a **perfect score it did not earn**. It looks like
    success, which is why it has to be impossible rather than merely unlikely.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, ClassVar

import pytest

from agentsec.agent.accounting import BudgetExceededError, UsageAccountant
from agentsec.agent.provider import Message, ModelRequest, ProviderError, Usage
from agentsec.agent.providers import TOKEN_SAFETY_FACTOR, AnthropicProvider, _estimate_tokens
from agentsec.eval.cache import ResponseCache, request_key
from agentsec.eval.checkpoint import RunDirectory, RunStatus
from agentsec.eval.resilience import (
    FatalRunError,
    RetryLog,
    Severity,
    TerminalCallError,
    backoff_delay,
    classify,
    with_retry,
)

pytestmark = pytest.mark.authz

HAIKU = "claude-haiku-4-5-20251001"
PLAN = '{"hypotheses": [], "actions": []}'


# =========================================================== fakes


class FakeRateLimit(Exception):  # noqa: N818
    """Stands in for anthropic.RateLimitError.

    Named without an Error suffix on purpose: classification is by *type name*, and these
    fakes exist to prove that the name is what the classifier reads. The suffix convention
    would defeat the test.
    """


class FakeOverloaded(Exception):  # noqa: N818
    pass


FakeOverloaded.__name__ = "OverloadedError"
FakeRateLimit.__name__ = "RateLimitError"


class FakeAuthError(Exception):
    pass


FakeAuthError.__name__ = "AuthenticationError"


class FakeBadRequest(Exception):  # noqa: N818
    pass


FakeBadRequest.__name__ = "BadRequestError"


@dataclass
class FakeUsage:
    input_tokens: int = 1000
    output_tokens: int = 40


@dataclass
class FakeBlock:
    type: str = "text"
    text: str = PLAN


@dataclass
class FakeResponse:
    model: str = HAIKU
    stop_reason: str = "end_turn"
    content: list[FakeBlock] = field(default_factory=lambda: [FakeBlock()])
    usage: FakeUsage = field(default_factory=FakeUsage)


@dataclass
class FakeCount:
    input_tokens: int = 1234


@dataclass
class FakeMessages:
    """A messages endpoint that can be told to misbehave."""

    fail_with: list[Exception] = field(default_factory=list)
    calls: int = 0
    count_calls: int = 0
    response: FakeResponse = field(default_factory=FakeResponse)
    count_fails: bool = False
    hang_seconds: float = 0.0

    async def create(self, **payload: Any) -> FakeResponse:
        self.calls += 1
        if self.hang_seconds:
            await asyncio.sleep(self.hang_seconds)
        if self.fail_with:
            raise self.fail_with.pop(0)
        return self.response

    async def count_tokens(self, **payload: Any) -> FakeCount:
        self.count_calls += 1
        if self.count_fails:
            raise RuntimeError("count_tokens is unavailable")
        return FakeCount()


@dataclass
class FakeClient:
    messages: FakeMessages = field(default_factory=FakeMessages)


def request(purpose: str = "plan", system: str = "you propose") -> ModelRequest:
    return ModelRequest(
        model=HAIKU,
        system=system,
        messages=(Message(role="user", content="review repo-a"),),
        output_schema={"type": "object"},
        purpose=purpose,
    )


def provider(
    client: FakeClient, *, cache: ResponseCache | None = None, ceiling: float = 10.0
) -> tuple[AnthropicProvider, UsageAccountant]:
    accountant = UsageAccountant(max_usd=ceiling)
    return (
        AnthropicProvider("sk-fake", accountant, client=client, cache=cache),
        accountant,
    )


# =========================================================== classification


@pytest.mark.parametrize(
    ("error", "severity"),
    [
        (FakeRateLimit(), Severity.RETRYABLE),
        (FakeOverloaded(), Severity.RETRYABLE),
        (TimeoutError(), Severity.RETRYABLE),
        (ConnectionResetError(), Severity.RETRYABLE),
        (FakeAuthError(), Severity.FATAL),
        (FakeBadRequest(), Severity.TERMINAL),
    ],
)
def test_failures_are_classified_by_type(error: Exception, severity: Severity) -> None:
    """By type, not by message. Message matching breaks silently on an SDK upgrade, and
    the failure mode is a retry storm against an error that will never clear."""
    assert classify(error) is severity


def test_an_unknown_failure_is_terminal_not_retryable() -> None:
    """The conservative default on a funded run. Retrying something nobody has classified
    spends money to learn nothing."""
    assert classify(RuntimeError("something new")) is Severity.TERMINAL


def test_a_status_code_classifies_when_the_name_does_not() -> None:
    class Odd(Exception):  # noqa: N818
        status_code = 429

    assert classify(Odd()) is Severity.RETRYABLE

    class Forbidden(Exception):  # noqa: N818
        status_code = 403

    assert classify(Forbidden()) is Severity.FATAL


def test_backoff_is_jittered_and_bounded() -> None:
    """Ten cells retrying a rate limit on a fixed schedule re-collide on every attempt.
    Full jitter is what turns a thundering herd into a queue."""
    delays = {backoff_delay(3) for _ in range(50)}
    assert len(delays) > 20, "the schedule is not jittered"
    assert all(0.0 <= d <= 8.0 for d in delays)
    assert backoff_delay(99) <= 60.0


# =========================================================== retry


async def test_a_transient_failure_is_retried_and_succeeds() -> None:
    client = FakeClient(FakeMessages(fail_with=[FakeRateLimit(), FakeOverloaded()]))
    live, _ = provider(client)
    log = RetryLog()
    live._retry_log = log  # reaching in to read what a real run would record

    response = await live.complete(request())

    assert response.text == PLAN
    assert client.messages.calls == 3
    assert log.retries == 2
    assert set(log.by_kind) == {"RateLimitError", "OverloadedError"}


async def test_a_fatal_failure_stops_the_run() -> None:
    """An authentication failure will fail identically on every retry. Burning the retry
    budget to confirm that wastes the operator's time and tells them nothing."""
    client = FakeClient(FakeMessages(fail_with=[FakeAuthError()]))
    live, _ = provider(client)

    with pytest.raises(FatalRunError):
        await live.complete(request())
    assert client.messages.calls == 1


async def test_a_terminal_failure_stops_the_call_not_the_run() -> None:
    client = FakeClient(FakeMessages(fail_with=[FakeBadRequest()]))
    live, _ = provider(client)

    with pytest.raises(TerminalCallError):
        await live.complete(request())
    assert client.messages.calls == 1


async def test_retries_are_bounded() -> None:
    """A stuck cell must not hold a funded run open indefinitely."""
    client = FakeClient(FakeMessages(fail_with=[FakeRateLimit() for _ in range(50)]))
    live, _ = provider(client)

    async def instant(_: float) -> None:
        return None

    with pytest.raises(TerminalCallError, match="gave up"):
        await with_retry(
            lambda: live._client.messages.create(model=HAIKU),
            what="probe",
            sleeper=instant,
        )
    assert client.messages.calls <= 6


async def test_a_hung_request_is_timed_out() -> None:
    """The SDK has its own timeout, but a socket that hangs without it noticing would
    stall a cell forever, and a funded run cannot afford to find that out at the end."""
    client = FakeClient(FakeMessages(hang_seconds=30.0))

    async def attempt() -> Any:
        return await client.messages.create(model=HAIKU)

    async def instant(_: float) -> None:
        return None

    with pytest.raises(TerminalCallError):
        await with_retry(
            attempt, what="hang", timeout_seconds=0.05, max_attempts=2, sleeper=instant
        )


async def test_cancellation_is_never_retried_through() -> None:
    """A cancellation is the operator stopping the run. Retrying through it ignores them."""

    async def attempt() -> Any:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await with_retry(attempt, what="cancel", max_attempts=3)


# =========================================================== budget correctness


class HostileResponse:
    """A response object whose shape has changed under us.

    Not contrived: SDK response objects do change across versions, and the first thing
    that breaks is an attribute read during decoding - *after* the request has been sent
    and the money is committed.
    """

    model = HAIKU
    stop_reason = "end_turn"
    content: ClassVar[list[Any]] = []

    @property
    def usage(self) -> Any:
        raise AttributeError("usage moved in this SDK version")


async def test_the_reservation_is_released_when_decoding_fails() -> None:
    """The leak an earlier version had.

    Release was wrapped around the client call only, so an exception raised *after* the
    call - while decoding the response - held the reservation forever. A sweep that hit a
    few of those would stop early with money unspent, blaming a budget it had not used.

    Writing this test also found a worse bug behind it: the decoder read usage with a
    getattr default, so an unreadable usage object produced zero tokens, settled the call
    at $0.00, and left the ledger showing no spend at all. The run would have spent the
    real money while reporting none of it, and the ceiling could never have fired. Usage
    is now mandatory.
    """
    client = FakeClient(FakeMessages())
    client.messages.response = HostileResponse()  # type: ignore[assignment]
    live, accountant = provider(client)

    with pytest.raises(ProviderError, match="cannot be priced"):
        await live.complete(request())

    assert client.messages.calls == 1, "the request was sent, so the hold was real"
    assert accountant.ledger.reserved_usd == pytest.approx(0.0)
    assert accountant.remaining_usd == pytest.approx(10.0)


async def test_the_reservation_is_released_on_a_transient_giveup() -> None:
    client = FakeClient(FakeMessages(fail_with=[FakeRateLimit() for _ in range(50)]))
    live, accountant = provider(client)

    with pytest.raises(TerminalCallError):
        await live.complete(request())

    assert accountant.ledger.reserved_usd == pytest.approx(0.0)


async def test_the_budget_ceiling_refuses_a_call_it_cannot_afford() -> None:
    client = FakeClient()
    live, _ = provider(client, ceiling=0.000001)

    with pytest.raises(BudgetExceededError):
        await live.complete(request())
    assert client.messages.calls == 0, "the request was sent despite the ceiling"


async def test_exact_token_counting_is_used_when_available() -> None:
    """count_tokens is not billed, so an exact count makes the reservation tight rather
    than merely conservative."""
    client = FakeClient()
    live, _ = provider(client)

    await live.complete(request())

    assert client.messages.count_calls == 1


async def test_a_failure_to_count_does_not_prevent_the_call() -> None:
    """Counting is best-effort. A failure to *count* must never block a call the operator
    funded; the conservative heuristic covers it."""
    client = FakeClient(FakeMessages(count_fails=True))
    live, _ = provider(client)

    response = await live.complete(request())
    assert response.text == PLAN


def test_the_token_heuristic_errs_high() -> None:
    """The asymmetry decides the direction: over-reserving costs a little headroom that
    reconciliation returns, under-reserving costs money."""
    assert TOKEN_SAFETY_FACTOR > 1.0
    naive = (len("you propose") + len("review repo-a")) // 4
    assert _estimate_tokens(request()) > naive


# =========================================================== the cache


async def test_a_response_is_cached_the_moment_it_arrives(tmp_path: pathlib.Path) -> None:
    """Written before the caller does anything else with it. A response held in memory
    until the end of a cell is a response a crash in that cell loses, and it was paid for."""
    cache = ResponseCache(tmp_path / "cache")
    client = FakeClient()
    live, _ = provider(client, cache=cache)

    await live.complete(request())

    assert cache.count() == 1
    assert cache.stats.writes == 1


async def test_a_cached_response_is_never_bought_twice(tmp_path: pathlib.Path) -> None:
    cache = ResponseCache(tmp_path / "cache")
    client = FakeClient()
    live, accountant = provider(client, cache=cache)

    first = await live.complete(request())
    spent_after_first = accountant.ledger.settled_usd
    second = await live.complete(request())

    assert client.messages.calls == 1, "the second call hit the API"
    assert second.text == first.text
    assert accountant.ledger.settled_usd == spent_after_first
    assert cache.stats.hits == 1


async def test_a_cache_hit_does_not_consume_budget(tmp_path: pathlib.Path) -> None:
    """The cache is consulted *before* the reservation. Reserving for a free replay would
    make a resumed run appear to spend budget it is not spending, and could refuse a call
    the operator already funded."""
    cache = ResponseCache(tmp_path / "cache")
    client = FakeClient()

    live, accountant = provider(client, cache=cache, ceiling=10.0)
    await live.complete(request())

    # A second provider with a ceiling far too small for a real call. The replay must
    # still work, because it costs nothing.
    tiny, _ = provider(FakeClient(), cache=cache, ceiling=0.0000001)
    replayed = await tiny.complete(request())

    assert replayed.text == PLAN
    assert accountant.ledger.settled_usd > 0


async def test_a_corrupt_cache_entry_is_a_miss_not_a_crash(tmp_path: pathlib.Path) -> None:
    """A truncated entry from a crash mid-write must not poison the resume it exists to
    enable. It is also recorded, because silently re-buying is the loss being prevented."""
    cache = ResponseCache(tmp_path / "cache")
    client = FakeClient()
    live, _ = provider(client, cache=cache)
    await live.complete(request())

    for path in (tmp_path / "cache").rglob("*.json"):
        path.write_text("{ truncated", encoding="utf-8")

    fresh = ResponseCache(tmp_path / "cache")
    assert fresh.get(request()) is None
    assert fresh.stats.corrupt_entries


def test_the_cache_key_covers_the_schema(tmp_path: pathlib.Path) -> None:
    """A cache that ignored the schema would serve a response shaped for a different
    request."""
    with_schema = request()
    without = ModelRequest(
        model=HAIKU,
        system=with_schema.system,
        messages=with_schema.messages,
        output_schema=None,
        purpose="plan",
    )
    assert request_key(with_schema) != request_key(without)


def test_repeated_samples_get_distinct_cache_keys() -> None:
    """The measurement bug this prevents.

    A repeat that replayed the cache would add a trial to the denominator without adding
    an observation - three times the trials, one data point, a confidence interval three
    times tighter than the evidence supports. And it would cost nothing, which is exactly
    what would make it hard to notice.
    """
    assert request_key(request(purpose="plan")) != request_key(request(purpose="plan/s2"))


def test_a_sample_tag_does_not_change_the_prompt() -> None:
    """The other half of the same requirement: a re-sample must be the *same question*."""
    from agentsec.agent.provider import build_payload

    assert build_payload(request(purpose="plan")) == build_payload(request(purpose="plan/s2"))


def test_the_cache_records_what_each_response_cost(tmp_path: pathlib.Path) -> None:
    """So a resumed run can report what the whole run cost, not just the resumed part."""
    cache = ResponseCache(tmp_path / "cache")
    from agentsec.agent.provider import ModelResponse

    cache.put(
        request(),
        ModelResponse(model=HAIKU, text=PLAN, usage=Usage(1000, 40), provider="anthropic"),
        usd=0.0012,
    )
    assert cache.total_usd() == pytest.approx(0.0012)


# =========================================================== checkpoint and resume


def test_a_cell_is_written_the_moment_it_finishes(tmp_path: pathlib.Path) -> None:
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/x", "a/y"))
    directory.save_cell("a/x", {"authorization": {"unauthorized_attempts": 3}})

    assert directory.completed_cells() == {"a/x"}
    assert directory.remaining_cells == ("a/y",)


def test_a_crash_midway_keeps_everything_bought_so_far(tmp_path: pathlib.Path) -> None:
    """**The reason any of this exists.**

    A run that dies at 80% must not cost 100% and deliver nothing. The completed cells are
    on disk and the paid responses are in the cache, so the loss is time, not budget.
    """
    directory = RunDirectory.create(
        base=tmp_path, planned_cells=("a/1", "a/2", "a/3", "a/4", "a/5")
    )
    for cell in ("a/1", "a/2", "a/3", "a/4"):
        directory.save_cell(cell, {"authorization": {"unauthorized_attempts": 10}})
    directory.set_status(RunStatus.FAILED, "simulated crash")

    reopened = RunDirectory.open(directory.run_id, base=tmp_path)
    reopened.planned_cells = directory.planned_cells

    assert len(reopened.completed_cells()) == 4
    assert reopened.remaining_cells == ("a/5",)
    assert len(reopened.load_cells()) == 4


async def test_a_resume_re_buys_nothing(tmp_path: pathlib.Path) -> None:
    """The other half of the guarantee.

    A resume that re-purchased what the first attempt paid for would make the cache a
    performance optimisation rather than a budget control.
    """
    cache_dir = tmp_path / "cache"
    requests = [request(purpose=f"plan/s{i}") for i in range(1, 6)]

    first_client = FakeClient()
    first, first_accountant = provider(first_client, cache=ResponseCache(cache_dir))
    for item in requests[:3]:
        await first.complete(item)

    assert first_client.messages.calls == 3
    spent = first_accountant.ledger.settled_usd

    # The resume: a fresh provider and accountant over the same cache directory.
    second_client = FakeClient()
    second, second_accountant = provider(second_client, cache=ResponseCache(cache_dir))
    for item in requests:
        await second.complete(item)

    assert second_client.messages.calls == 2, "the resume re-bought cached responses"
    assert second_accountant.ledger.settled_usd < spent


def test_a_corrupt_cell_file_is_discarded_so_the_resume_redoes_it(
    tmp_path: pathlib.Path,
) -> None:
    """A half-written cell would turn a recoverable crash into an unrecoverable one. The
    cell is re-run, which costs nothing because its model calls are cached."""
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1",))
    directory.save_cell("a/1", {"authorization": {}})
    for path in directory.cells_dir.glob("*.json"):
        path.write_text("{ truncated", encoding="utf-8")

    assert directory.completed_cells() == set()


def test_a_partial_cell_is_not_mistaken_for_a_finished_one(tmp_path: pathlib.Path) -> None:
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1",))
    directory.save_cell("a/1", {"authorization": {}}, complete=False)
    assert directory.completed_cells() == set()


def test_resuming_a_completed_run_is_refused(tmp_path: pathlib.Path) -> None:
    """Appending to a result that has already been reported would produce a second version
    that does not match the artifact somebody quoted."""
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1",))
    directory.set_status(RunStatus.COMPLETED)

    with pytest.raises(ValueError, match="already completed"):
        RunDirectory.open(directory.run_id, base=tmp_path)


def test_writes_are_atomic(tmp_path: pathlib.Path) -> None:
    """No temp files left behind, and the target is either old or new - never truncated."""
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1",))
    for _ in range(5):
        directory.save_cell("a/1", {"authorization": {"unauthorized_attempts": 1}})

    assert not list(directory.cells_dir.glob("*.tmp"))
    assert not list(directory.cells_dir.glob(".*"))
    document = json.loads(next(directory.cells_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert document["complete"] is True


def test_progress_is_appended_so_a_dead_run_says_how_far_it_got(
    tmp_path: pathlib.Path,
) -> None:
    """The difference between "it failed" and "it failed after cell seven, in the approval
    arm"."""
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1",))
    directory.append_event({"event": "cell_started", "cell": "a/1"})
    directory.save_cell("a/1", {"authorization": {}})

    lines = directory.events_path.read_text(encoding="utf-8").strip().split("\n")
    events = [json.loads(line) for line in lines]
    assert any(e["event"] == "cell_started" for e in events)
    assert all("at" in e for e in events)


def test_progress_reports_a_fraction(tmp_path: pathlib.Path) -> None:
    directory = RunDirectory.create(base=tmp_path, planned_cells=("a/1", "a/2"))
    directory.save_cell("a/1", {"authorization": {}})
    assert directory.progress()["fraction"] == pytest.approx(0.5)


# =========================================================== preflight


async def test_a_dead_policy_engine_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """**The most dangerous failure available.**

    OPA fails closed by design (AS-008), so a run against an unreachable engine denies
    every action and reports a perfect score it did not earn. It looks exactly like
    success, which is why it must be impossible rather than merely unlikely.
    """
    import agentsec.eval.runner as module

    async def dead() -> bool:
        return False

    monkeypatch.setattr(module, "_opa_healthy", dead)
    result = await module.preflight(module.RunSettings(arms=("A2-policy",)))

    assert not result.ok
    assert any("fails closed" in blocker for blocker in result.blockers)


async def test_a_fail_closed_decision_counts_as_unhealthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A listening port proves a process is up. Only a real decision proves the bundle
    loaded - and a bundle that failed to load produces a silently-perfect run."""
    import datetime as dt

    import agentsec.eval.runner as module
    from agentsec.authz.models import PolicyDecision, PolicyOutcome

    class FailClosed:
        async def evaluate(self, request: object) -> PolicyDecision:
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                reason_code="engine_unreachable",
                fail_closed=True,
                evaluated_at=dt.datetime.now(dt.UTC),
            )

    monkeypatch.setattr(module, "OpaPolicyClient", FailClosed, raising=False)
    monkeypatch.setattr("agentsec.authz.engine.OpaPolicyClient", lambda **kwargs: FailClosed())
    assert await module._opa_healthy() is False


async def test_an_arm_referencing_a_missing_prompt_is_refused() -> None:
    """The bug the dry-run rehearsal found: A0-none referenced a prompt ADR-0003 described
    and nobody had written. On a live run it would have failed mid-sweep, after spending."""
    import agentsec.eval.runner as module

    original = module.ARMS
    broken = (module.Arm("A9-broken", "prompt.that.does.not.exist", False, False, False),)
    try:
        module.ARMS = broken  # type: ignore[misc]
        result = await module.preflight(module.RunSettings(arms=("A9-broken",)))
    finally:
        module.ARMS = original  # type: ignore[misc]

    assert not result.ok
    assert any("not in the registry" in blocker for blocker in result.blockers)


async def test_live_without_a_key_is_refused_at_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentsec.eval.runner as module
    from agentsec.config import Settings

    monkeypatch.setattr(
        "agentsec.config.load_settings", lambda **kw: Settings(anthropic_api_key=None)
    )
    result = await module.preflight(
        module.RunSettings(arms=("A0-none",), axes=("real",), live=True, max_usd=5.0)
    )
    assert any("ANTHROPIC_API_KEY" in blocker for blocker in result.blockers)


async def test_axis_a_without_live_warns_rather_than_blocks() -> None:
    """Useful as a rehearsal, meaningless as a measurement. Worth saying, not worth
    refusing."""
    import agentsec.eval.runner as module

    result = await module.preflight(module.RunSettings(arms=("A0-none",), axes=("real",)))
    assert result.ok
    assert any("mock" in warning for warning in result.warnings)


# =========================================================== projection and refusals


def test_the_projection_is_an_over_estimate() -> None:
    """An operator deciding whether $25 covers the plan needs the number that cannot be
    exceeded, not the one that is most likely."""
    from agentsec.eval.runner import RunSettings, project_cost

    projection = project_cost(RunSettings(axes=("real",), repeats=3))
    assert projection["live_calls"] > 0
    assert projection["worst_case_usd"] > 0
    assert "worst case" in projection["note"]


def test_the_projection_scales_with_repeats() -> None:
    """It has to agree with what the runner actually does. An earlier version multiplied
    by repeats while Axis A ignored them entirely."""
    from agentsec.eval.runner import RunSettings, project_cost

    one = project_cost(RunSettings(axes=("real",), repeats=1))["live_calls"]
    three = project_cost(RunSettings(axes=("real",), repeats=3))["live_calls"]
    assert three == one * 3


def test_axis_b_projects_zero_spend() -> None:
    from agentsec.eval.runner import RunSettings, project_cost

    assert project_cost(RunSettings(axes=("adversarial",)))["worst_case_usd"] == 0.0


async def test_dry_run_and_live_together_are_refused() -> None:
    from agentsec.eval.runner import RunSettings, SuiteError, run_suite

    with pytest.raises(SuiteError, match="contradictory"):
        await run_suite(RunSettings(suite="smoke", live=True, max_usd=5.0, dry_run=True))


# =========================================================== the rehearsal is faithful


async def test_the_dry_run_exercises_the_cache(tmp_path: pathlib.Path) -> None:
    """A dry run claims to rehearse the code a live run will execute.

    The mock bypassed the cache in the first version, so the rehearsal skipped the single
    mechanism a funded run depends on most - the one that turns a crash into lost time
    rather than lost budget. "Rehearses the code that will run" was false about the part
    that mattered. Found by inspecting a dry run's cache directory and finding it empty.
    """
    from agentsec.agent.providers import select_provider

    cache = ResponseCache(tmp_path / "cache")
    mock = select_provider(
        live=False, api_key=None, accountant=UsageAccountant(max_usd=1.0), cache=cache
    )

    first = await mock.complete(request())
    assert cache.count() == 1

    second = await mock.complete(request())
    assert second.text == first.text
    assert cache.stats.hits == 1
    assert len(mock.calls) == 1, "the mock answered twice instead of replaying the cache"


async def test_a_rehearsed_cache_entry_records_zero_cost(tmp_path: pathlib.Path) -> None:
    """A rehearsal must not imply that a resumed *live* run would be free."""
    from agentsec.agent.providers import select_provider

    cache = ResponseCache(tmp_path / "cache")
    mock = select_provider(
        live=False, api_key=None, accountant=UsageAccountant(max_usd=1.0), cache=cache
    )
    await mock.complete(request())

    assert cache.total_usd() == 0.0


async def test_a_dry_run_is_never_reportable() -> None:
    """Whatever suite it was asked for.

    The first version computed reportability from the preregistration lock and the smoke
    flag alone, so `--suite full --dry-run` produced an artifact with "reportable" in its
    filename. A rehearsal that measures nothing about a real model must not be quotable,
    and a filename is exactly how it would get quoted.
    """
    from agentsec.eval.runner import RunSettings, run_suite

    artifact = await run_suite(
        RunSettings(suite="full", dry_run=True, repeats=1, arms=("A0-none",))
    )

    assert artifact.reportable is False
    assert any("DRY RUN" in note for note in artifact.notes)
