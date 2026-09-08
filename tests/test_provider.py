"""Provider and budget tests (AS-024).

Two things are being checked, and the second matters more than the first.

**The request shape is right for each model.** Opus 5 and Haiku 4.5 do not accept the same
request, and a single hardcoded shape works for exactly one of them. These tests assert
the payload built for every model in the capability table — offline, because verifying it
against the live API would cost money to learn something a test can state for free.

**The budget ceiling actually holds.** Including under concurrency, which is where the
naive version fails: two callers each read a total below the ceiling, both proceed, and
the ceiling becomes advisory. The money is real, so the test is not optional.

Everything here runs with no API key and no network.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from agentsec.agent.accounting import BudgetExceededError, UsageAccountant
from agentsec.agent.provider import (
    MODEL_CAPABILITIES,
    Effort,
    Message,
    ModelRequest,
    ProviderError,
    ThinkingMode,
    UnknownModelError,
    Usage,
    build_payload,
    capabilities_for,
)
from agentsec.agent.providers import (
    AnthropicProvider,
    MockProvider,
    fingerprint,
    select_provider,
)

pytestmark = pytest.mark.authz

OPUS = "claude-opus-5"
HAIKU = "claude-haiku-4-5-20251001"


def request(model: str = HAIKU, **overrides: object) -> ModelRequest:
    base: dict[str, object] = {
        "model": model,
        "system": "You propose actions. You never authorise them.",
        "messages": (Message(role="user", content="review repo-a"),),
    }
    base.update(overrides)
    return ModelRequest(**base)  # type: ignore[arg-type]


# =========================================================== the capability table


def test_every_model_in_the_table_builds_a_payload() -> None:
    """The table is the whole point: adding a model must be a data change, not a branch."""
    for model in MODEL_CAPABILITIES:
        payload = build_payload(request(model))
        assert payload["model"] == model
        assert payload["max_tokens"] > 0


def test_opus_gets_adaptive_thinking_and_no_budget() -> None:
    """Opus 5 rejects ``budget_tokens`` with a 400. Sending one is not a degraded result,
    it is a failed request."""
    payload = build_payload(request(OPUS))
    assert payload["thinking"] == {"type": "adaptive"}
    assert "budget_tokens" not in json.dumps(payload["thinking"])


def test_haiku_gets_a_thinking_budget_and_never_adaptive() -> None:
    """Haiku 4.5 rejects adaptive thinking. This is the other half of the same 400."""
    payload = build_payload(request(HAIKU))
    thinking = payload["thinking"]
    assert thinking["type"] == "enabled"  # type: ignore[index]
    assert thinking["budget_tokens"] > 0  # type: ignore[index]


def test_the_two_models_produce_genuinely_different_requests() -> None:
    """Guards against the table collapsing into one shape that happens to pass both
    tests above while being identical - which would mean the table earns nothing."""
    assert build_payload(request(OPUS))["thinking"] != build_payload(request(HAIKU))["thinking"]


def test_effort_is_refused_on_a_model_that_errors_on_it() -> None:
    """Refused loudly rather than dropped. Silently proceeding without the caller's
    intent produces a run that is not the one they asked for."""
    with pytest.raises(ProviderError, match="does not support effort"):
        build_payload(request(HAIKU, effort=Effort.HIGH))


def test_effort_is_accepted_on_a_model_that_supports_it() -> None:
    payload = build_payload(request(OPUS, effort=Effort.HIGH))
    assert payload["output_config"]["effort"] == "high"  # type: ignore[index]


def test_temperature_is_refused_where_it_is_unsupported() -> None:
    with pytest.raises(ProviderError, match="temperature"):
        build_payload(request(OPUS, temperature=0.5))


def test_an_unknown_model_fails_closed() -> None:
    """Guessing a request shape is the failure this table exists to prevent: at best a
    400, at worst a silently different configuration if the shapes happen to overlap."""
    with pytest.raises(UnknownModelError, match="no capability entry"):
        capabilities_for("claude-something-new")


def test_the_bulk_model_is_a_dated_snapshot() -> None:
    """A published benchmark must not change when an alias is repointed."""
    assert HAIKU.endswith("-20251001")
    assert HAIKU in MODEL_CAPABILITIES


def test_output_tokens_are_clamped_to_what_the_model_allows() -> None:
    payload = build_payload(request(HAIKU, max_output_tokens=1_000_000))
    assert payload["max_tokens"] == MODEL_CAPABILITIES[HAIKU].max_output_tokens


# =========================================================== structured output


def test_a_schema_becomes_output_config_not_a_tool() -> None:
    """The architectural line.

    Declaring real tools to obtain strict structured output would hand the planner exactly
    the capability the whole system says it must never have. Structured output comes from
    output_config instead, and no code path here can produce a ``tools`` key.
    """
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"actions": {"type": "array", "items": {"type": "string"}}},
    }
    payload = build_payload(request(HAIKU, output_schema=schema))

    assert payload["output_config"]["format"]["schema"] == schema  # type: ignore[index]
    assert "tools" not in payload
    assert "tool_choice" not in payload


def test_no_request_field_can_express_a_tool() -> None:
    """Structural: the request type has no tools field, so a caller cannot pass one even
    by accident."""
    assert not hasattr(request(), "tools")
    assert "tools" not in ModelRequest.__dataclass_fields__


# =========================================================== the mock


async def test_the_mock_is_deterministic() -> None:
    """An ablation run that cannot be repeated is not a measurement."""
    provider = MockProvider(default_response='{"actions": []}')
    first = await provider.complete(request())
    second = await provider.complete(request())

    assert first.text == second.text
    assert first.usage.input_tokens == second.usage.input_tokens


async def test_the_mock_answers_per_request() -> None:
    provider = MockProvider()
    a, b = request(), request(HAIKU, system="different system prompt")
    provider.queue(a, '{"actions": ["a"]}')
    provider.queue(b, '{"actions": ["b"]}')

    assert (await provider.complete(a)).text == '{"actions": ["a"]}'
    assert (await provider.complete(b)).text == '{"actions": ["b"]}'


def test_the_fingerprint_ignores_sampling_settings() -> None:
    """Two calls that differ only in temperature are the same question. Keying on it would
    make a fixture miss for a reason nobody would think to look for."""
    assert fingerprint(request(HAIKU, temperature=0.0)) == fingerprint(
        request(HAIKU, temperature=1.0)
    )


def test_the_fingerprint_distinguishes_the_prompt() -> None:
    assert fingerprint(request()) != fingerprint(request(HAIKU, system="other"))


async def test_unparseable_output_is_reported_rather_than_raised() -> None:
    """A model returning text that is not JSON is a case the planner has to handle, not a
    crash. Schema validation is necessary and not sufficient; the semantic checks in
    AS-026 run afterwards either way."""
    provider = MockProvider(default_response="I refuse to answer in JSON.")
    response = await provider.complete(
        request(
            HAIKU,
            output_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {"a": {"type": "string"}},
            },
        )
    )

    assert response.parsed is None
    assert response.text


async def test_a_truncated_response_is_flagged() -> None:
    """A truncated plan parses as a shorter plan. Acting on the prefix of an intended
    action list is how a control that reads correct acts on half a decision."""
    provider = MockProvider(default_response='{"actions": [', stop_reason="max_tokens")
    response = await provider.complete(request())

    assert response.truncated is True


async def test_the_mock_records_what_it_was_asked() -> None:
    provider = MockProvider()
    await provider.complete(request(HAIKU, purpose="replan"))
    assert provider.calls[-1].purpose == "replan"


# =========================================================== the budget ceiling


async def test_a_request_that_would_exceed_the_ceiling_is_never_made() -> None:
    """Refused before the call, which is the entire design.

    Post-hoc accounting cannot stop an overrun it only discovers once the money is gone.
    """
    accountant = UsageAccountant(max_usd=0.01)
    with pytest.raises(BudgetExceededError):
        await accountant.reserve(OPUS, input_tokens=100_000, max_output_tokens=60_000)

    assert accountant.ledger.calls == 0
    assert accountant.ledger.settled_usd == 0.0


async def test_the_reservation_is_worst_case_and_settles_to_actual() -> None:
    """The ceiling is conservative in the safe direction, and the headroom returns as soon
    as the real usage is known."""
    accountant = UsageAccountant(max_usd=10.0)
    reservation = await accountant.reserve(HAIKU, input_tokens=1_000, max_output_tokens=8_000)

    held = accountant.ledger.reserved_usd
    assert held == pytest.approx((1_000 * 1.0 + 8_000 * 5.0) / 1_000_000)

    actual = await accountant.settle(reservation, Usage(input_tokens=1_000, output_tokens=50))

    assert accountant.ledger.reserved_usd == pytest.approx(0.0)
    assert actual < held, "actual usage is almost always below the worst case"
    assert accountant.ledger.settled_usd == pytest.approx(actual)


async def test_concurrent_reservations_cannot_collectively_exceed_the_ceiling() -> None:
    """The case the naive implementation gets wrong.

    Twenty callers each read a total below the ceiling and all proceed, and the ceiling
    becomes advisory. The money is real, so this test is not optional.
    """
    per_call = MODEL_CAPABILITIES[HAIKU].cost_usd(1_000, 8_000)
    ceiling = per_call * 5.5  # room for exactly five
    accountant = UsageAccountant(max_usd=ceiling)

    async def attempt() -> bool:
        try:
            await accountant.reserve(HAIKU, input_tokens=1_000, max_output_tokens=8_000)
        except BudgetExceededError:
            return False
        return True

    granted = sum(await asyncio.gather(*(attempt() for _ in range(20))))

    assert granted == 5
    assert accountant.ledger.committed_usd <= ceiling


async def test_a_failed_request_returns_its_hold() -> None:
    """A hold left behind after a failure shrinks the budget for the rest of the run, so a
    sweep that hit a few transient errors would stop early with money unspent."""
    accountant = UsageAccountant(max_usd=1.0)
    reservation = await accountant.reserve(HAIKU, input_tokens=1_000, max_output_tokens=8_000)
    await accountant.release(reservation)

    assert accountant.ledger.reserved_usd == pytest.approx(0.0)
    assert accountant.remaining_usd == pytest.approx(1.0)


async def test_a_reservation_cannot_be_settled_twice() -> None:
    """Settling twice credits the hold back twice and inflates the remaining budget - a
    bookkeeping bug that spends real money."""
    accountant = UsageAccountant(max_usd=1.0)
    reservation = await accountant.reserve(HAIKU, input_tokens=100, max_output_tokens=100)
    await accountant.settle(reservation, Usage(input_tokens=100, output_tokens=10))

    with pytest.raises(ValueError, match="not open"):
        await accountant.settle(reservation, Usage(input_tokens=100, output_tokens=10))


def test_a_non_positive_ceiling_is_refused() -> None:
    with pytest.raises(ValueError, match="positive"):
        UsageAccountant(max_usd=0.0)


async def test_the_report_carries_what_an_artifact_needs() -> None:
    accountant = UsageAccountant(max_usd=25.0)
    reservation = await accountant.reserve(HAIKU, input_tokens=1_000, max_output_tokens=1_000)
    await accountant.settle(reservation, Usage(input_tokens=1_000, output_tokens=200))

    report = accountant.report()
    assert report["ceiling_usd"] == 25.0
    assert report["calls"] == 1
    assert HAIKU in report["per_model_usd"]  # type: ignore[operator]


# =========================================================== provider selection


def test_the_default_provider_cannot_spend_money() -> None:
    """``--live`` must be passed explicitly and truthfully. There is deliberately no
    "detect a key and use it" path: a key present in the environment for unrelated reasons
    would silently turn a free run into a paid one."""
    provider = select_provider(
        live=False, api_key="sk-ant-something", accountant=UsageAccountant(max_usd=25.0)
    )
    assert isinstance(provider, MockProvider)


def test_live_without_a_key_is_an_error_not_a_silent_downgrade() -> None:
    """Falling back to the mock here would produce a run labelled live that never called
    a model, which is worse than failing."""
    with pytest.raises(ProviderError, match="no API key"):
        select_provider(live=True, api_key=None, accountant=UsageAccountant(max_usd=25.0))


def test_the_mock_is_not_a_subclass_of_the_live_provider() -> None:
    """No inheritance means no path by which the mock accidentally acquires a network
    call, which is what makes the credential-free CI guarantee structural."""
    assert not issubclass(MockProvider, AnthropicProvider)
    assert not issubclass(AnthropicProvider, MockProvider)


def test_the_pricing_pin_is_recorded() -> None:
    """A cost ceiling computed from stale prices is a ceiling in name only."""
    from agentsec.agent.provider import PRICING_PINNED

    assert PRICING_PINNED
    assert MODEL_CAPABILITIES[OPUS].input_usd_per_mtok == 5.0
    assert MODEL_CAPABILITIES[OPUS].output_usd_per_mtok == 25.0
    assert MODEL_CAPABILITIES[HAIKU].input_usd_per_mtok == 1.0
    assert MODEL_CAPABILITIES[HAIKU].output_usd_per_mtok == 5.0


def test_every_capability_entry_is_internally_consistent() -> None:
    for model, capabilities in MODEL_CAPABILITIES.items():
        assert capabilities.model == model
        assert capabilities.input_usd_per_mtok > 0
        assert capabilities.output_usd_per_mtok >= capabilities.input_usd_per_mtok
        assert capabilities.max_output_tokens > 0
        if capabilities.thinking is ThinkingMode.BUDGETED:
            assert capabilities.default_thinking_budget > 0, model
