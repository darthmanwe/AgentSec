"""Model provider contracts and the per-model capability table (AS-024).

The model arrives last, and deliberately so: everything that constrains it was built and
verified before it existed. By the time a planner speaks here, the authorization kernel,
the gateway, the approval gate and the sandbox have all been proven without any model at
all. That ordering is the argument.

**Why a capability table rather than one request shape.** Claude Opus 5 and Claude Haiku
4.5 do not accept the same request. Opus 5 takes ``thinking={"type": "adaptive"}`` and an
``effort`` setting, and rejects ``budget_tokens``. Haiku 4.5 rejects adaptive thinking —
it wants ``{"type": "enabled", "budget_tokens": N}`` — and errors on ``effort``. A single
hardcoded request shape works for exactly one of the two models, and the evaluation needs
both: Haiku for the bulk sweep the budget can afford, Opus for the headline arm.

So the differences live in data, and request construction is driven by it. Adding a third
model is a table entry, not a branch in the request builder.

**Provenance travels with every response.** ``ModelResponse.model`` is whatever the
provider *returned*, not what was asked for. An alias can be repointed; a benchmark that
records the requested name would silently attribute one model's numbers to another.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from agentsec.agent.schema import validate_output_schema
from agentsec.log import get_logger

log = get_logger("agentsec.agent.provider")

#: The date the price table below was read from Anthropic's published pricing. Recorded
#: because a cost ceiling computed from stale prices is a ceiling in name only.
PRICING_PINNED: Final = "2026-08-31"


class ThinkingMode(enum.StrEnum):
    """How a model wants extended thinking configured.

    Three values because there are three incompatible shapes, not because three felt like
    a good number. Sending the wrong one is a 400, not a degraded result.
    """

    NONE = "none"
    ADAPTIVE = "adaptive"
    """``{"type": "adaptive"}``. Opus 5. Rejects ``budget_tokens``."""

    BUDGETED = "budgeted"
    """``{"type": "enabled", "budget_tokens": N}``. Haiku 4.5. Rejects adaptive."""


class Effort(enum.StrEnum):
    """Output effort, where the model supports it."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAX = "max"


class ProviderError(Exception):
    """The provider could not produce a usable response."""


class UnknownModelError(ProviderError):
    """A model with no capability entry. Fails closed rather than guessing a request shape.

    Guessing is the failure this table exists to prevent: an unknown model handled by
    "just send the default shape" is a 400 at best and, if the shapes happen to overlap,
    a silently different configuration at worst.
    """


class SchemaViolationError(ProviderError):
    """The model returned something the output schema does not accept."""


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """What one model accepts, and what it costs.

    Prices are per million tokens, pinned in code with :data:`PRICING_PINNED` recording
    when they were read. Pinned rather than fetched because the accountant has to reason
    about cost *before* a request, and a price lookup that needs the network cannot be
    part of a ceiling that is supposed to hold offline.
    """

    model: str
    thinking: ThinkingMode
    supports_effort: bool
    supports_temperature: bool
    input_usd_per_mtok: float
    output_usd_per_mtok: float
    max_output_tokens: int
    default_thinking_budget: int = 0
    """Only meaningful for BUDGETED. Ignored otherwise."""

    def cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.input_usd_per_mtok + output_tokens * self.output_usd_per_mtok
        ) / 1_000_000


#: The table. Every entry is a claim about a real API contract, and the two below differ
#: in every field that matters.
MODEL_CAPABILITIES: Final[dict[str, ModelCapabilities]] = {
    "claude-opus-5": ModelCapabilities(
        model="claude-opus-5",
        thinking=ThinkingMode.ADAPTIVE,
        supports_effort=True,
        supports_temperature=False,
        input_usd_per_mtok=5.0,
        output_usd_per_mtok=25.0,
        max_output_tokens=64_000,
    ),
    "claude-haiku-4-5-20251001": ModelCapabilities(
        model="claude-haiku-4-5-20251001",
        thinking=ThinkingMode.BUDGETED,
        supports_effort=False,
        supports_temperature=True,
        input_usd_per_mtok=1.0,
        output_usd_per_mtok=5.0,
        max_output_tokens=8_192,
        default_thinking_budget=4_096,
    ),
}


def capabilities_for(model: str) -> ModelCapabilities:
    """Look up a model, failing closed."""
    try:
        return MODEL_CAPABILITIES[model]
    except KeyError:
        raise UnknownModelError(
            f"{model!r} has no capability entry; known: {sorted(MODEL_CAPABILITIES)}. "
            "Add one rather than sending a guessed request shape."
        ) from None


@dataclass(frozen=True, slots=True)
class Message:
    """One turn. ``role`` is deliberately not an enum of every value the API allows: the
    planner only ever produces a user turn, and widening it here would widen it there."""

    role: str
    content: str


@dataclass(frozen=True, slots=True)
class Usage:
    """Tokens actually consumed, as the provider reported them."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """One call, before it is shaped for a particular provider.

    Note what is absent: there is no ``tools`` field. The planner must not be handed a
    tool surface — declaring real tools to obtain strict structured output would give the
    model exactly the capability the architecture says it must never have. Structured
    output comes from ``output_schema`` instead.
    """

    model: str
    system: str
    messages: tuple[Message, ...]
    max_output_tokens: int = 4_096
    output_schema: dict[str, Any] | None = None
    effort: Effort | None = None
    temperature: float | None = None
    thinking_budget: int | None = None
    purpose: str = "plan"
    """What this call is for. Persisted, so usage can be attributed per run stage."""


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """What came back, plus the provenance an artifact needs."""

    model: str
    """What the provider *returned*. An alias can be repointed; recording the requested
    name would attribute one model's numbers to another."""

    text: str
    usage: Usage
    stop_reason: str = ""
    latency_ms: float = 0.0
    provider: str = ""
    parsed: dict[str, Any] | None = None
    request_id: str | None = None
    thinking: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        """Whether the model ran out of room mid-answer.

        Worth its own property because a truncated plan parses as a shorter plan. Silently
        acting on the prefix of an intended action list is how a control that reads
        correct becomes one that acts on half a decision.
        """
        return self.stop_reason == "max_tokens"


@runtime_checkable
class ModelProvider(Protocol):
    """The seam the evaluation swaps.

    A protocol rather than a base class so the deterministic mock is not a subclass of the
    live provider — no inheritance means no path by which the mock accidentally acquires a
    network call.
    """

    name: str

    async def complete(self, request: ModelRequest) -> ModelResponse: ...


def response_usd(response: ModelResponse) -> float:
    """What one response cost *this run*.

    A replayed cache entry cost nothing now, whatever it cost when it was bought — that is
    the whole point of the cache, and charging a resume for calls it did not make would
    make a resumed run look more expensive than the run it completed. The mock costs
    nothing by construction.

    Returns 0.0 for a model absent from the capability table rather than raising: the
    response records what the API actually served, an alias can be repointed to a snapshot
    the table has never seen, and per-cell attribution is not the authority on spend. The
    ``UsageAccountant`` is, and it is what enforces the ceiling.
    """
    if response.metadata.get("cached") or response.provider == "mock":
        return 0.0
    capabilities = MODEL_CAPABILITIES.get(response.model)
    if capabilities is None:
        log.warning("cannot price response; model absent from the table", model=response.model)
        return 0.0
    return capabilities.cost_usd(response.usage.input_tokens, response.usage.output_tokens)


def build_thinking(capabilities: ModelCapabilities, budget: int | None) -> dict[str, Any] | None:
    """Shape the thinking configuration for one model.

    The whole reason the capability table exists, in eight lines. Getting this wrong is a
    400 from the API, which is the good outcome; the bad one is a request that succeeds
    with thinking silently disabled and a benchmark that attributes the difference to
    something else.
    """
    if capabilities.thinking is ThinkingMode.NONE:
        return None
    if capabilities.thinking is ThinkingMode.ADAPTIVE:
        # Adaptive takes no budget. Passing one is a 400.
        return {"type": "adaptive"}
    return {
        "type": "enabled",
        "budget_tokens": budget or capabilities.default_thinking_budget,
    }


def effective_max_tokens(request: ModelRequest) -> int:
    """The ``max_tokens`` that will actually be sent, thinking included.

    Extended thinking is *drawn from* ``max_tokens`` rather than added alongside it, and
    the API requires strictly more than the thinking budget so there is room left to
    answer. The capability table did not encode that, so a 4,096-token request against a
    model whose default thinking budget is also 4,096 produced::

        400 `max_tokens` must be greater than `thinking.budget_tokens`

    on every call of a funded smoke run. ``max_output_tokens`` therefore means *tokens for
    the answer*, and the thinking budget is added on top before the model ceiling is
    applied.

    Exposed rather than inlined because the cost projection must price the request that
    will really be sent. It previously hardcoded 4,096 and would have under-quoted the run
    the moment these numbers diverged.
    """
    capabilities = capabilities_for(request.model)
    thinking = build_thinking(capabilities, request.thinking_budget)
    budget = int(thinking.get("budget_tokens", 0)) if thinking else 0
    total = min(request.max_output_tokens + budget, capabilities.max_output_tokens)
    if budget and total <= budget:
        raise ProviderError(
            f"{request.model}: a thinking budget of {budget} leaves no room to answer "
            f"within the model's {capabilities.max_output_tokens}-token ceiling. Lower "
            f"the budget or raise max_output_tokens."
        )
    return total


def build_payload(request: ModelRequest) -> dict[str, Any]:
    """Turn a provider-neutral request into an Anthropic Messages payload.

    Pure, and separated from the transport for exactly that reason: the per-model
    differences this function encodes are the part that must be checked, and checking them
    must not require a paid API call. ``tests/test_provider.py`` asserts the shape for
    every model in the table.
    """
    capabilities = capabilities_for(request.model)

    payload: dict[str, Any] = {
        "model": request.model,
        "system": request.system,
        "messages": [{"role": m.role, "content": m.content} for m in request.messages],
        "max_tokens": effective_max_tokens(request),
    }

    thinking = build_thinking(capabilities, request.thinking_budget)
    if thinking is not None:
        payload["thinking"] = thinking

    output_config: dict[str, Any] = {}
    if request.output_schema is not None:
        # Checked before dispatch, not after a 400. The funded run's first smoke attempt
        # lost all 22 calls to a schema keyword the API refuses; the request never had to
        # leave the process to be known bad.
        validate_output_schema(request.output_schema)
        output_config["format"] = {
            "type": "json_schema",
            "schema": request.output_schema,
        }
    if request.effort is not None:
        if not capabilities.supports_effort:
            # Dropped rather than sent. Sending it is an error on models that lack it, and
            # silently proceeding without the caller's intent is worse than saying so.
            raise ProviderError(
                f"{request.model} does not support effort; remove it or use a model that does"
            )
        output_config["effort"] = request.effort.value
    if output_config:
        payload["output_config"] = output_config

    if request.temperature is not None:
        if not capabilities.supports_temperature:
            raise ProviderError(f"{request.model} does not accept temperature")
        payload["temperature"] = request.temperature

    return payload


def coerce_messages(messages: Sequence[Message] | Sequence[dict[str, str]]) -> tuple[Message, ...]:
    """Accept either shape at the boundary, store one shape inside."""
    return tuple(
        message if isinstance(message, Message) else Message(**message) for message in messages
    )


__all__ = [
    "MODEL_CAPABILITIES",
    "PRICING_PINNED",
    "Effort",
    "Message",
    "ModelCapabilities",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderError",
    "SchemaViolationError",
    "ThinkingMode",
    "UnknownModelError",
    "Usage",
    "build_payload",
    "build_thinking",
    "capabilities_for",
    "coerce_messages",
]
