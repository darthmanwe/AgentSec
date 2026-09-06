"""Concrete providers: a deterministic mock and the live Anthropic client (AS-024).

Two implementations of the same protocol, and the mock is not a subclass of the live one.
That is deliberate: no inheritance means no path by which the mock accidentally acquires a
network call, and the CI guarantee — the whole suite runs with ``ANTHROPIC_API_KEY``
empty — is structural rather than a matter of remembering to patch something.

The live client is imported *inside* the constructor. The package therefore imports fine
without the Anthropic SDK installed, and nothing on the mock path can transitively drag in
an HTTP client.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from agentsec.agent.accounting import UsageAccountant
from agentsec.agent.provider import (
    ModelRequest,
    ModelResponse,
    ProviderError,
    Usage,
    build_payload,
    capabilities_for,
)
from agentsec.log import get_logger

log = get_logger("agentsec.agent.providers")

Responder = Callable[[ModelRequest], str]


@dataclass
class MockProvider:
    """A provider that never touches the network and always answers the same way.

    Two properties matter and both are load-bearing for the evaluation.

    **Deterministic.** The same request produces the same response, byte for byte, because
    the reply is selected by hashing the request. An ablation run that cannot be repeated
    is not a measurement, and a mock that returned varying text would make every
    difference between cells uninterpretable.

    **Free.** This is what the ``--live`` flag defaults away from. Most of the suite, and
    all of CI, runs here.
    """

    name: str = "mock"
    responses: dict[str, str] = field(default_factory=dict)
    """Keyed by request fingerprint. A miss falls back to :attr:`default_response`."""

    responder: Responder | None = None
    """Full control for a test that needs to vary the answer by request."""

    default_response: str = "{}"
    calls: list[ModelRequest] = field(default_factory=list)
    latency_ms: float = 0.0
    stop_reason: str = "end_turn"

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        text = self._select(request)

        parsed: dict[str, Any] | None = None
        if request.output_schema is not None:
            try:
                candidate = json.loads(text)
                parsed = candidate if isinstance(candidate, dict) else None
            except json.JSONDecodeError:
                # Left as None rather than raising: a model returning unparseable text is
                # a case the planner has to handle, and the mock exists partly to produce
                # it on demand.
                parsed = None

        usage = Usage(
            input_tokens=_estimate_tokens(request),
            output_tokens=max(1, len(text) // 4),
        )
        return ModelResponse(
            model=request.model,
            text=text,
            usage=usage,
            stop_reason=self.stop_reason,
            latency_ms=self.latency_ms,
            provider=self.name,
            parsed=parsed,
            metadata={"mock": True},
        )

    def _select(self, request: ModelRequest) -> str:
        if self.responder is not None:
            return self.responder(request)
        return self.responses.get(fingerprint(request), self.default_response)

    def queue(self, request: ModelRequest, response: str) -> None:
        self.responses[fingerprint(request)] = response


def fingerprint(request: ModelRequest) -> str:
    """A stable identity for a request.

    Covers the model, the system prompt and every message. Deliberately excludes sampling
    settings: two calls that differ only in temperature are the same question, and keying
    on them would make a fixture miss for a reason nobody would think to look for.
    """
    material = json.dumps(
        {
            "model": request.model,
            "system": request.system,
            "messages": [[m.role, m.content] for m in request.messages],
            "purpose": request.purpose,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _estimate_tokens(request: ModelRequest) -> int:
    """Roughly four characters per token. Good enough for a mock, and used for nothing
    that spends money."""
    characters = len(request.system) + sum(len(m.content) for m in request.messages)
    return max(1, characters // 4)


class AnthropicProvider:
    """The live client.

    Every call passes through the accountant first: a reservation is taken for the worst
    case, the request is made, and the reservation is reconciled against actual usage. A
    request that cannot fit under the ceiling is never sent.

    The SDK is imported here rather than at module scope so that importing ``agentsec``
    does not require it, and so nothing on the mock path can reach an HTTP client
    transitively.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        accountant: UsageAccountant,
        *,
        client: Any | None = None,
        max_retries: int = 2,
    ) -> None:
        if not api_key and client is None:
            # Fails at construction rather than at the first call. A provider built
            # without a key is a provider that will fail in the middle of a sweep.
            raise ProviderError("AnthropicProvider requires an API key")
        self._accountant = accountant
        if client is not None:
            self._client = client
        else:
            try:
                from anthropic import AsyncAnthropic
            except ImportError as error:  # pragma: no cover - exercised only without the SDK
                raise ProviderError(
                    "the anthropic SDK is not installed; live calls are unavailable"
                ) from error
            self._client = AsyncAnthropic(api_key=api_key, max_retries=max_retries)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        capabilities = capabilities_for(request.model)
        payload = build_payload(request)

        reservation = await self._accountant.reserve(
            request.model,
            input_tokens=_estimate_tokens(request),
            max_output_tokens=min(request.max_output_tokens, capabilities.max_output_tokens),
            purpose=request.purpose,
        )

        started = time.monotonic()
        try:
            raw = await self._client.messages.create(**payload)
        except Exception as error:
            # The request failed, so it cost nothing. Holding the reservation would shrink
            # the budget for the rest of the run and stop a sweep early with money unspent.
            await self._accountant.release(reservation)
            raise ProviderError(
                f"anthropic request failed: {type(error).__name__}: {error}"
            ) from error

        latency_ms = (time.monotonic() - started) * 1000
        response = _decode(raw, request, latency_ms)
        await self._accountant.settle(reservation, response.usage)
        return response


def _decode(raw: Any, request: ModelRequest, latency_ms: float) -> ModelResponse:
    """Turn an SDK response into a provider-neutral one.

    Read defensively. The SDK's response objects change shape across versions, and a
    KeyError in the middle of a paid sweep loses the call *and* the money.
    """
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    for block in getattr(raw, "content", None) or []:
        kind = getattr(block, "type", None)
        if kind == "text":
            text_parts.append(str(getattr(block, "text", "")))
        elif kind == "thinking":
            thinking_parts.append(str(getattr(block, "thinking", "")))

    text = "".join(text_parts)
    usage_obj = getattr(raw, "usage", None)
    usage = Usage(
        input_tokens=int(getattr(usage_obj, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage_obj, "output_tokens", 0) or 0),
        cache_read_tokens=int(getattr(usage_obj, "cache_read_input_tokens", 0) or 0),
        cache_creation_tokens=int(getattr(usage_obj, "cache_creation_input_tokens", 0) or 0),
    )

    parsed: dict[str, Any] | None = None
    if request.output_schema is not None and text.strip():
        try:
            candidate = json.loads(text)
            parsed = candidate if isinstance(candidate, dict) else None
        except json.JSONDecodeError:
            parsed = None

    return ModelResponse(
        # What the API returned, not what was requested. An alias can be repointed.
        model=str(getattr(raw, "model", request.model)),
        text=text,
        usage=usage,
        stop_reason=str(getattr(raw, "stop_reason", "") or ""),
        latency_ms=latency_ms,
        provider="anthropic",
        parsed=parsed,
        request_id=getattr(raw, "_request_id", None),
        thinking="".join(thinking_parts),
    )


def select_provider(
    *,
    live: bool,
    api_key: str | None,
    accountant: UsageAccountant,
    mock_responses: Mapping[str, str] | None = None,
) -> Any:
    """Choose a provider. **The default is the one that cannot spend money.**

    ``live`` has to be passed explicitly and truthfully; there is no "detect a key and use
    it" path, because a key present in the environment for unrelated reasons would then
    silently turn a free run into a paid one.
    """
    if not live:
        return MockProvider(responses=dict(mock_responses or {}))
    if not api_key:
        raise ProviderError("--live was requested but no API key is configured")
    log.warning(
        "live provider selected; this run will spend real credit",
        ceiling_usd=accountant.ceiling_usd,
    )
    return AnthropicProvider(api_key, accountant)


__all__ = [
    "AnthropicProvider",
    "MockProvider",
    "fingerprint",
    "select_provider",
]
