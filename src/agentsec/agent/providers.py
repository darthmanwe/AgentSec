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
from typing import Any, Final

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
    cache: Any | None = None
    """Optional, and the reason it exists is not performance.

    A dry run claims to rehearse the code a live run will execute. If the mock bypassed
    the cache, the rehearsal would skip the single mechanism the funded run most depends
    on - the one that makes a crash cost time instead of budget - and "rehearses the code
    that will run" would be false about the part that matters. So the mock reads and writes
    the cache too, at a recorded cost of zero."""

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if self.cache is not None:
            cached = self.cache.get(request)
            if cached is not None:
                replayed: ModelResponse = cached.as_response()
                return replayed

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
        response = ModelResponse(
            model=request.model,
            text=text,
            usage=usage,
            stop_reason=self.stop_reason,
            latency_ms=self.latency_ms,
            provider=self.name,
            parsed=parsed,
            metadata={"mock": True},
        )
        if self.cache is not None:
            # Cost zero: a rehearsal must not imply a resumed live run would be free.
            self.cache.put(request, response, 0.0)
        return response

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


#: Safety multiplier on the character heuristic.
#:
#: Four characters per token is a reasonable average and a bad *reservation*: it
#: under-counts code, JSON and non-Latin text, and an under-reservation makes the budget
#: ceiling weaker than the number the operator set. The accountant reconciles against
#: actual usage afterwards, so over-reserving costs nothing but a little headroom, while
#: under-reserving costs money. The asymmetry decides the direction.
TOKEN_SAFETY_FACTOR: Final = 1.35


def _estimate_tokens(request: ModelRequest) -> int:
    """A deliberately conservative token estimate.

    Used for the pre-request reservation, so it errs high. See TOKEN_SAFETY_FACTOR.
    """
    characters = len(request.system) + sum(len(m.content) for m in request.messages)
    schema = len(json.dumps(request.output_schema)) if request.output_schema else 0
    return max(1, int(((characters + schema) / 4) * TOKEN_SAFETY_FACTOR))


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
        cache: Any | None = None,
        retry_log: Any | None = None,
        count_tokens: bool = True,
    ) -> None:
        if not api_key and client is None:
            # Fails at construction rather than at the first call. A provider built
            # without a key is a provider that will fail in the middle of a sweep.
            raise ProviderError("AnthropicProvider requires an API key")
        self._accountant = accountant
        self._cache = cache
        self._retry_log = retry_log
        self._count_tokens = count_tokens
        if client is not None:
            self._client = client
        else:
            try:
                from anthropic import AsyncAnthropic
            except ImportError as error:  # pragma: no cover - exercised only without the SDK
                raise ProviderError(
                    "the anthropic SDK is not installed; live calls are unavailable"
                ) from error
            # The SDK retries too, and that is fine: its retries handle the fast transient
            # cases and ours handle the slow ones (a rate-limit window outlasts any
            # sensible client-level schedule). Both are bounded, so they compose.
            self._client = AsyncAnthropic(api_key=api_key, max_retries=max_retries)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        """Make one call, or replay one already paid for.

        The cache is consulted **before** the reservation. A cached response costs
        nothing, so reserving against the ceiling for it would make a resumed run appear
        to spend budget it is not spending - and could refuse a call the operator has
        already funded.
        """
        if self._cache is not None:
            cached = self._cache.get(request)
            if cached is not None:
                replayed: ModelResponse = cached.as_response()
                return replayed

        capabilities = capabilities_for(request.model)
        payload = build_payload(request)
        estimated = await self._estimate_input_tokens(request, payload)

        reservation = await self._accountant.reserve(
            request.model,
            input_tokens=estimated,
            max_output_tokens=min(request.max_output_tokens, capabilities.max_output_tokens),
            purpose=request.purpose,
        )

        started = time.monotonic()
        try:
            raw = await self._request_with_retry(payload, request)
            latency_ms = (time.monotonic() - started) * 1000
            response = _decode(raw, request, latency_ms)
        except BaseException:
            # Released on *every* failure path, not only on a transport error. An earlier
            # version released only around the client call, so an exception while decoding
            # a response would leak the hold - and a sweep that hit a few of those would
            # stop early with money unspent, blaming a budget it had not used.
            await self._accountant.release(reservation)
            raise

        actual_usd = await self._accountant.settle(reservation, response.usage)

        # Written before returning, so a crash in whatever the caller does next cannot
        # lose a response that has been paid for.
        if self._cache is not None:
            self._cache.put(request, response, actual_usd)
        return response

    async def _request_with_retry(self, payload: dict[str, Any], request: ModelRequest) -> Any:
        """Send the request, retrying transient failures with backoff.

        Imported here rather than at module scope so the mock path stays free of it.
        """
        from agentsec.eval.resilience import with_retry

        async def attempt() -> Any:
            return await self._client.messages.create(**payload)

        return await with_retry(
            attempt,
            what=f"{request.model} {request.purpose}",
            retry_log=self._retry_log,
        )

    async def _estimate_input_tokens(self, request: ModelRequest, payload: dict[str, Any]) -> int:
        """Count input tokens exactly where the API will do it for free.

        ``messages.count_tokens`` is not billed, and an exact count makes the reservation
        tight instead of merely conservative. It is best-effort: if the endpoint is
        unavailable or the SDK version lacks it, the conservative character heuristic is
        used instead. A failure to *count* must never prevent a call the operator funded.
        """
        if not self._count_tokens:
            return _estimate_tokens(request)
        try:
            counted = await self._client.messages.count_tokens(
                model=payload["model"],
                system=payload.get("system"),
                messages=payload["messages"],
            )
            tokens = int(getattr(counted, "input_tokens", 0) or 0)
        except Exception:  # counting is best-effort by design; see the docstring
            return _estimate_tokens(request)
        return tokens if tokens > 0 else _estimate_tokens(request)


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

    # Usage is *required*, unlike everything else here.
    #
    # An earlier version read it with getattr defaults like the other fields, which meant
    # an unreadable usage object silently produced zero tokens - so the accountant settled
    # every call at $0.00, the ledger showed no spend, and the budget ceiling could never
    # trigger. The run would spend the real money while reporting none of it. A fault
    # injection test found this by handing the decoder a response whose shape had changed.
    #
    # A response that cannot be priced cannot be accounted for, and failing the call is
    # strictly better than under-reporting the spend: the reservation is released, the
    # cell is recorded as unscoreable, and the operator finds out immediately.
    usage_obj = getattr(raw, "usage", None)
    if usage_obj is None:
        raise ProviderError(
            f"{getattr(raw, 'model', 'unknown')} returned a response with no usage; "
            "refusing to settle a call that cannot be priced"
        )
    try:
        input_tokens = int(usage_obj.input_tokens or 0)
        output_tokens = int(usage_obj.output_tokens or 0)
    except (AttributeError, TypeError, ValueError) as error:
        raise ProviderError(
            f"could not read token usage ({type(error).__name__}); refusing to settle a "
            "call that cannot be priced"
        ) from error

    usage = Usage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
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
    cache: Any | None = None,
    retry_log: Any | None = None,
) -> Any:
    """Choose a provider. **The default is the one that cannot spend money.**

    ``live`` has to be passed explicitly and truthfully; there is no "detect a key and use
    it" path, because a key present in the environment for unrelated reasons would then
    silently turn a free run into a paid one.
    """
    if not live:
        # The cache is wired into the mock as well, so a dry run rehearses the resume path
        # rather than skipping the mechanism the funded run depends on most.
        return MockProvider(responses=dict(mock_responses or {}), cache=cache)
    if not api_key:
        raise ProviderError("--live was requested but no API key is configured")
    log.warning(
        "live provider selected; this run will spend real credit",
        ceiling_usd=accountant.ceiling_usd,
    )
    return AnthropicProvider(api_key, accountant, cache=cache, retry_log=retry_log)


__all__ = [
    "TOKEN_SAFETY_FACTOR",
    "AnthropicProvider",
    "MockProvider",
    "fingerprint",
    "select_provider",
]
