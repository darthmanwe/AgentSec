"""MCP Gateway core authorization path (AS-014).

The only supported route from AgentSec to a tool backend. Everything the planner might
want to do arrives here, and this is the last place anything can be stopped.

**The ordering is the design.** Each check is placed so that failing it is impossible to
reach a backend from:

1. registry lookup — an unknown tool has no definition, so nothing downstream can run
2. argument validation — against the *registry's* schema, never the server's
3. canonicalisation — produces the exact bytes that will be dispatched (AS-007)
4. capability verification — every binding, against the request about to be sent
5. execution ledger — consulted **before** redemption, so retries do not deadlock
6. redemption — single use, enforced by a database constraint
7. dispatch — only now does a backend hear about any of this

A denial at any step returns before step 7. That is asserted directly: the test backend
records every invocation, and every denial test requires the recording to be empty. "No
backend call happened" is the property AS-012 could not assert because no gateway existed;
it lives here now.

Capability enforcement is gateway-only (ADR-0001). The MCP servers are private stdio
subprocesses this gateway spawns; they do not independently verify grants, because a
second redemption of a single-use token would conflict with the first.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import enum
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

import jsonschema

from agentsec.authz.capabilities import (
    CapabilityDenial,
    CapabilityRedeemer,
    CapabilityVerifier,
    ExpectedBinding,
    compute_request_hash,
)
from agentsec.authz.digest import canonicalize
from agentsec.authz.models import ActionIntent, Principal, TrustLevel
from agentsec.gateway.registry import ToolRegistry, UnknownToolError
from agentsec.log import get_logger

log = get_logger("agentsec.gateway")

#: Hard ceiling regardless of what a registry entry asks for. A registry edit should not
#: be able to hand a backend unbounded memory.
ABSOLUTE_MAX_RESULT_BYTES: Final = 16 * 1024 * 1024

Clock = Callable[[], dt.datetime]


class GatewayDenial(enum.StrEnum):
    """Why the gateway refused. Granular so reports can separate causes."""

    UNKNOWN_TOOL = "gateway_unknown_tool"
    INVALID_ARGUMENTS = "gateway_invalid_arguments"
    SCHEME_NOT_PERMITTED = "gateway_scheme_not_permitted_for_tool"
    NO_CAPABILITY = "gateway_no_capability_presented"
    CAPABILITY_REJECTED = "gateway_capability_rejected"
    REPLAYED = "gateway_capability_replayed"
    NO_BACKEND = "gateway_no_backend_registered"
    TIMEOUT = "gateway_backend_timeout"
    OVERSIZED_RESULT = "gateway_oversized_result"
    BACKEND_ERROR = "gateway_backend_error"


@dataclass(frozen=True, slots=True)
class ToolResult:
    """What a backend returned. Always carries a trust label."""

    payload: Any
    trust: TrustLevel = TrustLevel.UNTRUSTED


@runtime_checkable
class ToolBackend(Protocol):
    """A tool implementation. Real MCP servers arrive in AS-015 onward.

    Backends never see a capability token and never make an authorization decision. By
    the time one is called, everything has already been decided.
    """

    async def invoke(self, tool: str, operation: str, arguments: dict[str, Any]) -> Any: ...


@runtime_checkable
class ExecutionLedger(Protocol):
    """Seam for AS-022. Consulted before redemption so a retry of a completed operation
    returns its cached result rather than presenting a spent capability.

    Optional here: AS-014 must not implement AS-022. When absent, every dispatch is treated
    as a first attempt — correct for reads, and the mutating paths that need it do not
    exist until AS-022 lands.
    """

    async def completed_result(self, operation_id: str) -> Any | None: ...

    async def record_completion(self, operation_id: str, result: Any) -> None: ...


@runtime_checkable
class AuditSink(Protocol):
    async def record(self, event_type: str, payload: dict[str, Any]) -> None: ...


class InMemoryAuditSink:
    """Audit sink for tests and for the offline evaluation path."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def record(self, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append((event_type, payload))

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [payload for name, payload in self.events if name == event_type]


@dataclass(frozen=True, slots=True)
class DispatchRequest:
    """One attempt to invoke a tool."""

    principal: Principal
    intent: ActionIntent
    workflow_id: str
    capability_token: str | None
    operation_id: str
    run_id: str | None = None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    """The outcome, including whether a backend was reached."""

    ok: bool
    denial: GatewayDenial | None = None
    detail: str | None = None
    result: ToolResult | None = None
    action_digest: str | None = None
    duration_ms: float | None = None
    reached_backend: bool = False

    def __post_init__(self) -> None:
        if self.ok and self.denial is not None:
            raise ValueError("a successful dispatch cannot carry a denial")
        if not self.ok and self.denial is None:
            raise ValueError("a refused dispatch must say why")
        if not self.ok and self.reached_backend and self.denial not in _BACKEND_STAGE_DENIALS:
            # Structural guard: only failures that happen *at* the backend may claim to
            # have reached it. Anything else marking reached_backend would mean an
            # authorization failure let a call through.
            raise ValueError(f"denial {self.denial} must not report reaching the backend")


_BACKEND_STAGE_DENIALS: Final = frozenset(
    {GatewayDenial.TIMEOUT, GatewayDenial.OVERSIZED_RESULT, GatewayDenial.BACKEND_ERROR}
)


class McpGateway:
    """The sole dispatch path."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        verifier: CapabilityVerifier,
        redeemer: CapabilityRedeemer | None = None,
        backends: dict[str, ToolBackend] | None = None,
        audit: AuditSink | None = None,
        ledger: ExecutionLedger | None = None,
        audience: str = "agentsec-gateway",
        environment: str = "local",
        policy_bundle_hash: str | None = None,
    ) -> None:
        self._registry = registry
        self._verifier = verifier
        self._redeemer = redeemer
        self._backends = backends or {}
        self._audit = audit or InMemoryAuditSink()
        self._ledger = ledger
        self._audience = audience
        self._environment = environment
        self._policy_bundle_hash = policy_bundle_hash

    @property
    def registry_hash(self) -> str:
        return self._registry.hash

    def register_backend(self, tool: str, backend: ToolBackend) -> None:
        self._backends[tool] = backend

    async def dispatch(self, request: DispatchRequest) -> GatewayResult:
        started = time.perf_counter()
        intent = request.intent

        # 1. Registry. An unknown tool has no definition, so nothing below can run.
        try:
            definition = self._registry.lookup(intent.tool, intent.operation)
        except UnknownToolError as exc:
            return await self._deny(request, GatewayDenial.UNKNOWN_TOOL, str(exc), started)

        # 2. Scheme binding, from the registry rather than from the caller.
        if intent.resource.scheme not in definition.resource_schemes:
            return await self._deny(
                request,
                GatewayDenial.SCHEME_NOT_PERMITTED,
                f"{definition.qualified_name} may not address {intent.resource.scheme}://",
                started,
            )

        # 3. Arguments, against the *registry's* schema. A server-supplied schema would let
        #    a poisoned server widen what it accepts.
        if definition.argument_schema:
            try:
                jsonschema.validate(intent.arguments, definition.argument_schema)
            except jsonschema.ValidationError as exc:
                return await self._deny(
                    request, GatewayDenial.INVALID_ARGUMENTS, exc.message, started
                )

        # 4. Canonicalise: these are the bytes that will be dispatched, and the ones the
        #    capability is checked against.
        action = canonicalize(request.principal, intent, workflow_id=request.workflow_id)

        # 5. Capability.
        if request.capability_token is None:
            return await self._deny(
                request,
                GatewayDenial.NO_CAPABILITY,
                "no capability presented",
                started,
                action_digest=action.digest,
            )

        expected = ExpectedBinding(
            subject=request.principal.id,
            audience=self._audience,
            environment=self._environment,
            workflow_id=request.workflow_id,
            action_digest=action.digest,
            request_hash=compute_request_hash(action.arguments),
            tool=intent.tool,
            resource=intent.resource.uri,
            required_scopes=definition.required_scopes,
            registry_hash=self._registry.hash,
            policy_bundle_hash=self._policy_bundle_hash,
        )
        verification = self._verifier.verify(request.capability_token, expected)
        if not verification.ok:
            assert verification.denial is not None
            return await self._deny(
                request,
                GatewayDenial.CAPABILITY_REJECTED,
                verification.denial.value,
                started,
                action_digest=action.digest,
            )

        # 6. Execution ledger BEFORE redemption. A retry whose operation already completed
        #    returns the cached result and never presents a spent capability.
        if self._ledger is not None:
            cached = await self._ledger.completed_result(request.operation_id)
            if cached is not None:
                return GatewayResult(
                    ok=True,
                    result=ToolResult(cached, definition.result_trust),
                    action_digest=action.digest,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    reached_backend=False,
                )

        # 7. Redeem. Single use, enforced by the database constraint.
        assert verification.claims is not None
        if self._redeemer is not None and not await self._redeemer.redeem(
            verification.claims, operation_id=request.operation_id
        ):
            return await self._deny(
                request,
                GatewayDenial.REPLAYED,
                CapabilityDenial.REPLAYED.value,
                started,
                action_digest=action.digest,
            )

        # 8. Dispatch. Nothing before this point has spoken to a backend.
        backend = self._backends.get(intent.tool)
        if backend is None:
            return await self._deny(
                request,
                GatewayDenial.NO_BACKEND,
                f"no backend for {intent.tool}",
                started,
                action_digest=action.digest,
            )

        try:
            payload = await asyncio.wait_for(
                backend.invoke(intent.tool, intent.operation, action.arguments),
                timeout=definition.timeout_seconds,
            )
        except TimeoutError:
            return await self._deny(
                request,
                GatewayDenial.TIMEOUT,
                f"backend exceeded {definition.timeout_seconds}s",
                started,
                action_digest=action.digest,
                reached_backend=True,
            )
        except Exception as exc:
            log.exception("backend invocation failed", tool=intent.tool)
            return await self._deny(
                request,
                GatewayDenial.BACKEND_ERROR,
                type(exc).__name__,
                started,
                action_digest=action.digest,
                reached_backend=True,
            )

        # 9. Result size. Enforced after the call because a backend can return anything,
        #    and refused rather than truncated: a silently shortened result is a lie the
        #    planner would reason over.
        limit = min(definition.max_result_bytes, ABSOLUTE_MAX_RESULT_BYTES)
        size = _payload_size(payload)
        if size > limit:
            return await self._deny(
                request,
                GatewayDenial.OVERSIZED_RESULT,
                f"{size} bytes exceeds {limit}",
                started,
                action_digest=action.digest,
                reached_backend=True,
            )

        if self._ledger is not None:
            await self._ledger.record_completion(request.operation_id, payload)

        duration_ms = (time.perf_counter() - started) * 1000
        await self._audit.record(
            "gateway.dispatch",
            {
                "outcome": "EXECUTED",
                "tool": intent.tool,
                "operation": intent.operation,
                "resource": intent.resource.uri,
                "action_digest": action.digest,
                "run_id": request.run_id,
                "workflow_id": request.workflow_id,
                "operation_id": request.operation_id,
                "result_bytes": size,
                "duration_ms": duration_ms,
                "trust_label": definition.result_trust.value,
            },
        )
        log.info(
            "tool dispatched",
            tool=intent.tool,
            operation=intent.operation,
            action_digest=action.digest,
            result_bytes=size,
            duration_ms=duration_ms,
        )
        return GatewayResult(
            ok=True,
            result=ToolResult(payload, definition.result_trust),
            action_digest=action.digest,
            duration_ms=duration_ms,
            reached_backend=True,
        )

    async def _deny(
        self,
        request: DispatchRequest,
        denial: GatewayDenial,
        detail: str,
        started: float,
        *,
        action_digest: str | None = None,
        reached_backend: bool = False,
    ) -> GatewayResult:
        duration_ms = (time.perf_counter() - started) * 1000
        await self._audit.record(
            "gateway.denied",
            {
                "outcome": "DENIED",
                "denial": denial.value,
                "detail": detail,
                "tool": request.intent.tool,
                "operation": request.intent.operation,
                "resource": request.intent.resource.uri,
                "action_digest": action_digest,
                "run_id": request.run_id,
                "workflow_id": request.workflow_id,
                "operation_id": request.operation_id,
                "reached_backend": reached_backend,
                "duration_ms": duration_ms,
            },
        )
        log.warning(
            "tool dispatch denied",
            denial=denial.value,
            tool=request.intent.tool,
            operation=request.intent.operation,
            reached_backend=reached_backend,
        )
        return GatewayResult(
            ok=False,
            denial=denial,
            detail=detail,
            action_digest=action_digest,
            duration_ms=duration_ms,
            reached_backend=reached_backend,
        )


def _payload_size(payload: Any) -> int:
    """Serialised size of a result, for limit enforcement."""
    try:
        return len(json.dumps(payload, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return len(str(payload).encode("utf-8"))


@dataclass
class RecordingBackend:
    """A backend that records every invocation.

    Lives in the source tree rather than the tests because the "zero backend calls"
    property is what AS-014 exists to guarantee, and the evaluation harness (AS-038) needs
    the same instrument to count executions.
    """

    responses: dict[str, Any] = field(default_factory=dict)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    delay_seconds: float = 0.0
    raises: Exception | None = None

    async def invoke(self, tool: str, operation: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((tool, operation, arguments))
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.raises is not None:
            raise self.raises
        return self.responses.get(f"{tool}.{operation}", {"ok": True})

    @property
    def call_count(self) -> int:
        return len(self.calls)


__all__ = [
    "ABSOLUTE_MAX_RESULT_BYTES",
    "AuditSink",
    "DispatchRequest",
    "ExecutionLedger",
    "GatewayDenial",
    "GatewayResult",
    "InMemoryAuditSink",
    "McpGateway",
    "RecordingBackend",
    "ToolBackend",
    "ToolResult",
]
