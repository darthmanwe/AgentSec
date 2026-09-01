"""Policy engine tests (AS-008).

The fail-closed invariant is the point of this file. Every way the engine can fail gets a
test asserting DENY, because the failure this prevents — an outage silently becoming an
allow — is the one that would matter most and show up least.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import httpx
import pytest

from agentsec.authz.engine import (
    DEFAULT_DECISION_PATH,
    MAX_RESPONSE_BYTES,
    DenyAllPolicyEngine,
    OpaPolicyClient,
    PolicyEngine,
)
from agentsec.authz.models import (
    ActionIntent,
    AuthorizationRequest,
    ObligationKind,
    PolicyOutcome,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
)

pytestmark = pytest.mark.authz

NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)


def make_request(**intent_overrides: Any) -> AuthorizationRequest:
    intent = ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
        **intent_overrides,
    )
    return AuthorizationRequest(
        principal=Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1"),
        intent=intent,
        requested_at=NOW,
    )


def client_returning(handler: Any) -> OpaPolicyClient:
    transport = httpx.MockTransport(handler)
    return OpaPolicyClient(
        "http://opa:8181",
        client=httpx.AsyncClient(transport=transport),
        timeout_seconds=0.5,
    )


def json_response(payload: Any, status: int = 200) -> Any:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


# --------------------------------------------------------------------------- happy path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ALLOW", PolicyOutcome.ALLOW),
        ("DENY", PolicyOutcome.DENY),
        ("REQUIRE_APPROVAL", PolicyOutcome.REQUIRE_APPROVAL),
    ],
)
async def test_each_outcome_parses(raw: str, expected: PolicyOutcome) -> None:
    engine = client_returning(json_response({"result": {"outcome": raw, "reason_code": "ok"}}))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is expected
    assert decision.fail_closed is False
    assert decision.latency_ms is not None
    await engine.aclose()


async def test_obligations_are_parsed() -> None:
    engine = client_returning(
        json_response(
            {
                "result": {
                    "outcome": "REQUIRE_APPROVAL",
                    "reason_code": "jira_write_requires_approval",
                    "obligations": [
                        {"kind": "capability_ttl_seconds", "value": 45},
                        {"kind": "max_result_bytes", "value": 65536},
                    ],
                }
            }
        )
    )
    decision = await engine.evaluate(make_request())
    assert decision.obligation(ObligationKind.CAPABILITY_TTL_SECONDS) == 45
    await engine.aclose()


async def test_unknown_obligation_is_ignored_not_fatal() -> None:
    """An obligation can only constrain an outcome already granted; it can never widen one.
    An unknown *outcome*, by contrast, is fatal — see below."""
    engine = client_returning(
        json_response(
            {
                "result": {
                    "outcome": "ALLOW",
                    "reason_code": "ok",
                    "obligations": [{"kind": "from_the_future", "value": 1}],
                }
            }
        )
    )
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.obligations == ()
    await engine.aclose()


# --------------------------------------------------------------------------- fail closed


async def test_timeout_denies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("too slow", request=request)

    engine = client_returning(handler)
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.fail_closed is True
    assert decision.reason_code == "policy_engine_timeout"
    await engine.aclose()


async def test_connection_failure_denies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host", request=request)

    engine = client_returning(handler)
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_engine_unreachable"
    await engine.aclose()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 502, 503])
async def test_any_non_200_denies(status: int) -> None:
    engine = client_returning(json_response({"result": {"outcome": "ALLOW"}}, status=status))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.fail_closed is True
    await engine.aclose()


async def test_malformed_json_denies() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"this is not json")

    engine = client_returning(handler)
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_engine_malformed_response"
    await engine.aclose()


async def test_undefined_decision_denies() -> None:
    """OPA omits `result` when the queried path is undefined. Default-deny in the bundle
    should make that impossible, but an undefined decision must never read as permission."""
    engine = client_returning(json_response({}))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_decision_undefined"
    await engine.aclose()


@pytest.mark.parametrize(
    "outcome",
    ["ALLOWED", "allow", "PERMIT", "", None, 1, True, "MAYBE"],
)
async def test_unknown_outcome_denies(outcome: Any) -> None:
    """An unrecognised outcome is not a reason to guess. Note `"allow"` lowercase is
    rejected too: near-miss spellings are exactly how a policy bug becomes an allow."""
    engine = client_returning(json_response({"result": {"outcome": outcome, "reason_code": "ok"}}))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_engine_unknown_outcome"
    await engine.aclose()


async def test_missing_reason_code_denies() -> None:
    """Reason codes are the audit trail. An allow that cannot say why is not usable
    evidence."""
    engine = client_returning(json_response({"result": {"outcome": "ALLOW"}}))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_engine_missing_reason_code"
    await engine.aclose()


async def test_non_object_result_denies() -> None:
    engine = client_returning(json_response({"result": "ALLOW"}))
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    await engine.aclose()


async def test_oversized_response_denies() -> None:
    """An engine returning something enormous is malfunctioning; parsing it would turn a
    policy outage into a memory problem."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

    engine = client_returning(handler)
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reason_code == "policy_engine_oversized_response"
    await engine.aclose()


async def test_malformed_obligations_deny() -> None:
    engine = client_returning(
        json_response({"result": {"outcome": "ALLOW", "reason_code": "ok", "obligations": "nope"}})
    )
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    await engine.aclose()


async def test_evaluate_never_raises() -> None:
    """The contract that makes the rest safe: a caller catching an exception is a caller
    that might decide to continue."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("something entirely unexpected")

    engine = client_returning(handler)
    decision = await engine.evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.fail_closed is True
    await engine.aclose()


async def test_no_failure_path_ever_allows() -> None:
    """Swept assertion over every failure mode at once, so a newly added path that returns
    ALLOW cannot slip through by not having its own test."""
    handlers = [
        json_response({}),
        json_response({"result": {}}),
        json_response({"result": {"outcome": "ALLOW"}}),
        json_response({"result": {"outcome": "NONSENSE", "reason_code": "x"}}),
        json_response({"result": {"outcome": "ALLOW", "reason_code": ""}}),
        json_response({"result": None}),
        json_response({"result": {"outcome": "ALLOW", "reason_code": "ok"}}, status=500),
    ]
    for handler in handlers:
        engine = client_returning(handler)
        decision = await engine.evaluate(make_request())
        assert not decision.permits_execution, f"a failure path allowed execution: {handler}"
        await engine.aclose()


# --------------------------------------------------------------------------- input doc


async def test_input_document_carries_no_untrusted_text() -> None:
    """Only a count of untrusted context reaches the policy, never the content. Putting
    attacker-controlled text into the policy input would give it a route into the decision
    itself."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured.update(_json.loads(request.content))
        return httpx.Response(200, json={"result": {"outcome": "ALLOW", "reason_code": "ok"}})

    engine = client_returning(handler)
    await engine.evaluate(make_request())
    body = captured["input"]

    assert body["action"]["argument_keys"] == ["path"]
    assert "arguments" not in body["action"], "argument values must not reach the policy"
    assert body["untrusted_context_count"] == 0
    await engine.aclose()


async def test_decision_url_uses_the_configured_path() -> None:
    engine = OpaPolicyClient("http://opa:8181/")
    assert engine.decision_url == f"http://opa:8181/v1/data/{DEFAULT_DECISION_PATH}"
    await engine.aclose()


# --------------------------------------------------------------------------- default


async def test_deny_all_engine_denies() -> None:
    """`no engine configured` must be a working, denying configuration rather than a crash
    somebody works around by skipping the check."""
    decision = await DenyAllPolicyEngine().evaluate(make_request())
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.fail_closed is True


def test_engines_satisfy_the_protocol() -> None:
    assert isinstance(DenyAllPolicyEngine(), PolicyEngine)
    assert isinstance(OpaPolicyClient("http://opa:8181"), PolicyEngine)
