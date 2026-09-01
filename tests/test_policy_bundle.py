"""End-to-end policy tests against a live OPA (AS-009).

The Rego unit tests in `policy/agentsec/authz_test.rego` cover the rules. These cover the
seam between the Python client and the real engine, which is where the confused-deputy gap
was actually found: every Rego test paired a tool with its own natural scheme, so none of
them ever asked what happens when `fixture_repo` is pointed at a `vuln://` resource.

    docker compose up -d opa
    uv run pytest -m integration
"""

from __future__ import annotations

import datetime as dt

import httpx
import pytest

from agentsec.authz.engine import OpaPolicyClient
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

pytestmark = [pytest.mark.integration, pytest.mark.authz]

OPA_URL = "http://localhost:8181"


def opa_reachable() -> bool:
    try:
        return httpx.get(f"{OPA_URL}/health", timeout=2.0).status_code == httpx.codes.OK
    except Exception:
        return False


requires_opa = pytest.mark.skipif(
    not opa_reachable(), reason="OPA not reachable (docker compose up -d opa)"
)


def request_for(tool: str, operation: str, risk: RiskClass, scheme: str) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1"),
        intent=ActionIntent(
            tool=tool,
            operation=operation,
            resource=ResourceRef(scheme=scheme, identifier="repo-a/src/main.py"),
            arguments={"path": "src/main.py"},
            risk_class=risk,
        ),
        requested_at=dt.datetime.now(dt.UTC),
    )


@pytest.mark.parametrize(
    ("tool", "operation", "risk", "scheme", "outcome", "reason"),
    [
        ("fixture_repo", "read_file", RiskClass.READ_ONLY, "fixture", "ALLOW", "read_permitted"),
        ("vuln_intel", "lookup_cve", RiskClass.READ_ONLY, "vuln", "ALLOW", "read_permitted"),
        ("semgrep", "scan_repository", RiskClass.READ_ONLY, "fixture", "ALLOW", "read_permitted"),
        (
            "fake_jira",
            "create_issue",
            RiskClass.HIGH_RISK_WRITE,
            "jira",
            "REQUIRE_APPROVAL",
            "mutating_operation_requires_approval",
        ),
        (
            "github",
            "comment_pull_request",
            RiskClass.HIGH_RISK_WRITE,
            "github",
            "REQUIRE_APPROVAL",
            "mutating_operation_requires_approval",
        ),
        (
            "fake_cloud",
            "apply_remediation",
            RiskClass.IRREVERSIBLE,
            "cloud",
            "REQUIRE_APPROVAL",
            "mutating_operation_requires_approval",
        ),
        (
            "fake_cloud",
            "export_secret",
            RiskClass.SECRET_ACCESS,
            "cloud",
            "DENY",
            "secret_access_always_denied",
        ),
        (
            "github",
            "delete_branch",
            RiskClass.IRREVERSIBLE,
            "github",
            "DENY",
            "operation_forbidden",
        ),
        ("mystery_tool", "read_file", RiskClass.READ_ONLY, "fixture", "DENY", "unknown_tool"),
        ("fixture_repo", "exfiltrate", RiskClass.READ_ONLY, "fixture", "DENY", "default_deny"),
        (
            "fixture_repo",
            "read_file",
            RiskClass.READ_ONLY,
            "vuln",
            "DENY",
            "resource_scheme_not_permitted_for_tool",
        ),
        (
            "fake_jira",
            "read_issue",
            RiskClass.READ_ONLY,
            "cloud",
            "DENY",
            "resource_scheme_not_permitted_for_tool",
        ),
    ],
)
@requires_opa
async def test_live_policy_decisions(
    tool: str, operation: str, risk: RiskClass, scheme: str, outcome: str, reason: str
) -> None:
    async with OpaPolicyClient(OPA_URL) as opa:
        decision = await opa.evaluate(request_for(tool, operation, risk, scheme))
    assert decision.outcome.value == outcome
    assert decision.reason_code == reason
    assert decision.fail_closed is False


@requires_opa
async def test_allow_carries_obligations() -> None:
    async with OpaPolicyClient(OPA_URL) as opa:
        decision = await opa.evaluate(
            request_for("fixture_repo", "read_file", RiskClass.READ_ONLY, "fixture")
        )
    ttl = decision.obligation(ObligationKind.CAPABILITY_TTL_SECONDS)
    assert isinstance(ttl, int)
    assert 30 <= ttl <= 120, "capability TTL must stay inside the AS-011 window"
    assert decision.obligation(ObligationKind.MAX_RESULT_BYTES) is not None


@requires_opa
async def test_no_scenario_in_the_matrix_is_allowed_by_accident() -> None:
    """Sweep every tool against every scheme and assert that only declared pairings are
    permitted. This is the shape of check that would have caught the confused-deputy gap
    before it reached a live query."""
    tools = ["fixture_repo", "vuln_intel", "fake_cloud", "fake_jira", "github"]
    schemes = ["fixture", "vuln", "cloud", "jira", "github"]
    natural = {
        "fixture_repo": "fixture",
        "vuln_intel": "vuln",
        "fake_cloud": "cloud",
        "fake_jira": "jira",
        "github": "github",
    }
    operations = {
        "fixture_repo": "read_file",
        "vuln_intel": "lookup_cve",
        "fake_cloud": "list_resources",
        "fake_jira": "read_issue",
        "github": "read_file",
    }

    async with OpaPolicyClient(OPA_URL) as opa:
        for tool in tools:
            for scheme in schemes:
                decision = await opa.evaluate(
                    request_for(tool, operations[tool], RiskClass.READ_ONLY, scheme)
                )
                if scheme == natural[tool]:
                    assert decision.outcome is PolicyOutcome.ALLOW, f"{tool} on {scheme}"
                else:
                    assert not decision.permits_execution, (
                        f"{tool} was permitted to address {scheme}://"
                    )


async def test_unreachable_engine_denies_without_needing_the_container() -> None:
    """The S1 gate requirement, provable without stopping the real OPA: point the client at
    a dead port and confirm the decision is a fail-closed DENY."""
    async with OpaPolicyClient("http://127.0.0.1:9", timeout_seconds=1.0) as opa:
        decision = await opa.evaluate(
            request_for("fixture_repo", "read_file", RiskClass.READ_ONLY, "fixture")
        )
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.fail_closed is True
    assert not decision.permits_execution
