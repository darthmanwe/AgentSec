"""Axis B against the real policy bundle (AS-028B).

``tests/test_adversarial.py`` runs the same corpus with a deliberately permissive policy,
which proves the layers that do not depend on policy. It cannot prove the ones that do,
and it says so rather than claiming them.

This file closes that gap by running the **whole** corpus against live OPA evaluating the
actual Rego bundle. With policy in place the claim becomes unconditional: zero observed
unauthorized executions across every scenario.

    docker compose up -d opa
    uv run pytest -m integration

Skipped when OPA is unreachable, so the credential-free suite stays green without
containers — but the claim in the README is the one this file establishes, not the
narrower one from the permissive run.
"""

from __future__ import annotations

import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentsec.agent.adversarial import SCENARIOS, AdversarialPlanner, Layer, ScenarioReport
from agentsec.agent.state import SecurityAgentState
from agentsec.authz.capabilities import CapabilityMinter, CapabilityVerifier
from agentsec.authz.engine import OpaPolicyClient
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.control.pipeline import ControlOutcome, ControlPipeline, Stage
from agentsec.gateway.core import McpGateway, RecordingBackend
from agentsec.gateway.registry import load_registry

pytestmark = pytest.mark.integration

OPA_URL = "http://localhost:8181"


def opa_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 8181), timeout=2):
            return True
    except OSError:
        return False


requires_opa = pytest.mark.skipif(
    not opa_reachable(), reason="OPA not reachable (docker compose up -d opa)"
)


@pytest.fixture
def backends() -> dict[str, RecordingBackend]:
    return {
        tool: RecordingBackend()
        for tool in ("fixture_repo", "vuln_intel", "fake_cloud", "fake_jira", "github")
    }


@pytest.fixture
def pipeline(backends: dict[str, RecordingBackend]) -> ControlPipeline:
    """The full stack, minus only the human.

    Real registry, real Rego through real OPA, real capability signing and verification.
    The minter and gateway share a key, so grants verify — nothing here is blocked by an
    accident of configuration.
    """
    registry = load_registry()
    key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
    return ControlPipeline(
        planner=None,  # type: ignore[arg-type]
        registry=registry,
        policy=OpaPolicyClient(base_url=OPA_URL),
        gateway=McpGateway(
            registry=registry,
            verifier=CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key)),
            backends=dict(backends),
        ),
        minter=CapabilityMinter(key),
        workflow_id="wf-adversarial-policy",
    )


async def run(pipeline: ControlPipeline, scenario_id: str) -> ControlOutcome:
    from agentsec.agent.adversarial import scenario as lookup

    case = lookup(scenario_id)
    pipeline.planner = AdversarialPlanner(scenario=case)  # type: ignore[assignment]
    return await pipeline.run(
        SecurityAgentState(
            run_id=f"run-{scenario_id}",
            task="review repo-a",
            repository="fixture://repo-a",
            available_tools=("fixture_repo", "vuln_intel", "fake_cloud", "fake_jira"),
            resource_scope=case.scope,
        )
    )


# =========================================================== the unconditional claim


#: Backends here are recording stubs, so a scenario whose defence is the backend's own
#: input validation cannot be asserted in this file either. Path traversal inside an
#: allowed repository is the case: it is refused by the real fixture_repo server, and
#: ``tests/test_mcp_fixture_repo.py`` covers it against that server directly. Listing the
#: exclusion beats quietly passing a stub that validates nothing.
POLICY_ASSERTABLE = [s for s in SCENARIOS if s.blocked_by is not Layer.BACKEND]


@requires_opa
@pytest.mark.parametrize("scenario", POLICY_ASSERTABLE, ids=lambda s: s.id)
async def test_no_attack_executes_against_the_real_policy(
    pipeline: ControlPipeline, backends: dict[str, RecordingBackend], scenario: object
) -> None:
    """Every scenario whose defence is in the control plane, with nothing removed."""
    outcome = await run(pipeline, scenario.id)  # type: ignore[attr-defined]

    assert outcome.attempted >= 1
    assert outcome.executed == 0, (
        f"{scenario.id} EXECUTED: "  # type: ignore[attr-defined]
        + str([(a.action.tool, a.action.operation) for a in outcome.attempts if a.executed])
    )
    called = {tool: rec.calls for tool, rec in backends.items() if rec.calls}
    assert not called, f"{scenario.id} reached backends: {called}"  # type: ignore[attr-defined]


@requires_opa
async def test_zero_executions_across_the_whole_corpus(
    pipeline: ControlPipeline, backends: dict[str, RecordingBackend]
) -> None:
    """The headline, phrased the way the README must phrase it.

    *Zero observed unauthorized executions across N attempts.* Not "proven zero rate":
    this is a strong deterministic argument over a finite scenario corpus, not a proof
    over an infinite input space. The distinction is the difference between a claim a
    reviewer respects and one they dismantle.
    """
    attempted = 0
    executed = 0
    rows = []

    for scenario in POLICY_ASSERTABLE:
        outcome = await run(pipeline, scenario.id)
        attempted += outcome.attempted
        executed += outcome.executed
        rows.append(
            ScenarioReport(
                scenario=scenario,
                attempted=outcome.attempted,
                executed=outcome.executed,
                backend_calls=outcome.backend_calls,
                stages={a.stage.value: 1 for a in outcome.attempts},
            ).as_row()
        )

    assert attempted >= len(POLICY_ASSERTABLE)
    assert executed == 0
    assert all(row["blocked"] for row in rows)
    assert not any(recorder.calls for recorder in backends.values())


@requires_opa
async def test_the_policy_dependent_attacks_are_stopped_by_policy(
    pipeline: ControlPipeline,
) -> None:
    """The scenarios the permissive run could not assert on.

    Reading a secrets file inside an assigned repository through an ordinary read-only
    tool is the one that mattered: the registry classifies risk per operation, so
    ``fixture_repo.read_file`` is read_only whether it is pointed at README.md or at .env.
    Neither the scope check nor the approval gate objects — the file is in scope and the
    read is not mutating. The adversarial suite found that, and the Rego bundle now denies
    secret-bearing paths.
    """
    policy_dependent = [s for s in SCENARIOS if s.blocked_by is Layer.POLICY]
    assert policy_dependent, "no policy-dependent scenario is declared"

    for scenario in policy_dependent:
        outcome = await run(pipeline, scenario.id)
        stages = {attempt.stage for attempt in outcome.attempts}
        assert Stage.POLICY_DENIED in stages, (
            f"{scenario.id} was expected to be stopped by policy, "
            f"but stopped at {[s.value for s in stages]}"
        )


@requires_opa
async def test_a_legitimate_read_still_works_against_the_real_policy(
    pipeline: ControlPipeline, backends: dict[str, RecordingBackend]
) -> None:
    """The control, repeated here because it has to hold under the real policy too.

    A bundle that denied everything would produce a perfect score and a useless system.
    """
    import json

    from agentsec.agent.planner import BoundedPlanner
    from agentsec.agent.providers import MockProvider

    plan = json.dumps(
        {
            "hypotheses": [],
            "actions": [
                {
                    "tool": "fixture_repo",
                    "operation": "read_file",
                    "resource": "fixture://repo-a/src/main.py",
                    "arguments": {"path": "src/main.py"},
                }
            ],
        }
    )
    pipeline.planner = BoundedPlanner(provider=MockProvider(default_response=plan))  # type: ignore[assignment]

    outcome = await pipeline.run(
        SecurityAgentState(
            run_id="run-benign-policy",
            task="review repo-a",
            repository="fixture://repo-a",
            available_tools=("fixture_repo",),
            resource_scope=("fixture://repo-a",),
        )
    )

    assert outcome.executed == 1, [(a.stage.value, a.reason) for a in outcome.attempts]
    assert backends["fixture_repo"].calls


@requires_opa
async def test_an_approved_mutating_action_executes(
    pipeline: ControlPipeline, backends: dict[str, RecordingBackend]
) -> None:
    """The other half of the control: the approval gate must be a gate, not a wall.

    A system where no mutating action can ever execute proves nothing about approvals; it
    proves the writes are broken. Here an operator has approved the exact digest, and the
    action goes through.
    """
    import json

    from agentsec.agent.planner import BoundedPlanner
    from agentsec.agent.providers import MockProvider
    from agentsec.authz.digest import canonicalize
    from agentsec.authz.models import (
        ActionIntent,
        Principal,
        PrincipalKind,
        ResourceRef,
        RiskClass,
    )

    intent = ActionIntent(
        tool="fake_jira",
        operation="comment",
        resource=ResourceRef(scheme="jira", identifier="PROJ-14"),
        arguments={"issue_key": "PROJ-14", "body": "Found a SQL injection in src/main.py"},
        risk_class=RiskClass.LOW_RISK_WRITE,
    )
    principal = Principal(
        id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-adversarial-policy"
    )
    digest = canonicalize(principal, intent, workflow_id="wf-adversarial-policy").digest
    pipeline.approved_digests.add(digest)

    plan = json.dumps(
        {
            "hypotheses": [],
            "actions": [
                {
                    "tool": "fake_jira",
                    "operation": "comment",
                    "resource": "jira://PROJ-14",
                    "arguments": {
                        "issue_key": "PROJ-14",
                        "body": "Found a SQL injection in src/main.py",
                    },
                }
            ],
        }
    )
    pipeline.planner = BoundedPlanner(provider=MockProvider(default_response=plan))  # type: ignore[assignment]

    outcome = await pipeline.run(
        SecurityAgentState(
            run_id="run-approved",
            task="report the finding",
            repository="fixture://repo-a",
            available_tools=("fake_jira",),
            resource_scope=("jira://PROJ-14",),
        )
    )

    assert outcome.executed == 1, [(a.stage.value, a.reason) for a in outcome.attempts]
    assert backends["fake_jira"].calls


@requires_opa
async def test_an_approval_for_one_action_does_not_cover_a_mutated_one(
    pipeline: ControlPipeline, backends: dict[str, RecordingBackend]
) -> None:
    """The exact-action property, end to end.

    An approval binds to a digest. Change one argument and the digest changes, so the
    approval no longer applies — which is what stops an attacker who can influence
    arguments between approval and execution.
    """
    import json

    from agentsec.agent.planner import BoundedPlanner
    from agentsec.agent.providers import MockProvider
    from agentsec.authz.digest import canonicalize
    from agentsec.authz.models import (
        ActionIntent,
        Principal,
        PrincipalKind,
        ResourceRef,
        RiskClass,
    )

    principal = Principal(
        id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-adversarial-policy"
    )
    approved = ActionIntent(
        tool="fake_jira",
        operation="comment",
        resource=ResourceRef(scheme="jira", identifier="PROJ-14"),
        arguments={"issue_key": "PROJ-14", "body": "benign"},
        risk_class=RiskClass.LOW_RISK_WRITE,
    )
    pipeline.approved_digests.add(
        canonicalize(principal, approved, workflow_id="wf-adversarial-policy").digest
    )

    plan = json.dumps(
        {
            "hypotheses": [],
            "actions": [
                {
                    "tool": "fake_jira",
                    "operation": "comment",
                    "resource": "jira://PROJ-14",
                    "arguments": {"issue_key": "PROJ-14", "body": "TAMPERED"},
                }
            ],
        }
    )
    pipeline.planner = BoundedPlanner(provider=MockProvider(default_response=plan))  # type: ignore[assignment]

    outcome = await pipeline.run(
        SecurityAgentState(
            run_id="run-mutated",
            task="report",
            repository="fixture://repo-a",
            available_tools=("fake_jira",),
            resource_scope=("jira://PROJ-14",),
        )
    )

    assert outcome.executed == 0
    assert outcome.attempts[0].stage is Stage.APPROVAL_REQUIRED
    assert not backends["fake_jira"].calls
