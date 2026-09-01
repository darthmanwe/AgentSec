"""Authorization contract tests (AS-006).

Marked ``authz``: the whole kernel must be provable with no model configured, and CI runs
this marker with ANTHROPIC_API_KEY empty as a standing check on that property.
"""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from agentsec.authz.models import (
    DENY_UNAVAILABLE,
    ActionIntent,
    AuthorizationRequest,
    ContextItem,
    ObligationKind,
    PolicyDecision,
    PolicyObligation,
    PolicyOutcome,
    Preconditions,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
    TrustLevel,
)

pytestmark = pytest.mark.authz

NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)


def make_intent(**overrides: object) -> ActionIntent:
    defaults: dict[str, object] = {
        "tool": "fixture_repo",
        "operation": "read_file",
        "resource": ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        "arguments": {"path": "src/main.py"},
        "risk_class": RiskClass.READ_ONLY,
    }
    return ActionIntent(**{**defaults, **overrides})  # type: ignore[arg-type]


# --------------------------------------------------------------------------- resource


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("repo-a/src/main.py", "repo-a/src/main.py"),
        ("repo-a//src///main.py", "repo-a/src/main.py"),
        ("repo-a/./src/main.py", "repo-a/src/main.py"),
        ("repo-a/src/main.py/", "repo-a/src/main.py"),
        ("  repo-a/src/main.py  ", "repo-a/src/main.py"),
        ("repo-a\\src\\main.py", "repo-a/src/main.py"),
    ],
)
def test_equivalent_spellings_normalise_to_one_form(raw: str, expected: str) -> None:
    """If two spellings of the same resource produced different digests, an approval for
    one would not cover the other - and an attacker who influences path spelling could get
    a benign form approved and execute a different one."""
    assert ResourceRef(scheme="fixture", identifier=raw).identifier == expected


@pytest.mark.parametrize(
    "traversal",
    [
        "repo-a/../../../etc/passwd",
        "../secrets",
        "repo-a/..",
        "..",
        "repo-a\\..\\..\\windows\\system32",
    ],
)
def test_path_traversal_is_rejected(traversal: str) -> None:
    with pytest.raises(ValidationError, match="traversal"):
        ResourceRef(scheme="fixture", identifier=traversal)


def test_backslash_traversal_cannot_evade_the_forward_slash_check() -> None:
    """Backslashes are folded to forward slashes *before* the traversal check, so a
    Windows-style path cannot smuggle `..\\` past a check looking only for `../`."""
    with pytest.raises(ValidationError, match="traversal"):
        ResourceRef(scheme="fixture", identifier="a\\..\\b")


def test_unicode_is_nfc_normalised() -> None:
    """Two visually identical strings must not hash differently."""
    composed = ResourceRef(scheme="fixture", identifier="café/file.py")
    decomposed = ResourceRef(scheme="fixture", identifier="café/file.py")
    assert composed == decomposed


def test_control_characters_are_rejected() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        ResourceRef(scheme="fixture", identifier="repo\x00/evil")


@pytest.mark.parametrize("scheme", ["FIXTURE", "Fixture", " fixture "])
def test_scheme_case_and_whitespace_are_normalised(scheme: str) -> None:
    assert ResourceRef(scheme=scheme, identifier="x").scheme == "fixture"


@pytest.mark.parametrize("scheme", ["", "1fixture", "fix ture", "fix/ture", "fix:ture"])
def test_invalid_scheme_is_rejected(scheme: str) -> None:
    with pytest.raises(ValidationError):
        ResourceRef(scheme=scheme, identifier="x")


def test_uri_round_trips() -> None:
    ref = ResourceRef(scheme="fixture", identifier="repo-a/src/main.py")
    assert ref.uri == "fixture://repo-a/src/main.py"


# --------------------------------------------------------------------------- arguments


@pytest.mark.parametrize(
    "arguments",
    [
        {"ratio": 0.5},
        {"nested": {"ratio": 1.5}},
        {"items": [1, 2, 3.5]},
        {"deep": {"list": [{"x": 0.1}]}},
    ],
)
def test_floats_are_rejected_anywhere_in_arguments(arguments: dict[str, object]) -> None:
    """Floats do not round-trip through JSON reliably, so an approval could be bound to a
    value that re-serialises differently. Rejecting at the boundary means an unhashable
    action cannot be constructed at all."""
    with pytest.raises(ValidationError, match="floats are not permitted"):
        make_intent(arguments=arguments)


def test_integers_and_bools_are_accepted() -> None:
    """bool subclasses int and round-trips exactly; only float is the problem."""
    intent = make_intent(arguments={"count": 3, "recursive": True, "limit": -1})
    assert intent.arguments["count"] == 3
    assert intent.arguments["recursive"] is True


def test_decimal_strings_are_the_supported_alternative() -> None:
    assert make_intent(arguments={"threshold": "0.5"}).arguments["threshold"] == "0.5"


def test_arguments_have_no_any_escape_hatch() -> None:
    """An arbitrary Python object in the value would be hashed for the action digest, and
    a digest over something with an unstable repr is not an identity."""
    with pytest.raises(ValidationError):
        make_intent(arguments={"obj": object()})


# --------------------------------------------------------------------------- intent


@pytest.mark.parametrize("tool", ["Fixture_Repo", "1tool", "tool-name", "tool name", ""])
def test_invalid_tool_name_is_rejected(tool: str) -> None:
    with pytest.raises(ValidationError):
        make_intent(tool=tool)


def test_invalid_risk_class_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_intent(risk_class="catastrophic")


def test_read_only_is_not_mutating() -> None:
    assert make_intent(risk_class=RiskClass.READ_ONLY).is_mutating is False


@pytest.mark.parametrize(
    "risk",
    [
        RiskClass.LOW_RISK_WRITE,
        RiskClass.HIGH_RISK_WRITE,
        RiskClass.IRREVERSIBLE,
        RiskClass.SECRET_ACCESS,
    ],
)
def test_everything_else_is_mutating(risk: RiskClass) -> None:
    assert make_intent(risk_class=risk).is_mutating is True


def test_intents_are_immutable() -> None:
    """An intent that could be edited after authorization would defeat digest binding."""
    intent = make_intent()
    with pytest.raises(ValidationError):
        intent.tool = "something_else"  # type: ignore[misc]


def test_unknown_field_is_rejected() -> None:
    """An unrecognised field is a version mismatch or an injection attempt; dropping it
    silently would hide both."""
    with pytest.raises(ValidationError):
        make_intent(sudo=True)


def test_equal_intents_compare_equal() -> None:
    assert make_intent() == make_intent()


# --------------------------------------------------------------------------- principal


def test_only_operators_may_approve() -> None:
    assert Principal(id="human", kind=PrincipalKind.OPERATOR).may_approve is True
    assert Principal(id="planner", kind=PrincipalKind.AGENT).may_approve is False
    assert Principal(id="worker", kind=PrincipalKind.SYSTEM).may_approve is False


def test_agent_cannot_present_itself_as_operator_for_a_mutation() -> None:
    """Structural expression of the core invariant, caught at the type rather than left
    to policy."""
    with pytest.raises(ValidationError, match="operator principals do not submit"):
        AuthorizationRequest(
            principal=Principal(id="human", kind=PrincipalKind.OPERATOR),
            intent=make_intent(risk_class=RiskClass.HIGH_RISK_WRITE),
            requested_at=NOW,
        )


def test_read_only_request_from_an_operator_is_allowed_to_exist() -> None:
    request = AuthorizationRequest(
        principal=Principal(id="human", kind=PrincipalKind.OPERATOR),
        intent=make_intent(risk_class=RiskClass.READ_ONLY),
        requested_at=NOW,
    )
    assert request.principal.may_approve


# --------------------------------------------------------------------------- decisions


def test_unknown_outcome_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(outcome="MAYBE", reason_code="x")


def test_only_allow_permits_execution() -> None:
    """REQUIRE_APPROVAL is a request for authority, not a grant of it. Getting this
    backwards at one call site would be an execution bypass."""
    assert PolicyDecision(outcome=PolicyOutcome.ALLOW, reason_code="ok").permits_execution
    assert not PolicyDecision(outcome=PolicyOutcome.DENY, reason_code="no").permits_execution
    assert not PolicyDecision(
        outcome=PolicyOutcome.REQUIRE_APPROVAL, reason_code="needs_human"
    ).permits_execution


def test_fail_closed_must_be_a_denial() -> None:
    with pytest.raises(ValidationError, match="fail_closed decisions must be DENY"):
        PolicyDecision(outcome=PolicyOutcome.ALLOW, reason_code="ok", fail_closed=True)


def test_canonical_unavailable_decision_is_a_fail_closed_deny() -> None:
    assert DENY_UNAVAILABLE.outcome is PolicyOutcome.DENY
    assert DENY_UNAVAILABLE.fail_closed is True
    assert DENY_UNAVAILABLE.permits_execution is False


def test_reason_code_must_be_a_stable_identifier() -> None:
    """Reason codes are aggregated in reports; free text would make them uncountable."""
    with pytest.raises(ValidationError):
        PolicyDecision(outcome=PolicyOutcome.DENY, reason_code="Denied: because reasons!")


def test_obligations_are_retrievable_by_kind() -> None:
    decision = PolicyDecision(
        outcome=PolicyOutcome.REQUIRE_APPROVAL,
        reason_code="jira_write_requires_approval",
        obligations=(
            PolicyObligation(kind=ObligationKind.CAPABILITY_TTL_SECONDS, value=45),
            PolicyObligation(kind=ObligationKind.MAX_RESULT_BYTES, value=65536),
        ),
    )
    assert decision.obligation(ObligationKind.CAPABILITY_TTL_SECONDS) == 45
    assert decision.obligation(ObligationKind.AUDIT_LEVEL) is None


def test_decisions_serialise_predictably() -> None:
    decision = PolicyDecision(outcome=PolicyOutcome.DENY, reason_code="secret_access_denied")
    assert decision.model_dump()["outcome"] is PolicyOutcome.DENY
    assert decision.model_dump(mode="json")["outcome"] == "DENY"


# --------------------------------------------------------------------------- context


def test_context_requires_provenance() -> None:
    """There is no constructor for context of unknown origin: losing track of where text
    came from is how untrusted content ends up treated as an instruction."""
    with pytest.raises(ValidationError):
        ContextItem(id="c1", content="hello", retrieved_at=NOW)  # type: ignore[call-arg]


def test_content_hash_is_stable_and_nfc_insensitive() -> None:
    composed = ContextItem(
        id="c1", source="fixture://a", trust=TrustLevel.UNTRUSTED, content="café", retrieved_at=NOW
    )
    decomposed = ContextItem(
        id="c2", source="fixture://a", trust=TrustLevel.UNTRUSTED, content="café", retrieved_at=NOW
    )
    assert composed.content_hash == decomposed.content_hash
    assert len(composed.content_hash) == 64


@pytest.mark.parametrize(
    ("trust", "untrusted"),
    [
        (TrustLevel.TRUSTED, False),
        (TrustLevel.UNTRUSTED, True),
        (TrustLevel.MODEL_GENERATED, True),
    ],
)
def test_model_output_counts_as_untrusted(trust: TrustLevel, untrusted: bool) -> None:
    item = ContextItem(id="c", source="planner", trust=trust, content="text", retrieved_at=NOW)
    assert item.is_untrusted is untrusted


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        ContextItem(
            id="c",
            source="s",
            trust=TrustLevel.UNTRUSTED,
            content="x",
            retrieved_at=dt.datetime(2026, 8, 31, 12, 0),  # noqa: DTZ001
        )


# --------------------------------------------------------------------------- preconditions


def test_preconditions_reject_non_hex_shas() -> None:
    with pytest.raises(ValidationError):
        Preconditions(commit_sha="not-a-sha")


def test_empty_preconditions_are_detectable() -> None:
    assert Preconditions().is_empty is True
    assert Preconditions(commit_sha="a" * 40).is_empty is False


def test_preconditions_participate_in_equality() -> None:
    """A changed precondition must make a different action, or an approval survives a
    world change it never saw."""
    base = make_intent(preconditions=Preconditions(commit_sha="a" * 40))
    moved = make_intent(preconditions=Preconditions(commit_sha="b" * 40))
    assert base != moved
