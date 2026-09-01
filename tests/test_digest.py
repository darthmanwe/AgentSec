"""Canonical action digest tests (AS-007).

The golden fixtures are the important part. They pin the algorithm so an accidental change
fails here rather than silently invalidating every stored approval — a failure that would
otherwise surface as "approvals mysteriously stopped matching" long after the commit that
caused it.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agentsec.authz.digest import (
    DIGEST_DOMAIN,
    MAX_DEPTH,
    CanonicalisationError,
    build_payload,
    canonical_json,
    canonicalize,
    compute_digest,
    digests_match,
)
from agentsec.authz.models import (
    ActionIntent,
    Preconditions,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
)

pytestmark = pytest.mark.authz

GOLDEN = pathlib.Path(__file__).parent / "data" / "digest_golden.json"
AGENT = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-1")


def read_action(**overrides: object) -> ActionIntent:
    base = ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
    )
    return base.model_copy(update=overrides) if overrides else base


def digest(intent: ActionIntent, principal: Principal = AGENT, workflow_id: str = "wf-1") -> str:
    return compute_digest(principal, intent, workflow_id=workflow_id)


# --------------------------------------------------------------------------- golden


@pytest.fixture(scope="module")
def golden() -> dict[str, dict[str, str]]:
    data = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert data["domain"] == DIGEST_DOMAIN, (
        "fixture domain does not match the implementation; bump one or the other deliberately"
    )
    return {case["name"]: case for case in data["cases"]}


def test_golden_fixtures_exist(golden: dict[str, dict[str, str]]) -> None:
    assert len(golden) >= 20


def test_baseline_digest_is_unchanged(golden: dict[str, dict[str, str]]) -> None:
    """If this fails, the algorithm changed. Either bump the domain string or fix the bug —
    do not regenerate the fixtures to make it pass."""
    assert digest(read_action()) == golden["baseline_read"]["digest"]


def test_canonical_form_is_unchanged(golden: dict[str, dict[str, str]]) -> None:
    action = canonicalize(AGENT, read_action(), workflow_id="wf-1")
    assert action.canonical_bytes.decode("utf-8") == golden["baseline_read"]["canonical_json"]


def test_every_golden_case_still_reproduces(golden: dict[str, dict[str, str]]) -> None:
    """Regenerate the fixtures and compare digests wholesale, so a change to any rule is
    caught rather than only the handful with dedicated tests."""
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))
    from regen_digest_fixtures import build_cases

    for case in build_cases():
        name = str(case["name"])
        assert case["digest"] == golden[name]["digest"], f"digest changed for {name}"


# --------------------------------------------------------------------------- identity


def test_object_key_order_does_not_change_identity() -> None:
    assert digest(read_action(arguments={"b": 2, "a": 1})) == digest(
        read_action(arguments={"a": 1, "b": 2})
    )


def test_explicit_null_differs_from_an_absent_key() -> None:
    """{"force": null} passes an argument; {} omits it. Different actions."""
    assert digest(read_action(arguments={"p": "x", "force": None})) != digest(
        read_action(arguments={"p": "x"})
    )


def test_list_order_is_significant() -> None:
    """For a file list or a rule sequence, order changes behaviour."""
    assert digest(read_action(arguments={"paths": ["a", "b"]})) != digest(
        read_action(arguments={"paths": ["b", "a"]})
    )


def test_unicode_normalisation_folds_identical_renderings() -> None:
    """Composed and decomposed forms render identically; an approver cannot distinguish
    them, so they must not hash differently."""
    composed = "café"
    decomposed = "café"
    assert composed != decomposed
    assert digest(read_action(arguments={"n": composed})) == digest(
        read_action(arguments={"n": decomposed})
    )


def test_bool_does_not_collapse_into_int() -> None:
    """bool subclasses int in Python; unchecked, True would encode as 1."""
    assert digest(read_action(arguments={"f": True})) != digest(read_action(arguments={"f": 1}))
    assert digest(read_action(arguments={"f": False})) != digest(read_action(arguments={"f": 0}))


@pytest.mark.parametrize(
    "mutation",
    [
        {"tool": "fake_jira"},
        {"operation": "write_file"},
        {"arguments": {"path": "src/other.py"}},
        {"risk_class": RiskClass.HIGH_RISK_WRITE},
        {"resource": ResourceRef(scheme="fixture", identifier="repo-b/src/main.py")},
        {"preconditions": Preconditions(commit_sha="a" * 40)},
    ],
)
def test_any_mutation_changes_the_digest(mutation: dict[str, object]) -> None:
    """The core property. Argument mutation after approval must invalidate the approval."""
    assert digest(read_action(**mutation)) != digest(read_action())


def test_workflow_scoping() -> None:
    """An approval granted in one workflow must not replay into another."""
    assert digest(read_action(), workflow_id="wf-1") != digest(read_action(), workflow_id="wf-2")


def test_principal_scoping() -> None:
    other = Principal(id="other", kind=PrincipalKind.AGENT, workflow_id="wf-1")
    assert digest(read_action(), principal=other) != digest(read_action())


def test_blank_preconditions_equal_no_preconditions() -> None:
    """ "No preconditions" and "an empty preconditions object" are plainly the same action
    and must not produce different digests."""
    assert digest(read_action(preconditions=Preconditions())) == digest(read_action())


def test_resource_spellings_converge() -> None:
    weird = ResourceRef(scheme="FIXTURE", identifier="repo-a//src/./main.py")
    assert digest(read_action(resource=weird)) == digest(read_action())


def test_timestamps_are_not_part_of_identity() -> None:
    """The same action proposed twice is the same action. Including a clock reading would
    make every approval unmatchable."""
    assert digest(read_action()) == digest(read_action())
    payload = build_payload(AGENT, read_action(), workflow_id="wf-1")
    assert not any("time" in k or "_at" in k for k in payload)


def test_run_id_is_not_part_of_identity() -> None:
    """run_id identifies an execution, not an action; workflow_id already scopes it."""
    a = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-1")
    b = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-999")
    assert digest(read_action(), principal=a) == digest(read_action(), principal=b)


# --------------------------------------------------------------------------- dispatch


def test_canonical_action_exposes_the_bytes_to_dispatch() -> None:
    """The guarantee that makes the rest meaningful.

    Hashing a normalised form and then sending the caller's original input is a signature
    bypass: the approved bytes and the executed bytes would differ. Callers dispatch
    ``.arguments``, and this test is what enforces that the normalised value is what they
    get.
    """
    action = canonicalize(AGENT, read_action(arguments={"n": "café"}), workflow_id="wf-1")
    assert action.arguments["n"] == "café", "dispatched value must be the canonical form"


def test_canonical_bytes_carry_the_domain_prefix() -> None:
    action = canonicalize(AGENT, read_action(), workflow_id="wf-1")
    assert action.canonical_bytes.startswith(DIGEST_DOMAIN.encode() + b"\n")


def test_qualified_name_round_trips() -> None:
    assert canonicalize(AGENT, read_action(), workflow_id="wf-1").qualified_name == (
        "fixture_repo.read_file"
    )


# --------------------------------------------------------------------------- rejection


def test_floats_are_rejected() -> None:
    """Also blocked at the model boundary (AS-006); checked here too because this module
    must be safe against callers that build a payload directly."""
    with pytest.raises(CanonicalisationError, match="floats cannot be canonicalised"):
        canonical_json_of({"ratio": 0.5})


def canonical_json_of(arguments: dict[str, object]) -> bytes:
    from agentsec.authz.digest import _canonicalise_value

    return canonical_json(_canonicalise_value(arguments))


def test_unsupported_types_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="no canonical representation"):
        canonical_json_of({"obj": object()})


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="keys must be strings"):
        canonical_json_of({1: "x"})  # type: ignore[dict-item]


def test_duplicate_keys_after_normalisation_are_rejected() -> None:
    """Two distinct keys normalising to the same string would make the encoding depend on
    dict iteration order."""
    with pytest.raises(CanonicalisationError, match="duplicate key"):
        canonical_json_of({"café": 1, "café": 2})


def test_excessive_nesting_is_rejected() -> None:
    """Unbounded recursion over attacker-influenced input is a denial of service."""
    payload: dict[str, object] = {"leaf": 1}
    for _ in range(MAX_DEPTH + 5):
        payload = {"d": payload}
    with pytest.raises(CanonicalisationError, match="nesting exceeds"):
        canonical_json_of(payload)


def test_nesting_within_the_limit_is_accepted() -> None:
    payload: dict[str, object] = {"leaf": 1}
    for _ in range(MAX_DEPTH - 4):
        payload = {"d": payload}
    assert canonical_json_of(payload)


# --------------------------------------------------------------------------- encoding


def test_serialisation_has_no_whitespace_and_sorted_keys() -> None:
    body = canonical_json({"b": 1, "a": {"z": 1, "y": 2}})
    assert body == b'{"a":{"y":2,"z":1},"b":1}'


def test_serialisation_keeps_utf8_rather_than_escaping() -> None:
    assert "café".encode() in canonical_json({"n": "café"})


def test_digest_is_lowercase_hex_of_expected_length() -> None:
    value = digest(read_action())
    assert len(value) == 64
    assert value == value.lower()
    assert all(c in "0123456789abcdef" for c in value)


def test_digests_match_is_usable_for_comparison() -> None:
    a = digest(read_action())
    assert digests_match(a, a)
    assert not digests_match(a, digest(read_action(tool="fake_jira")))
