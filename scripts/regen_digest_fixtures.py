"""Regenerate the canonical-digest golden fixtures (AS-007).

Run deliberately, never reflexively. If this changes an existing digest, either the domain
string in ``digest.py`` must be bumped or the change is a bug: every stored approval,
capability grant and ledger entry is keyed on digests produced under the current scheme.

    uv run python scripts/regen_digest_fixtures.py
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from agentsec.authz.digest import canonicalize  # noqa: E402
from agentsec.authz.models import (  # noqa: E402
    ActionIntent,
    Preconditions,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
)

FIXTURE_PATH = REPO_ROOT / "tests" / "data" / "digest_golden.json"

AGENT = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-1")


def case(
    name: str,
    intent: ActionIntent,
    *,
    principal: Principal = AGENT,
    workflow_id: str | None = "wf-1",
    note: str = "",
) -> dict[str, object]:
    action = canonicalize(principal, intent, workflow_id=workflow_id)
    return {
        "name": name,
        "note": note,
        "digest": action.digest,
        "canonical_json": action.canonical_bytes.decode("utf-8"),
    }


def build_cases() -> list[dict[str, object]]:
    read = ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
    )
    return [
        case("baseline_read", read, note="the reference action every other case varies from"),
        case(
            "key_order_invariant",
            read.model_copy(update={"arguments": {"b": 2, "a": 1}}),
            note="must equal reordered_keys below",
        ),
        case(
            "reordered_keys",
            read.model_copy(update={"arguments": {"a": 1, "b": 2}}),
            note="same digest as key_order_invariant: object key order is not identity",
        ),
        case(
            "null_argument",
            read.model_copy(update={"arguments": {"path": "x", "force": None}}),
            note="distinct from absent_argument: an explicit null is not an omission",
        ),
        case(
            "absent_argument",
            read.model_copy(update={"arguments": {"path": "x"}}),
            note="distinct from null_argument",
        ),
        case(
            "list_order_ab",
            read.model_copy(update={"arguments": {"paths": ["a", "b"]}}),
            note="distinct from list_order_ba: list order is significant",
        ),
        case("list_order_ba", read.model_copy(update={"arguments": {"paths": ["b", "a"]}})),
        case(
            "unicode_nfc",
            read.model_copy(update={"arguments": {"name": "café"}}),
            note="composed form; must equal unicode_nfd",
        ),
        case(
            "unicode_nfd",
            read.model_copy(update={"arguments": {"name": "café"}}),
            note="decomposed form; NFC normalisation makes this equal unicode_nfc",
        ),
        case(
            "bool_true",
            read.model_copy(update={"arguments": {"flag": True}}),
            note="distinct from int_one: bool must not collapse to 1",
        ),
        case("int_one", read.model_copy(update={"arguments": {"flag": 1}})),
        case(
            "nested_structure",
            read.model_copy(
                update={"arguments": {"filter": {"langs": ["py", "go"], "depth": 3, "x": None}}}
            ),
        ),
        case(
            "with_preconditions",
            read.model_copy(update={"preconditions": Preconditions(commit_sha="a" * 40)}),
            note="distinct from baseline_read: a precondition is part of action identity",
        ),
        case(
            "precondition_moved",
            read.model_copy(update={"preconditions": Preconditions(commit_sha="b" * 40)}),
            note="a moved PR head is a different action requiring fresh approval",
        ),
        case(
            "empty_preconditions_equal_none",
            read.model_copy(update={"preconditions": Preconditions()}),
            note="must equal baseline_read: a blank preconditions object encodes as null",
        ),
        case(
            "different_workflow",
            read,
            workflow_id="wf-2",
            note="an approval in one workflow must not replay into another",
        ),
        case(
            "different_principal",
            read,
            principal=Principal(id="other_planner", kind=PrincipalKind.AGENT, workflow_id="wf-1"),
            note="authority granted to one principal must not transfer",
        ),
        case(
            "mutating_action",
            ActionIntent(
                tool="fake_jira",
                operation="create_issue",
                resource=ResourceRef(scheme="jira", identifier="PROJ"),
                arguments={"summary": "Fix SQLi in login", "priority": "high"},
                risk_class=RiskClass.HIGH_RISK_WRITE,
            ),
        ),
        case(
            "reclassified_risk",
            ActionIntent(
                tool="fake_jira",
                operation="create_issue",
                resource=ResourceRef(scheme="jira", identifier="PROJ"),
                arguments={"summary": "Fix SQLi in login", "priority": "high"},
                risk_class=RiskClass.IRREVERSIBLE,
            ),
            note="registry reclassification invalidates approvals granted under the old class",
        ),
        case(
            "resource_normalisation",
            read.model_copy(
                update={
                    "resource": ResourceRef(scheme="FIXTURE", identifier="repo-a//src/./main.py")
                }
            ),
            note="must equal baseline_read: equivalent spellings are one action",
        ),
    ]


def main() -> int:
    cases = build_cases()
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(
        json.dumps(
            {
                "_comment": (
                    "Golden fixtures for the canonical action digest (AS-007). Generated by "
                    "scripts/regen_digest_fixtures.py. A change to an existing digest means "
                    "either the domain string must be bumped or the change is a bug - see "
                    "docs/CANONICAL_ACTION_DIGEST.md."
                ),
                "domain": "agentsec.action.v1",
                "cases": cases,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(cases)} fixtures to {FIXTURE_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
