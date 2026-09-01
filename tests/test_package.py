"""Execution-package validator tests (Rev 0).

The backlog under docs/execution-package is the authoritative work list, and the validator
is what stops its derived artifacts drifting from the issue files. These tests check the
validator itself — a broken checker that always passes is worse than no checker.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validate_package import (  # noqa: E402
    ORDER,
    check_acyclic,
    check_deps,
    check_order,
    load_issues,
    sha256,
)


@pytest.fixture(scope="module")
def issues() -> dict[str, object]:
    return load_issues()  # type: ignore[return-value]


def test_manifest_hashing_ignores_line_endings(tmp_path: pathlib.Path) -> None:
    """Regression guard for a real CI failure.

    Raw-byte hashing made the manifest platform-dependent: a Windows working tree holds
    CRLF, .gitattributes normalises to LF in the repository, and CI's Linux checkout then
    disagreed with all 45 hashes. The failure said nothing about integrity, which is
    exactly the kind of noise that trains people to ignore a red build.
    """
    crlf = tmp_path / "crlf.md"
    lf = tmp_path / "lf.md"
    crlf.write_bytes(b"# Title\r\n\r\nBody line\r\n")
    lf.write_bytes(b"# Title\n\nBody line\n")

    assert hashlib.sha256(crlf.read_bytes()) != hashlib.sha256(lf.read_bytes())
    assert sha256(crlf) == sha256(lf)


def test_content_changes_still_alter_the_hash(tmp_path: pathlib.Path) -> None:
    """Normalisation must not make the manifest blind to real edits."""
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_bytes(b"original\n")
    b.write_bytes(b"tampered\n")
    assert sha256(a) != sha256(b)


def test_every_issue_parses(issues: dict[str, object]) -> None:
    assert len(issues) == len(ORDER) == 45


def test_dependencies_all_resolve(issues: dict[str, object]) -> None:
    errors: list[str] = []
    check_deps(issues, errors)  # type: ignore[arg-type]
    assert errors == []


def test_dependency_graph_is_acyclic(issues: dict[str, object]) -> None:
    errors: list[str] = []
    check_acyclic(issues, errors)  # type: ignore[arg-type]
    assert errors == []


def test_execution_order_is_topological(issues: dict[str, object]) -> None:
    """The ordering corrections from rev 2 are asserted here rather than trusted."""
    errors: list[str] = []
    check_order(issues, errors)  # type: ignore[arg-type]
    assert errors == []


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("AS-027", "AS-026"),  # prompt registry before the planner whose prompts it governs
        ("AS-039", "AS-038"),  # thresholds pre-registered before the ablation runner
        ("AS-031A", "AS-029"),  # sandbox exists before any scanner does
        ("AS-031A", "AS-030"),
        ("AS-015", "AS-016"),  # MCP spike settles the protocol before the other servers
        ("AS-028B", "AS-038"),  # adversarial planner exists before the ablation uses it
    ],
)
def test_rev2_reorderings_hold(earlier: str, later: str) -> None:
    """Each of these was a dependency error in the original package. Asserting them
    directly means a future edit to ORDER cannot silently undo the fix."""
    assert ORDER.index(earlier) < ORDER.index(later), f"{earlier} must precede {later}"


def test_new_issues_are_present() -> None:
    for issue_id in ("AS-000", "AS-028B", "AS-031A", "AS-031B"):
        assert issue_id in ORDER
