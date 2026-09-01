"""Smoke tests for the project skeleton (AS-001)."""

from __future__ import annotations

import pathlib
import tomllib

import agentsec

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_package_imports() -> None:
    assert agentsec.__version__


def test_pyproject_parses() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["name"] == "agentsec"
    assert data["project"]["requires-python"] == ">=3.12"


def test_version_matches_pyproject() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == agentsec.__version__


def test_runtime_dependencies_are_pinned_exactly() -> None:
    """Every runtime dependency is pinned to an exact version.

    Replaces the AS-001 "no dependencies yet" guard, which AS-002 legitimately retired
    by adding pydantic. A published benchmark whose dependency versions float is not
    reproducible, so ranges are rejected rather than discouraged.
    """
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for dep in data["project"]["dependencies"]:
        assert "==" in dep, f"dependency is not pinned to an exact version: {dep}"


def test_package_is_typed() -> None:
    assert (REPO_ROOT / "src" / "agentsec" / "py.typed").exists()


def test_threat_model_exists_with_out_of_scope_section() -> None:
    """AS-000 acceptance criterion, enforced as a test so it cannot silently rot."""
    text = (REPO_ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "## 6. Out of scope" in text
    # The section must be non-empty: at least a few enumerated exclusions.
    out_of_scope = text.split("## 6. Out of scope", 1)[1].split("## 7.", 1)[0]
    assert out_of_scope.count("\n1. ") + out_of_scope.count("\n2. ") >= 2
