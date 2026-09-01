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


def test_no_runtime_dependencies_yet() -> None:
    """AS-001 is a foundation issue: dependencies arrive with the issue that needs them.

    This guards against speculative dependency creep during early work. Delete or
    amend it in the first issue that legitimately adds a runtime dependency.
    """
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == []


def test_package_is_typed() -> None:
    assert (REPO_ROOT / "src" / "agentsec" / "py.typed").exists()


def test_threat_model_exists_with_out_of_scope_section() -> None:
    """AS-000 acceptance criterion, enforced as a test so it cannot silently rot."""
    text = (REPO_ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "## 6. Out of scope" in text
    # The section must be non-empty: at least a few enumerated exclusions.
    out_of_scope = text.split("## 6. Out of scope", 1)[1].split("## 7.", 1)[0]
    assert out_of_scope.count("\n1. ") + out_of_scope.count("\n2. ") >= 2
