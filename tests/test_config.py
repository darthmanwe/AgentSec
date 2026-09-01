"""Configuration and secret-handling tests (AS-002).

The acceptance criterion is that no plaintext secret appears in a safe snapshot. These
tests use obviously-fake values and then assert their *absence*, so a regression shows up
as a failing test rather than as a leaked value in a log nobody reads.
"""

from __future__ import annotations

import json

import pytest
from pydantic import SecretStr, ValidationError

from agentsec.config import REDACTED, Mode, Settings, load_settings

FAKE_API_KEY = "sk-ant-FAKE-DO-NOT-USE-0123456789abcdef"
FAKE_DB_PASSWORD = "hunter2-not-a-real-password"
FAKE_DB_URL = f"postgresql+asyncpg://agentsec:{FAKE_DB_PASSWORD}@localhost:5432/agentsec"


@pytest.fixture
def settings() -> Settings:
    return load_settings(
        mode=Mode.LOCAL,
        anthropic_api_key=SecretStr(FAKE_API_KEY),
        github_token=SecretStr("ghp_FAKE_TOKEN_0123456789"),
        operator_token=SecretStr("op_FAKE_TOKEN_0123456789"),
        database_url=SecretStr(FAKE_DB_URL),
    )


# --------------------------------------------------------------------------- redaction


def test_secrets_are_redacted_in_safe_dump(settings: Settings) -> None:
    dumped = settings.safe_dump()
    assert dumped["anthropic_api_key"] == REDACTED
    assert dumped["github_token"] == REDACTED
    assert dumped["operator_token"] == REDACTED
    assert dumped["database_url"] == REDACTED


def test_no_plaintext_secret_survives_serialisation(settings: Settings) -> None:
    """The real assertion: search the rendered output for every secret value."""
    blob = settings.safe_json()
    for secret in (FAKE_API_KEY, FAKE_DB_PASSWORD, FAKE_DB_URL, "ghp_FAKE_TOKEN_0123456789"):
        assert secret not in blob, f"secret leaked into safe_json(): {secret[:12]}..."


def test_unset_secret_reports_as_unset_not_redacted() -> None:
    """An absent credential and a hidden one are different facts.

    Reporting ``None`` as REDACTED would make a misconfigured deployment look correctly
    configured, which is exactly the confusion this project cannot afford.
    """
    dumped = load_settings(mode=Mode.EVAL).safe_dump()
    assert dumped["anthropic_api_key"] is None


def test_nested_settings_are_included(settings: Settings) -> None:
    dumped = settings.safe_dump()
    assert dumped["authz"]["capability_ttl_seconds"] == 60
    assert dumped["budget"]["max_usd"] == 25.0
    assert dumped["model"]["headline"] == "claude-opus-5"


def test_repr_does_not_leak(settings: Settings) -> None:
    """pydantic's SecretStr covers repr, but assert it rather than assuming it."""
    assert FAKE_API_KEY not in repr(settings)
    assert FAKE_DB_PASSWORD not in repr(settings)


# --------------------------------------------------------------------------- determinism


def test_safe_dump_is_deterministic(settings: Settings) -> None:
    """Snapshots are embedded in evaluation artifacts; unstable ordering means spurious
    diffs between identical runs."""
    assert settings.safe_json() == settings.safe_json()
    keys = list(settings.safe_dump())
    assert keys == sorted(keys)


def test_safe_json_is_valid_json(settings: Settings) -> None:
    assert json.loads(settings.safe_json())["mode"] == "local"


# --------------------------------------------------------------------------- modes


def test_eval_mode_needs_no_credentials() -> None:
    """The property CI depends on: the offline path must not require secrets."""
    cfg = load_settings(mode=Mode.EVAL)
    assert cfg.requires_credentials is False
    assert cfg.anthropic_api_key is None


def test_default_mode_is_eval() -> None:
    """Fail closed into offline operation rather than reaching for absent credentials."""
    assert load_settings().mode is Mode.EVAL


def test_demo_mode_requires_an_api_key() -> None:
    with pytest.raises(ValidationError, match="requires AGENTSEC_ANTHROPIC_API_KEY"):
        load_settings(mode=Mode.DEMO)


def test_demo_mode_accepts_an_api_key() -> None:
    cfg = load_settings(mode=Mode.DEMO, anthropic_api_key=SecretStr(FAKE_API_KEY))
    assert cfg.requires_credentials is True


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize("ttl", [29, 121, 0, -1])
def test_capability_ttl_outside_the_specified_window_is_rejected(ttl: int) -> None:
    """AS-011 specifies 30-120s. Authority that outlives reasoning about it is not
    authority that can be audited."""
    with pytest.raises(ValidationError):
        load_settings(authz={"capability_ttl_seconds": ttl})


@pytest.mark.parametrize("ttl", [30, 60, 120])
def test_capability_ttl_inside_the_window_is_accepted(ttl: int) -> None:
    assert load_settings(authz={"capability_ttl_seconds": ttl}).authz.capability_ttl_seconds == ttl


@pytest.mark.parametrize("budget", [0, -5.0, 1001.0])
def test_budget_must_be_positive_and_bounded(budget: float) -> None:
    with pytest.raises(ValidationError):
        load_settings(budget={"max_usd": budget})


def test_unknown_setting_is_rejected() -> None:
    """extra='forbid': a typo in an env var must fail loudly, not be silently ignored."""
    with pytest.raises(ValidationError):
        load_settings(definitely_not_a_setting="x")


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        load_settings(log_level="CHATTY")


def test_settings_are_frozen() -> None:
    """Configuration must not drift mid-run; an evaluation artifact records one snapshot."""
    cfg = load_settings()
    with pytest.raises(ValidationError):
        cfg.mode = Mode.DEMO  # type: ignore[misc]
