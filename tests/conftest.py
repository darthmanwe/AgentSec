"""Test isolation from the developer's own configuration.

The suite reads ``Settings``, and ``Settings`` reads ``.env`` and the ambient environment.
That means a developer who configures a real API key changes the result of the test suite
— which is how ``test_unset_secret_reports_as_unset_not_redacted`` began failing the
moment a key existed on this machine, having passed in CI forever.

That is worse than an inconvenience for this project specifically. "The authorization
kernel runs with no credentials at all" is an advertised property, asserted by several
hundred tests. A suite whose behaviour quietly changes when credentials appear cannot
support that claim: it would be asserting the property only on machines that never had
any.

So every test builds settings from a known-empty environment. A test that wants
configuration passes it explicitly to ``load_settings``, which is clearer than depending
on what happens to be in the shell.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

from agentsec import config as config_module

#: Every settings class that reads a dotenv. Missing one would leave a partial isolation,
#: which is harder to notice than none at all.
_SETTINGS_CLASSES: tuple[Any, ...] = (
    config_module.Settings,
    config_module.ModelSettings,
    config_module.BudgetSettings,
    config_module.AuthzSettings,
)


@pytest.fixture(autouse=True)
def _isolate_settings_from_developer_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    for name in [key for key in dict(os.environ) if key.startswith("AGENTSEC_")]:
        monkeypatch.delenv(name, raising=False)

    for cls in _SETTINGS_CLASSES:
        isolated = dict(cls.model_config)
        isolated["env_file"] = None
        monkeypatch.setattr(cls, "model_config", isolated)

    yield
