"""Typed configuration with a hard separation between safe config and secrets (AS-002).

Two rules govern this module:

1. **Secrets are typed, not named.** Anything sensitive is a ``SecretStr``. Redaction
   here is driven by the field's *type*, not by guessing from its name, so a new secret
   field cannot be forgotten. (The pattern-driven redactor in AS-003 handles arbitrary
   nested data, where types are unavailable — a genuinely different problem.)

2. **Eval mode must work with no credentials at all.** The authorization kernel and the
   deterministic evaluation axis are provable without a model, and configuration must not
   quietly reintroduce a dependency on one. ``Mode.EVAL`` rejects any requirement for an
   API key rather than warning about it.
"""

from __future__ import annotations

import enum
import json
from typing import Any, Final, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REDACTED = "**REDACTED**"
"""Placeholder substituted for every secret value in a safe snapshot."""


class Mode(enum.StrEnum):
    """Runtime mode. Determines which configuration is required, not merely expected."""

    LOCAL = "local"
    """Interactive development. May use a live model; requires local infrastructure."""

    EVAL = "eval"
    """Benchmark execution. Must run offline and without credentials by default."""

    DEMO = "demo"
    """Recorded demonstration. Live model and infrastructure expected."""


class ModelSettings(BaseSettings):
    """Model selection.

    Two tiers, because the evaluation budget does not stretch to running every ablation
    cell on the headline model. Both are pinned deliberately:

    * ``headline_model`` has no dated snapshot form; record ``response.model`` per call
      so artifacts state what actually ran.
    * ``bulk_model`` uses the dated snapshot rather than the moving alias, because a
      published benchmark must not change when an alias is repointed.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSEC_MODEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        # The dotenv source hands every key to every group. Unknown nested keys are
        # caught by Settings._route_nested_group_keys, which knows which group owns
        # each prefix; forbidding here would only reject the other groups' keys.
        extra="ignore",
    )

    headline: str = "claude-opus-5"
    bulk: str = "claude-haiku-4-5-20251001"


class BudgetSettings(BaseSettings):
    """Hard ceiling on live API spend.

    The accountant reserves worst-case cost *before* each request and reconciles after
    (AS-024). Post-hoc accounting cannot prevent an overrun it only discovers once the
    money is gone.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSEC_BUDGET_",
        env_file=".env",
        env_file_encoding="utf-8",
        # The dotenv source hands every key to every group. Unknown nested keys are
        # caught by Settings._route_nested_group_keys, which knows which group owns
        # each prefix; forbidding here would only reject the other groups' keys.
        extra="ignore",
    )

    max_usd: float = Field(default=25.0, gt=0, le=1000.0)
    """Abort the run rather than exceed this. Deliberately low by default."""

    require_explicit_live_flag: bool = True
    """When true, live calls need an explicit --live flag; otherwise the mock is used."""


class AuthzSettings(BaseSettings):
    """Authorization kernel timings and key identity."""

    model_config = SettingsConfigDict(
        env_prefix="AGENTSEC_AUTHZ_",
        env_file=".env",
        env_file_encoding="utf-8",
        # The dotenv source hands every key to every group. Unknown nested keys are
        # caught by Settings._route_nested_group_keys, which knows which group owns
        # each prefix; forbidding here would only reject the other groups' keys.
        extra="ignore",
    )

    capability_ttl_seconds: int = Field(default=60, ge=30, le=120)
    """Capability grant lifetime. Bounded by design: long-lived authority is not authority
    that can be reasoned about. The 30-120s window is specified by AS-011."""

    approval_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    """How long an approval stays valid. A capability never outlives its approval; the
    effective expiry is min(now + capability_ttl, approval_expiry)."""

    signing_key_path: str = "keys/capability_signing_ed25519.pem"
    """Ed25519 private key. Never committed; see docs/THREAT_MODEL.md section 6."""

    signing_key_id: str = "dev-key-1"
    """The ``kid`` claim, so keys can rotate without invalidating audit history."""

    policy_decision_timeout_seconds: float = Field(default=2.0, gt=0, le=30.0)
    """OPA request timeout. Exceeding it is a DENY, never a fallback-allow."""


#: Nested groups keyed by the parent-relative prefix that routes to them. Used to keep
#: ``extra="forbid"`` meaningful on the root model while the groups read their own keys.
_NESTED_GROUPS: Final[dict[str, type[BaseSettings]]] = {
    "model_": ModelSettings,
    "budget_": BudgetSettings,
    "authz_": AuthzSettings,
}


class Settings(BaseSettings):
    """Root configuration.

    Loaded from environment variables and an optional ``.env``. Field names map to
    ``AGENTSEC_``-prefixed variables; nested groups carry their own prefixes.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSEC_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    mode: Mode = Mode.EVAL
    """Defaults to the mode that needs nothing. A misconfigured deployment should fail
    closed into offline operation, not reach for credentials it was not given."""

    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    # --- infrastructure ---------------------------------------------------------
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://agentsec:devonly@localhost:5432/agentsec"
    )
    """Secret because it carries a password, even in development. Development credentials
    are still credentials, and a config snapshot ends up in logs and issue reports."""

    opa_url: str = "http://localhost:8181"
    temporal_address: str = "localhost:7233"
    temporal_task_queue: str = "agentsec-main"

    # --- credentials ------------------------------------------------------------
    anthropic_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    operator_token: SecretStr | None = None
    """Authenticates the approving operator. Demo-grade by design (AS-010)."""

    # --- nested groups ----------------------------------------------------------
    model: ModelSettings = Field(default_factory=ModelSettings)
    budget: BudgetSettings = Field(default_factory=BudgetSettings)
    authz: AuthzSettings = Field(default_factory=AuthzSettings)

    @model_validator(mode="before")
    @classmethod
    def _route_nested_group_keys(cls, data: Any) -> Any:
        """Hand ``AGENTSEC_MODEL_*`` and friends to their own group, without losing strictness.

        The nested groups declare their own ``env_prefix``, so ``AGENTSEC_MODEL_BULK`` is
        theirs to read. The parent sees the same key, strips ``AGENTSEC_``, finds no
        ``model_bulk`` field and — under ``extra="forbid"`` — refuses the whole
        configuration. That made ``.env.example`` unloadable: copying the file the README
        tells you to copy produced nine validation errors.

        Dropping the keys wholesale would fix the crash and cost the reason ``forbid`` is
        set, because ``AGENTSEC_MODEL_BULKK`` would then be ignored in silence. So each key
        is checked against the group that owns it and only then dropped, leaving the group
        to read it from the environment itself.
        """
        if not isinstance(data, dict):
            return data
        kept: dict[Any, Any] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                kept[key] = value
                continue
            # Extras arrive with the root prefix still attached (``agentsec_model_bulk``),
            # while an explicit keyword override arrives without it. Accept both.
            lowered = key.lower().removeprefix("agentsec_")
            for prefix, group in _NESTED_GROUPS.items():
                if not lowered.startswith(prefix):
                    continue
                field = lowered[len(prefix) :]
                if field not in group.model_fields:
                    raise ValueError(
                        f"AGENTSEC_{lowered.upper()} is not a setting. {group.__name__} accepts "
                        f"{sorted(group.model_fields)}."
                    )
                break
            else:
                kept[key] = value
        return kept

    @model_validator(mode="after")
    def _validate_mode_requirements(self) -> Self:
        """Per-mode requirements, enforced rather than documented.

        The interesting direction is the negative one: EVAL must not *require* a key. A
        configuration that silently accepts one is fine (it may be present in the shell
        for other reasons); a configuration that demands one has broken the offline
        guarantee.
        """
        if self.mode is Mode.DEMO and self.anthropic_api_key is None:
            raise ValueError(
                "mode=demo requires AGENTSEC_ANTHROPIC_API_KEY. Use mode=eval for offline runs."
            )
        return self

    @property
    def requires_credentials(self) -> bool:
        """Whether this configuration cannot function without secrets.

        Always False in eval mode. Asserted by the test suite, because this is the
        property CI depends on.
        """
        return self.mode is Mode.DEMO

    def safe_dump(self) -> dict[str, Any]:
        """A deterministic, secret-free snapshot suitable for logs, traces and reports.

        Determinism matters: this snapshot is embedded in evaluation artifacts, so an
        unstable ordering would produce spurious diffs between otherwise identical runs.
        Keys are sorted recursively.
        """
        return _redact_typed(self.model_dump(mode="python"), self)

    def safe_json(self) -> str:
        """``safe_dump`` rendered as stable JSON."""
        return json.dumps(self.safe_dump(), sort_keys=True, indent=2, default=str)


def _redact_typed(data: dict[str, Any], model: BaseSettings) -> dict[str, Any]:
    """Replace every ``SecretStr``-typed field with the redaction marker.

    Type-driven rather than name-driven: a field is redacted because it was *declared*
    secret, so adding a secret field with an innocuous name cannot leak it.
    """
    out: dict[str, Any] = {}
    for key in sorted(data):
        value = data[key]
        attr = getattr(model, key, None)
        if isinstance(attr, SecretStr):
            out[key] = REDACTED
        elif attr is None and _is_secret_field(model, key):
            out[key] = None  # unset secrets report as unset, not as redacted
        elif isinstance(attr, BaseSettings) and isinstance(value, dict):
            out[key] = _redact_typed(value, attr)
        elif isinstance(value, enum.Enum):
            out[key] = value.value
        else:
            out[key] = value
    return out


def _is_secret_field(model: BaseSettings, name: str) -> bool:
    field = type(model).model_fields.get(name)
    if field is None:
        return False
    return "SecretStr" in str(field.annotation)


def load_settings(**overrides: Any) -> Settings:
    """Build settings from the environment, with explicit overrides for tests."""
    return Settings(**overrides)


__all__ = [
    "REDACTED",
    "AuthzSettings",
    "BudgetSettings",
    "Mode",
    "ModelSettings",
    "Settings",
    "load_settings",
]
