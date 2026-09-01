"""Trusted tool registry and risk metadata (AS-013).

**The registry is authoritative; an MCP server's self-description is not.** A server
announcing its own tools, schemas and risk levels is untrusted input — it is exactly the
channel a compromised or poisoned server would use to tell us that its
``delete_everything`` operation is a harmless read. Everything the gateway needs to make a
decision comes from this file, which is version-controlled, hashed, and validated at load.

Loading is strict and fails at startup. A registry that silently drops a malformed entry
would leave the tool undefined at dispatch time, and "undefined" is a state somebody
eventually handles by guessing.

The registry hash is bound into every capability grant (AS-011), so a registry change
invalidates grants minted under the previous one. That is deliberate: if a tool has been
reclassified, the authorization that produced an outstanding grant no longer describes
reality.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Annotated, Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.authz.digest import canonical_json
from agentsec.authz.models import RiskClass, TrustLevel

REGISTRY_DOMAIN: Final = "agentsec.registry.v1"

DEFAULT_REGISTRY_PATH: Final = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent / "registry" / "tools.json"
)

#: Characters that would make an entry a wildcard rather than an enumeration.
_WILDCARD_CHARS: Final = frozenset("*?[]")


class RegistryError(Exception):
    """Raised when the registry is malformed. Always fatal at startup."""


class UnknownToolError(Exception):
    """Raised when a lookup misses. Fails closed: there is no default tool."""


class ToolDefinition(BaseModel):
    """What the gateway is permitted to believe about one tool operation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)]
    operation: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)]
    description: Annotated[str, Field(min_length=1, max_length=500)]

    risk_class: RiskClass
    resource_schemes: tuple[str, ...]
    required_scopes: tuple[str, ...]
    requires_approval: bool
    idempotent: bool
    """Whether repeating the call is safe. Must be stated explicitly for every entry -
    there is no safe default, and guessing wrong in either direction is a bug: guessing
    idempotent for a write duplicates effects, guessing non-idempotent for a read makes
    retries impossible."""

    result_trust: TrustLevel
    """Trust label applied to whatever this tool returns. Every backend response is
    untrusted; this field exists so that is stated per tool rather than assumed."""

    timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    max_result_bytes: Annotated[int, Field(gt=0, le=16 * 1024 * 1024)]
    argument_schema: dict[str, Any] = Field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{self.tool}.{self.operation}"

    @property
    def is_mutating(self) -> bool:
        return self.risk_class is not RiskClass.READ_ONLY

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if not self.resource_schemes:
            raise ValueError(f"{self.qualified_name}: must declare at least one resource scheme")
        if not self.required_scopes:
            raise ValueError(
                f"{self.qualified_name}: must declare at least one scope; a tool requiring "
                "no scope can be invoked by any capability"
            )

        for field_name, values in (
            ("resource_schemes", self.resource_schemes),
            ("required_scopes", self.required_scopes),
        ):
            for value in values:
                if _WILDCARD_CHARS & set(value):
                    raise ValueError(
                        f"{self.qualified_name}: wildcard in {field_name} ({value!r}). "
                        "Entries are enumerated, never patterned - a wildcard is how a "
                        "registry grows access nobody reviewed."
                    )

        if self.risk_class is RiskClass.SECRET_ACCESS:
            # Policy denies this class unconditionally, so an entry carrying it could never
            # be invoked. Registering one means somebody misunderstood the model, and a
            # dead entry that looks live is worse than a loud failure.
            raise ValueError(
                f"{self.qualified_name}: secret_access is always denied by policy and must "
                "not appear in the registry"
            )

        if self.is_mutating and not self.requires_approval:
            raise ValueError(
                f"{self.qualified_name}: risk class {self.risk_class.value} is mutating and "
                "must require approval"
            )

        if not self.is_mutating and self.requires_approval:
            raise ValueError(
                f"{self.qualified_name}: a read-only operation should not require approval; "
                "approval fatigue is what makes operators rubber-stamp the ones that matter"
            )

        if self.result_trust is TrustLevel.TRUSTED:
            raise ValueError(
                f"{self.qualified_name}: no tool result is trusted. Backend responses are "
                "attacker-influenced by definition"
            )
        return self


class ToolRegistry:
    """An immutable, hashed set of tool definitions."""

    def __init__(self, definitions: list[ToolDefinition], *, version: str) -> None:
        self._version = version
        self._by_name: dict[str, ToolDefinition] = {}
        for definition in definitions:
            if definition.qualified_name in self._by_name:
                raise RegistryError(f"duplicate registry entry: {definition.qualified_name}")
            self._by_name[definition.qualified_name] = definition
        self._hash = self._compute_hash()

    @property
    def version(self) -> str:
        return self._version

    @property
    def hash(self) -> str:
        """SHA-256 over the canonical form of every entry.

        Bound into capability grants, so a registry change invalidates outstanding
        authority minted under the previous one.
        """
        return self._hash

    @property
    def tools(self) -> frozenset[str]:
        return frozenset(d.tool for d in self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, qualified_name: str) -> bool:
        return qualified_name in self._by_name

    def entries(self) -> list[ToolDefinition]:
        return [self._by_name[name] for name in sorted(self._by_name)]

    def lookup(self, tool: str, operation: str) -> ToolDefinition:
        """Resolve a tool operation. Raises rather than returning a permissive default."""
        try:
            return self._by_name[f"{tool}.{operation}"]
        except KeyError:
            raise UnknownToolError(
                f"{tool}.{operation} is not in the trusted registry "
                f"(version {self._version}, hash {self._hash[:12]})"
            ) from None

    def operations_for(self, tool: str) -> frozenset[str]:
        return frozenset(d.operation for d in self._by_name.values() if d.tool == tool)

    def _compute_hash(self) -> str:
        payload = {
            "domain": REGISTRY_DOMAIN,
            "version": self._version,
            "entries": [json.loads(entry.model_dump_json()) for entry in self.entries()],
        }
        return hashlib.sha256(
            REGISTRY_DOMAIN.encode("utf-8") + b"\n" + canonical_json(payload)
        ).hexdigest()


def load_registry(path: pathlib.Path | None = None) -> ToolRegistry:
    """Load and validate the registry. Raises ``RegistryError`` on any problem.

    Strict by design: a registry that skipped a malformed entry would leave that tool
    undefined at dispatch time, and undefined is a state somebody eventually handles by
    guessing.
    """
    registry_path = path or DEFAULT_REGISTRY_PATH
    if not registry_path.exists():
        raise RegistryError(f"tool registry not found at {registry_path}")

    try:
        document = json.loads(registry_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"tool registry at {registry_path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict) or "entries" not in document:
        raise RegistryError("tool registry must be an object with an 'entries' array")

    version = str(document.get("version", "unversioned"))
    definitions: list[ToolDefinition] = []
    for index, raw in enumerate(document["entries"]):
        try:
            definitions.append(ToolDefinition.model_validate(raw))
        except Exception as exc:
            name = raw.get("tool", "?") if isinstance(raw, dict) else "?"
            raise RegistryError(f"invalid registry entry #{index} ({name}): {exc}") from exc

    if not definitions:
        raise RegistryError("tool registry is empty")

    return ToolRegistry(definitions, version=version)


__all__ = [
    "DEFAULT_REGISTRY_PATH",
    "REGISTRY_DOMAIN",
    "RegistryError",
    "ToolDefinition",
    "ToolRegistry",
    "UnknownToolError",
    "load_registry",
]
