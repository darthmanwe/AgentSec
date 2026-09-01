"""Shared helpers for the fixture MCP servers (AS-016 … AS-018).

Two things every fixture server needs and must not implement differently:

**Provenance on every response.** A server that returns bare data loses the trust label,
and untrusted text with its label stripped is how injection content ends up being read as
instruction.

**Idempotent mutation.** Writes are keyed on an operation id supplied by the caller. A
repeat of the same key returns the original result rather than performing the effect
again — which is what lets a Temporal retry be safe (AS-022).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Final

#: Every fixture server labels its output untrusted. Nothing a backend returns is trusted;
#: see docs/THREAT_MODEL.md section 4.
TRUST_UNTRUSTED: Final = "untrusted"


class FixtureServerError(Exception):
    """Raised for a bad request. Surfaces to the gateway as a tool error, never as data."""


def log(server: str, message: str) -> None:
    """Diagnostics to stderr. stdout is the protocol stream and a stray write corrupts it."""
    sys.stderr.write(f"[{server}] {message}\n")
    sys.stderr.flush()


def provenance(source: str, *, snapshot: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"source": source, "trust": TRUST_UNTRUSTED}
    if snapshot is not None:
        # Which pinned data answered. Without it, a reproduced benchmark cannot prove it
        # ran against the same corpus.
        body["snapshot"] = snapshot
    return body


@dataclass
class IdempotencyLedger:
    """Remembers what each operation id already produced.

    Deliberately per-server-process and in memory: these are fixture backends, and the
    durable ledger is AS-022's job at the workflow layer. What this provides is the
    backend half of at-most-once — a repeat of the same key does not perform the effect
    twice, and returns the original result so the caller cannot tell a retry from the
    first attempt except by the ``replayed`` flag.
    """

    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, operation_id: str) -> dict[str, Any] | None:
        stored = self.entries.get(operation_id)
        if stored is None:
            return None
        return {**stored, "replayed": True}

    def put(self, operation_id: str, result: dict[str, Any]) -> dict[str, Any]:
        self.entries[operation_id] = result
        return {**result, "replayed": False}

    def clear(self) -> None:
        self.entries.clear()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureServerError(message)


__all__ = [
    "TRUST_UNTRUSTED",
    "FixtureServerError",
    "IdempotencyLedger",
    "log",
    "provenance",
    "require",
]
