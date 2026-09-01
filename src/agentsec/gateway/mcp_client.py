"""MCP client adapter: the gateway's connection to a real MCP server (AS-015).

Implements the ``ToolBackend`` protocol over the actual Model Context Protocol, so the
gateway is a genuine MCP client rather than a wrapper around an in-process object.

Notes from the AS-015 compatibility spike, recorded because they are the things that
break somebody picking this up:

* **``FastMCP`` is gone.** mcp 2.x renamed it to ``MCPServer``
  (``mcp.server.mcpserver``). Code written from 1.x knowledge fails at import.
* **stdout is the protocol stream.** A stray ``print`` in a server corrupts it, and the
  symptom is a server that stops responding rather than an error. Ruff's T20 rule bans
  ``print`` repo-wide; servers log to stderr.
* **Server stderr is captured, not inherited.** Left inheriting, a chatty server
  interleaves with the parent's own output and, on Windows, can block on a full pipe.
* **Sessions are scoped explicitly.** ``session_scope`` gives one server process per
  scope. Evaluation cases take a fresh scope each, because stateful backends (cloud,
  Jira) leaking between cases would make the benchmark measure ordering.

The client never sees a capability token and makes no authorization decision. Everything
has been decided before it is called (ADR-0001).
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters, stdio_client

from agentsec.log import get_logger

log = get_logger("agentsec.gateway.mcp")


class McpBackendError(Exception):
    """Raised when a server misbehaves. The gateway turns this into a denial."""


@dataclass(frozen=True, slots=True)
class McpServerSpec:
    """How to launch one MCP server subprocess."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    @classmethod
    def python_module(
        cls, module: str, *args: str, env: dict[str, str] | None = None, cwd: str | None = None
    ) -> McpServerSpec:
        """Launch a server module with the *current* interpreter.

        ``sys.executable`` rather than "python": on Windows the interpreter on PATH is
        frequently not the one running this process, and the server would start in an
        environment without the project's dependencies.
        """
        return cls(command=sys.executable, args=["-m", module, *args], env=env or {}, cwd=cwd)

    def to_parameters(self) -> StdioServerParameters:
        return StdioServerParameters(
            command=self.command,
            args=self.args,
            env={**self.env} or None,
            cwd=self.cwd,
        )


def extract_payload(result: Any) -> Any:
    """Pull a usable value out of a tool result.

    Prefers ``structured_content``, which is what a server returning a dict produces.
    Falls back to parsing the text block, because a server is free to return only text
    and the gateway should not care which it chose.
    """
    if getattr(result, "is_error", False):
        raise McpBackendError(_first_text(result) or "tool reported an error")

    structured = getattr(result, "structured_content", None)
    if structured is not None:
        # Servers commonly wrap a returned dict under a "result" key.
        if isinstance(structured, dict) and set(structured) == {"result"}:
            return structured["result"]
        return structured

    text = _first_text(result)
    if text is None:
        raise McpBackendError("tool returned no content")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _first_text(result: Any) -> str | None:
    for block in getattr(result, "content", []) or []:
        if getattr(block, "type", None) == "text":
            text: str = block.text
            return text
    return None


class McpBackend:
    """A live session to one MCP server. Implements ``ToolBackend``."""

    def __init__(self, session: ClientSession, *, tool_name: str) -> None:
        self._session = session
        self._tool_name = tool_name

    @property
    def session(self) -> ClientSession:
        return self._session

    async def list_operations(self) -> list[str]:
        """What the server says it offers.

        Used for the spike's protocol checks and for diagnostics — **never** as
        authorization input. The trusted registry decides what may be called; a server's
        self-description is exactly the channel a poisoned server would use to advertise
        something it should not have.
        """
        listing = await self._session.list_tools()
        return [tool.name for tool in listing.tools]

    async def invoke(self, tool: str, operation: str, arguments: dict[str, Any]) -> Any:
        if tool != self._tool_name:
            raise McpBackendError(f"backend for {self._tool_name!r} was asked to serve {tool!r}")
        result = await self._session.call_tool(operation, arguments)
        return extract_payload(result)


@asynccontextmanager
async def session_scope(
    spec: McpServerSpec, *, tool_name: str, errlog: Any | None = None
) -> AsyncIterator[McpBackend]:
    """Start a server subprocess and yield a connected backend.

    One process per scope. Both context managers unwind on exit, so the subprocess is
    terminated and its pipes closed even when the body raises — a leaked server process
    holding a stdio pipe is a hang on the next run, not a tidy failure.
    """
    parameters = spec.to_parameters()
    stream = errlog if errlog is not None else sys.stderr

    async with (
        stdio_client(parameters, errlog=stream) as (read, write),
        ClientSession(read, write) as session,
    ):
        initialize = await session.initialize()
        log.info(
            "mcp session established",
            tool=tool_name,
            server=getattr(initialize.server_info, "name", "?"),
            protocol_version=str(session.protocol_version),
        )
        yield McpBackend(session, tool_name=tool_name)


def fixture_repo_spec(
    corpus_root: pathlib.Path, assigned_repo: str, *, extra_env: dict[str, str] | None = None
) -> McpServerSpec:
    """Spec for the fixture repository server, scoped to one repository.

    The assignment is passed through the environment and enforced by the server at
    startup, so a process cannot be talked into serving a different repository later.
    """
    import os

    env = {
        # PATH and the interpreter's own variables must survive, or the subprocess
        # cannot import its dependencies on Windows.
        **{k: v for k, v in os.environ.items() if k in {"PATH", "SYSTEMROOT", "PYTHONPATH"}},
        "AGENTSEC_FIXTURE_ROOT": str(corpus_root),
        "AGENTSEC_ASSIGNED_REPO": assigned_repo,
        **(extra_env or {}),
    }
    return McpServerSpec.python_module("agentsec.mcp_servers.fixture_repo", env=env)


__all__ = [
    "McpBackend",
    "McpBackendError",
    "McpServerSpec",
    "extract_payload",
    "fixture_repo_spec",
    "session_scope",
]
