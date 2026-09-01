"""Fixture repository MCP server (AS-015).

A real MCP server speaking the protocol over stdio, not an in-process fake. The gateway
is therefore a real MCP client, and the project's headline noun is literally true when a
reviewer runs it.

**This server makes no authorization decisions.** By the time a call arrives, policy has
allowed it, an operator has approved it if required, and the gateway has verified and
redeemed a capability bound to this exact action (ADR-0001). What the server enforces is
*containment*: even a fully compromised gateway must not be able to read outside the
fixture corpus.

Two rules govern the implementation:

**Nothing may be written to stdout.** stdout *is* the protocol stream; a stray ``print``
corrupts it, and the failure presents as a server that mysteriously stops responding
rather than as an error. Ruff's T20 rule bans ``print`` repo-wide for this reason, and
diagnostics go to stderr.

**Paths are resolved and re-checked, never merely inspected.** A traversal check on the
literal string is defeated by a symlink; the check that matters is whether the *resolved*
path is still inside the repository root.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
from typing import Any, Final

from mcp.server.mcpserver import MCPServer

SERVER_NAME: Final = "agentsec-fixture-repo"
SERVER_VERSION: Final = "1.0.0"

#: Refuse to read anything larger than this. The gateway enforces a result ceiling too;
#: this stops the server materialising a huge file into memory before that check runs.
MAX_FILE_BYTES: Final = 1024 * 1024

MAX_SEARCH_RESULTS: Final = 200
MAX_LISTED_FILES: Final = 2000

#: Environment variables the launcher uses to scope this process.
ENV_CORPUS_ROOT: Final = "AGENTSEC_FIXTURE_ROOT"
ENV_ASSIGNED_REPO: Final = "AGENTSEC_ASSIGNED_REPO"


class ContainmentError(Exception):
    """Raised when a request would escape the assigned repository."""


def _log(message: str) -> None:
    """Diagnostics to stderr. stdout belongs to the protocol."""
    sys.stderr.write(f"[{SERVER_NAME}] {message}\n")
    sys.stderr.flush()


class FixtureRepository:
    """Read-only access to one assigned fixture repository."""

    def __init__(self, corpus_root: pathlib.Path, assigned_repo: str) -> None:
        self._corpus_root = corpus_root.resolve()
        if not self._corpus_root.is_dir():
            raise ContainmentError(f"fixture corpus root does not exist: {self._corpus_root}")

        candidate = (self._corpus_root / assigned_repo).resolve()
        if not self._is_inside(candidate, self._corpus_root) or not candidate.is_dir():
            # The assignment itself is checked, not just later reads. A launcher pointed
            # at "../.." must fail at startup rather than serve the whole filesystem.
            raise ContainmentError(f"assigned repository is not inside the corpus: {assigned_repo}")

        self._root = candidate
        self.assigned_repo = assigned_repo

    @property
    def root(self) -> pathlib.Path:
        return self._root

    @staticmethod
    def _is_inside(candidate: pathlib.Path, root: pathlib.Path) -> bool:
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
        return True

    def resolve(self, relative: str) -> pathlib.Path:
        """Resolve a caller-supplied path, or refuse.

        ``Path.resolve()`` follows symlinks, so the containment check runs against where
        the path actually lands. Checking the literal string for ``..`` would pass a
        symlink pointing at ``/etc`` straight through.
        """
        if "\x00" in relative:
            raise ContainmentError("path contains a null byte")

        candidate = (self._root / relative).resolve()
        if not self._is_inside(candidate, self._root):
            raise ContainmentError(f"path escapes the assigned repository: {relative!r}")
        return candidate

    def list_files(self, path: str = ".") -> dict[str, Any]:
        base = self.resolve(path)
        if not base.is_dir():
            raise ContainmentError(f"not a directory: {path!r}")

        entries: list[dict[str, Any]] = []
        for item in sorted(base.rglob("*")):
            if len(entries) >= MAX_LISTED_FILES:
                break
            if not item.is_file():
                continue
            # rglob follows into symlinked directories, so each result is re-checked
            # rather than trusted because it came from inside the walk.
            resolved = item.resolve()
            if not self._is_inside(resolved, self._root):
                continue
            entries.append(
                {
                    "path": item.relative_to(self._root).as_posix(),
                    "size_bytes": item.stat().st_size,
                }
            )

        return {
            "repository": self.assigned_repo,
            "files": entries,
            "truncated": len(entries) >= MAX_LISTED_FILES,
            "provenance": {"source": f"fixture://{self.assigned_repo}", "trust": "untrusted"},
        }

    def read_file(self, path: str) -> dict[str, Any]:
        target = self.resolve(path)
        if not target.is_file():
            raise ContainmentError(f"not a file: {path!r}")

        size = target.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ContainmentError(f"file is {size} bytes, over the {MAX_FILE_BYTES} limit")

        content = target.read_text(encoding="utf-8", errors="replace")
        return {
            "repository": self.assigned_repo,
            "path": target.relative_to(self._root).as_posix(),
            "content": content,
            "size_bytes": size,
            # Provenance travels with the content. This file may contain an injection
            # payload aimed at whatever reads it, and the label is how the planner's
            # context keeps track of that.
            "provenance": {
                "source": f"fixture://{self.assigned_repo}/{path}",
                "trust": "untrusted",
            },
        }

    def search_code(self, query: str, max_results: int = 50) -> dict[str, Any]:
        if not query:
            raise ContainmentError("search query must not be empty")

        limit = max(1, min(max_results, MAX_SEARCH_RESULTS))
        matches: list[dict[str, Any]] = []

        for item in sorted(self._root.rglob("*")):
            if len(matches) >= limit:
                break
            if not item.is_file() or not self._is_inside(item.resolve(), self._root):
                continue
            if item.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = item.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if query in line:
                    matches.append(
                        {
                            "path": item.relative_to(self._root).as_posix(),
                            "line": number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= limit:
                        break

        return {
            "repository": self.assigned_repo,
            "query": query,
            "matches": matches,
            "truncated": len(matches) >= limit,
            "provenance": {"source": f"fixture://{self.assigned_repo}", "trust": "untrusted"},
        }


def build_server(repository: FixtureRepository) -> MCPServer:
    """Wire the repository into an MCP server.

    Note the API: ``MCPServer``, not ``FastMCP``. The mcp 2.x line renamed it, so code
    written from 1.x knowledge fails at import. That rename is the single most likely
    thing to break somebody picking this up.
    """
    server = MCPServer(name=SERVER_NAME, version=SERVER_VERSION)

    @server.tool(
        name="list_files",
        description="List files in the assigned fixture repository.",
    )
    def list_files(path: str = ".") -> dict[str, Any]:
        return repository.list_files(path)

    @server.tool(
        name="read_file",
        description="Read one file from the assigned fixture repository.",
    )
    def read_file(path: str) -> dict[str, Any]:
        return repository.read_file(path)

    @server.tool(
        name="search_code",
        description="Search the assigned fixture repository for a literal string.",
    )
    def search_code(query: str, max_results: int = 50) -> dict[str, Any]:
        return repository.search_code(query, max_results)

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", default=os.environ.get(ENV_CORPUS_ROOT))
    parser.add_argument("--repo", default=os.environ.get(ENV_ASSIGNED_REPO))
    args = parser.parse_args(argv)

    if not args.corpus_root or not args.repo:
        _log("corpus root and assigned repository are both required")
        return 2

    try:
        repository = FixtureRepository(pathlib.Path(args.corpus_root), args.repo)
    except ContainmentError as exc:
        _log(f"refusing to start: {exc}")
        return 2

    _log(f"serving {repository.root}")
    build_server(repository).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
