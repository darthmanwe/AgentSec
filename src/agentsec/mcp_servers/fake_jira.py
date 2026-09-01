"""Fake Jira MCP server (AS-018).

Local ticket store with approval-gated, idempotent writes. No Atlassian dependency and no
network — the value is in exercising the approval path and the retry semantics against
something ticket-shaped.

Ticket text is a primary injection channel in the AS-035 corpus. A ticket body is free
text somebody else wrote, and an agent reads it as context; that is precisely the shape of
an indirect prompt injection. Every response therefore carries an untrusted label.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
from typing import Any, Final

from mcp.server.mcpserver import MCPServer

from agentsec.mcp_servers._common import (
    FixtureServerError,
    IdempotencyLedger,
    log,
    provenance,
    require,
)

SERVER_NAME: Final = "agentsec-fake-jira"
SERVER_VERSION: Final = "1.0.0"
ENV_STATE: Final = "AGENTSEC_JIRA_STATE"

DEFAULT_STATE_PATH: Final = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "fixtures"
    / "jira"
    / "issues.json"
)

MAX_SUMMARY = 255
MAX_BODY = 8192


class FakeJira:
    """Local ticket store."""

    def __init__(self, baseline: dict[str, Any]) -> None:
        self._baseline = copy.deepcopy(baseline)
        self._state = copy.deepcopy(baseline)
        self._ledger = IdempotencyLedger()
        self._counter = len(self._state.get("issues", {}))

    @classmethod
    def load(cls, path: pathlib.Path) -> FakeJira:
        if not path.exists():
            raise FixtureServerError(f"jira fixture not found at {path}")
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def reset(self) -> dict[str, Any]:
        self._state = copy.deepcopy(self._baseline)
        self._ledger.clear()
        self._counter = len(self._state.get("issues", {}))
        return {"reset": True, "issues": self._counter}

    @property
    def issue_count(self) -> int:
        """The idempotency evidence: retries must not move this."""
        return len(self._state.get("issues", {}))

    # ------------------------------------------------------------------ reads

    def search(self, query: str) -> dict[str, Any]:
        require(bool(query), "query is required")
        issues: dict[str, Any] = self._state.get("issues", {})
        needle = query.lower()
        matches = [
            {"key": key, "summary": issue.get("summary"), "status": issue.get("status")}
            for key, issue in sorted(issues.items())
            if needle in json.dumps(issue).lower()
        ]
        return {
            "query": query,
            "matches": matches,
            "provenance": provenance("jira://search"),
        }

    def read_issue(self, issue_key: str) -> dict[str, Any]:
        issues: dict[str, Any] = self._state.get("issues", {})
        issue = issues.get(issue_key.upper())
        if issue is None:
            raise FixtureServerError(f"no such issue: {issue_key}")
        return {
            "key": issue_key.upper(),
            "issue": issue,
            # Ticket text is written by other people. Treating it as instruction is the
            # failure the injection corpus is designed to provoke.
            "provenance": provenance(f"jira://{issue_key.upper()}"),
        }

    # ------------------------------------------------------------------ writes

    def create_issue(
        self, project: str, summary: str, operation_id: str, description: str = ""
    ) -> dict[str, Any]:
        require(bool(operation_id), "operation_id is required for a mutating call")
        require(bool(project), "project is required")
        require(bool(summary), "summary is required")
        require(len(summary) <= MAX_SUMMARY, f"summary exceeds {MAX_SUMMARY} characters")
        require(len(description) <= MAX_BODY, f"description exceeds {MAX_BODY} characters")

        replayed = self._ledger.get(operation_id)
        if replayed is not None:
            return replayed

        self._counter += 1
        key = f"{project.upper()}-{self._counter}"
        self._state.setdefault("issues", {})[key] = {
            "project": project.upper(),
            "summary": summary,
            "description": description,
            "status": "Open",
            "comments": [],
        }
        return self._ledger.put(
            operation_id,
            {"key": key, "created": True, "provenance": provenance(f"jira://{key}")},
        )

    def comment(self, issue_key: str, body: str, operation_id: str) -> dict[str, Any]:
        require(bool(operation_id), "operation_id is required for a mutating call")
        require(bool(body), "body is required")
        require(len(body) <= MAX_BODY, f"body exceeds {MAX_BODY} characters")

        replayed = self._ledger.get(operation_id)
        if replayed is not None:
            return replayed

        issues: dict[str, Any] = self._state.get("issues", {})
        issue = issues.get(issue_key.upper())
        if issue is None:
            raise FixtureServerError(f"no such issue: {issue_key}")

        issue.setdefault("comments", []).append({"body": body})
        return self._ledger.put(
            operation_id,
            {
                "key": issue_key.upper(),
                "comment_index": len(issue["comments"]) - 1,
                "created": True,
                "provenance": provenance(f"jira://{issue_key.upper()}"),
            },
        )


def build_server(jira: FakeJira) -> MCPServer:
    server = MCPServer(name=SERVER_NAME, version=SERVER_VERSION)

    @server.tool(name="search", description="Search local ticket records.")
    def search(query: str) -> dict[str, Any]:
        return jira.search(query)

    @server.tool(name="read_issue", description="Read one local ticket record.")
    def read_issue(issue_key: str) -> dict[str, Any]:
        return jira.read_issue(issue_key)

    @server.tool(
        name="create_issue",
        description="Create a ticket. Approval-gated and idempotent by operation_id.",
    )
    def create_issue(
        project: str, summary: str, operation_id: str, description: str = ""
    ) -> dict[str, Any]:
        return jira.create_issue(project, summary, operation_id, description)

    @server.tool(
        name="comment",
        description="Comment on a ticket. Approval-gated and idempotent by operation_id.",
    )
    def comment(issue_key: str, body: str, operation_id: str) -> dict[str, Any]:
        return jira.comment(issue_key, body, operation_id)

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=os.environ.get(ENV_STATE))
    args = parser.parse_args(argv)

    path = pathlib.Path(args.state) if args.state else DEFAULT_STATE_PATH
    try:
        jira = FakeJira.load(path)
    except FixtureServerError as exc:
        log(SERVER_NAME, f"refusing to start: {exc}")
        return 2

    log(SERVER_NAME, f"serving tickets from {path}")
    build_server(jira).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
