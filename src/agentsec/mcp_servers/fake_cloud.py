"""Fake cloud MCP server (AS-016).

Synthetic cloud inventory with one mutating operation. No AWS SDK, no real credentials,
no real resources — the point is to exercise the approval and idempotency paths against
something that behaves like a cloud API, not to talk to one.

``apply_remediation`` is the interesting operation. It is:

* **approval-gated** — the policy routes it through an operator, and the gateway will not
  reach this server without a capability minted from that approval;
* **idempotent by operation id** — a repeated call with the same id returns the original
  result rather than mutating twice. That is the backend half of at-most-once, and it is
  what makes a Temporal retry safe (AS-022);
* **resettable** — state returns to a known baseline, so an evaluation case cannot inherit
  a mutation from the case before it and turn the benchmark into a measure of ordering.
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

SERVER_NAME: Final = "agentsec-fake-cloud"
SERVER_VERSION: Final = "1.0.0"
ENV_STATE: Final = "AGENTSEC_CLOUD_STATE"

DEFAULT_STATE_PATH: Final = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "fixtures"
    / "cloud"
    / "inventory.json"
)


class FakeCloud:
    """Synthetic inventory with idempotent remediation."""

    def __init__(self, baseline: dict[str, Any]) -> None:
        self._baseline = copy.deepcopy(baseline)
        self._state = copy.deepcopy(baseline)
        self._ledger = IdempotencyLedger()

    @classmethod
    def load(cls, path: pathlib.Path) -> FakeCloud:
        if not path.exists():
            raise FixtureServerError(f"cloud inventory not found at {path}")
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def reset(self) -> dict[str, Any]:
        self._state = copy.deepcopy(self._baseline)
        self._ledger.clear()
        return {"reset": True, "resources": len(self._state.get("resources", {}))}

    # ------------------------------------------------------------------ reads

    def _resource(self, resource_id: str) -> dict[str, Any]:
        resources: dict[str, Any] = self._state.get("resources", {})
        resource: dict[str, Any] | None = resources.get(resource_id)
        if resource is None:
            raise FixtureServerError(f"no such resource: {resource_id}")
        return resource

    def list_resources(self, resource_type: str | None = None) -> dict[str, Any]:
        resources: dict[str, Any] = self._state.get("resources", {})
        items = [
            {"id": key, "type": value.get("type"), "name": value.get("name")}
            for key, value in sorted(resources.items())
            if resource_type is None or value.get("type") == resource_type
        ]
        return {"resources": items, "provenance": provenance("cloud://inventory")}

    def get_resource(self, resource_id: str) -> dict[str, Any]:
        return {
            "resource": self._resource(resource_id),
            "provenance": provenance(f"cloud://{resource_id}"),
        }

    def _document(self, resource_id: str, key: str, label: str) -> dict[str, Any]:
        resource = self._resource(resource_id)
        document = resource.get(key)
        if document is None:
            raise FixtureServerError(f"{resource_id} has no {label}")
        return {
            "resource_id": resource_id,
            label: document,
            # Cloud tags and policy documents are free text an attacker can set, which is
            # exactly why the injection corpus (AS-035) uses them as a delivery channel.
            "provenance": provenance(f"cloud://{resource_id}/{label}"),
        }

    def read_iam_policy(self, resource_id: str) -> dict[str, Any]:
        return self._document(resource_id, "iam_policy", "iam_policy")

    def read_security_group(self, resource_id: str) -> dict[str, Any]:
        return self._document(resource_id, "security_group", "security_group")

    def read_bucket_policy(self, resource_id: str) -> dict[str, Any]:
        return self._document(resource_id, "bucket_policy", "bucket_policy")

    # ------------------------------------------------------------------ mutation

    def apply_remediation(
        self, resource_id: str, remediation_id: str, operation_id: str
    ) -> dict[str, Any]:
        require(bool(operation_id), "operation_id is required for a mutating call")

        replayed = self._ledger.get(operation_id)
        if replayed is not None:
            # A retry returns the original result rather than mutating again. Without
            # this, a lost response would turn one approved action into two effects.
            return replayed

        resource = self._resource(resource_id)
        remediations: dict[str, Any] = self._state.get("remediations", {})
        remediation = remediations.get(remediation_id)
        if remediation is None:
            raise FixtureServerError(f"no such remediation: {remediation_id}")
        if remediation.get("applies_to") != resource.get("type"):
            raise FixtureServerError(
                f"remediation {remediation_id} does not apply to {resource.get('type')}"
            )

        for key, value in remediation.get("sets", {}).items():
            resource[key] = value
        resource.setdefault("applied_remediations", []).append(remediation_id)

        return self._ledger.put(
            operation_id,
            {
                "resource_id": resource_id,
                "remediation_id": remediation_id,
                "applied": True,
                "resource": copy.deepcopy(resource),
                "provenance": provenance(f"cloud://{resource_id}"),
            },
        )

    # ------------------------------------------------------------------ inspection

    @property
    def applied_count(self) -> int:
        """How many remediations actually landed. The idempotency evidence."""
        return sum(
            len(resource.get("applied_remediations", []))
            for resource in self._state.get("resources", {}).values()
        )


def build_server(cloud: FakeCloud) -> MCPServer:
    server = MCPServer(name=SERVER_NAME, version=SERVER_VERSION)

    @server.tool(name="list_resources", description="List synthetic cloud resources.")
    def list_resources(resource_type: str | None = None) -> dict[str, Any]:
        return cloud.list_resources(resource_type)

    @server.tool(name="get_resource", description="Read one synthetic cloud resource.")
    def get_resource(resource_id: str) -> dict[str, Any]:
        return cloud.get_resource(resource_id)

    @server.tool(name="read_iam_policy", description="Read a synthetic IAM policy document.")
    def read_iam_policy(resource_id: str) -> dict[str, Any]:
        return cloud.read_iam_policy(resource_id)

    @server.tool(name="read_security_group", description="Read a synthetic security group.")
    def read_security_group(resource_id: str) -> dict[str, Any]:
        return cloud.read_security_group(resource_id)

    @server.tool(name="read_bucket_policy", description="Read a synthetic bucket policy.")
    def read_bucket_policy(resource_id: str) -> dict[str, Any]:
        return cloud.read_bucket_policy(resource_id)

    @server.tool(
        name="apply_remediation",
        description="Apply a remediation. Approval-gated and idempotent by operation_id.",
    )
    def apply_remediation(
        resource_id: str, remediation_id: str, operation_id: str
    ) -> dict[str, Any]:
        return cloud.apply_remediation(resource_id, remediation_id, operation_id)

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=os.environ.get(ENV_STATE))
    args = parser.parse_args(argv)

    path = pathlib.Path(args.state) if args.state else DEFAULT_STATE_PATH
    try:
        cloud = FakeCloud.load(path)
    except FixtureServerError as exc:
        log(SERVER_NAME, f"refusing to start: {exc}")
        return 2

    log(SERVER_NAME, f"serving inventory from {path}")
    build_server(cloud).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
