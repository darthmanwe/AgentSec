"""Offline vulnerability intelligence MCP server (AS-017).

Answers from a **pinned snapshot committed to the repository**, never from the network.
That is a reproducibility requirement, not a convenience: a benchmark whose vulnerability
data changes underneath it produces numbers that cannot be re-derived, and "the CVE
database updated" is not an explanation anyone can check.

Every response carries the snapshot version, so a published result can state exactly what
it was measured against.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
from typing import Any, Final

from mcp.server.mcpserver import MCPServer

from agentsec.mcp_servers._common import FixtureServerError, log, provenance, require

SERVER_NAME: Final = "agentsec-vuln-intel"
SERVER_VERSION: Final = "1.0.0"
ENV_SNAPSHOT: Final = "AGENTSEC_VULN_SNAPSHOT"

DEFAULT_SNAPSHOT_PATH: Final = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "fixtures"
    / "vuln"
    / "snapshot.json"
)

#: Rejected rather than normalised. A version string this server cannot parse means the
#: caller and the snapshot disagree about what a version is, and guessing produces a
#: confident wrong answer instead of an error.
_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*([.\-+][A-Za-z0-9.\-+]+)?$")
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class VulnerabilitySnapshot:
    """A pinned, offline vulnerability dataset."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.version: str = str(document.get("snapshot_version", "unknown"))
        self._packages: dict[str, list[dict[str, Any]]] = document.get("packages", {})
        self._cves: dict[str, dict[str, Any]] = document.get("cves", {})
        self._advisories: dict[str, dict[str, Any]] = document.get("advisories", {})

    @classmethod
    def load(cls, path: pathlib.Path) -> VulnerabilitySnapshot:
        if not path.exists():
            raise FixtureServerError(f"vulnerability snapshot not found at {path}")
        return cls(json.loads(path.read_text(encoding="utf-8")))

    @staticmethod
    def _key(ecosystem: str, name: str) -> str:
        return f"{ecosystem.lower()}:{name.lower()}"

    def lookup_package(self, ecosystem: str, name: str, version: str) -> dict[str, Any]:
        require(bool(ecosystem and name and version), "ecosystem, name and version are required")
        require(bool(_VERSION.match(version)), f"malformed version: {version!r}")

        entries = self._packages.get(self._key(ecosystem, name), [])
        affected = [entry for entry in entries if version in entry.get("affected_versions", [])]
        return {
            "ecosystem": ecosystem,
            "package": name,
            "version": version,
            "vulnerable": bool(affected),
            "vulnerabilities": affected,
            "provenance": provenance(f"vuln://{ecosystem}/{name}", snapshot=self.version),
        }

    def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        # Case-folded before matching, consistent with lookup_package. Inconsistent
        # handling of an identifier is how a caller gets "not found" for a record that
        # is right there.
        normalised = cve_id.upper()
        require(bool(_CVE.match(normalised)), f"malformed CVE identifier: {cve_id!r}")
        record = self._cves.get(normalised)
        return {
            "cve_id": normalised,
            "found": record is not None,
            "record": record,
            "provenance": provenance(f"vuln://cve/{normalised}", snapshot=self.version),
        }

    def lookup_advisory(self, advisory_id: str) -> dict[str, Any]:
        require(bool(advisory_id), "advisory_id is required")
        record = self._advisories.get(advisory_id.upper())
        return {
            "advisory_id": advisory_id.upper(),
            "found": record is not None,
            "record": record,
            "provenance": provenance(f"vuln://advisory/{advisory_id}", snapshot=self.version),
        }


def build_server(snapshot: VulnerabilitySnapshot) -> MCPServer:
    server = MCPServer(name=SERVER_NAME, version=SERVER_VERSION)

    @server.tool(
        name="lookup_package", description="Look up vulnerabilities for a package version."
    )
    def lookup_package(ecosystem: str, name: str, version: str) -> dict[str, Any]:
        return snapshot.lookup_package(ecosystem, name, version)

    @server.tool(name="lookup_cve", description="Look up a CVE record in the pinned snapshot.")
    def lookup_cve(cve_id: str) -> dict[str, Any]:
        return snapshot.lookup_cve(cve_id)

    @server.tool(name="lookup_advisory", description="Look up an advisory in the pinned snapshot.")
    def lookup_advisory(advisory_id: str) -> dict[str, Any]:
        return snapshot.lookup_advisory(advisory_id)

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", default=os.environ.get(ENV_SNAPSHOT))
    args = parser.parse_args(argv)

    path = pathlib.Path(args.snapshot) if args.snapshot else DEFAULT_SNAPSHOT_PATH
    try:
        snapshot = VulnerabilitySnapshot.load(path)
    except FixtureServerError as exc:
        log(SERVER_NAME, f"refusing to start: {exc}")
        return 2

    log(SERVER_NAME, f"serving snapshot {snapshot.version} from {path}")
    build_server(snapshot).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
