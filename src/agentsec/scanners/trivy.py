"""Typed Trivy adapter (AS-030).

Same shape as the Semgrep adapter and the same rule: an enumerated mode and a validated
path, never a command. See :mod:`agentsec.scanners.base` for why that is load-bearing.

**The vulnerability database is pinned and offline.** Trivy ships without one and fetches
it from a registry on first run. Two things break if that fetch happens during a scan.
The evaluation promises offline reproducibility, which a network call contradicts
outright; and a database that updates between runs means the same repository scores
differently on Tuesday than it did on Monday, so a published number cannot be checked.

The resolution is to make the fetch an explicit, separate, privileged step. Exactly one
operation here touches the network — :meth:`TrivyScanner.ensure_database` — and it runs
with the workspace absent and the cache volume as its only mount. Every scan afterwards
runs with ``--network none``, ``--skip-db-update``, ``--skip-java-db-update`` and
``--offline-scan``, against a read-only cache. The database version travels on every
result so an artifact says which one produced it.
"""

from __future__ import annotations

import enum
import json
import time
from typing import Any, Final

from agentsec.images import BUSYBOX, TRIVY
from agentsec.log import get_logger
from agentsec.sandbox import SCRATCH, DockerSandbox, SandboxLimits, Workspace
from agentsec.scanners.base import (
    Finding,
    ScannerError,
    ScanResult,
    Severity,
    UnknownRulesetError,
    clamp,
    safe_target,
)

log = get_logger("agentsec.scanners.trivy")

CACHE_MOUNT: Final = "/trivy-cache"
CACHE_VOLUME: Final = "agentsec-trivy-cache"

MAX_OUTPUT_BYTES: Final = 8 * 1024 * 1024

_SEVERITY: Final[dict[str, Severity]] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_ENVIRONMENT: Final[dict[str, str]] = {
    "HOME": SCRATCH,
    "XDG_CACHE_HOME": f"{SCRATCH}/cache",
    "TRIVY_NO_PROGRESS": "true",
}


class ScanMode(enum.StrEnum):
    """What Trivy is being asked to look for.

    An enumeration rather than a ``--scanners`` string, so the set of things a caller can
    request is closed. ``VULNERABILITY`` is the only one that needs the database, which is
    why the other two keep working when it has never been fetched.
    """

    VULNERABILITY = "vuln"
    MISCONFIGURATION = "misconfig"
    # Suppression: this names a scanner mode, not a credential. Bandit's S105 matches on
    # the member name containing "SECRET", the same false positive RiskClass carries.
    SECRET = "secret"  # noqa: S105


class TrivyScanner:
    """Dependency, filesystem and infrastructure scanning over a staged workspace.

    As with Semgrep: no argv, no flags, no free-form options. A caller picks a mode from
    :class:`ScanMode` and a path that :func:`~agentsec.scanners.base.safe_target`
    accepts, and nothing else reaches the process.
    """

    name = "trivy"

    def __init__(
        self, sandbox: DockerSandbox | None = None, *, timeout_seconds: float = 300.0
    ) -> None:
        self._sandbox = sandbox or DockerSandbox(
            limits=SandboxLimits(cpus="2", memory="2g", timeout_seconds=timeout_seconds)
        )
        self._timeout = timeout_seconds
        self._database_version: str | None = None

    # ------------------------------------------------------------------ database

    async def ensure_database(self, *, force: bool = False) -> str:
        """Fetch the vulnerability database into the cache volume.

        **The one operation in this module that touches the network.** Kept separate and
        explicit for that reason: a scan that silently downloads is a scan whose result
        depends on the day it ran. Call it once during setup, then scan offline forever.

        The cache is mounted as a writable workspace here rather than as a read-only
        auxiliary volume, because this is the only step that writes to it.
        """
        await self._sandbox.ensure_volume(CACHE_VOLUME, run_id="trivy-cache")

        if not force and await self._database_present():
            return await self.database_version()

        log.info("fetching trivy database", volume=CACHE_VOLUME)
        result = await self._sandbox.seed_volume(
            CACHE_VOLUME,
            str(TRIVY),
            ["--cache-dir", CACHE_MOUNT, "image", "--download-db-only"],
            mount=CACHE_MOUNT,
            network=True,
            env={"TRIVY_NO_PROGRESS": "true"},
            timeout_seconds=max(self._timeout, 600.0),
        )
        if not result.ok:
            raise ScannerError(f"trivy database fetch failed: {result.stderr[-800:]}")
        self._database_version = None
        return await self.database_version()

    async def database_version(self) -> str:
        """The database's own version stamp, read from its metadata.

        Recorded on every result. A benchmark whose database version is reconstructed from
        memory afterwards is a benchmark nobody can reproduce.
        """
        if self._database_version is not None:
            return self._database_version

        result = await self._sandbox.run(
            str(BUSYBOX),
            ["cat", f"{CACHE_MOUNT}/db/metadata.json"],
            run_id="trivy-db",
            timeout_seconds=60.0,
            extra_volumes={CACHE_VOLUME: CACHE_MOUNT},
        )
        if not result.ok:
            self._database_version = "absent"
            return self._database_version

        try:
            metadata = json.loads(result.stdout)
            version = f"v{metadata.get('Version')}@{metadata.get('UpdatedAt')}"
        except (json.JSONDecodeError, AttributeError):
            version = "unparseable"
        self._database_version = version
        return version

    async def _database_present(self) -> bool:
        """Checked unprivileged and read-only, exactly as a scan will see it.

        Probing through the privileged path would answer a different question: whether
        root can see the database, when what matters is whether uid 65534 can.
        """
        result = await self._sandbox.run(
            str(BUSYBOX),
            ["test", "-f", f"{CACHE_MOUNT}/db/trivy.db"],
            run_id="trivy-db",
            timeout_seconds=60.0,
            extra_volumes={CACHE_VOLUME: CACHE_MOUNT},
        )
        return result.ok

    # ------------------------------------------------------------------ scanning

    async def scan_dependency_manifest(self, workspace: Workspace, path: str) -> ScanResult:
        """Scan one manifest - requirements.txt, package-lock.json - for known advisories."""
        return await self._scan(workspace, safe_target(path), ScanMode.VULNERABILITY)

    async def scan_filesystem(
        self, workspace: Workspace, path: str = ".", *, mode: ScanMode = ScanMode.VULNERABILITY
    ) -> ScanResult:
        """Scan a tree in the requested mode."""
        if not isinstance(mode, ScanMode):
            # Fails closed. A string that fell through would become a --scanners value,
            # which is precisely the free-form flag this interface exists to prevent.
            raise UnknownRulesetError(f"{mode!r} is not a ScanMode")
        return await self._scan(workspace, safe_target(path), mode)

    async def scan_iac(self, workspace: Workspace, path: str = ".") -> ScanResult:
        """Scan infrastructure definitions - Dockerfile, Terraform, Kubernetes."""
        return await self._scan(workspace, safe_target(path), ScanMode.MISCONFIGURATION)

    async def _scan(self, workspace: Workspace, target: str, mode: ScanMode) -> ScanResult:
        argv = [
            "--cache-dir",
            CACHE_MOUNT,
            "filesystem",
            "--scanners",
            mode.value,
            "--format",
            "json",
            "--quiet",
            # Offline in four separate ways, because each covers a different fetch and any
            # one of them alone would leave a path to the network.
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            target,
        ]

        database = await self.database_version() if mode is ScanMode.VULNERABILITY else None
        if mode is ScanMode.VULNERABILITY and database == "absent":
            raise ScannerError(
                "the trivy vulnerability database has not been fetched; "
                "call ensure_database() once during setup"
            )

        started = time.monotonic()
        result = await self._sandbox.run(
            str(TRIVY),
            argv,
            workspace=workspace,
            run_id=workspace.run_id,
            timeout_seconds=self._timeout,
            extra_volumes={CACHE_VOLUME: CACHE_MOUNT},
            env=_ENVIRONMENT,
        )
        duration = time.monotonic() - started

        if result.timed_out:
            raise ScannerError(f"trivy timed out after {self._timeout}s on {target!r}")
        if result.exit_code != 0:
            raise ScannerError(f"trivy failed ({result.exit_code}): {result.stderr[-800:]}")
        if not result.stdout.strip():
            # Same failure the Semgrep adapter was caught by: a scanner that did not run
            # must never be reported as a clean result.
            raise ScannerError(
                f"trivy produced no output; the scan did not run: {result.stderr.strip()[-500:]}"
            )

        payload, truncated = clamp(result.stdout, MAX_OUTPUT_BYTES)
        findings = _parse(payload, mode, truncated=truncated)
        log.info(
            "trivy scan complete",
            target=target,
            mode=mode.value,
            findings=len(findings),
            seconds=round(duration, 2),
        )
        return ScanResult(
            scanner=self.name,
            tool_version=TRIVY.tag,
            findings=findings,
            target=target,
            duration_seconds=duration,
            truncated=truncated,
            database_version=database,
            metadata={"mode": mode.value, "image": str(TRIVY)},
        )


def _parse(payload: str, mode: ScanMode, *, truncated: bool) -> tuple[Finding, ...]:
    """Turn Trivy's JSON into normalised findings.

    Read defensively throughout: this describes attacker-authored content, so no field is
    trusted to exist or to be the type the schema promises.
    """
    try:
        document: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as error:
        if truncated:
            raise ScannerError("trivy output exceeded the size cap and cannot be parsed") from error
        raise ScannerError(f"trivy produced unparseable JSON: {error}") from error

    findings: list[Finding] = []
    for raw_result in document.get("Results") or []:
        result = _mapping(raw_result)
        path = str(result.get("Target") or "").lstrip("./")

        for raw in result.get("Vulnerabilities") or []:
            item = _mapping(raw)
            findings.append(
                Finding(
                    scanner="trivy",
                    rule_id=str(item.get("VulnerabilityID") or "unknown"),
                    severity=_SEVERITY.get(str(item.get("Severity", "")).upper(), Severity.INFO),
                    message=str(item.get("Title") or item.get("Description") or "").strip()[:1000],
                    path=path,
                    identifier=str(item.get("VulnerabilityID") or "") or None,
                    package=str(item.get("PkgName") or "") or None,
                    installed_version=str(item.get("InstalledVersion") or "") or None,
                    fixed_version=str(item.get("FixedVersion") or "") or None,
                )
            )

        for raw in result.get("Misconfigurations") or []:
            item = _mapping(raw)
            location = _mapping(item.get("CauseMetadata"))
            findings.append(
                Finding(
                    scanner="trivy",
                    rule_id=str(item.get("ID") or "unknown"),
                    severity=_SEVERITY.get(str(item.get("Severity", "")).upper(), Severity.INFO),
                    message=str(item.get("Title") or item.get("Message") or "").strip()[:1000],
                    path=path,
                    line=location.get("StartLine")
                    if isinstance(location.get("StartLine"), int)
                    else None,
                    identifier=str(item.get("ID") or "") or None,
                )
            )

        for raw in result.get("Secrets") or []:
            item = _mapping(raw)
            findings.append(
                Finding(
                    scanner="trivy",
                    rule_id=str(item.get("RuleID") or "unknown"),
                    severity=_SEVERITY.get(str(item.get("Severity", "")).upper(), Severity.INFO),
                    # Never the matched text: that is the secret itself, and putting it in
                    # a finding moves it into logs, reports and eval artifacts.
                    message=str(item.get("Title") or "").strip()[:1000],
                    path=path,
                    line=item.get("StartLine") if isinstance(item.get("StartLine"), int) else None,
                )
            )

    return tuple(sorted(findings, key=Finding.key))


def _mapping(value: object) -> dict[str, Any]:
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


__all__ = ["CACHE_MOUNT", "CACHE_VOLUME", "ScanMode", "TrivyScanner"]
