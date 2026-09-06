"""Typed Semgrep adapter (AS-029).

Runs in the sandbox from its first commit. That ordering is why AS-031A was split out and
moved ahead of this issue: with the sandbox second, this adapter would have been written
and debugged against a host install and would have grown around its absence. On this host
it could not have been — Semgrep has no supported native Windows install.

**Rules are first-party.** ``policy/semgrep/agentsec.yaml`` rather than the registry.
Semgrep's community rules are under the Semgrep Rules License v1.0, limited to internal
non-competing use, which is not defensible to vendor into a public portfolio repository.
It is also better engineering here: the evaluation needs a fixed denominator, and a
drifting upstream registry means last month's numbers cannot be reproduced.

**The ruleset never leaves the host as a path.** It is staged into its own read-only
volume, separate from the code under scan, so the scan cannot read its own rules as
source and a poisoned repository cannot shadow them with a file of the same name.
"""

from __future__ import annotations

import json
import pathlib
import time
from typing import Any, Final

from agentsec.images import SEMGREP
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

log = get_logger("agentsec.scanners.semgrep")

RULES_MOUNT: Final = "/agentsec-rules"
RULES_VOLUME: Final = "agentsec-semgrep-rules"

#: Semgrep prefixes every rule id with the directory the config came from, so a rule
#: written as ``agentsec.python.sql-injection-concat`` is reported as
#: ``agentsec-rules.agentsec.python.sql-injection-concat``. Stripped here, derived from
#: the mount so the two cannot drift: the evaluation compares rule ids against a
#: ground-truth table, and an id that changes when a mount path changes would silently
#: turn every true positive into a miss.
_REPORTED_PREFIX: Final = f"{RULES_MOUNT.lstrip('/')}."

#: The only rulesets that may be requested. An enumeration, not a path parameter: a path
#: parameter is how a caller eventually points the scanner at a file it wrote.
RULESETS: Final[dict[str, str]] = {
    "agentsec": "agentsec.yaml",
}

DEFAULT_RULESET: Final = "agentsec"

#: Semgrep will use every core it can see, which on this host is 32 of them. Two is both
#: a stability control on a shared workstation and, in the sandbox, redundant with the
#: CPU cap - stating it explicitly means the limit does not depend on the cap being right.
JOBS: Final = "2"

MAX_OUTPUT_BYTES: Final = 4 * 1024 * 1024

#: Semgrep severities are a three-value scale. Mapped rather than passed through so the
#: evaluation counts one kind of thing across both scanners.
_SEVERITY: Final[dict[str, Severity]] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

RULES_DIR: Final = pathlib.Path(__file__).resolve().parents[3] / "policy" / "semgrep"

#: Semgrep writes a settings file at startup and refuses to run without somewhere to put
#: it. Under a read-only root filesystem as uid 65534 there is no home directory, so it
#: crashed before scanning anything - and exited 1 while doing so, which is also its
#: "found something" code. Pointing it at the noexec tmpfs gives it the scratch space it
#: wants without giving up the read-only root.
_ENVIRONMENT: Final[dict[str, str]] = {
    "HOME": SCRATCH,
    "XDG_CONFIG_HOME": f"{SCRATCH}/config",
    "XDG_CACHE_HOME": f"{SCRATCH}/cache",
    "SEMGREP_SETTINGS_FILE": f"{SCRATCH}/semgrep-settings.yml",
    "SEMGREP_VERSION_CACHE_PATH": f"{SCRATCH}/semgrep-version",
}


class SemgrepScanner:
    """Static analysis over a staged workspace.

    Note what the public methods do *not* accept: no argv, no flags, no rule path, no
    "extra options". A caller chooses a target and a ruleset id from an allowlist. There
    is deliberately no parameter through which a planner could influence the command line.
    """

    name = "semgrep"

    def __init__(
        self,
        sandbox: DockerSandbox | None = None,
        *,
        rules_dir: pathlib.Path = RULES_DIR,
        timeout_seconds: float = 180.0,
    ) -> None:
        self._sandbox = sandbox or DockerSandbox(
            limits=SandboxLimits(cpus="2", memory="2g", timeout_seconds=timeout_seconds)
        )
        self._rules_dir = rules_dir
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------ preparation

    async def ensure_rules(self) -> str:
        """Stage the first-party ruleset into its own read-only volume.

        Separate from the workspace on purpose. Mixing rules into the code under scan
        would make the ruleset an input to its own analysis, and would let a repository
        containing ``agentsec.yaml`` shadow the real one.
        """
        files: dict[str, str | bytes] = {}
        for path in sorted(self._rules_dir.glob("*.yaml")):
            files[path.name] = path.read_bytes()
        if not files:
            raise ScannerError(f"no rulesets found in {self._rules_dir}")

        await self._sandbox.ensure_volume(RULES_VOLUME, run_id="semgrep-rules")
        await self._sandbox.stage_into(RULES_VOLUME, files)
        return RULES_VOLUME

    # ------------------------------------------------------------------ scanning

    async def scan_repository(
        self, workspace: Workspace, *, ruleset: str = DEFAULT_RULESET
    ) -> ScanResult:
        """Scan everything staged in the workspace."""
        return await self._scan(workspace, ".", ruleset=ruleset)

    async def scan_path(
        self, workspace: Workspace, path: str, *, ruleset: str = DEFAULT_RULESET
    ) -> ScanResult:
        """Scan one path within the workspace."""
        return await self._scan(workspace, safe_target(path), ruleset=ruleset)

    async def _scan(self, workspace: Workspace, target: str, *, ruleset: str) -> ScanResult:
        if ruleset not in RULESETS:
            # Fails closed and names the allowlist. An unknown ruleset that fell back to a
            # default would report "no findings" for a scan that never ran the rules the
            # caller asked for, which is worse than an error.
            raise UnknownRulesetError(
                f"{ruleset!r} is not an allowlisted ruleset; known: {sorted(RULESETS)}"
            )
        await self.ensure_rules()

        argv = [
            "semgrep",
            "scan",
            "--config",
            f"{RULES_MOUNT}/{RULESETS[ruleset]}",
            "--json",
            "--quiet",
            "--no-git-ignore",
            # No network under any circumstance: --network none already guarantees it, but
            # Semgrep's own flags say so too, so a future caller enabling the network does
            # not silently turn on metrics and registry fetches.
            "--metrics",
            "off",
            "--disable-version-check",
            "--jobs",
            JOBS,
            "--timeout",
            str(int(self._timeout)),
            target,
        ]

        started = time.monotonic()
        result = await self._sandbox.run(
            str(SEMGREP),
            argv,
            workspace=workspace,
            run_id=workspace.run_id,
            timeout_seconds=self._timeout,
            extra_volumes={RULES_VOLUME: RULES_MOUNT},
            env=_ENVIRONMENT,
        )
        duration = time.monotonic() - started

        if result.timed_out:
            raise ScannerError(f"semgrep timed out after {self._timeout}s on {target!r}")
        if result.exit_code not in (0, 1):
            raise ScannerError(f"semgrep failed ({result.exit_code}): {result.stderr[:500]}")

        # Exit code 1 means *either* "findings were reported" or "semgrep crashed", and
        # the first version of this adapter could not tell them apart - so a scanner that
        # died at startup reported a clean repository. Empty stdout settles it: a
        # successful scan always emits a JSON document, even when it finds nothing.
        if not result.stdout.strip():
            raise ScannerError(
                f"semgrep produced no output (exit {result.exit_code}); "
                f"the scan did not run: {result.stderr.strip()[-500:]}"
            )

        payload, truncated = clamp(result.stdout, MAX_OUTPUT_BYTES)
        findings, version = _parse(payload, truncated=truncated)
        log.info(
            "semgrep scan complete",
            target=target,
            ruleset=ruleset,
            findings=len(findings),
            seconds=round(duration, 2),
        )
        return ScanResult(
            scanner=self.name,
            tool_version=version,
            findings=findings,
            target=target,
            duration_seconds=duration,
            truncated=truncated,
            metadata={"ruleset": ruleset, "image": str(SEMGREP)},
        )


def _parse(payload: str, *, truncated: bool) -> tuple[tuple[Finding, ...], str]:
    """Turn Semgrep's JSON into normalised findings.

    Everything a scanner emits about attacker-authored code is untrusted: rule ids,
    messages and paths all originate in a document this project does not control. Fields
    are read defensively and coerced, never trusted to be present or to be the type the
    schema says.
    """
    if not payload.strip():
        # Reached only if a caller parses output the scan path already rejected. Raising
        # keeps the invariant in one place: no output means no scan, never a clean result.
        raise ScannerError("semgrep produced no output; the scan did not run")
    try:
        document: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as error:
        if truncated:
            # Expected: the output was cut mid-object because it exceeded the cap. Say so
            # plainly rather than reporting a parse bug.
            raise ScannerError(
                "semgrep output exceeded the size cap and cannot be parsed"
            ) from error
        raise ScannerError(f"semgrep produced unparseable JSON: {error}") from error

    version = str(document.get("version") or "unknown")
    findings = []
    for raw in document.get("results") or []:
        if not isinstance(raw, dict):
            continue
        extra = _mapping(raw.get("extra"))
        start = _mapping(raw.get("start"))
        severity = _SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.INFO)
        findings.append(
            Finding(
                scanner="semgrep",
                rule_id=_rule_id(raw.get("check_id")),
                severity=severity,
                message=str(extra.get("message") or "").strip()[:1000],
                path=str(raw.get("path") or "").lstrip("./"),
                line=int(start["line"]) if isinstance(start.get("line"), int) else None,
                identifier=_cwe(extra),
            )
        )
    return tuple(sorted(findings, key=Finding.key)), version


def _rule_id(value: object) -> str:
    """Strip the config-path prefix Semgrep prepends to every rule id."""
    reported = str(value or "unknown")
    return reported[len(_REPORTED_PREFIX) :] if reported.startswith(_REPORTED_PREFIX) else reported


def _mapping(value: object) -> dict[str, Any]:
    """Coerce an untrusted field to a mapping.

    Scanner output describes attacker-authored code, so every nested object is something
    this project did not write. Returning an empty mapping for anything that is not one
    keeps the parser total: a malformed result yields fewer findings, never a crash in the
    middle of a scan whose other findings were real.
    """
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def _cwe(extra: dict[str, Any]) -> str | None:
    metadata = _mapping(extra.get("metadata"))
    if not metadata:
        return None
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])[:200]
    return str(cwe)[:200] if cwe else None


__all__ = ["DEFAULT_RULESET", "JOBS", "RULESETS", "RULES_MOUNT", "RULES_VOLUME", "SemgrepScanner"]
