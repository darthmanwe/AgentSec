"""Scanner adapter tests (AS-029, AS-030).

The acceptance criteria for both issues are negative — "no generic command parameter",
"no shell=True or free-form flags from the model" — so most of what follows checks that
something is *impossible* rather than that something works.

That is checked structurally, by inspecting the adapters' signatures and the argv they
build. A review can confirm today's code has no command parameter; only a test confirms
tomorrow's does not, and the person who adds one will be solving a real problem under
time pressure.

The container tests need Docker and run under ``-m sandbox``. The Trivy ones additionally
need the vulnerability database, which is fetched once and then never touched again.
"""

from __future__ import annotations

import inspect
import pathlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from agentsec.sandbox import DockerSandbox, SandboxLimits, docker_available
from agentsec.scanners.base import (
    Finding,
    InvalidTargetError,
    ScannerError,
    ScanResult,
    Severity,
    UnknownRulesetError,
    clamp,
    safe_target,
)
from agentsec.scanners.semgrep import RULESETS, SemgrepScanner
from agentsec.scanners.trivy import ScanMode, TrivyScanner

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "repos"

requires_docker = pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")

#: Parameter names that would let a caller influence the command line. Checked by name
#: because that is how such a parameter arrives: someone needs one more flag and adds
#: ``extra_args`` rather than extending the enumeration.
FORBIDDEN_PARAMETERS = {
    "args",
    "argv",
    "cmd",
    "command",
    "extra_args",
    "extra_flags",
    "flags",
    "options",
    "opts",
    "raw",
    "shell",
}


# =========================================================== the interface is closed


@pytest.mark.parametrize("scanner", [SemgrepScanner, TrivyScanner], ids=lambda c: c.__name__)
def test_no_public_method_accepts_a_command(scanner: type) -> None:
    """The AS-029 and AS-030 acceptance criteria, as a test rather than a review note.

    A scanner adapter that takes an argument list or a flags string is a remote code
    execution primitive wearing a typed interface, and the planner - which reads
    attacker-authored repository text - is the least trustworthy component in the system.
    """
    for name, method in inspect.getmembers(scanner, inspect.isfunction):
        if name.startswith("_"):
            continue
        parameters = set(inspect.signature(method).parameters)
        offending = parameters & FORBIDDEN_PARAMETERS
        assert not offending, f"{scanner.__name__}.{name} accepts {sorted(offending)}"


@pytest.mark.parametrize("scanner", [SemgrepScanner, TrivyScanner], ids=lambda c: c.__name__)
def test_the_adapters_are_actually_being_inspected(scanner: type) -> None:
    """Guards against the check above passing because it found no methods to look at."""
    public = [
        n for n, _ in inspect.getmembers(scanner, inspect.isfunction) if not n.startswith("_")
    ]
    assert len(public) >= 2, public


def test_no_scanner_module_uses_a_shell() -> None:
    """``shell=True`` turns every argument into a command. Nothing here may reach for it."""
    for module in ("semgrep", "trivy", "base"):
        source = (
            pathlib.Path(__file__).resolve().parent.parent
            / "src"
            / "agentsec"
            / "scanners"
            / f"{module}.py"
        ).read_text(encoding="utf-8")
        assert "shell=True" not in source, module
        assert "os.system" not in source, module


# =========================================================== target validation


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../../secrets",
        "..",
        "src/../../escape",
        "C:\\Windows\\System32",
        "src/main.py\x00.txt",
        "a" * 600,
    ],
)
def test_an_unsafe_target_is_rejected(path: str) -> None:
    """The sandbox already confines the process, so this is defence in depth. It is also
    what keeps a scan of ``../../etc`` from being a *coherent request* - and an incoherent
    request that returns findings is one somebody will act on."""
    with pytest.raises(InvalidTargetError):
        safe_target(path)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/main.py", "src/main.py"),
        ("./src/main.py", "src/main.py"),
        ("src/./main.py", "src/main.py"),
        ("", "."),
        (".", "."),
        ("infra", "infra"),
    ],
)
def test_a_safe_target_is_normalised(path: str, expected: str) -> None:
    assert safe_target(path) == expected


def test_a_traversal_that_stays_inside_is_allowed() -> None:
    """``src/../main.py`` resolves inside the workspace, so rejecting it would be wrong."""
    assert safe_target("src/../main.py") == "main.py"


# =========================================================== allowlists


async def test_an_unknown_semgrep_ruleset_is_refused() -> None:
    """Fails closed and names the allowlist. Falling back to a default would report "no
    findings" for a scan that never ran the rules the caller asked for."""
    scanner = SemgrepScanner(DockerSandbox())
    with pytest.raises(UnknownRulesetError, match="not an allowlisted ruleset"):
        await scanner.scan_repository(_workspace(), ruleset="p/owasp-top-ten")


async def test_a_non_enum_trivy_mode_is_refused() -> None:
    """A string that fell through would become a --scanners value, which is precisely the
    free-form flag this interface exists to prevent."""
    scanner = TrivyScanner(DockerSandbox())
    with pytest.raises(UnknownRulesetError):
        await scanner.scan_filesystem(_workspace(), ".", mode="vuln,secret,misconfig")  # type: ignore[arg-type]


def test_the_semgrep_allowlist_is_an_enumeration_not_a_path() -> None:
    for key, value in RULESETS.items():
        assert "/" not in value and "\\" not in value, f"{key} points outside the rules volume"
        assert not value.startswith("."), key


def test_the_first_party_ruleset_exists_and_is_first_party() -> None:
    """Registry rules are under the Semgrep Rules License v1.0 - internal, non-competing
    use only - which is not defensible to vendor into a public repository."""
    rules = pathlib.Path(__file__).resolve().parent.parent / "policy" / "semgrep" / "agentsec.yaml"
    text = rules.read_text(encoding="utf-8")
    assert "rules:" in text
    assert "p/" not in text, "a registry pack reference leaked into the first-party ruleset"
    assert text.count("id: agentsec.") >= 5


# =========================================================== normalisation and parsing


def test_severity_ranks_are_ordered() -> None:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert [s.rank for s in order] == sorted(s.rank for s in order)


def test_findings_filter_by_minimum_severity() -> None:
    result = ScanResult(
        scanner="semgrep",
        tool_version="1.0",
        findings=(
            Finding("semgrep", "a", Severity.LOW, "", "x.py"),
            Finding("semgrep", "b", Severity.HIGH, "", "y.py"),
        ),
    )
    assert result.count == 2
    assert [f.rule_id for f in result.by_severity(Severity.MEDIUM)] == ["b"]


def test_output_is_bounded_and_says_when_it_was_cut() -> None:
    """A repository crafted to produce a million findings is a denial of service against
    whatever parses them. The flag is returned rather than logged so a result built from
    partial output is never mistaken for a complete one."""
    text, truncated = clamp("x" * 100, 10)
    assert len(text) == 10
    assert truncated is True

    text, truncated = clamp("short", 10)
    assert truncated is False


def test_semgrep_rule_ids_drop_the_config_path_prefix() -> None:
    """Semgrep prefixes rule ids with the directory the config came from. The evaluation
    compares ids against a ground-truth table, so an id that changes when a mount path
    changes would silently turn every true positive into a miss."""
    from agentsec.scanners.semgrep import _rule_id

    assert _rule_id("agentsec-rules.agentsec.python.sql-injection-concat") == (
        "agentsec.python.sql-injection-concat"
    )
    assert _rule_id("agentsec.python.eval-of-input") == "agentsec.python.eval-of-input"
    assert _rule_id(None) == "unknown"


def test_a_semgrep_scan_that_produced_no_output_is_an_error_not_a_clean_result() -> None:
    """The bug this project actually hit.

    Semgrep exits 1 both when it finds something and when it crashes, so a scanner that
    died at startup - it could not write its settings file under a read-only root - was
    reported as a clean repository. Empty output now settles it: a successful scan always
    emits a JSON document, even when it finds nothing.
    """
    from agentsec.scanners.semgrep import _parse

    with pytest.raises(ScannerError, match="did not run"):
        _parse("", truncated=False)


def test_a_malformed_scanner_result_does_not_crash_the_parser() -> None:
    """Scanner output describes attacker-authored code, so every nested object is
    something this project did not write."""
    from agentsec.scanners.semgrep import _parse

    findings, version = _parse(
        '{"version": "1.0", "results": ['
        '  "not an object",'
        '  {"check_id": null, "extra": "not an object", "start": 7},'
        '  {"check_id": "x", "extra": {"severity": "NONSENSE"}, "path": "a.py"}'
        "]}",
        truncated=False,
    )
    assert version == "1.0"
    assert len(findings) == 2
    assert all(f.severity is Severity.INFO for f in findings)


def test_truncated_output_reports_the_cap_rather_than_a_parse_bug() -> None:
    from agentsec.scanners.semgrep import _parse

    with pytest.raises(ScannerError, match="size cap"):
        _parse('{"version": "1.0", "results": [{"check', truncated=True)


# =========================================================== container-backed


def _workspace() -> object:
    from agentsec.sandbox import Workspace

    return Workspace(run_id="unused", name="agentsec-ws-unused")


@pytest.mark.sandbox
@requires_docker
class TestSemgrepInTheSandbox:
    @pytest_asyncio.fixture
    async def sandbox(self) -> AsyncIterator[DockerSandbox]:
        yield DockerSandbox(limits=SandboxLimits(timeout_seconds=300))

    async def test_the_known_sqli_fixture_is_detected(self, sandbox: DockerSandbox) -> None:
        """Ground truth: repo-a/src/main.py concatenates user input into a query."""
        scanner = SemgrepScanner(sandbox, timeout_seconds=240)
        async with sandbox.workspace("semgrep-sqli") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-a")
            result = await scanner.scan_repository(space)

        assert "agentsec.python.sql-injection-concat" in result.rule_ids()
        finding = next(f for f in result.findings if f.rule_id.endswith("sql-injection-concat"))
        assert finding.path == "src/main.py"
        assert finding.severity is Severity.HIGH
        assert result.tool_version != "unknown", "the scan reported no version; did it run?"

    async def test_the_clean_fixture_produces_nothing(self, sandbox: DockerSandbox) -> None:
        """A ruleset that fires on everything is as useless as one that fires on nothing."""
        scanner = SemgrepScanner(sandbox, timeout_seconds=240)
        async with sandbox.workspace("semgrep-clean") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-a" / "src", prefix="")
            result = await scanner.scan_path(space, "safe.py")

        assert result.count == 0

    async def test_a_missing_path_does_not_report_a_clean_repository(
        self, sandbox: DockerSandbox
    ) -> None:
        scanner = SemgrepScanner(sandbox, timeout_seconds=240)
        async with sandbox.workspace("semgrep-missing") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-a")
            with pytest.raises(ScannerError):
                await scanner.scan_path(space, "does/not/exist.py")


@pytest.mark.sandbox
@requires_docker
class TestTrivyInTheSandbox:
    @pytest_asyncio.fixture
    async def scanner(self) -> AsyncIterator[TrivyScanner]:
        sandbox = DockerSandbox(limits=SandboxLimits(timeout_seconds=600))
        scanner = TrivyScanner(sandbox, timeout_seconds=600)
        # The one network call in the whole module, and only if the cache is empty.
        await scanner.ensure_database()
        yield scanner

    async def test_a_vulnerable_manifest_is_detected(self, scanner: TrivyScanner) -> None:
        sandbox = scanner._sandbox  # the fixture owns it
        async with sandbox.workspace("trivy-deps") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-c")
            result = await scanner.scan_dependency_manifest(space, "requirements.txt")

        assert result.count > 0
        assert all(f.rule_id.startswith(("CVE-", "GHSA-")) for f in result.findings)
        assert {f.package for f in result.findings} & {"requests", "urllib3", "Jinja2", "PyYAML"}
        assert any(f.fixed_version for f in result.findings), "no remediation advice"

    async def test_the_database_version_travels_on_the_result(self, scanner: TrivyScanner) -> None:
        """A benchmark whose database version is reconstructed from memory afterwards is a
        benchmark nobody can reproduce."""
        sandbox = scanner._sandbox
        async with sandbox.workspace("trivy-version") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-c")
            result = await scanner.scan_dependency_manifest(space, "requirements.txt")

        assert result.database_version
        assert result.database_version not in {"absent", "unparseable"}

    async def test_an_iac_misconfiguration_is_detected(self, scanner: TrivyScanner) -> None:
        """Ground truth: the fixture Dockerfile runs as root and bakes a key into a layer."""
        sandbox = scanner._sandbox
        async with sandbox.workspace("trivy-iac") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-c")
            result = await scanner.scan_iac(space, "infra")

        assert result.count > 0
        messages = " ".join(f.message for f in result.findings).lower()
        assert "root" in messages
        assert result.by_severity(Severity.HIGH)

    async def test_scans_run_with_the_network_off(self, scanner: TrivyScanner) -> None:
        """The offline claim, checked rather than asserted in a docstring.

        Every scan runs under --network none, so a scan that completed is a scan that
        needed no network. If Trivy tried to update its database mid-scan it would fail
        here rather than quietly producing numbers nobody can reproduce.
        """
        sandbox = scanner._sandbox
        async with sandbox.workspace("trivy-offline") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-c")
            command = sandbox.build_command("image", ["x"], container_name="probe", workspace=space)
            assert command[command.index("--network") + 1] == "none"

            result = await scanner.scan_dependency_manifest(space, "requirements.txt")
            assert result.count > 0

    async def test_secret_mode_does_not_need_the_database(self, scanner: TrivyScanner) -> None:
        sandbox = scanner._sandbox
        async with sandbox.workspace("trivy-secret") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-c")
            result = await scanner.scan_filesystem(space, ".", mode=ScanMode.SECRET)

        assert result.database_version is None, "secret mode must not claim a database"
