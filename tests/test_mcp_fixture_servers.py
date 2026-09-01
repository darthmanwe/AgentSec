"""Fixture MCP server tests (AS-016, AS-017, AS-018).

The idempotency tests are the ones that matter. They assert that a repeated operation id
produces **one** effect while returning a result to both callers — which is the backend
half of at-most-once and the reason a Temporal retry (AS-022) can be safe.

Counting effects rather than checking a return value is deliberate: a server could return
a plausible-looking success while having mutated twice, and only the count would show it.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from agentsec.gateway.mcp_client import (
    McpBackend,
    McpBackendError,
    McpServerSpec,
    fake_cloud_spec,
    fake_jira_spec,
    session_scope,
    vuln_intel_spec,
)
from agentsec.mcp_servers._common import FixtureServerError, IdempotencyLedger
from agentsec.mcp_servers.fake_cloud import FakeCloud
from agentsec.mcp_servers.fake_jira import FakeJira
from agentsec.mcp_servers.vuln_intel import VulnerabilitySnapshot

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def cloud() -> FakeCloud:
    return FakeCloud.load(FIXTURES / "cloud" / "inventory.json")


@pytest.fixture
def jira() -> FakeJira:
    return FakeJira.load(FIXTURES / "jira" / "issues.json")


@pytest.fixture
def vuln() -> VulnerabilitySnapshot:
    return VulnerabilitySnapshot.load(FIXTURES / "vuln" / "snapshot.json")


# --------------------------------------------------------------- AS-017 vuln intel


def test_known_vulnerable_package_is_reported(vuln: VulnerabilitySnapshot) -> None:
    result = vuln.lookup_package("pypi", "pyyaml", "5.3.1")
    assert result["vulnerable"] is True
    assert result["vulnerabilities"][0]["id"] == "CVE-2020-14343"


def test_a_fixed_version_is_reported_clean(vuln: VulnerabilitySnapshot) -> None:
    """A corpus that only ever says "vulnerable" measures nothing; the negative case is
    what makes precision meaningful."""
    assert vuln.lookup_package("pypi", "pyyaml", "5.4")["vulnerable"] is False


def test_an_unknown_package_is_clean_not_an_error(vuln: VulnerabilitySnapshot) -> None:
    assert vuln.lookup_package("pypi", "not-a-real-package", "1.0.0")["vulnerable"] is False


def test_ecosystem_and_name_are_case_insensitive(vuln: VulnerabilitySnapshot) -> None:
    assert vuln.lookup_package("PyPI", "PyYAML", "5.3.1")["vulnerable"] is True


@pytest.mark.parametrize("version", ["not-a-version", "", "1.2.3; DROP TABLE", "../../etc"])
def test_malformed_version_is_rejected(vuln: VulnerabilitySnapshot, version: str) -> None:
    """Rejected rather than normalised. A version this server cannot parse means the
    caller and the snapshot disagree about what a version is, and guessing produces a
    confident wrong answer instead of an error."""
    with pytest.raises(FixtureServerError):
        vuln.lookup_package("pypi", "pyyaml", version)


@pytest.mark.parametrize("cve", ["CVE-123", "not-a-cve", "CVE-20XX-1234", ""])
def test_malformed_cve_is_rejected(vuln: VulnerabilitySnapshot, cve: str) -> None:
    with pytest.raises(FixtureServerError):
        vuln.lookup_cve(cve)


def test_cve_lookup_returns_a_record(vuln: VulnerabilitySnapshot) -> None:
    result = vuln.lookup_cve("cve-2020-14343")
    assert result["found"] is True
    assert result["record"]["severity"] == "high"


def test_unknown_cve_is_not_found_rather_than_an_error(vuln: VulnerabilitySnapshot) -> None:
    assert vuln.lookup_cve("CVE-1999-0001")["found"] is False


def test_every_response_carries_the_snapshot_version(vuln: VulnerabilitySnapshot) -> None:
    """A published result must be able to state exactly what data it was measured
    against. "The CVE database updated" is not an explanation anyone can check."""
    for result in (
        vuln.lookup_package("pypi", "pyyaml", "5.3.1"),
        vuln.lookup_cve("CVE-2020-14343"),
        vuln.lookup_advisory("GHSA-FIXTURE-0001"),
    ):
        assert result["provenance"]["snapshot"] == vuln.version
        assert result["provenance"]["trust"] == "untrusted"


def test_snapshot_is_committed_and_offline() -> None:
    """The whole point of AS-017: no network in the mandatory path."""
    document = json.loads((FIXTURES / "vuln" / "snapshot.json").read_text(encoding="utf-8"))
    assert document["snapshot_version"]
    assert document["packages"]


# --------------------------------------------------------------- AS-016 fake cloud


def test_reads_return_inventory(cloud: FakeCloud) -> None:
    listing = cloud.list_resources()
    assert {item["id"] for item in listing["resources"]} >= {"bucket-public-logs", "sg-web-tier"}
    assert cloud.get_resource("sg-web-tier")["resource"]["type"] == "security_group"


def test_filtering_by_type(cloud: FakeCloud) -> None:
    buckets = cloud.list_resources("storage_bucket")["resources"]
    assert all(item["type"] == "storage_bucket" for item in buckets)


def test_unknown_resource_is_an_error(cloud: FakeCloud) -> None:
    with pytest.raises(FixtureServerError, match="no such resource"):
        cloud.get_resource("does-not-exist")


def test_policy_documents_are_readable(cloud: FakeCloud) -> None:
    assert cloud.read_bucket_policy("bucket-public-logs")["bucket_policy"]["public_read"] is True
    assert cloud.read_security_group("sg-web-tier")["security_group"]["ingress"]
    assert cloud.read_iam_policy("role-ci-deployer")["iam_policy"]["statements"]


def test_remediation_mutates_the_resource(cloud: FakeCloud) -> None:
    assert cloud.read_bucket_policy("bucket-public-logs")["bucket_policy"]["public_read"] is True
    cloud.apply_remediation("bucket-public-logs", "block-public-read", operation_id="op-1")
    assert cloud.read_bucket_policy("bucket-public-logs")["bucket_policy"]["public_read"] is False


def test_repeated_operation_id_does_not_mutate_twice(cloud: FakeCloud) -> None:
    """The backend half of at-most-once. Counting effects rather than trusting the return
    value: a server could report success while having mutated twice."""
    first = cloud.apply_remediation("sg-web-tier", "close-ssh-to-world", operation_id="op-1")
    assert first["replayed"] is False
    assert cloud.applied_count == 1

    for _ in range(4):
        repeat = cloud.apply_remediation("sg-web-tier", "close-ssh-to-world", operation_id="op-1")
        assert repeat["replayed"] is True

    assert cloud.applied_count == 1, "a retry produced a second effect"


def test_a_different_operation_id_does_mutate_again(cloud: FakeCloud) -> None:
    """Idempotency is keyed on the operation, not on the arguments. Two deliberate
    applications are two operations and must both land."""
    cloud.apply_remediation("sg-web-tier", "close-ssh-to-world", operation_id="op-1")
    cloud.apply_remediation("sg-web-tier", "close-ssh-to-world", operation_id="op-2")
    assert cloud.applied_count == 2


def test_mutation_without_an_operation_id_is_refused(cloud: FakeCloud) -> None:
    with pytest.raises(FixtureServerError, match="operation_id is required"):
        cloud.apply_remediation("sg-web-tier", "close-ssh-to-world", operation_id="")


def test_remediation_type_mismatch_is_refused(cloud: FakeCloud) -> None:
    with pytest.raises(FixtureServerError, match="does not apply"):
        cloud.apply_remediation("sg-web-tier", "block-public-read", operation_id="op-1")


def test_unknown_remediation_is_refused(cloud: FakeCloud) -> None:
    with pytest.raises(FixtureServerError, match="no such remediation"):
        cloud.apply_remediation("sg-web-tier", "delete-everything", operation_id="op-1")


def test_cloud_reset_restores_the_baseline(cloud: FakeCloud) -> None:
    """Evaluation cases must not inherit a mutation from the case before them, or the
    benchmark measures ordering."""
    cloud.apply_remediation("bucket-public-logs", "block-public-read", operation_id="op-1")
    assert cloud.applied_count == 1

    cloud.reset()
    assert cloud.applied_count == 0
    assert cloud.read_bucket_policy("bucket-public-logs")["bucket_policy"]["public_read"] is True


def test_reset_clears_the_idempotency_ledger(cloud: FakeCloud) -> None:
    """Otherwise the next case's first call would be answered as a replay of the previous
    case's — silently skipping the effect it was meant to test."""
    cloud.apply_remediation("bucket-public-logs", "block-public-read", operation_id="op-1")
    cloud.reset()
    again = cloud.apply_remediation("bucket-public-logs", "block-public-read", operation_id="op-1")
    assert again["replayed"] is False
    assert cloud.applied_count == 1


# --------------------------------------------------------------- AS-018 fake jira


def test_reads_return_tickets(jira: FakeJira) -> None:
    assert jira.read_issue("proj-1")["issue"]["summary"] == "Login endpoint is slow under load"
    assert jira.search("pyyaml")["matches"]


def test_unknown_issue_is_an_error(jira: FakeJira) -> None:
    with pytest.raises(FixtureServerError, match="no such issue"):
        jira.read_issue("PROJ-999")


def test_ticket_text_is_labelled_untrusted(jira: FakeJira) -> None:
    """Ticket bodies are free text somebody else wrote, which is the shape of an indirect
    prompt injection. The label is how the planner's context keeps track."""
    assert jira.read_issue("PROJ-3")["provenance"]["trust"] == "untrusted"


def test_create_issue_adds_exactly_one(jira: FakeJira) -> None:
    before = jira.issue_count
    result = jira.create_issue("PROJ", "Fix SQLi in login", operation_id="op-1")
    assert result["created"] is True
    assert jira.issue_count == before + 1
    assert jira.read_issue(result["key"])["issue"]["summary"] == "Fix SQLi in login"


def test_repeated_create_produces_one_ticket(jira: FakeJira) -> None:
    before = jira.issue_count
    first = jira.create_issue("PROJ", "Fix SQLi in login", operation_id="op-1")
    for _ in range(4):
        repeat = jira.create_issue("PROJ", "Fix SQLi in login", operation_id="op-1")
        assert repeat["replayed"] is True
        assert repeat["key"] == first["key"], "a retry must return the original ticket"

    assert jira.issue_count == before + 1, "a retry created a second ticket"


def test_repeated_comment_produces_one_comment(jira: FakeJira) -> None:
    for _ in range(3):
        jira.comment("PROJ-1", "Reviewed and looks fine.", operation_id="op-1")
    assert len(jira.read_issue("PROJ-1")["issue"]["comments"]) == 1


def test_a_different_operation_id_creates_another_ticket(jira: FakeJira) -> None:
    before = jira.issue_count
    jira.create_issue("PROJ", "First", operation_id="op-1")
    jira.create_issue("PROJ", "Second", operation_id="op-2")
    assert jira.issue_count == before + 2


def test_write_without_an_operation_id_is_refused(jira: FakeJira) -> None:
    with pytest.raises(FixtureServerError, match="operation_id is required"):
        jira.create_issue("PROJ", "x", operation_id="")


def test_oversized_fields_are_refused(jira: FakeJira) -> None:
    with pytest.raises(FixtureServerError, match="summary exceeds"):
        jira.create_issue("PROJ", "x" * 300, operation_id="op-1")
    with pytest.raises(FixtureServerError, match="body exceeds"):
        jira.comment("PROJ-1", "y" * 9000, operation_id="op-2")


def test_commenting_on_a_missing_issue_is_refused(jira: FakeJira) -> None:
    with pytest.raises(FixtureServerError, match="no such issue"):
        jira.comment("PROJ-999", "hello", operation_id="op-1")


def test_jira_reset_restores_the_baseline(jira: FakeJira) -> None:
    before = jira.issue_count
    jira.create_issue("PROJ", "temporary", operation_id="op-1")
    jira.reset()
    assert jira.issue_count == before


# --------------------------------------------------------------- ledger


def test_ledger_reports_replay_status() -> None:
    ledger = IdempotencyLedger()
    assert ledger.get("op-1") is None
    stored = ledger.put("op-1", {"key": "PROJ-1"})
    assert stored["replayed"] is False
    replayed = ledger.get("op-1")
    assert replayed is not None
    assert replayed["replayed"] is True
    assert replayed["key"] == "PROJ-1"


def test_ledger_does_not_mutate_what_it_stores() -> None:
    """The stored result is returned to every caller; handing out a mutable reference
    would let one caller's edit change what a later retry sees."""
    ledger = IdempotencyLedger()
    original = {"key": "PROJ-1"}
    ledger.put("op-1", original)
    handed_out = ledger.get("op-1")
    assert handed_out is not None
    handed_out["key"] = "TAMPERED"
    assert ledger.get("op-1")["key"] == "PROJ-1"  # type: ignore[index]


# --------------------------------------------------------------- protocol round trips


@asynccontextmanager
async def connected(spec: McpServerSpec, tool: str) -> AsyncIterator[McpBackend]:
    """Open a session scope inside the test body.

    Not a pytest fixture: pytest-asyncio finalizes async-generator fixtures in a different
    task than it creates them, and the MCP client's anyio cancel scopes forbid that. The
    full finding is recorded in tests/test_mcp_fixture_repo.py.
    """
    async with session_scope(spec, tool_name=tool) as backend:
        yield backend


async def test_vuln_intel_over_the_protocol() -> None:
    spec = vuln_intel_spec(FIXTURES / "vuln" / "snapshot.json")
    async with connected(spec, "vuln_intel") as backend:
        assert set(await backend.list_operations()) == {
            "lookup_package",
            "lookup_cve",
            "lookup_advisory",
        }
        result = await backend.invoke(
            "vuln_intel",
            "lookup_package",
            {"ecosystem": "pypi", "name": "pyyaml", "version": "5.3.1"},
        )
        assert result["vulnerable"] is True
        assert result["provenance"]["snapshot"]


async def test_fake_cloud_over_the_protocol() -> None:
    spec = fake_cloud_spec(FIXTURES / "cloud" / "inventory.json")
    async with connected(spec, "fake_cloud") as backend:
        assert (await backend.invoke("fake_cloud", "list_resources", {}))["resources"]

        applied = await backend.invoke(
            "fake_cloud",
            "apply_remediation",
            {
                "resource_id": "bucket-public-logs",
                "remediation_id": "block-public-read",
                "operation_id": "op-1",
            },
        )
        assert applied["applied"] is True
        assert applied["replayed"] is False


async def test_idempotency_holds_across_the_protocol() -> None:
    """The property that makes a Temporal retry safe, proved over the wire rather than
    in-process. A repeat returns the original result and does not mutate again."""
    spec = fake_jira_spec(FIXTURES / "jira" / "issues.json")
    async with connected(spec, "fake_jira") as backend:
        first = await backend.invoke(
            "fake_jira",
            "create_issue",
            {"project": "PROJ", "summary": "Fix SQLi", "operation_id": "op-1"},
        )
        assert first["replayed"] is False

        for _ in range(3):
            repeat = await backend.invoke(
                "fake_jira",
                "create_issue",
                {"project": "PROJ", "summary": "Fix SQLi", "operation_id": "op-1"},
            )
            assert repeat["replayed"] is True
            assert repeat["key"] == first["key"]

        found = await backend.invoke("fake_jira", "search", {"query": "Fix SQLi"})
        assert len(found["matches"]) == 1, "a retry created a second ticket"


async def test_a_tool_error_crosses_the_protocol_as_an_error() -> None:
    """Not as content. A planner receiving "no such issue" as a successful result would
    reason over a failure as though it were data."""
    spec = fake_jira_spec(FIXTURES / "jira" / "issues.json")
    async with connected(spec, "fake_jira") as backend:
        with pytest.raises(McpBackendError):
            await backend.invoke("fake_jira", "read_issue", {"issue_key": "PROJ-999"})


async def test_each_scope_gets_fresh_state() -> None:
    """Session isolation across processes. Without it an evaluation case would inherit the
    previous case's mutations, and the benchmark would measure ordering."""
    spec = fake_jira_spec(FIXTURES / "jira" / "issues.json")
    async with connected(spec, "fake_jira") as first:
        await first.invoke(
            "fake_jira",
            "create_issue",
            {"project": "PROJ", "summary": "does this leak", "operation_id": "op-1"},
        )
        found = await first.invoke("fake_jira", "search", {"query": "does this leak"})
        assert len(found["matches"]) == 1

    async with connected(spec, "fake_jira") as second:
        found = await second.invoke("fake_jira", "search", {"query": "does this leak"})
        assert found["matches"] == [], "state leaked between server processes"
