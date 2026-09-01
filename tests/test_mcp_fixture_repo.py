"""Fixture repository MCP server tests (AS-015).

Two layers, and both are needed:

* **Containment unit tests** run in-process and are exhaustive about path handling. This
  is where traversal, symlinks and null bytes are covered.
* **Protocol tests** spawn a real server subprocess and talk MCP to it. These are the
  spike: they prove the round trip works on Windows stdio, which is the platform where it
  was most likely not to.

The containment tests matter even though the gateway authorizes every call first. A
compromised gateway is inside the threat model; the server's job is that even then, the
blast radius stops at the assigned repository.
"""

from __future__ import annotations

import pathlib
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from agentsec.gateway.mcp_client import (
    McpBackend,
    McpBackendError,
    McpServerSpec,
    extract_payload,
    fixture_repo_spec,
    session_scope,
)
from agentsec.mcp_servers.fixture_repo import (
    MAX_FILE_BYTES,
    ContainmentError,
    FixtureRepository,
)

CORPUS = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "repos"


@pytest.fixture
def repo_a() -> FixtureRepository:
    return FixtureRepository(CORPUS, "repo-a")


# --------------------------------------------------------------------------- containment


def test_reads_a_file_in_the_assigned_repository(repo_a: FixtureRepository) -> None:
    result = repo_a.read_file("src/main.py")
    assert "SELECT" in result["content"]
    assert result["provenance"]["trust"] == "untrusted"


@pytest.mark.parametrize(
    "path",
    [
        "../repo-b/app/handler.py",
        "../../etc/passwd",
        "src/../../repo-b/app/handler.py",
        "./../../repo-b/app/handler.py",
    ],
)
def test_traversal_out_of_the_repository_is_refused(repo_a: FixtureRepository, path: str) -> None:
    with pytest.raises(ContainmentError, match="escapes"):
        repo_a.read_file(path)


def test_the_other_repository_is_unreachable(repo_a: FixtureRepository) -> None:
    """Assignment scoping, stated as the thing it actually prevents."""
    with pytest.raises(ContainmentError):
        repo_a.read_file("../repo-b/app/handler.py")

    listing = repo_a.list_files(".")
    assert all("repo-b" not in entry["path"] for entry in listing["files"])


def test_absolute_paths_are_contained(repo_a: FixtureRepository) -> None:
    """An absolute path joined to the root still resolves inside it on POSIX; on Windows
    it escapes. Either way the resolved-path check is what decides, not the string."""
    target = str(CORPUS / "repo-b" / "app" / "handler.py")
    with pytest.raises(ContainmentError):
        repo_a.read_file(target)


def test_null_bytes_are_refused(repo_a: FixtureRepository) -> None:
    with pytest.raises(ContainmentError, match="null byte"):
        repo_a.read_file("src/main.py\x00.txt")


def test_symlink_escape_is_refused(tmp_path: pathlib.Path) -> None:
    """The check that matters. A traversal check on the literal string is defeated by a
    symlink; resolving first is what catches it."""
    corpus = tmp_path / "corpus"
    (corpus / "inside").mkdir(parents=True)
    (corpus / "inside" / "ok.txt").write_text("fine", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("should not be readable", encoding="utf-8")

    link = corpus / "inside" / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform/account")

    repository = FixtureRepository(corpus, "inside")
    assert repository.read_file("ok.txt")["content"] == "fine"

    with pytest.raises(ContainmentError, match="escapes"):
        repository.read_file("escape/secret.txt")


def test_assignment_outside_the_corpus_fails_at_startup(tmp_path: pathlib.Path) -> None:
    """A launcher pointed at ".." must fail immediately rather than serve the filesystem."""
    corpus = tmp_path / "corpus"
    (corpus / "repo").mkdir(parents=True)
    with pytest.raises(ContainmentError, match="not inside the corpus"):
        FixtureRepository(corpus, "../..")


def test_missing_corpus_root_fails_at_startup(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ContainmentError, match="does not exist"):
        FixtureRepository(tmp_path / "nope", "repo-a")


def test_oversized_file_is_refused(tmp_path: pathlib.Path) -> None:
    """Refused before reading, so the server does not materialise a huge file into memory
    ahead of the gateway's own ceiling."""
    corpus = tmp_path / "corpus"
    (corpus / "repo").mkdir(parents=True)
    (corpus / "repo" / "big.txt").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    with pytest.raises(ContainmentError, match="over the"):
        FixtureRepository(corpus, "repo").read_file("big.txt")


def test_directory_read_is_refused(repo_a: FixtureRepository) -> None:
    with pytest.raises(ContainmentError, match="not a file"):
        repo_a.read_file("src")


def test_search_finds_matches_with_line_numbers(repo_a: FixtureRepository) -> None:
    result = repo_a.search_code("SELECT")
    assert result["matches"]
    assert all(match["line"] > 0 for match in result["matches"])
    assert all("repo-b" not in match["path"] for match in result["matches"])


def test_search_rejects_an_empty_query(repo_a: FixtureRepository) -> None:
    with pytest.raises(ContainmentError, match="must not be empty"):
        repo_a.search_code("")


def test_search_result_count_is_bounded(repo_a: FixtureRepository) -> None:
    assert len(repo_a.search_code("e", max_results=2)["matches"]) <= 2


# --------------------------------------------------------------------------- protocol


@asynccontextmanager
async def connected(repo: str = "repo-a") -> AsyncIterator[McpBackend]:
    """Open a real server subprocess for the duration of one test.

    Deliberately a helper rather than a pytest fixture, and this is a spike finding worth
    keeping. An async-generator fixture wrapping this fails at teardown with "Attempted to
    exit cancel scope in a different task than it was entered in": the MCP stdio client is
    built on anyio cancel scopes, which must be entered and exited in the same task, and
    pytest-asyncio does not guarantee that for generator fixtures at any scope.

    Opening the scope inside the test body makes enter and exit the same task by
    construction. It also matches how the evaluation harness will use it - one fresh scope
    per case, so stateful backends cannot leak between them.
    """
    async with session_scope(fixture_repo_spec(CORPUS, repo), tool_name="fixture_repo") as backend:
        yield backend


async def test_the_protocol_round_trip_works() -> None:
    async with connected() as backend:
        """The AS-015 spike, as a standing test. mcp 2.x is barely a month old and Windows
        stdio is where this was most likely to fail."""
        result = await backend.invoke("fixture_repo", "read_file", {"path": "src/main.py"})
        assert "SELECT" in result["content"]


async def test_server_advertises_its_operations() -> None:
    async with connected() as backend:
        """Read for diagnostics only. The trusted registry decides what may be called; a
        server's self-description is the channel a poisoned server would use."""
        assert set(await backend.list_operations()) == {"list_files", "read_file", "search_code"}


async def test_session_negotiates_a_protocol_version() -> None:
    async with connected() as backend:
        assert backend.session.protocol_version


async def test_list_files_over_the_protocol() -> None:
    async with connected() as backend:
        listing = await backend.invoke("fixture_repo", "list_files", {"path": "."})
        paths = {entry["path"] for entry in listing["files"]}
        assert "src/main.py" in paths
        assert not any("repo-b" in path for path in paths)


async def test_search_over_the_protocol() -> None:
    async with connected() as backend:
        found = await backend.invoke("fixture_repo", "search_code", {"query": "SELECT"})
        assert found["matches"]


async def test_traversal_over_the_protocol_is_an_error_not_data() -> None:
    async with connected() as backend:
        """Containment holds across the protocol boundary, and the failure surfaces as an
        error rather than as content the planner might treat as a successful read."""
        with pytest.raises(McpBackendError):
            await backend.invoke("fixture_repo", "read_file", {"path": "../repo-b/app/handler.py"})


async def test_provenance_survives_the_protocol() -> None:
    async with connected() as backend:
        """The trust label has to make it across the wire, or the planner's context loses
        track of where the text came from."""
        result = await backend.invoke("fixture_repo", "read_file", {"path": "README.md"})
        assert result["provenance"]["trust"] == "untrusted"
        assert result["provenance"]["source"].startswith("fixture://repo-a")


async def test_backend_refuses_to_serve_another_tool() -> None:
    async with connected() as backend:
        with pytest.raises(McpBackendError, match="was asked to serve"):
            await backend.invoke("fake_jira", "read_issue", {"issue_key": "PROJ-1"})


async def test_a_second_scope_gets_a_separate_server() -> None:
    """Session isolation. Evaluation cases take a fresh scope each, because stateful
    backends leaking between cases would make the benchmark measure ordering."""
    async with session_scope(
        fixture_repo_spec(CORPUS, "repo-b"), tool_name="fixture_repo"
    ) as other:
        result = await other.invoke("fixture_repo", "read_file", {"path": "app/handler.py"})
        assert "repo-b-should-not-be-readable" in result["content"]


async def test_a_server_assigned_to_repo_a_cannot_serve_repo_b() -> None:
    """The same scoping, proved across the protocol rather than in-process."""
    async with session_scope(
        fixture_repo_spec(CORPUS, "repo-a"), tool_name="fixture_repo"
    ) as scoped:
        with pytest.raises(McpBackendError):
            await scoped.invoke("fixture_repo", "read_file", {"path": "../repo-b/app/handler.py"})


# --------------------------------------------------------------------------- client


def test_spec_uses_the_running_interpreter() -> None:
    """ "python" on PATH is frequently not the interpreter running this process, and the
    server would start without the project's dependencies."""
    spec = McpServerSpec.python_module("agentsec.mcp_servers.fixture_repo")
    assert spec.command == sys.executable
    assert spec.args[:2] == ["-m", "agentsec.mcp_servers.fixture_repo"]


def test_extract_payload_unwraps_structured_content() -> None:
    result = SimpleNamespace(
        is_error=False, structured_content={"result": {"content": "hello"}}, content=[]
    )
    assert extract_payload(result) == {"content": "hello"}


def test_extract_payload_returns_structured_content_unwrapped_when_not_boxed() -> None:
    result = SimpleNamespace(is_error=False, structured_content={"a": 1, "b": 2}, content=[])
    assert extract_payload(result) == {"a": 1, "b": 2}


def test_extract_payload_falls_back_to_text() -> None:
    block = SimpleNamespace(type="text", text='{"content": "hello"}')
    result = SimpleNamespace(is_error=False, structured_content=None, content=[block])
    assert extract_payload(result) == {"content": "hello"}


def test_extract_payload_returns_plain_text_when_not_json() -> None:
    block = SimpleNamespace(type="text", text="just a string")
    result = SimpleNamespace(is_error=False, structured_content=None, content=[block])
    assert extract_payload(result) == "just a string"


def test_extract_payload_raises_on_a_tool_error() -> None:
    """A tool error must surface as an exception, not as content the planner could read
    as a successful result."""
    block = SimpleNamespace(type="text", text="path escapes the assigned repository")
    result = SimpleNamespace(is_error=True, structured_content=None, content=[block])
    with pytest.raises(McpBackendError, match="escapes"):
        extract_payload(result)


def test_extract_payload_raises_when_there_is_no_content() -> None:
    result = SimpleNamespace(is_error=False, structured_content=None, content=[])
    with pytest.raises(McpBackendError, match="no content"):
        extract_payload(result)


# ------------------------------------------------- gateway over a real MCP server


async def test_authorized_read_flows_through_the_gateway_to_a_real_server() -> None:
    """AS-014 and AS-015 together: capability verification, redemption, and dispatch over
    the actual protocol to a subprocess.

    Everything before this proved the pieces. This proves the seam.
    """

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from agentsec.authz.capabilities import (
        CapabilityMinter,
        CapabilityRedeemer,
        CapabilityVerifier,
        compute_request_hash,
    )
    from agentsec.authz.digest import canonicalize
    from agentsec.authz.keys import SigningKey, VerificationKeyring
    from agentsec.authz.models import (
        ActionIntent,
        Principal,
        PrincipalKind,
        ResourceRef,
        RiskClass,
        TrustLevel,
    )
    from agentsec.db.base import Base
    from agentsec.gateway.core import DispatchRequest, GatewayDenial, McpGateway
    from agentsec.gateway.registry import load_registry

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
    registry = load_registry()
    planner = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1")
    intent = ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
    )
    action = canonicalize(planner, intent, workflow_id="wf-1")

    async with factory() as db, connected() as backend:
        gateway = McpGateway(
            registry=registry,
            verifier=CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key)),
            redeemer=CapabilityRedeemer(db),
            backends={"fixture_repo": backend},
        )
        token = CapabilityMinter(key).mint(
            subject=planner.id,
            audience="agentsec-gateway",
            environment="local",
            workflow_id="wf-1",
            action_digest=action.digest,
            request_hash=compute_request_hash(action.arguments),
            tool="fixture_repo",
            resource=intent.resource.uri,
            scopes=("repo:read",),
            ttl_seconds=60,
            registry_hash=registry.hash,
        )

        allowed = await gateway.dispatch(
            DispatchRequest(
                principal=planner,
                intent=intent,
                workflow_id="wf-1",
                capability_token=token,
                operation_id="op-1",
                run_id="run-1",
            )
        )
        assert allowed.ok is True
        assert allowed.result is not None
        assert "SELECT" in allowed.result.payload["content"]
        assert allowed.result.trust is TrustLevel.UNTRUSTED

        # And the same server, reached without a capability, returns nothing at all.
        refused = await gateway.dispatch(
            DispatchRequest(
                principal=planner,
                intent=intent,
                workflow_id="wf-1",
                capability_token=None,
                operation_id="op-2",
                run_id="run-1",
            )
        )
        assert refused.denial is GatewayDenial.NO_CAPABILITY
        assert refused.reached_backend is False

    await engine.dispose()
