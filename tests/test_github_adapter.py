"""GitHub adapter tests (AS-033).

Every test here runs against an in-process fake, so the suite needs no credentials and no
network — the AS-033 acceptance criterion. Optional live tests are marked ``live`` and
never run in CI.

**Read the names carefully.** None of them claims exactly-once, because GitHub's
issue-comment endpoint exposes no idempotency key and cannot provide it. What is claimed
and tested is at-most-once with reconciliation: the effect happens zero or one times, and
a retry whose predecessor succeeded finds its own marker instead of posting again.

Assertions count *comments on the fake*, not return values. A duplicate write that
returned a plausible object would satisfy a weaker test and be the exact bug this whole
mechanism exists to prevent.
"""

from __future__ import annotations

import datetime as dt

import httpx
import pytest

from agentsec.adapters.github import (
    MARKER_PREFIX,
    WRITE_SCOPE,
    CapabilityRequiredError,
    FakeGitHub,
    GitHubAdapter,
    GitHubError,
    Outcome,
    RepositoryNotAllowedError,
    operation_marker,
    require_allowed,
)
from agentsec.authz.capabilities import CapabilityClaims

pytestmark = pytest.mark.authz

ALLOWED = "darthmanwe/AgentSec"
OTHER = "someone-else/private-repo"
ALLOWLIST = frozenset({ALLOWED})
OPERATION = "wf-1:" + "a" * 64 + ":0"


def capability(
    *, resource: str = f"github://{ALLOWED}", scopes: tuple[str, ...] = (WRITE_SCOPE,)
) -> CapabilityClaims:
    now = dt.datetime.now(dt.UTC)
    return CapabilityClaims(
        jti="cap-1",
        subject="planner",
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest="a" * 64,
        request_hash="b" * 64,
        tool="github",
        resource=resource,
        scopes=scopes,
        key_id="k1",
        issued_at=now,
        expires_at=now + dt.timedelta(seconds=60),
    )


@pytest.fixture
def github() -> FakeGitHub:
    fake = FakeGitHub()
    fake.files[(ALLOWED, "src/main.py")] = "print('hello')\n"
    fake.files[(OTHER, "secrets.env")] = "TOKEN=should-never-be-read\n"
    fake.head_shas[(ALLOWED, 7)] = "c" * 40
    return fake


@pytest.fixture
def adapter(github: FakeGitHub) -> GitHubAdapter:
    return GitHubAdapter(
        allowlist=ALLOWLIST,
        token="not-a-real-token",
        client=httpx.AsyncClient(transport=github.transport()),
    )


# --------------------------------------------------------------------------- allowlist


async def test_a_read_cannot_cross_the_allowlist(adapter: GitHubAdapter) -> None:
    with pytest.raises(RepositoryNotAllowedError, match="not on the allowlist"):
        await adapter.read_file(OTHER, "secrets.env")


async def test_no_request_is_made_for_a_disallowed_repository(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """Denied before dispatch, not after. A check that runs after the request has already
    leaked the repository name and the token to a host outside the allowlist."""
    with pytest.raises(RepositoryNotAllowedError):
        await adapter.read_file(OTHER, "secrets.env")
    assert github.requests == []


@pytest.mark.parametrize(
    "repository",
    [
        "not-a-repo",
        "../../etc/passwd",
        "darthmanwe/AgentSec/../../other",
        "darthmanwe%2FAgentSec",
        "darthmanwe/AgentSec ",
        "",
    ],
)
def test_a_malformed_repository_is_rejected_before_the_allowlist(repository: str) -> None:
    with pytest.raises(RepositoryNotAllowedError):
        require_allowed(repository, ALLOWLIST)


def test_the_allowlist_is_an_enumeration_not_a_pattern() -> None:
    """A pattern like ``darthmanwe/*`` looks equivalent and is not: it silently grants
    every repository created afterwards, including one an attacker persuaded somebody to
    create."""
    with pytest.raises(RepositoryNotAllowedError):
        require_allowed("darthmanwe/some-other-repo", ALLOWLIST)


async def test_a_search_cannot_escape_its_repository(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """The repo qualifier is added by the adapter, so a caller writing their own
    ``repo:`` term cannot search across GitHub."""
    await adapter.search_code(ALLOWED, "password repo:someone-else/private-repo")

    query = github.requests[-1].query
    assert f"repo%3A{ALLOWED.replace('/', '%2F')}" in query or f"repo:{ALLOWED}" in query, query


# --------------------------------------------------------------------------- reads


async def test_a_file_reads_back(adapter: GitHubAdapter) -> None:
    content = await adapter.read_file(ALLOWED, "src/main.py")
    assert content.text == "print('hello')\n"
    assert content.repository == ALLOWED
    assert content.sha


async def test_a_missing_file_is_an_error_not_an_empty_string(adapter: GitHubAdapter) -> None:
    """An empty string would flow into the planner's context as "this file is empty",
    which is a different and confidently wrong claim."""
    with pytest.raises(GitHubError, match="404"):
        await adapter.read_file(ALLOWED, "does/not/exist.py")


async def test_the_head_sha_is_readable_as_an_approval_precondition(
    adapter: GitHubAdapter,
) -> None:
    """An approval granted against one head SHA must not authorise a comment on a branch
    that has since moved: the reviewer approved a diff, and the diff changed."""
    assert await adapter.pull_request_head_sha(ALLOWED, 7) == "c" * 40


# --------------------------------------------------------------------------- the write


async def test_a_comment_without_a_capability_cannot_even_be_expressed() -> None:
    """The structural form of "the LLM must never mint authority".

    The capability is a required keyword argument of a type only the authorization kernel
    produces. There is no overload, no default, and no bypass flag.
    """
    import inspect

    signature = inspect.signature(GitHubAdapter.comment_on_pull_request)
    parameter = signature.parameters["capability"]
    assert parameter.default is inspect.Parameter.empty, "a capability must never default"
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


async def test_a_capability_without_the_write_scope_is_refused(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    with pytest.raises(CapabilityRequiredError, match=WRITE_SCOPE):
        await adapter.comment_on_pull_request(
            ALLOWED,
            7,
            "findings",
            capability=capability(scopes=("github:read",)),
            operation_id=OPERATION,
        )
    assert github.comment_count(ALLOWED, 7) == 0


async def test_a_capability_for_another_repository_is_refused(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """Holding a capability is not enough; it has to be the right one. A grant bound to a
    different resource is exactly what a confused-deputy attack produces."""
    with pytest.raises(CapabilityRequiredError, match="bound to"):
        await adapter.comment_on_pull_request(
            ALLOWED,
            7,
            "findings",
            capability=capability(resource=f"github://{OTHER}"),
            operation_id=OPERATION,
        )
    assert github.comment_count(ALLOWED, 7) == 0


async def test_an_approved_comment_is_posted(adapter: GitHubAdapter, github: FakeGitHub) -> None:
    comment = await adapter.comment_on_pull_request(
        ALLOWED,
        7,
        "Found a SQL injection in src/main.py",
        capability=capability(),
        operation_id=OPERATION,
    )

    assert comment.outcome is Outcome.CREATED
    assert github.comment_count(ALLOWED, 7) == 1
    assert comment.external_ref


async def test_the_operation_marker_is_hidden_and_does_not_leak_the_operation_id(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """An operation id contains the workflow id and the action digest, and a public
    comment is not the place to publish either."""
    await adapter.comment_on_pull_request(
        ALLOWED, 7, "findings", capability=capability(), operation_id=OPERATION
    )
    body = github.comments[(ALLOWED, 7)][0]["body"]

    assert MARKER_PREFIX in body
    assert body.strip().endswith("-->"), (
        "the marker must be an HTML comment, so it renders as nothing"
    )
    assert OPERATION not in body
    assert "a" * 64 not in body


# ------------------------------------------------- at-most-once with reconciliation


async def test_a_retry_of_the_same_operation_produces_one_comment(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """The claim, measured on the backend rather than in a return value.

    Not "exactly once": GitHub cannot provide that. What is shown is that the second
    attempt finds its own marker and reconciles, so the number of comments stays at one.
    """
    first = await adapter.comment_on_pull_request(
        ALLOWED, 7, "findings", capability=capability(), operation_id=OPERATION
    )
    second = await adapter.comment_on_pull_request(
        ALLOWED, 7, "findings", capability=capability(), operation_id=OPERATION
    )

    assert first.outcome is Outcome.CREATED
    assert second.outcome is Outcome.RECONCILED
    assert second.id == first.id
    assert github.comment_count(ALLOWED, 7) == 1


async def test_a_retry_after_a_lost_acknowledgement_does_not_duplicate(
    github: FakeGitHub,
) -> None:
    """The fault this mechanism exists for.

    The comment is written and the response is dropped, so the caller has no idea whether
    the effect happened. A naive retry posts a second comment; this one finds the marker.
    """
    github.fail_after_write = True
    adapter = GitHubAdapter(
        allowlist=ALLOWLIST, client=httpx.AsyncClient(transport=github.transport())
    )

    with pytest.raises(GitHubError, match="502"):
        await adapter.comment_on_pull_request(
            ALLOWED, 7, "findings", capability=capability(), operation_id=OPERATION
        )
    assert github.comment_count(ALLOWED, 7) == 1, "the write did land, the answer was lost"

    github.fail_after_write = False
    recovered = await adapter.comment_on_pull_request(
        ALLOWED, 7, "findings", capability=capability(), operation_id=OPERATION
    )

    assert recovered.outcome is Outcome.RECONCILED
    assert github.comment_count(ALLOWED, 7) == 1, "the retry must not add a second comment"


async def test_a_different_operation_posts_its_own_comment(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """Two intentionally distinct actions are two effects. A marker scheme that merged
    them would silently lose the second, which is the mirror-image bug."""
    await adapter.comment_on_pull_request(
        ALLOWED, 7, "first", capability=capability(), operation_id="wf-1:" + "a" * 64 + ":0"
    )
    await adapter.comment_on_pull_request(
        ALLOWED, 7, "second", capability=capability(), operation_id="wf-1:" + "a" * 64 + ":1"
    )
    assert github.comment_count(ALLOWED, 7) == 2


async def test_changing_the_body_under_the_same_operation_does_not_post_again(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    """A mutated argument must not ride an existing operation's identity.

    The adapter reconciles on the marker, so the altered body is *not* written — and the
    authorization kernel is what actually refuses the mutation, because a changed argument
    changes the action digest and therefore needs its own approval (AS-007, AS-010).
    """
    await adapter.comment_on_pull_request(
        ALLOWED, 7, "original findings", capability=capability(), operation_id=OPERATION
    )
    second = await adapter.comment_on_pull_request(
        ALLOWED, 7, "TAMPERED", capability=capability(), operation_id=OPERATION
    )

    assert second.outcome is Outcome.RECONCILED
    assert github.comment_count(ALLOWED, 7) == 1
    assert "TAMPERED" not in github.comments[(ALLOWED, 7)][0]["body"]


def test_markers_are_distinct_per_operation() -> None:
    assert operation_marker("wf-1:x:0") != operation_marker("wf-1:x:1")
    assert operation_marker("wf-1:x:0") == operation_marker("wf-1:x:0")


async def test_an_oversized_body_is_refused_before_dispatch(
    adapter: GitHubAdapter, github: FakeGitHub
) -> None:
    with pytest.raises(GitHubError, match="exceeds"):
        await adapter.comment_on_pull_request(
            ALLOWED, 7, "x" * 70_000, capability=capability(), operation_id=OPERATION
        )
    assert github.comment_count(ALLOWED, 7) == 0


# --------------------------------------------------------------------------- credentials


def test_the_adapter_exposes_no_way_to_read_its_token() -> None:
    """Structural, not a promise. The token is held for the transport and there is no
    method that returns it, so it cannot reach a planner or a result."""
    adapter = GitHubAdapter(allowlist=ALLOWLIST, token="ghp_secret")
    public = [name for name in dir(adapter) if not name.startswith("_")]
    for name in public:
        attribute = getattr(adapter, name)
        assert "ghp_secret" not in str(attribute), name


def test_the_suite_needs_no_credentials() -> None:
    """The AS-033 acceptance criterion. Every test above drives an in-process fake."""
    fake = FakeGitHub()
    adapter = GitHubAdapter(
        allowlist=ALLOWLIST, client=httpx.AsyncClient(transport=fake.transport())
    )
    # Reaching past the public API deliberately: the point is that a token absent from
    # the constructor is absent from the wire, which no public method can show.
    assert "Authorization" not in adapter._headers
