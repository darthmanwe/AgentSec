"""The approval UI (AS-042).

A human-facing front end for the same ``ApprovalService`` the ``agentsec approve`` CLI
drives. It **consumes** that path rather than replacing it: two ways to record a decision
would be two places for the authorization rules to drift apart, and the CLI is the one
with the test suite.

This page renders attacker-controlled text on purpose. The evidence panel shows the
untrusted context an action was proposed from — repository READMEs, code comments, issue
text, tool output — which in the evaluation corpus is a set of prompt-injection payloads
written specifically to manipulate whoever reads them. An XSS in the approval UI of a
prompt-injection defence project would be the single most quotable failure available, so
escaping here is a security control rather than presentation.

Four defences, because escaping alone has been enough for nobody:

1. **Every interpolation is escaped where it is interpolated.** There is no template
   engine and no "safe" marker to forget. :func:`e` is the only way text reaches the page.
2. **A Content-Security-Policy that allows almost nothing.** No scripts from anywhere, no
   images, no frames, no external anything. The page needs none of it, and a policy that
   permits nothing cannot be bypassed by an escaping bug. This is the defence that holds
   when the first one fails.
3. **Origin checked on every state-changing request**, alongside a per-session CSRF token
   compared in constant time. A form post from a malicious page must not approve an action.
4. **Nothing ever renders as HTML.** The evidence panel is plain text in a ``<pre>``.
   Markdown rendering would reintroduce the entire problem for a formatting nicety no
   operator needs while deciding whether to authorize a production change.

Demo-grade authentication, as the threat model states: a shared operator token compared in
constant time, where no configured token authenticates nobody rather than everybody.
"""

from __future__ import annotations

import datetime as dt
import hmac
import html
import secrets
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from agentsec.authz.approvals import ApprovalError, ApprovalService, authenticate_operator
from agentsec.config import Settings, load_settings
from agentsec.db.models import Approval, ApprovalState, Run
from agentsec.log import get_logger

log = get_logger("agentsec.ui")

#: ``style-src 'unsafe-inline'`` is the single concession, for the one inline stylesheet.
#: It cannot execute anything: script-src inherits ``default-src 'none'``, so even a
#: successful injection has nothing to run with.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

SESSION_COOKIE = "agentsec_session"
CSRF_FIELD = "csrf_token"

_STYLE = (
    "body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:52rem;padding:0 1rem}"
    "table{border-collapse:collapse;width:100%}"
    "td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
    "pre{background:#f6f6f6;padding:.75rem;overflow-x:auto;white-space:pre-wrap;"
    "word-break:break-word}"
    ".warn{border-left:4px solid #b40;background:#fff6f2;padding:.75rem}"
    "button{font:inherit;padding:.4rem .9rem}"
)


def e(value: Any) -> str:
    """Escape anything for HTML text or an attribute value.

    The only route by which text reaches the page. ``quote=True`` always, so one function
    is correct in both positions — a separate "for attributes" variant would be a second
    thing to pick wrongly.
    """
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str) -> str:
    """Wrap already-escaped content in the shell."""
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>{e(title)}</title><style>{_STYLE}</style></head><body>"
        f"{body}</body></html>"
    )


def _html(content: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(content, status_code=status, headers=dict(SECURITY_HEADERS))


# --------------------------------------------------------------------------- auth


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _expected_token(request: Request) -> str | None:
    secret = _settings(request).operator_token
    return secret.get_secret_value() if secret is not None else None


def _operator(request: Request) -> Any:
    """Authenticate from the server-side session.

    The token lives in the session rather than being resubmitted per request, so it does
    not end up in a URL, a log line or a Referer header.
    """
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    session = request.app.state.sessions.get(session_id)
    if session is None:
        return None
    return authenticate_operator(session["token"], _expected_token(request))


def _csrf_ok(request: Request, presented: str | None) -> bool:
    """Origin *and* token. Either alone has known gaps."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin:
        host = urlparse(origin).netloc
        if host and host != request.headers.get("host"):
            log.warning("cross-origin state change refused", origin=host)
            return False

    session_id = request.cookies.get(SESSION_COOKIE)
    session = request.app.state.sessions.get(session_id) if session_id else None
    if session is None or not presented:
        return False
    return hmac.compare_digest(str(session["csrf"]), presented)


# --------------------------------------------------------------------------- views


def _login_page(message: str = "") -> str:
    warning = f'<p class="warn">{e(message)}</p>' if message else ""
    return _page(
        "AgentSec — sign in",
        "<h1>AgentSec approvals</h1>"
        + warning
        + '<form method=post action="/login">'
        "<p><label>Operator token <input type=password name=token autocomplete=off></label></p>"
        "<p><button type=submit>Sign in</button></p></form>"
        "<p><small>Demo-grade authentication: a shared token, as the threat model states. "
        "Not an auth product.</small></p>",
    )


async def login_form(request: Request) -> Response:
    return _html(_login_page())


async def login(request: Request) -> Response:
    form = await request.form()
    token = str(form.get("token") or "")
    if authenticate_operator(token, _expected_token(request)) is None:
        # Deliberately does not say which of the two was wrong.
        return _html(_login_page("Not authenticated."), status=401)

    session_id = secrets.token_urlsafe(32)
    request.app.state.sessions[session_id] = {"token": token, "csrf": secrets.token_urlsafe(32)}
    response = RedirectResponse("/", status_code=303, headers=dict(SECURITY_HEADERS))
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


async def index(request: Request) -> Response:
    if _operator(request) is None:
        return _html(_login_page(), status=401)

    rows: list[str] = []
    async with request.app.state.session_factory() as session:
        statement = (
            select(Approval)
            .where(Approval.state == ApprovalState.PENDING)
            .order_by(Approval.created_at.desc())
            .limit(100)
        )
        for approval in (await session.execute(statement)).scalars():
            rows.append(
                "<tr>"
                f'<td><a href="/approval/{e(approval.id)}">{e(approval.id)}</a></td>'
                f"<td>{e(approval.run_id)}</td>"
                f"<td><code>{e(approval.action_digest[:16])}</code></td>"
                f"<td>{e(approval.expires_at)}</td>"
                "</tr>"
            )

    table = (
        "<table><tr><th>Approval<th>Run<th>Digest<th>Expires</tr>" + "".join(rows) + "</table>"
        if rows
        else "<p>Nothing awaiting a decision.</p>"
    )
    return _html(_page("AgentSec — pending approvals", "<h1>Pending approvals</h1>" + table))


def _render_evidence(evidence_refs: Any) -> str:
    """Flatten the recorded evidence into plain text.

    Returns text, never markup. The caller escapes it, and it goes inside a ``<pre>``.
    """
    items = evidence_refs.get("items") if isinstance(evidence_refs, dict) else None
    if not isinstance(items, list):
        return ""
    return "\n\n".join(
        f"--- {item.get('source', '?')} [{item.get('trust', '?')}] ---\n{item.get('content', '')}"
        for item in items
        if isinstance(item, dict)
    )


async def detail(request: Request) -> Response:
    if _operator(request) is None:
        return _html(_login_page(), status=401)

    approval_id = str(request.path_params["approval_id"])
    async with request.app.state.session_factory() as session:
        approval = await session.get(Approval, approval_id)
        if approval is None:
            return _html(_page("Not found", "<h1>No such approval</h1>"), status=404)
        run = await session.get(Run, approval.run_id)
        task = run.task if run else ""
        repository = run.repository if run else ""
        evidence = _render_evidence(approval.evidence_refs)
        state = approval.state.value
        digest = approval.action_digest
        context_digest = approval.approval_context_digest
        expires_at = approval.expires_at

    session_id = request.cookies.get(SESSION_COOKIE)
    csrf = request.app.state.sessions[session_id]["csrf"]

    body = (
        f"<h1>Approval {e(approval_id)}</h1>"
        "<table>"
        f"<tr><th>Task<td>{e(task)}</tr>"
        f"<tr><th>Repository<td>{e(repository)}</tr>"
        f"<tr><th>Action digest<td><code>{e(digest)}</code></tr>"
        f"<tr><th>Evidence digest<td><code>{e(context_digest)}</code></tr>"
        f"<tr><th>State<td>{e(state)}</tr>"
        f"<tr><th>Expires<td>{e(expires_at)}</tr>"
        "</table>"
        '<p class="warn">The evidence below is <strong>untrusted input</strong>. It may '
        "contain text written to manipulate whoever reads it. It is shown so you can judge "
        "the action, and it is never an instruction.</p>"
        f"<h2>Evidence</h2><pre>{e(evidence)}</pre>"
        f'<form method=post action="/approval/{e(approval_id)}/decide">'
        f'<input type=hidden name="{CSRF_FIELD}" value="{e(csrf)}">'
        "<p><label>Note <input name=note maxlength=200></label></p>"
        "<p><button type=submit name=decision value=approve>Approve this exact action</button> "
        "<button type=submit name=decision value=deny>Deny</button></p>"
        "</form>"
    )
    return _html(_page(f"Approval {approval_id}", body))


async def decide(request: Request) -> Response:
    operator = _operator(request)
    if operator is None:
        return _html(_login_page(), status=401)

    form = await request.form()
    if not _csrf_ok(request, str(form.get(CSRF_FIELD) or "")):
        return _html(
            _page("Refused", "<h1>Request refused</h1><p>Origin or token check failed.</p>"),
            status=403,
        )

    approved = str(form.get("decision")) == "approve"
    approval_id = str(request.path_params["approval_id"])
    note = str(form.get("note") or "")[:200]

    async with request.app.state.session_factory() as session:
        service = ApprovalService(session)
        try:
            await service.decide(
                approval_id, approver=operator, approved=approved, note=note or None
            )
        except ApprovalError as error:
            # Commit rather than roll back, for the same reason the CLI does: deciding a
            # lapsed approval marks it EXPIRED and *then* raises, and discarding that would
            # leave the row PENDING forever.
            await session.commit()
            return _html(
                _page("Refused", f"<h1>Could not record the decision</h1><p>{e(error)}</p>"),
                status=409,
            )
        await session.commit()

    log.info(
        "approval decided from the UI",
        approval_id=approval_id,
        approved=approved,
        operator=operator.id,
    )
    return RedirectResponse("/", status_code=303, headers=dict(SECURITY_HEADERS))


def create_app(settings: Settings | None = None, session_factory: Any = None) -> Starlette:
    """Build the application.

    ``session_factory`` is injected so tests drive the real views against a real
    ``ApprovalService`` on SQLite, rather than asserting against a mocked page. An XSS test
    against a mock proves nothing about the page an operator loads.
    """
    resolved = settings or load_settings()
    app = Starlette(
        routes=[
            Route("/", index),
            Route("/login", login_form),
            Route("/login", login, methods=["POST"]),
            Route("/approval/{approval_id}", detail),
            Route("/approval/{approval_id}/decide", decide, methods=["POST"]),
        ]
    )
    app.state.settings = resolved
    app.state.sessions = {}
    if session_factory is not None:
        app.state.session_factory = session_factory
    else:  # pragma: no cover - exercised by the runnable server, not by tests
        from agentsec.db.session import create_engine, create_session_factory

        app.state.session_factory = create_session_factory(create_engine(resolved))
    app.state.started_at = dt.datetime.now(dt.UTC)
    return app


__all__ = ["CONTENT_SECURITY_POLICY", "SECURITY_HEADERS", "create_app", "e"]
